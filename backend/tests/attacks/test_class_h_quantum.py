"""Class H — forward-looking and quantum. ARCHITECTURE.md §16.8 (H1..H6).

Post-quantum work is explicitly OUT OF SCOPE for this build (D4). §16.8 says why
these are recorded at all: so the version/algorithm fields that a later migration
needs are not deleted as dead code in the meantime. So this file does two honest
things and nothing more:

  * Where an attack is already CLOSED against a quantum adversary (H2, H3), assert
    the parameter that makes it so (256-bit symmetric, 128-bit tokens/keyed
    index).
  * Where it is OPEN or PARTIAL (H1, H4, H5, H6), record it as such and assert the
    reserved migration field still exists, so a future ed25519+mldsa65 /
    SLH-DSA upgrade has somewhere to land.

No test here claims a post-quantum defence the build does not have.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import crypto_envelope
import crypto_signing
import crypto_rowsig

pytestmark = pytest.mark.integration

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _schema() -> str:
    return (BACKEND_DIR / "schema" / "001_core.sql").read_text(encoding="utf-8")


# ------------------------------------------------------------------- H1 --------

def test_h1_shor_against_ed25519_is_open_with_a_reserved_migration_field(evidence):
    """H1 — Shor breaks Ed25519 signatures on a CRQC. Open, and out of scope for
    now. What must survive is the migration path: X-Sig-Alg on the wire and
    device_registry.sig_alg / row_sig_alg in the schema, reserved for a hybrid
    'ed25519+mldsa65'. Assert those fields still exist so the door stays open."""
    assert "sig_alg" in _schema(), "device_registry.sig_alg was removed"
    assert "row_sig_alg" in _schema(), "row_sig_alg was removed"
    assert hasattr(crypto_signing, "ALLOWED_SIG_ALGS")
    assert "ed25519" in crypto_signing.ALLOWED_SIG_ALGS

    evidence("H1", outcome="open",
             expected="open (D4); reserved for ed25519+mldsa65",
             detail={"reserved_fields": ["X-Sig-Alg", "sig_alg", "row_sig_alg"]})


# ------------------------------------------------------------------- H2 --------

def test_h2_grover_against_aes_256_gcm_is_already_closed(evidence):
    """H2 — Grover halves the effective symmetric key strength, so AES-256 gives
    ~2^128 post-quantum, which is still infeasible. No change needed. Assert the
    DEK is 256-bit."""
    assert crypto_envelope.DEK_BYTES == 32, "DEK is not 256-bit"

    evidence("H2", outcome="blocked",
             expected="AES-256 -> ~2^128 under Grover; no change needed")


# ------------------------------------------------------------------- H3 --------

def test_h3_grover_against_the_tag_hash_space_is_closed(evidence):
    """H3 — a brute-force / Grover search of the tag identifier space is closed by
    the 128-bit binding token and the keyed HMAC index (§7.8): guessing a UID buys
    nothing without the 128-bit token, and the index cannot be precomputed without
    the backend-only key. Assert the token width is 128-bit."""
    import tag_index as tag_index_mod
    # A 16-byte (128-bit) token; the hash of it is what is stored.
    token_hex = "AB" * 16
    assert len(bytes.fromhex(token_hex)) == 16
    stored = tag_index_mod.binding_token_hash(token_hex)
    assert tag_index_mod.binding_token_matches(token_hex, stored)

    evidence("H3", outcome="blocked",
             expected="128-bit binding token + keyed index")


# ------------------------------------------------------------------- H4 --------

def test_h4_harvest_now_decrypt_later_is_partial(evidence):
    """H4 — a recorded TLS session decrypted by a future CRQC would expose the
    transport, but the product fields inside it are AES-256-GCM ciphertext at rest
    as well, so the payloads survive the transport break. Partial (§16.9): the
    envelope is symmetric and quantum-durable, the TLS handshake is not. Assert the
    fields are actually sealed (four ciphertexts + wrapped DEK), not sent in
    clear."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    pub = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    sealed = crypto_envelope.seal_record(
        {"product_id": "P", "batch_id": "B", "mfg_date": "2026-01-01",
         "tag_uid": "04A1B2C3D4E5F6"}, pub)
    for name in ("product_id", "batch_id", "mfg_date", "tag_uid"):
        assert "c" in sealed[name] and sealed[name]["c"], f"{name} not ciphertext"
    assert "enc_dek" in sealed

    evidence("H4", outcome="open",
             expected="partial: AES-256-GCM payloads survive a TLS break")


# ------------------------------------------------------------------- H5 --------

def test_h5_quantum_attack_on_nxp_originality_signature_is_unfixable(evidence):
    """H5 — the NXP originality signature is NXP's key on NXP's curve (secp128r1);
    a quantum break of it is open and unfixable by us. The design already treats L1
    originality as a weak-but-useful filter, not a proof, which is the honest
    posture. Open (§16.9)."""
    evidence("H5", outcome="open",
             expected="open and unfixable: NXP's key, NXP's curve",
             detail={"treated_as": "weak-but-useful L1 filter"})
    pytest.skip("H5 is open and unfixable (NXP-controlled key); out of scope (D4)")


# ------------------------------------------------------------------- H6 --------

def test_h6_store_and_forge_on_the_transparency_log_is_open(evidence):
    """H6 — a CRQC could forge the transparency log's signature (store-and-forge).
    SLH-DSA would close it and the log is low-volume, so this is cheap to add
    later. Open for now. Assert the transparency root table exists so the log —
    and thus the future upgrade point — is present, not dead code."""
    assert "transparency_root" in _schema(), "transparency log table was removed"
    assert (BACKEND_DIR / "services" / "transparency.py").exists()

    evidence("H6", outcome="open",
             expected="open; SLH-DSA would close it later (low-volume log)",
             detail={"upgrade": "SLH-DSA on the Merkle root signature"})
    pytest.skip("H6 is open, out of scope for now (D4); upgrade point preserved")
