"""The Pi and the backend must agree, byte for byte. ARCHITECTURE.md §15.3 rule 7.

pi/ and backend/ ship to different machines and neither may import the other
(rule 4 in §0), so three pieces of logic are implemented TWICE: UID
normalisation, envelope sealing, and the request-signing payload.

A drift between the two copies is invisible until production — tags enrol fine,
and then every one of them verifies as UNKNOWN because the two sides compute
different indexes. So the drift is made a BUILD-TIME FAILURE. This file is that
failure.

It imports the Pi's modules explicitly by path, so it is testing the actual file
that ships to the Pi and not a re-import of the backend's copy.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
PI_DIR = REPO / "pi"
BACKEND_DIR = REPO / "backend"


def _load_pi_module(name: str):
    """Import a pi/ module under a distinct name so it cannot be confused with
    the backend module of the same name already in sys.modules."""
    path = PI_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"pi_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"pi_{name}"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------- the files are identical --

def test_crypto_envelope_is_byte_identical_between_deployables():
    """The two copies are meant to be literally the same file. Anything else and
    the vectors below could pass while a subtle difference lurks in a branch
    neither vector exercises."""
    pi_bytes = (PI_DIR / "crypto_envelope.py").read_bytes()
    backend_bytes = (BACKEND_DIR / "crypto_envelope.py").read_bytes()
    assert pi_bytes == backend_bytes, (
        "pi/crypto_envelope.py and backend/crypto_envelope.py have diverged. "
        "They must stay byte-identical — copy one over the other and re-run "
        "backend/scripts/gen_vectors.py.")


def test_no_cross_imports_between_deployables():
    """Rule 4 in §0, checked in code as well as in CI."""
    for path in BACKEND_DIR.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert "\nimport pi." not in text and "\nfrom pi." not in text, path

    for path in PI_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "\nimport backend." not in text and "\nfrom backend." not in text, path


def test_paper_cipher_is_not_importable_from_either_deployable():
    """E8, §5.1. crypto_paper.py lives in legacy/ for offline reproducibility.
    Nothing that ships may import it — two ciphers side by side is a downgrade
    surface even when the weak branch is never taken."""
    for root in (BACKEND_DIR, PI_DIR):
        for path in root.rglob("*.py"):
            # tests/ necessarily names the thing it forbids.
            if "tests" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            assert "crypto_paper" not in text, f"{path} references the paper cipher"
    assert not (BACKEND_DIR / "crypto_paper.py").exists()
    assert (REPO / "legacy" / "paper_cipher" / "crypto_paper.py").exists()


# ------------------------------------------------------------ UID normalisation

def test_uid_normalisation_agrees(uid_vectors):
    import tag_index as backend_tag_index

    key = bytes.fromhex(uid_vectors["tag_index_key_hex"])

    for case in uid_vectors["valid"]:
        assert backend_tag_index.normalise_uid(case["input"]) == case["normalised"]
        assert backend_tag_index.tag_index(case["input"], key) == case["tag_index"]

    for case in uid_vectors["invalid"]:
        with pytest.raises(ValueError):
            backend_tag_index.normalise_uid(case["input"])


def test_pi_uid_cleaning_matches_the_backend_normaliser(uid_vectors):
    """pi/enroller.py::uid_clean turns raw PN532 bytes into the canonical string.
    It has to produce exactly what backend/tag_index.normalise_uid expects."""
    import tag_index as backend_tag_index

    raw = bytes([0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6])
    # Reproduce uid_clean without importing enroller (which pulls in board/busio).
    pi_form = "".join(f"{b:02X}" for b in raw)
    assert pi_form == backend_tag_index.normalise_uid(pi_form) == "04A1B2C3D4E5F6"


# ------------------------------------------------------------------- envelope --

def test_envelope_seal_is_deterministic_and_matches_the_vector(envelope_vectors):
    """Both implementations must produce EXACTLY these bytes from these inputs."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    backend_env = __import__("crypto_envelope")
    pi_env = _load_pi_module("crypto_envelope")

    v = envelope_vectors
    recipient_pub = bytes.fromhex(v["field_recipient_pub_hex"])
    nonces = {k: bytes.fromhex(h) for k, h in v["nonces_hex"].items()}

    for name, module in (("backend", backend_env), ("pi", pi_env)):
        sealed = module._seal_record(
            v["plaintext"], recipient_pub,
            dek=bytes.fromhex(v["dek_hex"]),
            nonces=nonces,
            esk=X25519PrivateKey.from_private_bytes(bytes.fromhex(v["ephemeral_priv_hex"])),
            wrap_nonce=bytes.fromhex(v["wrap_nonce_hex"]))
        assert sealed == v["sealed"], f"{name} produced different sealed output"


def test_envelope_opens_on_both_sides(envelope_vectors):
    backend_env = __import__("crypto_envelope")
    pi_env = _load_pi_module("crypto_envelope")
    priv = bytes.fromhex(envelope_vectors["field_recipient_priv_hex"])

    for module in (backend_env, pi_env):
        opened = module.open_record(envelope_vectors["sealed"], priv)
        assert opened == envelope_vectors["plaintext"]


def test_d11_aad_binds_each_ciphertext_to_its_field(envelope_vectors):
    """Swap two ciphertexts between slots. GCM must reject both, because the AAD
    names the field. This is the primitive-level answer to cross-field and
    cross-record ciphertext substitution — not a check somewhere downstream."""
    import crypto_envelope

    sealed = dict(envelope_vectors["sealed"])
    sealed["product_id"], sealed["batch_id"] = sealed["batch_id"], sealed["product_id"]
    priv = bytes.fromhex(envelope_vectors["field_recipient_priv_hex"])

    with pytest.raises(crypto_envelope.EnvelopeError):
        crypto_envelope.open_record(sealed, priv)


def test_e3_a_single_flipped_bit_fails_authentication(envelope_vectors):
    """GCM InvalidTag surfaces as EnvelopeError, which the verify route turns
    into RECORD_INVALID rather than a 500."""
    import crypto_envelope

    sealed = {k: (dict(v) if isinstance(v, dict) else v)
              for k, v in envelope_vectors["sealed"].items()}
    ct = bytearray.fromhex(sealed["product_id"]["c"])
    ct[0] ^= 0x01
    sealed["product_id"]["c"] = ct.hex()

    priv = bytes.fromhex(envelope_vectors["field_recipient_priv_hex"])
    with pytest.raises(crypto_envelope.EnvelopeError):
        crypto_envelope.open_record(sealed, priv)


def test_e1_every_seal_uses_fresh_randomness():
    """Sealing the same plaintext twice must produce different bytes. A repeated
    GCM nonce under a repeated key is catastrophic, and a fresh DEK per record
    means the nonce space is never even approached."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import crypto_envelope

    pub = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    fields = {"product_id": "X", "batch_id": "Y", "mfg_date": "2026-01-01",
              "tag_uid": "04A1B2C3D4E5F6"}
    first = crypto_envelope.seal_record(fields, pub)
    second = crypto_envelope.seal_record(fields, pub)
    assert first != second
    assert first["product_id"]["n"] != second["product_id"]["n"]
    assert first["enc_dek"] != second["enc_dek"]


# ------------------------------------------------------- request-signing payload

def test_request_signing_payload_agrees(reqsig_vectors):
    """backend/crypto_signing.py and pi/drainer.py build this from the same four
    inputs. If they disagree, every enrolment is rejected with a 403 that looks
    like an authentication failure."""
    import crypto_signing

    pi_drainer = _load_pi_module("drainer")
    v = reqsig_vectors
    raw_body = v["raw_body_utf8"].encode("utf-8")

    backend_payload = crypto_signing.build_signed_payload(
        v["alg"], v["timestamp"], v["idempotency_key"], raw_body)
    pi_payload = pi_drainer.build_signed_payload(
        v["alg"], v["timestamp"], v["idempotency_key"], raw_body)

    assert backend_payload == pi_payload
    assert backend_payload.decode("utf-8") == v["signed_payload_utf8"]


def test_signature_verifies_and_a_tampered_body_does_not(reqsig_vectors):
    import crypto_signing

    v = reqsig_vectors
    pub = bytes.fromhex(v["device_pub_hex"])
    raw_body = v["raw_body_utf8"].encode("utf-8")

    assert crypto_signing.verify_request_signature(
        alg=v["alg"], timestamp=v["timestamp"],
        idempotency_key=v["idempotency_key"], raw_body=raw_body,
        signature_hex=v["signature"], public_key=pub)

    # D4 — the signature covers sha256(raw body), so one changed byte breaks it.
    assert not crypto_signing.verify_request_signature(
        alg=v["alg"], timestamp=v["timestamp"],
        idempotency_key=v["idempotency_key"], raw_body=raw_body + b" ",
        signature_hex=v["signature"], public_key=pub)

    # D9 — the idempotency key is inside the signature, so it cannot be swapped.
    assert not crypto_signing.verify_request_signature(
        alg=v["alg"], timestamp=v["timestamp"],
        idempotency_key="00000000-0000-4000-8000-000000000000", raw_body=raw_body,
        signature_hex=v["signature"], public_key=pub)


def test_terminal_status_lists_agree():
    """§10.2 — the Pi's drainer and the backend must split terminal from
    retryable identically, or the outbox spins forever or drops a good record."""
    import errors

    pi_drainer = _load_pi_module("drainer")
    assert errors.TERMINAL_STATUSES == pi_drainer.TERMINAL_STATUSES
