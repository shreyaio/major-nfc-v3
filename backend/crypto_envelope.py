"""Envelope encryption of product fields. ARCHITECTURE.md §7.3.

    *** THIS FILE IS BYTE-IDENTICAL BETWEEN pi/ AND backend/ ***

The duplication is deliberate (rule 4 in §0): pi/ and backend/ ship to different
machines and neither may import the other. The two copies are pinned by
backend/tests/vectors/envelope.json, and a CI test runs both against it. A drift
here is invisible until production, so it is made a build-time failure instead.

Scheme, per record:

 1. The Pi generates a random 32-byte DEK (data encryption key).
 2. Each field is encrypted separately with AES-256-GCM under the DEK, with a
    fresh 12-byte nonce. AAD is MANDATORY and binds the ciphertext to its slot:
        aad = b"nfcmed/v2/field/" + field_name
    This is what stops D11 (cross-field or cross-record ciphertext substitution)
    at the primitive level, rather than with a check somewhere downstream.
 3. The DEK is wrapped to the BACKEND's X25519 public key:
        shared   = X25519(ephemeral_sk, FIELD_RECIPIENT_PUB)
        wrap_key = HKDF-SHA256(shared, info=b"nfcmed/v2/dek-wrap", len=32)
        enc_dek  = epk(32) || nonce(12) || AESGCM(wrap_key, nonce, DEK, b"nfcmed/v2/dek")
 4. The Pi sends the four ciphertexts + enc_dek. IT KEEPS NO COPY OF THE DEK.

Why this rather than v1's HKDF-from-a-shared-master: v1 required the same
symmetric AES_MASTER_KEY on both ends, so under the project's own threat model —
an adversary who obtains the backend's entire configuration — the confidentiality
claim was void. Envelope-to-public-key means the Pi cannot decrypt the register,
and reading the backend's environment variables is not sufficient either, because
FIELD_RECIPIENT_KEY is itself stored wrapped under KEK (§7.6).

Residual risk, stated plainly: a full host compromise of the running backend
still yields the unwrapped key in memory. Only an HSM removes that, and there is
no free HSM. (E10.)
"""
from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FIELD_AAD_PREFIX = b"nfcmed/v2/field/"
DEK_AAD = b"nfcmed/v2/dek"
DEK_WRAP_INFO = b"nfcmed/v2/dek-wrap"

DEK_BYTES = 32
NONCE_BYTES = 12
EPK_BYTES = 32

SEALED_FIELDS = ("product_id", "batch_id", "mfg_date", "tag_uid")


class EnvelopeError(ValueError):
    """Sealing or opening failed. Never leaks key material in its message."""


def field_aad(name: str) -> bytes:
    return FIELD_AAD_PREFIX + name.encode("ascii")


def _wrap_key(shared: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=DEK_WRAP_INFO).derive(shared)


def seal_record(fields: dict[str, str], recipient_pub: bytes) -> dict:
    """Seal the four product fields to the backend's X25519 public key."""
    return _seal_record(fields, recipient_pub,
                        dek=os.urandom(DEK_BYTES),
                        nonces={n: os.urandom(NONCE_BYTES) for n in fields},
                        esk=X25519PrivateKey.generate(),
                        wrap_nonce=os.urandom(NONCE_BYTES))


def _seal_record(fields: dict[str, str], recipient_pub: bytes, *,
                 dek: bytes, nonces: dict[str, bytes],
                 esk: X25519PrivateKey, wrap_nonce: bytes) -> dict:
    """Deterministic core. Randomness is injected so the test vector can pin the
    exact bytes both implementations must produce."""
    if len(recipient_pub) != 32:
        raise EnvelopeError("FIELD_RECIPIENT_PUB must be 32 bytes")
    if len(dek) != DEK_BYTES:
        raise EnvelopeError("DEK must be 32 bytes")

    out: dict[str, object] = {}
    aead = AESGCM(dek)
    for name in sorted(fields):
        value = fields[name]
        nonce = nonces[name]
        if len(nonce) != NONCE_BYTES:
            raise EnvelopeError(f"nonce for {name} must be 12 bytes")
        ct = aead.encrypt(nonce, value.encode("utf-8"), field_aad(name))
        out[name] = {"n": nonce.hex(), "c": ct.hex()}

    shared = esk.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    wrapped = AESGCM(_wrap_key(shared)).encrypt(wrap_nonce, dek, DEK_AAD)
    epk = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    out["enc_dek"] = (epk + wrap_nonce + wrapped).hex()
    return out


def unwrap_dek(enc_dek_hex: str, recipient_priv: bytes) -> bytes:
    """Recover the DEK. Backend only — the Pi has no recipient private key."""
    try:
        blob = bytes.fromhex(enc_dek_hex)
    except ValueError as exc:
        raise EnvelopeError("enc_dek is not hex") from exc
    if len(blob) < EPK_BYTES + NONCE_BYTES + 16:
        raise EnvelopeError("enc_dek too short")

    epk = blob[:EPK_BYTES]
    nonce = blob[EPK_BYTES:EPK_BYTES + NONCE_BYTES]
    wrapped = blob[EPK_BYTES + NONCE_BYTES:]
    try:
        shared = X25519PrivateKey.from_private_bytes(recipient_priv).exchange(
            X25519PublicKey.from_public_bytes(epk))
        return AESGCM(_wrap_key(shared)).decrypt(nonce, wrapped, DEK_AAD)
    except EnvelopeError:
        raise
    except Exception as exc:  # InvalidTag and friends
        raise EnvelopeError("dek unwrap failed") from exc


def open_field(sealed_field: dict | str, dek: bytes, name: str) -> str:
    """Decrypt one field. Raises EnvelopeError on any tamper (GCM InvalidTag)."""
    if isinstance(sealed_field, str):
        try:
            sealed_field = json.loads(sealed_field)
        except json.JSONDecodeError as exc:
            raise EnvelopeError(f"{name} ciphertext is not valid JSON") from exc
    try:
        nonce = bytes.fromhex(sealed_field["n"])
        ct = bytes.fromhex(sealed_field["c"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EnvelopeError(f"{name} ciphertext is malformed") from exc
    try:
        return AESGCM(dek).decrypt(nonce, ct, field_aad(name)).decode("utf-8")
    except Exception as exc:  # InvalidTag
        raise EnvelopeError(f"{name} failed authentication") from exc


def open_record(sealed: dict, recipient_priv: bytes,
                only: tuple[str, ...] | None = None) -> dict[str, str]:
    """Decrypt some or all fields. `only` exists because the enrol path needs
    just tag_uid and mfg_date — nothing should decrypt data it does not need."""
    dek = unwrap_dek(sealed["enc_dek"], recipient_priv)
    names = only if only is not None else SEALED_FIELDS
    return {name: open_field(sealed[name], dek, name) for name in names}
