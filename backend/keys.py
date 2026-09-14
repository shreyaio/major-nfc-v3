"""Envelope unwrap and the in-memory key registry. ARCHITECTURE.md §7.6.

FIELD_RECIPIENT_KEY and ROW_SIGNING_KEY are never stored raw in Render's
environment. They are stored wrapped under KEK:

    <hex: nonce(12) || AESGCM(KEK).encrypt(nonce, privkey, b"nfcmed/v2/kek-wrap")>

This module unwraps both at boot and holds them in memory only. They are never
written to disk, never logged, never returned by any route.

What this buys: reading the backend's environment variables is no longer
sufficient to decrypt the register or forge a row signature — which is exactly
what threat-model capability (v) requires. The point is only defensible if KEK
lives somewhere with genuinely different access control from the Render
dashboard. If you put KEK next to the wrapped blobs, you have gained nothing.

What it does not buy: immunity to a full host compromise of the running process,
which still yields the unwrapped keys in memory. Only an HSM removes that and
there is no free HSM (E10, §2 residual risk 4).
"""
from __future__ import annotations

import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import ConfigError

log = logging.getLogger(__name__)

WRAP_AAD = b"nfcmed/v2/kek-wrap"  # must match scripts/wrap_secret.py

_field_recipient_priv: bytes | None = None
_row_signing_key: Ed25519PrivateKey | None = None
_row_key_version: int = 1


def _unwrap(kek: bytes, wrapped_hex: str, name: str) -> bytes:
    try:
        blob = bytes.fromhex(wrapped_hex)
    except ValueError as exc:
        raise ConfigError(f"{name} is not hex") from exc
    if len(blob) < 12 + 16:
        raise ConfigError(f"{name} is too short to be a wrapped secret")
    try:
        return AESGCM(kek).decrypt(blob[:12], blob[12:], WRAP_AAD)
    except Exception as exc:  # InvalidTag
        raise ConfigError(
            f"{name} failed to unwrap — wrong KEK, or the blob was truncated "
            f"when it was pasted") from exc


def load(cfg) -> None:
    """Unwrap both operational private keys. Refuses to start on any failure —
    starting with a nil key is never acceptable (§15.4)."""
    global _field_recipient_priv, _row_signing_key, _row_key_version

    field_priv = _unwrap(cfg.kek, cfg.field_recipient_key_wrapped,
                         "FIELD_RECIPIENT_KEY_WRAPPED")
    if len(field_priv) != 32:
        raise ConfigError("FIELD_RECIPIENT_KEY must be 32 bytes after unwrapping")

    row_priv = _unwrap(cfg.kek, cfg.row_signing_key_wrapped, "ROW_SIGNING_KEY_WRAPPED")
    if len(row_priv) != 32:
        raise ConfigError("ROW_SIGNING_KEY must be 32 bytes after unwrapping")

    row_sk = Ed25519PrivateKey.from_private_bytes(row_priv)

    # Cross-check against the public half in config. A mismatch means the wrapped
    # blob and ROW_SIGNING_PUBKEY came from different gen_keys runs — which would
    # make every row this instance signs unverifiable by anyone else.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    derived_pub = row_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if derived_pub != cfg.row_signing_pubkey:
        raise ConfigError(
            "ROW_SIGNING_PUBKEY does not match the unwrapped ROW_SIGNING_KEY — "
            "they are from different key generations")

    _field_recipient_priv = field_priv
    _row_signing_key = row_sk
    _row_key_version = cfg.row_key_version
    log.info("keys_loaded", extra={"row_key_version": _row_key_version})


def loaded() -> bool:
    return _field_recipient_priv is not None and _row_signing_key is not None


def field_recipient_private_key() -> bytes:
    if _field_recipient_priv is None:
        raise ConfigError("field recipient key not loaded")
    return _field_recipient_priv


def row_signing_key() -> Ed25519PrivateKey:
    if _row_signing_key is None:
        raise ConfigError("row signing key not loaded")
    return _row_signing_key


def row_key_version() -> int:
    return _row_key_version


def reset() -> None:
    """Test hook only."""
    global _field_recipient_priv, _row_signing_key
    _field_recipient_priv = None
    _row_signing_key = None
