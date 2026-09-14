"""Row integrity: Ed25519 signatures over every security-relevant field.
ARCHITECTURE.md §7.4.

v1's `payload_hash` was an unkeyed SHA-256 over four public ciphertext values.
An attacker with database write access could change the expiry date and simply
recompute it (F13, F15, D12). It was a checksum, not an integrity control.

v2 signs the row with ROW_SIGNING_KEY, which lives only in the backend's memory
and never in the database. Note what is inside the signature: expiry_date,
status, crypto_version, enrol_counter, binding_token_hash. An attacker with full
read/write access to the register can now change none of them without detection
on the next verification. That is the single highest-leverage change in the
backend, and it is what makes the second claim in §19 true.

Verified on EVERY verify. Mismatch -> verdict RECORD_INVALID, never AUTHENTIC,
plus an audit row with result="row_sig_invalid".
"""
from __future__ import annotations

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROW_SIG_DOMAIN = b"nfcmed/v2/row:"

# Order is irrelevant (canonical() sorts), but the SET is load-bearing: adding a
# security-relevant column later without adding it here leaves that column
# unprotected. If you add a column that a verdict depends on, add it here too.
ROW_SIG_FIELDS = [
    "tag_index", "binding_token_hash",
    "product_id_ct", "batch_id_ct", "mfg_date_ct", "tag_uid_ct",
    "enc_dek", "shelf_life", "expiry_date", "crypto_version",
    "enrol_counter", "batch_ref", "status", "device_id",
    "originality_status", "enrolled_at", "row_sig_alg", "row_key_version",
]

ALLOWED_ROW_SIG_ALGS = frozenset({"ed25519"})


class RowSigError(ValueError):
    pass


def canonical(row: dict) -> bytes:
    """Deterministic JSON over exactly ROW_SIG_FIELDS.

    `default=str` is what makes dates and UUIDs stable: a DATE column comes back
    from psycopg2 as datetime.date and must serialise the same way here as it did
    at signing time. Pinned by tests/vectors/rowsig.json.
    """
    missing = [k for k in ROW_SIG_FIELDS if k not in row]
    if missing:
        raise RowSigError(f"row is missing signed fields: {', '.join(missing)}")
    return json.dumps({k: row[k] for k in ROW_SIG_FIELDS},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def sign_row(row: dict, signing_key: Ed25519PrivateKey) -> str:
    return signing_key.sign(ROW_SIG_DOMAIN + canonical(row)).hex()


def verify_row(row: dict, signature_hex: str, public_key: bytes) -> bool:
    """Never raises. Any malformed input is a failed verification, not an error —
    fail closed (§15.3 rule 1)."""
    if row.get("row_sig_alg") not in ALLOWED_ROW_SIG_ALGS:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    try:
        message = ROW_SIG_DOMAIN + canonical(row)
    except RowSigError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def signable_view(row: dict) -> dict:
    """Project a full DB row (or an about-to-be-inserted dict) down to just the
    signed fields, normalising types so signing and verifying agree.

    dates -> ISO strings, UUID -> str. Doing this in one place is what stops
    "it verified at write time and failed at read time" — the classic
    canonicalisation drift bug.
    """
    out = {}
    for key in ROW_SIG_FIELDS:
        value = row.get(key)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            value = str(value)
        out[key] = value
    return out
