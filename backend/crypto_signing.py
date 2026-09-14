"""Request signature verification, algorithm-versioned. ARCHITECTURE.md §7.7.

Headers on a signed request:

    X-Device-Id:       <uuid>          which device_registry row
    X-Timestamp:       <unix seconds>
    X-Sig-Alg:         ed25519         reserved: ed25519+mldsa65
    X-Signature:       <hex>
    X-Idempotency-Key: <uuid4>

    signed_payload = b"nfcmed/v2/req:" + alg + "\n" + timestamp + "\n"
                   + idempotency_key + "\n"
                   + sha256(raw_request_body_bytes).hexdigest()

Three deliberate differences from v1:

 1. HASH THE RAW BODY BYTES rather than re-serialising the parsed JSON. v1
    rebuilt json.dumps(body, sort_keys=True) server-side, which makes the
    signature depend on Python's JSON serialiser agreeing with the client's.
    Hashing the received bytes removes an entire class of canonicalisation
    mismatch — and it means the signature is verified BEFORE anything parses the
    body, so unparsed attacker data never reaches a parser (D1).
 2. THE IDEMPOTENCY KEY IS INSIDE THE SIGNATURE, so it cannot be swapped (D9).
 3. THE TIMESTAMP WINDOW IS EXPLICITLY TWO-SIDED. v1 used abs(), which is
    already two-sided — keep that, and test the future-dated case (D8), which
    was never tested.

X-Sig-Alg is validated against an allow-list of one. It exists so ML-DSA can be
added later by extending the allow-list and device_registry.sig_alg — no schema
migration, no route changes. That is the whole of the crypto-agility requirement
for this build (D4, H1).
"""
from __future__ import annotations

import hashlib
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQ_SIG_DOMAIN = b"nfcmed/v2/req:"
ALLOWED_SIG_ALGS = frozenset({"ed25519"})

DEFAULT_WINDOW_SECONDS = 30


def build_signed_payload(alg: str, timestamp: str, idempotency_key: str,
                         raw_body: bytes) -> bytes:
    """Both the Pi and the backend build this from the same four inputs. The Pi
    has its own copy (pi/drainer.py) — they are pinned by a shared test vector."""
    body_hash = hashlib.sha256(raw_body).hexdigest()
    return (REQ_SIG_DOMAIN + alg.encode("ascii") + b"\n"
            + timestamp.encode("ascii") + b"\n"
            + idempotency_key.encode("ascii") + b"\n"
            + body_hash.encode("ascii"))


def timestamp_in_window(timestamp: str, *, window: int = DEFAULT_WINDOW_SECONDS,
                        now: float | None = None) -> bool:
    """Two-sided. A future-dated timestamp is rejected exactly like a stale one
    (D7, D8) — a clock ahead of the server is as much of a problem as one behind,
    and 'it was only in the future' is not a reason to accept a replay window."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    delta = current - ts
    return -window <= delta <= window


def verify_request_signature(*, alg: str, timestamp: str, idempotency_key: str,
                             raw_body: bytes, signature_hex: str,
                             public_key: bytes) -> bool:
    """Never raises — fails closed on any malformed input (D2)."""
    if alg not in ALLOWED_SIG_ALGS:
        return False
    if not signature_hex or not public_key:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    payload = build_signed_payload(alg, timestamp, idempotency_key, raw_body)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        return True
    except (InvalidSignature, ValueError):
        return False
