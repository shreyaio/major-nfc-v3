"""Keyed tag index and UID normalisation. ARCHITECTURE.md §7.8.

v1 used an unsalted SHA-256(UID) as the lookup key. That is precomputable: SN0
is fixed at 04h on all NXP chips and UIDs within a reel are contiguous, so the
identifier space is 2^48, not 2^56 (§1.2). A rainbow table over 2^48 is not
cheap, but it is not out of reach either, and it turns "know a UID" into "know
the database key".

v2 uses tag_index = HMAC-SHA256(TAG_INDEX_KEY, normalise_uid(uid)).

TAG_INDEX_KEY lives ONLY on the backend. The Pi never computes an index — it
sends the UID inside the sealed envelope and the backend derives the index after
decrypting at enrol time. At verify time the backend gets the UID directly from
the mirror and computes the index itself. So the products table contains no value
from which a UID can be recovered without both TAG_INDEX_KEY and the field
decryption key. Closes E5 and D9.
"""
from __future__ import annotations

import hashlib
import hmac
import re

UID_PATTERN = re.compile(r"[0-9A-F]{14}")


def normalise_uid(uid: str) -> str:
    """Canonical UID form: uppercase hex, no separators.

    MUST be identical on the Pi and the backend — a drift here means the index
    computed at enrolment and the index computed at verification do not match,
    and every genuine tag reads as UNKNOWN. Pinned by tests/vectors/uid.json.
    """
    if not isinstance(uid, str):
        raise ValueError("uid must be a string")
    u = uid.replace(":", "").replace("-", "").replace(" ", "").upper()
    if not UID_PATTERN.fullmatch(u):
        raise ValueError("uid must be 14 hex chars")
    return u


def tag_index(uid: str, key: bytes) -> str:
    return hmac.new(key, normalise_uid(uid).encode("ascii"), hashlib.sha256).hexdigest()


def binding_token_hash(token_hex: str) -> str:
    """SHA-256 of the 128-bit binding token written to the tag. Only the hash is
    stored, so a database read does not yield tokens that could be written onto
    blank tags."""
    token = token_hex.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{32}", token):
        raise ValueError("binding token must be 32 hex chars")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def binding_token_matches(token_hex: str, stored_hash: str) -> bool:
    """Constant-time (E7, §15.3 rule 5). Never raises."""
    try:
        candidate = binding_token_hash(token_hex)
    except (ValueError, AttributeError):
        return False
    if not isinstance(stored_hash, str):
        return False
    return hmac.compare_digest(candidate, stored_hash)
