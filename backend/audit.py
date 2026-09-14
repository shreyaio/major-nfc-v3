"""Hash-chained audit log and privacy helpers. ARCHITECTURE.md §9.9, §9.11.

Two contracts, both inherited from v1 and both kept exactly:

  - log_audit MUST NOT RAISE. A logging failure must never break its caller.
  - Audit on every branch, including early returns and failures (§15.3 rule 2).

What is new in v2 is the hash chain. Each entry commits to the previous entry's
hash, and the daily transparency job publishes the head. An attacker with
database access who deletes their own trace breaks the chain, and the break
becomes PUBLICLY PROVABLE (F25). Without this, the audit log is not independent
evidence for the paper — it can be edited by exactly the adversary it exists to
catch.

The FOR UPDATE matters. Two concurrent audit writes without it produce two
entries claiming the same prev_hash, which is indistinguishable from tampering.
If lock contention ever becomes a problem, batch the writes — do not drop the
lock.

Privacy (F30, India's DPDP Act 2023): consumer scan records tied to IP and time
are personal data. No raw IP and no raw User-Agent is ever written.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import db
import metrics

log = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

_ip_hash_seed: bytes = b""


def configure(cfg) -> None:
    global _ip_hash_seed
    _ip_hash_seed = cfg.ip_hash_seed


def hash_ip(ip: str | None) -> str | None:
    """Daily-rotating HMAC. Enough for rate limiting and same-source correlation
    within a day; useless afterwards. The raw IP is never written anywhere."""
    if not ip or not _ip_hash_seed:
        return None
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = hmac.new(_ip_hash_seed, day.encode(), hashlib.sha256).digest()
    return hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:32]


def classify_ua(ua: str | None) -> str:
    """Coarse bucket only. Never store the raw User-Agent string — it is a
    high-entropy fingerprint, and the coarse class is all the analysis needs."""
    if not ua:
        return "other"
    u = ua.lower()
    if any(bot in u for bot in ("bot", "crawler", "spider", "curl", "wget", "python-requests")):
        return "bot"
    if "android" in u:
        return "android-chrome" if "chrome" in u else "android-other"
    if "iphone" in u or "ipad" in u or "ios" in u:
        return "ios-safari" if "safari" in u and "crios" not in u else "ios-other"
    if any(d in u for d in ("windows", "macintosh", "x11", "linux")):
        return "desktop"
    return "other"


def canonical_json(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def log_audit(*, event_type: str, tag_index: str | None = None,
              actor: str | None = None, result: str | None = None,
              source_ip_hash: str | None = None, user_agent_class: str | None = None,
              detail: dict | None = None) -> None:
    """Best-effort, hash-chained. MUST NOT raise."""
    try:
        entry = {
            "event_type": event_type,
            "tag_index": tag_index,
            "actor": actor,
            "result": result,
            "source_ip_hash": source_ip_hash,
            "user_agent_class": user_agent_class,
            "detail": detail or {},
        }
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE")
            row = cur.fetchone()
            prev = row[0] if row else GENESIS_HASH
            entry_hash = hashlib.sha256(
                (prev + canonical_json(entry)).encode("utf-8")).hexdigest()
            cur.execute(
                "INSERT INTO audit_log (event_type, tag_index, actor, result, "
                "  source_ip_hash, user_agent_class, detail, prev_hash, entry_hash) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (event_type, tag_index, actor, result, source_ip_hash,
                 user_agent_class, json.dumps(entry["detail"], default=str),
                 prev, entry_hash))
    except Exception as exc:
        metrics.incr("audit_write_failures")
        log.warning("audit_write_failed",
                    extra={"error": str(exc), "event_type": event_type})


def chain_head() -> str:
    """The latest entry_hash, or the genesis value. Published daily (§14.3)."""
    try:
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            return row[0] if row else GENESIS_HASH
    except Exception:
        return GENESIS_HASH


def verify_chain(rows) -> int | None:
    """Walk (seq, event_type, ..., prev_hash, entry_hash) tuples in seq order and
    return the seq of the FIRST break, or None if the chain is intact.

    Used by scripts/verify_transparency.py and by tests/integration/
    test_audit_chain.py, which deletes a row via raw SQL and asserts the break is
    reported at the right index.
    """
    prev = GENESIS_HASH
    for row in rows:
        entry = {
            "event_type": row["event_type"],
            "tag_index": row["tag_index"],
            "actor": row["actor"],
            "result": row["result"],
            "source_ip_hash": row["source_ip_hash"],
            "user_agent_class": row["user_agent_class"],
            "detail": row["detail"] or {},
        }
        expected = hashlib.sha256((prev + canonical_json(entry)).encode("utf-8")).hexdigest()
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return row["seq"]
        prev = row["entry_hash"]
    return None
