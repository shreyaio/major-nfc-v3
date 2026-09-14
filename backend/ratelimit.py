"""Postgres-backed second-layer rate limiter. ARCHITECTURE.md §9, §11.3.

The FIRST layer is the Cloudflare Worker's KV limiter, which is global and sees
per-tag traffic across every edge location. This layer exists for the case where
the edge is bypassed — someone who discovers the Render origin and hits it
directly.

Why not flask-limiter's memory:// store, as v1 used? Because with gunicorn
--workers 2 each worker keeps its own counter, so the configured limit was
silently 2x looser than reported (F16). Any evaluation that reports rate-limiter
behaviour has to state the worker count, or the number means nothing. A shared
store removes the caveat entirely, and Postgres is the shared store we already
pay for.

Fixed windows, not sliding: a fixed window can let through up to 2x the limit
across a boundary. That is an acceptable, documented imprecision at this layer —
this is a backstop, not the primary control.

IP KEYING IS BY PREFIX (/24 IPv4, /48 IPv6), NOT BY ADDRESS. Carrier-grade NAT
in India means an entire operator region can share addresses and a busy
pharmacy's Wi-Fi is one IP. Keying on a single address throttles real consumers
before it throttles attackers (F21).
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

import db
import metrics
from errors import RateLimited

log = logging.getLogger(__name__)

# Origin-side limits from the §9.4 route inventory.
LIMITS = {
    "verify": (120, 60),   # 120 requests per 60 s
    "enrol": (60, 60),
    "reenrol": (5, 60),
    "report": (5, 60),
    "admin": (60, 60),
    "metrics": (60, 60),
}

_UPSERT = """
INSERT INTO rate_limit_bucket (bucket_key, window_start, hits)
VALUES (%s, %s, 1)
ON CONFLICT (bucket_key, window_start)
DO UPDATE SET hits = rate_limit_bucket.hits + 1
RETURNING hits
"""


def ip_prefix(ip: str | None) -> str:
    """/24 for IPv4, /48 for IPv6. Returns 'unknown' for anything unparseable —
    which then shares one bucket, deliberately: an unparseable source is more
    likely to be hostile than to be a pharmacy."""
    if not ip:
        return "unknown"
    candidate = ip.split(",")[0].strip()
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return "unknown"
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/48", strict=False))


def _window_start(window_seconds: int, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    epoch = int(now.timestamp()) // window_seconds * window_seconds
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def check(scope: str, identity: str) -> None:
    """Raise RateLimited (429 + Retry-After) if this identity is over the limit.

    Fails OPEN on a database error. That is a deliberate trade: this is the
    second of two layers, and an unreachable database already means the request
    is about to fail anyway. Failing closed here would turn a database blip into
    a total outage of the consumer path — and the consumer path being down IS a
    security failure (F22), not just an inconvenience.
    """
    limit, window = LIMITS.get(scope, (60, 60))
    bucket_key = f"{scope}:{identity}"
    start = _window_start(window)
    try:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute(_UPSERT, (bucket_key, start))
            hits = cur.fetchone()[0]
    except Exception as exc:
        log.warning("ratelimit_unavailable",
                    extra={"error": exc.__class__.__name__, "scope": scope})
        return

    if hits > limit:
        metrics.incr("rate_limited_total")
        retry_after = int((start + timedelta(seconds=window)
                           - datetime.now(timezone.utc)).total_seconds()) + 1
        raise RateLimited(f"{scope} limit {limit}/{window}s exceeded",
                          retry_after=max(retry_after, 1))


def sweep(older_than_seconds: int = 3600) -> int:
    """Delete expired windows. Called from the nightly Action so the table does
    not grow without bound on a free-tier database."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
    try:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM rate_limit_bucket WHERE window_start < %s", (cutoff,))
            return cur.rowcount
    except Exception as exc:
        log.warning("ratelimit_sweep_failed", extra={"error": exc.__class__.__name__})
        return 0
