"""In-process counters exposed at /metrics. ARCHITECTURE.md §14.5.

Deliberately tiny: a dict of counters and a lock. No Prometheus client, no
pushgateway, no time series database — all of which cost money or a server.

These are per-process. With --workers 2 you see one worker's view per scrape;
that is fine for the four alert signals below, which are all "is this non-zero"
rather than "what is the exact rate".

Four alert signals, and only four. Everything else is a dashboard number:

  divergence_incidents_total > 0   A possible clone is in circulation. SECURITY.
  originality_rejections   > 0     Supplier may have shipped counterfeit silicon.
  outbox depth > 0 for 15 min      Genuine packs shipping without records. (Pi side.)
  verify error rate > 1% / 5 min   The consumer path is broken.

Four signals that always mean something beat twenty that mostly do not.
"""
from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[str, int] = defaultdict(int)

# Declared up front so /metrics shows a 0 rather than omitting the key. A missing
# metric and a zero metric look the same to a human and very different to an alert.
KNOWN = (
    "verify_total",
    "verify_errors_total",
    "verify_verdict_authentic",
    "verify_verdict_expired",
    "verify_verdict_recalled",
    "verify_verdict_withdrawn",
    "verify_verdict_suspect_duplicate",
    "verify_verdict_mirror_disabled",
    "verify_verdict_record_invalid",
    "verify_verdict_unknown",
    "divergence_incidents_total",
    "originality_rejections",
    "enrol_total",
    "enrol_errors_total",
    "enrol_idempotent_replays",
    "rate_limited_total",
    "audit_write_failures",
    "row_sig_invalid_total",
)


def incr(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] += amount


def snapshot() -> dict[str, int]:
    with _lock:
        out = {k: 0 for k in KNOWN}
        out.update(_counters)
        return out


def reset() -> None:
    """Test hook only."""
    with _lock:
        _counters.clear()
