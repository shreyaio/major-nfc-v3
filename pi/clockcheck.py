"""NTP drift gate. ARCHITECTURE.md §12.5 (finding F9).

The request-signature window is +/-30 s. Packaging lines are often on isolated
networks with no NTP, and when the clock drifts every write is rejected with 403
— an error that looks like an authentication failure and will send you debugging
the wrong thing for an afternoon.

So: check the drift against the server before enrolling anything, refuse to
enrol if it is too large, and say exactly how to fix it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

log = logging.getLogger(__name__)

DEFAULT_MAX_DRIFT_S = 10
RECHECK_INTERVAL_S = 600  # every 10 minutes during a run


class ClockDriftError(RuntimeError):
    """The local clock is too far from the server's. Enrolment is disabled."""


def measure_drift(backend_url: str, timeout: int = 15) -> float:
    """Seconds of drift, positive or negative. Raises on an unreachable server."""
    resp = requests.get(f"{backend_url.rstrip('/')}/health", timeout=timeout)
    resp.raise_for_status()
    server = datetime.fromisoformat(resp.json()["server_time"])
    if server.tzinfo is None:
        server = server.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - server).total_seconds()


def assert_clock_sane(backend_url: str, max_drift_s: int = DEFAULT_MAX_DRIFT_S) -> float:
    drift = measure_drift(backend_url)
    if abs(drift) > max_drift_s:
        raise ClockDriftError(
            f"Local clock is {abs(drift):.0f}s from the server. "
            f"Enrolment is disabled.\n"
            f"Fix: sudo timedatectl set-ntp true && "
            f"sudo systemctl restart systemd-timesyncd\n"
            f"Then re-run. Do NOT proceed — every write will be rejected with a "
            f"403 that looks like an authentication failure.")
    log.info("clock ok, drift %.1fs", drift)
    return drift
