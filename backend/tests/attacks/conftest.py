"""Fixtures for the attack suite. ARCHITECTURE.md §17.3.

Scaffold only — see README.md in this directory. The evidence recorder below is
the piece worth having ready: v1's structured JSONL evidence + report generator
was a genuinely good idea, and the results are only citable if every test emits
the same shape.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "evidence"

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def evidence():
    """Append-only JSONL evidence records, one per attack test.

    `worker_count` is recorded because a rate-limit result without it is
    meaningless (§17.3): per-worker counters made v1's observed limits N times
    looser than the configured ones.
    """
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"attacks-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.jsonl"

    def record(attack_id: str, *, outcome: str, detail: dict | None = None,
               expected: str | None = None):
        entry = {
            "attack_id": attack_id,
            "outcome": outcome,            # blocked | detected | open | inconclusive
            "expected": expected,
            "detail": detail or {},
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "target": os.getenv("TEST_BASE_URL", ""),
            "worker_count": os.getenv("TEST_WORKER_COUNT", "unknown"),
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    return record
