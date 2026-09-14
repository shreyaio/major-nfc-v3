"""The durable enrolment outbox. ARCHITECTURE.md §5.4, §12.3.

THIS IS THE SINGLE MOST IMPORTANT CHANGE IN THE REBUILD.

v1 wrote the tag, then spawned a daemon thread that POSTed to the backend and
printed the result. If that POST failed — cold start, Wi-Fi drop, DNS, rate
limit — the tag was already on a pack and no record existed. That pack verifies
as `unknown` forever, and a consumer holding genuine medicine is told it is not
in the register. That is the most likely real-world failure of the entire system
and it has the worst possible user-facing outcome.

The fix: a durable local SQLite queue written and COMMITTED before any network
call, drained by a worker that retries until the server returns 2xx. Nothing is
deleted from it, ever.

Rules, all of them load-bearing:

  - enqueue() runs INSERT + COMMIT BEFORE enroller.py reports success to the
    operator. WAL mode and synchronous=FULL — a pack that ships while its record
    is lost to an unflushed page cache is the exact failure being fixed.
  - Terminal errors (400/403/409/413/415) mark `failed` and raise an operator
    alert. Everything else retries forever with backoff.
  - Drain on startup, before accepting new enrolments.
  - Nothing is deleted. `acked` rows are the reconciliation record.
"""
from __future__ import annotations

import json
import os
import random
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT    NOT NULL UNIQUE,
    payload         TEXT    NOT NULL,      -- the exact JSON body to POST
    state           TEXT    NOT NULL DEFAULT 'pending',  -- pending|inflight|acked|failed
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at REAL    NOT NULL DEFAULT 0,
    created_at      REAL    NOT NULL,
    acked_at        REAL,
    tag_index       TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(state, next_attempt_at);
"""

# 2, 4, 8, 16, 32, 60, 120, 300 s, then every 300 s indefinitely, ±20% jitter.
BACKOFF_SCHEDULE = (2, 4, 8, 16, 32, 60, 120, 300)
JITTER = 0.2


class OutboxFull(RuntimeError):
    """The disk cannot take another row. Refuse to enrol — writing a tag with no
    queued record is precisely what this module exists to prevent (§15.4)."""


class Outbox:
    def __init__(self, path: str = "./outbox.db"):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False,
                                     isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        # WAL survives a process kill; synchronous=FULL survives a power cut.
        # A packaging line loses power; this is not theoretical.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------ writing ---

    def enqueue(self, payload: dict, idempotency_key: str) -> int:
        """Durably queue one enrolment. Returns the row id.

        The caller MUST NOT report success to the operator until this returns.
        """
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        try:
            cur = self._conn.execute(
                "INSERT INTO outbox (idempotency_key, payload, created_at, "
                "  next_attempt_at) VALUES (?, ?, ?, ?)",
                (idempotency_key, body, time.time(), 0.0))
            return cur.lastrowid
        except sqlite3.IntegrityError:
            # Same idempotency key already queued. That is a success, not an
            # error: the record is already durable.
            row = self._conn.execute(
                "SELECT id FROM outbox WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            return row["id"]
        except sqlite3.OperationalError as exc:
            raise OutboxFull(f"cannot write to the outbox at {self.path}: {exc}") from exc

    # ------------------------------------------------------------ draining ---

    def claim_next(self) -> sqlite3.Row | None:
        """Take the oldest due pending row and mark it inflight, atomically."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT * FROM outbox WHERE state = 'pending' AND next_attempt_at <= ? "
                " ORDER BY id LIMIT 1", (now,)).fetchone()
            if row is None:
                self._conn.execute("COMMIT")
                return None
            self._conn.execute("UPDATE outbox SET state = 'inflight' WHERE id = ?",
                               (row["id"],))
            self._conn.execute("COMMIT")
            return row
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def mark_acked(self, row_id: int, tag_index: str | None = None) -> None:
        """2xx received. The row is KEPT — it is the reconciliation record."""
        self._conn.execute(
            "UPDATE outbox SET state = 'acked', acked_at = ?, last_error = NULL, "
            "  tag_index = COALESCE(?, tag_index) WHERE id = ?",
            (time.time(), tag_index, row_id))

    def mark_failed(self, row_id: int, error: str) -> None:
        """TERMINAL. 400/403/409/413/415 — the record will never succeed as-is,
        so retrying forever is wrong. Raise an operator alert instead."""
        self._conn.execute(
            "UPDATE outbox SET state = 'failed', last_error = ?, "
            "  attempts = attempts + 1 WHERE id = ?",
            (error[:500], row_id))

    def mark_retry(self, row_id: int, attempts: int, error: str,
                   retry_after: float | None = None) -> float:
        """Retryable: 429, 5xx, or any network error. Never gives up."""
        if retry_after is not None:
            delay = max(float(retry_after), 1.0)
        else:
            idx = min(attempts, len(BACKOFF_SCHEDULE) - 1)
            delay = BACKOFF_SCHEDULE[idx]
        delay *= 1 + random.uniform(-JITTER, JITTER)
        next_at = time.time() + delay
        self._conn.execute(
            "UPDATE outbox SET state = 'pending', attempts = ?, last_error = ?, "
            "  next_attempt_at = ? WHERE id = ?",
            (attempts + 1, error[:500], next_at, row_id))
        return delay

    def requeue_inflight(self) -> int:
        """Called at startup. A process killed mid-POST leaves rows inflight; the
        idempotency key makes re-sending them safe."""
        cur = self._conn.execute(
            "UPDATE outbox SET state = 'pending', next_attempt_at = 0 "
            " WHERE state = 'inflight'")
        return cur.rowcount

    # ------------------------------------------------------------ reporting --

    def depth(self) -> int:
        """Rows still owed to the backend. Depth above zero for more than 15
        minutes is an alerting signal (§14.5) — it means genuine packs are
        shipping without records. This is the 3 a.m. one."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM outbox WHERE state IN ('pending','inflight')"
        ).fetchone()
        return row["n"]

    def failed_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM outbox WHERE state = 'failed'").fetchone()
        return row["n"]

    def acked_rows(self):
        return self._conn.execute(
            "SELECT id, idempotency_key, tag_index, payload FROM outbox "
            " WHERE state = 'acked' ORDER BY id").fetchall()

    def failed_rows(self):
        return self._conn.execute(
            "SELECT id, idempotency_key, last_error, attempts FROM outbox "
            " WHERE state = 'failed' ORDER BY id").fetchall()

    def stats(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT state, COUNT(*) AS n FROM outbox GROUP BY state").fetchall()
        return {r["state"]: r["n"] for r in rows}

    def close(self) -> None:
        self._conn.close()


def open_outbox(path: str | None = None) -> Outbox:
    return Outbox(path or os.getenv("OUTBOX_PATH", "./outbox.db"))
