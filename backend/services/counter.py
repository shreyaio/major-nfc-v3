"""MTA state advance and CDD incident recording. ARCHITECTURE.md §9.7.

The pure decision lives in services/verification.py. This module does the two
things that need a database: advancing the counter high-water mark atomically,
and writing a divergence incident in one transaction with the state flip and the
audit row.
"""
from __future__ import annotations

import logging

import audit
import db
import metrics
from services.verification import Divergence, DivergenceKind

log = logging.getLogger(__name__)

# Doing the comparison in the WHERE clause is what makes MTA correct under
# concurrency. A read-then-write in Python is a race, and a mass-produced clone —
# many copies of one tag, tapped in many places at once — is precisely the
# workload that finds it.
_ADVANCE_SQL = """
UPDATE tag_counter_state
   SET max_counter       = %(counter)s,
       observation_count = observation_count + 1,
       last_seen_at      = NOW(),
       last_region       = COALESCE(%(region)s, last_region)
 WHERE tag_index  = %(tag_index)s
   AND max_counter < %(counter)s
   AND status      = 'ok'
RETURNING max_counter
"""


def load_state(cur, tag_index: str) -> dict | None:
    cur.execute(
        "SELECT tag_index, max_counter, observation_count, first_seen_at, "
        "       last_seen_at, last_region, status "
        "  FROM tag_counter_state WHERE tag_index = %s",
        (tag_index,))
    row = cur.fetchone()
    if row is None:
        return None
    cols = ("tag_index", "max_counter", "observation_count", "first_seen_at",
            "last_seen_at", "last_region", "status")
    return dict(zip(cols, row, strict=True))


def advance(cur, tag_index: str, counter: int, region: str | None = None) -> bool:
    """Atomically move the high-water mark. Returns False if it did not move.

    False means another request already advanced past this counter — which is
    itself a divergence, so the caller re-reads the state and routes back to
    step 6 of the state machine rather than treating it as a no-op.
    """
    cur.execute(_ADVANCE_SQL,
                {"tag_index": tag_index, "counter": counter, "region": region})
    return cur.fetchone() is not None


def record_divergence(tag_index: str, divergence: Divergence, *,
                      source_ip_hash: str | None = None,
                      user_agent_class: str | None = None) -> int | None:
    """Insert the incident, flip the state to sticky suspect, audit, and count.

    All of it in ONE transaction (§15.3 rule 3): an incident row without the
    state flip would let the next tap pass, and a state flip without the incident
    row would leave a human with nothing to triage.

    Returns the incident id, or None if the write failed (in which case the
    caller still returns SUSPECT_DUPLICATE — failing to record must never
    upgrade the verdict).
    """
    try:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO divergence_incident "
                "  (tag_index, observed_counter, expected_min, velocity_bound, kind, "
                "   source_ip_hash, user_agent_class) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (tag_index, divergence.observed_counter, divergence.expected_min,
                 divergence.velocity_bound, divergence.kind.value,
                 source_ip_hash, user_agent_class))
            incident_id = cur.fetchone()[0]

            # Sticky by design (G1). Only PATCH /api/v2/admin/incidents/<id> with
            # resolution "false_positive" can undo this, by a human, with a note.
            cur.execute(
                "UPDATE tag_counter_state SET status = 'suspect_duplicate' "
                " WHERE tag_index = %s AND status = 'ok'",
                (tag_index,))
    except Exception as exc:
        log.error("divergence_record_failed",
                  extra={"error": exc.__class__.__name__, "kind": divergence.kind.value})
        return None

    # Outside the transaction: audit must never be able to roll back the incident.
    audit.log_audit(event_type="verify", tag_index=tag_index, actor="public",
                    result="divergence",
                    source_ip_hash=source_ip_hash, user_agent_class=user_agent_class,
                    detail={"kind": divergence.kind.value,
                            "observed": divergence.observed_counter,
                            "expected_min": divergence.expected_min,
                            "velocity_bound": divergence.velocity_bound,
                            "incident_id": incident_id})
    # This counter is an alerting signal, not a dashboard number: any non-zero
    # value means a possible clone is in circulation (§14.5).
    metrics.incr("divergence_incidents_total")
    return incident_id


def create_initial_state(cur, tag_index: str, enrol_counter: int) -> None:
    """Called inside the enrolment transaction. The high-water mark starts at the
    counter value captured on the Pi, so a tag's very first consumer tap must
    already be strictly greater than what the packaging line saw."""
    cur.execute(
        "INSERT INTO tag_counter_state (tag_index, max_counter) VALUES (%s, %s) "
        "ON CONFLICT (tag_index) DO UPDATE SET max_counter = EXCLUDED.max_counter, "
        "    status = 'ok', observation_count = 0, last_seen_at = NOW()",
        (tag_index, enrol_counter))


def clear_suspect(cur, tag_index: str) -> None:
    """The ONLY path out of suspect_duplicate. Reached exclusively from
    PATCH /api/v2/admin/incidents/<id> with resolution='false_positive', by an
    authenticated human, with a note, and the action is audited."""
    cur.execute(
        "UPDATE tag_counter_state SET status = 'ok' "
        " WHERE tag_index = %s AND status = 'suspect_duplicate'",
        (tag_index,))


__all__ = [
    "DivergenceKind",
    "advance",
    "clear_suspect",
    "create_initial_state",
    "load_state",
    "record_divergence",
]
