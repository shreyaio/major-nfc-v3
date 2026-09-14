"""/api/v2/admin/* — batches, recall, incident triage, report triage.
ARCHITECTURE.md §10.5.

Every route here is guarded by @require_scope, every action writes an audit row
carrying the token's `sub` and `jti` (who did it), and that row is inside the
hash chain.

The most important route in this file is PATCH /incidents/<id>. Clearing a
suspect_duplicate state is reachable ONLY from here, with
resolution="false_positive", by a human, with a note, audited. There is no
automatic recovery path anywhere in the codebase. That stickiness is what closes
G1 — a counterfeiter must not be able to discover which stolen identifiers are
still good by probing the public API and watching a flag clear.
"""
from __future__ import annotations

import json
import logging

from flask import Blueprint, jsonify, request

import db
import ratelimit
from auth_admin import audit_admin, current_subject, require_scope
from errors import BadRequest, NotFound
from services import batches as batch_svc
from services import counter as counter_svc

log = logging.getLogger(__name__)

bp = Blueprint("admin", __name__, url_prefix="/api/v2/admin")

RESOLUTIONS = frozenset({"confirmed", "false_positive", "closed"})
TRIAGE_STATES = frozenset({"new", "reviewing", "actioned", "spam"})


@bp.before_request
def _limit():
    ratelimit.check("admin", ratelimit.ip_prefix(request.remote_addr))


def _json_body() -> dict:
    if (request.content_type or "").split(";")[0].strip() != "application/json":
        raise BadRequest("Content-Type must be application/json")
    try:
        body = json.loads(request.get_data(cache=False))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BadRequest("body is not valid JSON") from exc
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")
    return body


def _serialise(row: dict) -> dict:
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()}


# ------------------------------------------------------------------ batches ---

@bp.get("/batches")
@require_scope("batch:read", "batch:write")
def list_batches():
    status = request.args.get("status")
    return jsonify({"batches": [_serialise(b) for b in batch_svc.list_batches(status)]})


@bp.post("/batches")
@require_scope("batch:write")
def open_batch():
    body = _json_body()
    batch = batch_svc.open_batch(
        batch_ref=body.get("batch_ref"), product_name=body.get("product_name"),
        mfg_date=body.get("mfg_date"), shelf_life_days=body.get("shelf_life_days"),
        quota=body.get("quota"), opened_by=body.get("opened_by"),
        countersigned_by=body.get("countersigned_by"))
    audit_admin("batch_open", "success", batch_ref=batch["batch_ref"],
                quota=batch["quota"], opened_by=batch["opened_by"],
                countersigned_by=batch["countersigned_by"])
    return jsonify(_serialise(batch)), 201


@bp.post("/batches/<batch_ref>/close")
@require_scope("batch:write")
def close_batch(batch_ref: str):
    batch = batch_svc.close_batch(batch_ref)
    audit_admin("batch_close", "success", batch_ref=batch_ref,
                enrolled_count=batch["enrolled_count"])
    return jsonify(_serialise(batch))


@bp.post("/recall")
@require_scope("recall")
def recall():
    body = _json_body()
    batch_ref, notice = body.get("batch_ref"), body.get("notice")
    if not isinstance(batch_ref, str) or not batch_ref.strip():
        raise BadRequest("batch_ref is required")
    # The notice is what a patient reads on the verification page, so it is
    # mandatory. A recall with no explanation is a scary red screen with no
    # instruction, which is worse than useless in a health context.
    updated = batch_svc.recall_batch(batch_ref.strip(), notice)
    audit_admin("batch_recall", "success", batch_ref=batch_ref,
                rows_resigned=updated, notice=notice)
    return jsonify({"status": "recalled", "batch_ref": batch_ref,
                    "rows_resigned": updated})


# ---------------------------------------------------------------- incidents ---

_INCIDENT_COLS = ("id", "tag_index", "observed_counter", "expected_min",
                  "velocity_bound", "kind", "user_agent_class", "resolution",
                  "resolved_by", "resolved_at", "created_at")


@bp.get("/incidents")
@require_scope("incident:read", "incident:write")
def list_incidents():
    status = request.args.get("status", "open")
    if status not in {"open", "confirmed", "false_positive", "closed", "all"}:
        raise BadRequest("unknown incident status filter")
    sql = f"SELECT {', '.join(_INCIDENT_COLS)} FROM divergence_incident"  # noqa: S608 — interpolates a module-level column tuple, never user input
    params: tuple = ()
    if status != "all":
        sql += " WHERE resolution = %s"
        params = (status,)
    sql += " ORDER BY created_at DESC LIMIT 200"
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = [dict(zip(_INCIDENT_COLS, r, strict=True)) for r in cur.fetchall()]
    # source_ip_hash is deliberately NOT returned. It exists for same-day
    # correlation inside the database, not for a human to look at (§9.11).
    return jsonify({"incidents": [_serialise(r) for r in rows]})


@bp.patch("/incidents/<int:incident_id>")
@require_scope("incident:write")
def resolve_incident(incident_id: int):
    body = _json_body()
    resolution = body.get("resolution")
    note = body.get("note")
    if resolution not in RESOLUTIONS:
        raise BadRequest(f"resolution must be one of {sorted(RESOLUTIONS)}")
    if not isinstance(note, str) or len(note.strip()) < 4:
        raise BadRequest("a note is required — this decision has to be explainable")

    subject = current_subject()
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE divergence_incident SET resolution = %s, resolved_by = %s, "
            "       resolved_at = NOW() WHERE id = %s RETURNING tag_index",
            (resolution, subject, incident_id))
        row = cur.fetchone()
        if row is None:
            raise NotFound("no such incident")
        tag_index = row[0]

        # THE ONLY PATH OUT OF suspect_duplicate. By a human, with a note, and
        # only when they have decided the divergence was a false positive.
        if resolution == "false_positive":
            counter_svc.clear_suspect(cur, tag_index)

    audit_admin("incident_resolve", resolution, incident_id=incident_id,
                tag_index=tag_index, note=note.strip())
    return jsonify({"status": "updated", "id": incident_id, "resolution": resolution})


# -------------------------------------------------------------- reconcile ----

@bp.get("/reconcile")
@require_scope("batch:read", "batch:write")
def reconcile():
    """Does this tag_index exist and is it active? Used by
    `pi/drainer.py --reconcile` at the end of every batch (§12.4).

    This is deliberately behind a scope rather than public. A public
    "does this identifier exist" endpoint is an enumeration oracle, which is
    exactly what the keyed tag_index and the mandatory binding token exist to
    prevent (D21, E5). The Pi operator already holds a batch token.
    """
    tag_index = request.args.get("tag_index", "")
    if not tag_index or len(tag_index) > 128:
        raise BadRequest("tag_index is required")
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT status, batch_ref, enrolled_at FROM products "
                    " WHERE tag_index = %s", (tag_index,))
        row = cur.fetchone()
    if row is None:
        raise NotFound("no record for that tag_index")
    return jsonify({"tag_index": tag_index, "status": row[0], "batch_ref": row[1],
                    "enrolled_at": row[2].isoformat()})


# ------------------------------------------------------------------ reports ---

_REPORT_COLS = ("id", "tag_index", "verdict_shown", "pharmacy_name", "city",
                "note", "contact", "triage", "created_at")


@bp.get("/reports")
@require_scope("report:read", "report:write")
def list_reports():
    triage = request.args.get("triage", "new")
    if triage not in TRIAGE_STATES | {"all"}:
        raise BadRequest("unknown triage filter")
    sql = f"SELECT {', '.join(_REPORT_COLS)} FROM consumer_report"  # noqa: S608 — interpolates a module-level column tuple, never user input
    params: tuple = ()
    if triage != "all":
        sql += " WHERE triage = %s"
        params = (triage,)
    sql += " ORDER BY created_at DESC LIMIT 200"
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = [dict(zip(_REPORT_COLS, r, strict=True)) for r in cur.fetchall()]
    return jsonify({"reports": [_serialise(r) for r in rows]})


@bp.patch("/reports/<int:report_id>")
@require_scope("report:write")
def triage_report(report_id: int):
    body = _json_body()
    triage = body.get("triage")
    if triage not in TRIAGE_STATES:
        raise BadRequest(f"triage must be one of {sorted(TRIAGE_STATES)}")
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute("UPDATE consumer_report SET triage = %s WHERE id = %s "
                    "RETURNING id", (triage, report_id))
        if cur.fetchone() is None:
            raise NotFound("no such report")
    audit_admin("report_triage", triage, report_id=report_id)
    return jsonify({"status": "updated", "id": report_id, "triage": triage})
