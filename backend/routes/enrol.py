"""POST /api/v2/enrol and /api/v2/reenrol. ARCHITECTURE.md §9.5, §10.2.

Steps 1-6 of the order of operations live here (transport gates, device lookup,
signature over the RAW body, timestamp window, idempotency). Steps 7-16 are in
services/enrolment.py.

The split is deliberate: everything before step 7 must happen without parsing the
body, because unparsed attacker data must never reach a parser (D1).
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid

from flask import Blueprint, current_app, g, jsonify, request

import audit
import crypto_signing
import db
import metrics
import ratelimit
from errors import (
    AppError,
    BadRequest,
    BadSignature,
    IdempotencyConflict,
    PayloadTooLarge,
    UnsupportedMedia,
)
from services import enrolment

log = logging.getLogger(__name__)

bp = Blueprint("enrol", __name__, url_prefix="/api/v2")


def _device(device_id: str) -> dict:
    """device_registry lookup. A valid signature from an untrusted or revoked key
    is still a rejection (D3)."""
    try:
        uuid.UUID(device_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadSignature("X-Device-Id is not a uuid") from exc
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT device_id, public_key, sig_alg, status FROM device_registry "
            " WHERE device_id = %s", (device_id,))
        row = cur.fetchone()
    if row is None:
        raise BadSignature("unknown device")
    device = dict(zip(("device_id", "public_key", "sig_alg", "status"), row,
                      strict=True))
    if device["status"] != "active":
        raise BadSignature("device is revoked")
    return device


def _authenticate() -> tuple[dict, bytes, str, str]:
    """(device, raw_body, request_hash, idempotency_key). Raises on any failure.

    Order inside this function matters as much as the order outside it.
    """
    cfg = current_app.config["APP_CONFIG"]

    # 1. Method is enforced by the route decorator. Content-Type here (D18).
    if (request.content_type or "").split(";")[0].strip() != "application/json":
        raise UnsupportedMedia("Content-Type must be application/json")

    # 2. Size. MAX_CONTENT_LENGTH also enforces this at the WSGI layer; this is
    #    the explicit, codified error (D19).
    raw_body = request.get_data(cache=True, as_text=False)
    if len(raw_body) > cfg.max_body_bytes:
        raise PayloadTooLarge(f"body is {len(raw_body)} bytes")

    device_id = request.headers.get("X-Device-Id", "")
    timestamp = request.headers.get("X-Timestamp", "")
    alg = request.headers.get("X-Sig-Alg", "ed25519")
    signature = request.headers.get("X-Signature", "")
    idempotency_key = request.headers.get("X-Idempotency-Key", "")

    try:
        uuid.UUID(idempotency_key)
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadRequest("X-Idempotency-Key must be a uuid") from exc

    # 3. Device.
    device = _device(device_id)
    if device["sig_alg"] != alg:
        raise BadSignature("X-Sig-Alg does not match this device's registered alg")

    # 4. Signature over the RAW body bytes, BEFORE any field parsing.
    try:
        public_key = bytes.fromhex(device["public_key"])
    except ValueError as exc:
        raise BadSignature("device public key is malformed") from exc
    if not crypto_signing.verify_request_signature(
            alg=alg, timestamp=timestamp, idempotency_key=idempotency_key,
            raw_body=raw_body, signature_hex=signature, public_key=public_key):
        raise BadSignature("signature verification failed")

    # 5. Two-sided timestamp window. Checked after the signature so a bad clock
    #    cannot be used to probe which device ids exist.
    if not crypto_signing.timestamp_in_window(timestamp, window=cfg.timestamp_window_s):
        raise BadSignature("timestamp outside the allowed window")

    return device, raw_body, hashlib.sha256(raw_body).hexdigest(), idempotency_key


def _parse_json(raw_body: bytes, max_depth: int) -> dict:
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BadRequest("body is not valid JSON") from exc
    if _depth(body) > max_depth:
        # Billion-laughs shaped input (D19). Bounded nesting, checked before
        # anything walks the structure.
        raise BadRequest("JSON nesting is too deep")
    return body


def _depth(value, current: int = 1) -> int:
    if isinstance(value, dict):
        return max((_depth(v, current + 1) for v in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(v, current + 1) for v in value), default=current)
    return current


@bp.post("/enrol")
def enrol():
    cfg = current_app.config["APP_CONFIG"]
    ratelimit.check("enrol", ratelimit.ip_prefix(request.remote_addr))

    device, raw_body, request_hash, idempotency_key = _authenticate()
    g.actor = device["device_id"]

    # 6. Idempotency, before any work. A replay must not re-run the enrolment.
    with db.connection() as conn, conn.cursor() as cur:
        replay = enrolment.lookup_idempotency(cur, idempotency_key, request_hash)
    if replay is not None:
        status, stored = replay
        # 200, not the original 201: the caller can tell a replay from a fresh
        # enrolment, which is what makes the drainer's "409 from a replayed key
        # is a success" rule (§12.3) easy to get right.
        return jsonify(stored), 200

    body = _parse_json(raw_body, cfg.max_json_depth)

    try:
        status, response = enrolment.enrol(
            body=body, request_hash=request_hash, idempotency_key=idempotency_key,
            device_id=device["device_id"], cfg=cfg)
    except AppError as exc:
        metrics.incr("enrol_errors_total")
        audit.log_audit(event_type="enrol", actor=device["device_id"],
                        result=exc.code, detail={"detail": exc.detail})
        raise

    return jsonify(response), status


@bp.post("/reenrol")
def reenrol():
    """Explicit supersede. Identical to /enrol except that it requires a separate
    X-Batch-Authorisation token, marks the old row superseded, resets the counter
    state, and writes an audit entry with a MANDATORY free-text reason.

    There is no implicit supersede path anywhere in this codebase. A tag that is
    already enrolled and shows up again is a 409, not a quiet overwrite (D10).
    """
    from auth_admin import parse_token

    cfg = current_app.config["APP_CONFIG"]
    ratelimit.check("reenrol", ratelimit.ip_prefix(request.remote_addr))

    claims = parse_token(request.headers.get("X-Batch-Authorisation", ""))
    if "batch:write" not in claims.get("scopes", []):
        raise BadSignature("batch authorisation token lacks batch:write")

    device, raw_body, request_hash, idempotency_key = _authenticate()
    body = _parse_json(raw_body, cfg.max_json_depth)

    reason = body.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 8:
        raise BadRequest("reenrol requires a 'reason' of at least 8 characters")

    tag_index_hint = body.get("supersedes_tag_index")
    if not isinstance(tag_index_hint, str) or not tag_index_hint:
        raise BadRequest("reenrol requires 'supersedes_tag_index'")

    # The old row is ARCHIVED, never deleted — it is evidence, and a register
    # that forgets is not a register. products.tag_index is UNIQUE, so the old
    # row's index is tombstoned to free the live one for the new record. Its
    # counter state goes first because of the foreign key.
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM products WHERE tag_index = %s AND status = 'active' "
                    "FOR UPDATE", (tag_index_hint,))
        old = cur.fetchone()
        if old is None:
            raise IdempotencyConflict("no active record for that tag_index")
        old_id = old[0]
        cur.execute("DELETE FROM tag_counter_state WHERE tag_index = %s",
                    (tag_index_hint,))
        cur.execute(
            "UPDATE products SET status = 'superseded', tag_index = %s WHERE id = %s",
            (f"superseded:{old_id}:{tag_index_hint}", old_id))

    audit.log_audit(event_type="reenrol", tag_index=tag_index_hint,
                    actor=claims.get("sub"), result="superseded",
                    detail={"reason": reason.strip(), "device_id": device["device_id"],
                            "superseded_product_id": old_id,
                            "jti": claims.get("jti")})

    status, response = enrolment.enrol(
        body=body, request_hash=request_hash, idempotency_key=idempotency_key,
        device_id=device["device_id"], cfg=cfg)

    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE products SET superseded_by = "
            "  (SELECT id FROM products WHERE tag_index = %s) WHERE id = %s",
            (response["tag_index"], old_id))

    return jsonify(response), status
