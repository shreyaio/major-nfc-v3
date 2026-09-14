"""POST /api/v2/report — the consumer report channel. ARCHITECTURE.md §10.4.

A consumer holding a real suspicious pack is the single most valuable signal in
the system, and v1 discarded it entirely (F35). Rate limit it, triage it, but
never drop it.

Abuse control is PROOF-OF-WORK, not a CAPTCHA (G8). The page fetches a
challenge, finds a nonce where sha256(challenge || nonce) has POW_DIFFICULTY_BITS
leading zero bits, and submits it. That costs a phone about a second and a
flooder a great deal more — with no third-party service, no tracking, and no
cost. A CAPTCHA would put a Google dependency between a patient and a safety
answer, which is the wrong trade in this context.

The challenge is STATELESS: it is HMAC-signed by the server and carries its own
timestamp, so there is no challenge table to grow, to clean up, or to exhaust.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time

from flask import Blueprint, current_app, jsonify, request

import audit
import db
import ratelimit
from errors import BadRequest, Forbidden

log = logging.getLogger(__name__)

bp = Blueprint("report", __name__, url_prefix="/api/v2")

CHALLENGE_TTL_SECONDS = 600
MAX_NOTE_CHARS = 2000
MAX_FIELD_CHARS = 200

ALLOWED_VERDICTS = frozenset({
    "authentic", "expired", "recalled", "withdrawn", "suspect_duplicate",
    "mirror_disabled", "record_invalid", "unknown", "offline",
})


def _challenge_secret(cfg) -> bytes:
    # Derived from IP_HASH_SEED rather than adding another env var. Domain
    # separation keeps it independent of the IP pseudonymisation key.
    return hmac.new(cfg.ip_hash_seed, b"nfcmed/v2/pow", hashlib.sha256).digest()


def mint_challenge(cfg) -> str:
    nonce = secrets.token_hex(16)
    issued = str(int(time.time()))
    body = f"{nonce}.{issued}"
    mac = hmac.new(_challenge_secret(cfg), body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{mac}"


def check_challenge(cfg, challenge: str) -> None:
    parts = (challenge or "").split(".")
    if len(parts) != 3:
        raise Forbidden("proof-of-work challenge is malformed")
    nonce, issued, mac = parts
    expected = hmac.new(_challenge_secret(cfg), f"{nonce}.{issued}".encode(),
                        hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(mac, expected):
        raise Forbidden("proof-of-work challenge is not ours")
    try:
        age = time.time() - int(issued)
    except ValueError as exc:
        raise Forbidden("proof-of-work challenge is malformed") from exc
    if not -60 <= age <= CHALLENGE_TTL_SECONDS:
        raise Forbidden("proof-of-work challenge has expired")


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        while byte & 0x80 == 0:
            bits += 1
            byte <<= 1
        break
    return bits


def check_pow(cfg, challenge: str, nonce: int) -> None:
    if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
        raise BadRequest("pow.nonce must be a non-negative integer")
    digest = hashlib.sha256(f"{challenge}{nonce}".encode()).digest()
    if leading_zero_bits(digest) < cfg.pow_difficulty_bits:
        raise Forbidden("proof-of-work is insufficient")


def _clean(value, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadRequest("report fields must be strings")
    value = value.strip()
    if not value:
        return None
    if len(value) > limit:
        raise BadRequest(f"a report field exceeds {limit} characters")
    return value


@bp.get("/report/challenge")
def challenge():
    cfg = current_app.config["APP_CONFIG"]
    ratelimit.check("report", ratelimit.ip_prefix(request.remote_addr))
    return jsonify({"challenge": mint_challenge(cfg),
                    "difficulty_bits": cfg.pow_difficulty_bits,
                    "ttl_seconds": CHALLENGE_TTL_SECONDS})


@bp.post("/report")
def submit_report():
    cfg = current_app.config["APP_CONFIG"]
    ratelimit.check("report", ratelimit.ip_prefix(request.remote_addr))

    if (request.content_type or "").split(";")[0].strip() != "application/json":
        raise BadRequest("Content-Type must be application/json")
    try:
        body = json.loads(request.get_data(cache=False))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BadRequest("body is not valid JSON") from exc
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")

    pow_block = body.get("pow")
    if not isinstance(pow_block, dict):
        raise BadRequest("pow block is required")
    check_challenge(cfg, pow_block.get("challenge", ""))
    check_pow(cfg, pow_block.get("challenge", ""), pow_block.get("nonce"))

    verdict_shown = body.get("verdict_shown")
    if verdict_shown is not None and verdict_shown not in ALLOWED_VERDICTS:
        raise BadRequest("verdict_shown is not a known verdict")

    # tag_index is accepted as an opaque echo of what the verify response
    # returned. It is never trusted to identify a row for any privileged
    # purpose — it only groups reports for triage.
    tag_index = _clean(body.get("tag_index"), 64)

    fields = (tag_index, verdict_shown,
              _clean(body.get("pharmacy_name"), MAX_FIELD_CHARS),
              _clean(body.get("city"), MAX_FIELD_CHARS),
              _clean(body.get("note"), MAX_NOTE_CHARS),
              _clean(body.get("contact"), MAX_FIELD_CHARS))

    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO consumer_report (tag_index, verdict_shown, pharmacy_name, "
            "  city, note, contact) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            fields)
        report_id = cur.fetchone()[0]

    audit.log_audit(event_type="report", tag_index=tag_index, actor="public",
                    result="received",
                    source_ip_hash=audit.hash_ip(request.remote_addr),
                    user_agent_class=audit.classify_ua(request.headers.get("User-Agent")),
                    detail={"report_id": report_id, "verdict_shown": verdict_shown})

    return jsonify({"status": "received", "reference": report_id}), 201
