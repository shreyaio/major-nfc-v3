"""GET /api/v2/verify — the core consumer route. ARCHITECTURE.md §9.6-§9.8.

This route module does input handling and serialisation only. Every decision is
made by services/verification.decide(), which is a pure function and therefore
exhaustively unit-testable without Flask or a database.

Two anti-oracle requirements are implemented here rather than in the service,
because both are properties of the RESPONSE rather than of the verdict:

  1. Same shape and similar size for every verdict. `product` is always present
     as a key; it is null for negative verdicts. `unknown` must not be a visibly
     shorter response than `authentic` (F23, F24).
  2. A response-time floor. An `unknown` returns after one indexed lookup while
     an `authentic` does a lookup plus an X25519 unwrap plus four GCM
     decryptions. The difference is measurable and leaks registration status even
     with identical bodies (D22).

There is NO 404 on this route. An unregistered tag returns 200 with
{"verdict": "unknown"}. Status codes must not become a second, unnormalised
oracle alongside the response body (F23).
"""
from __future__ import annotations

import logging
import time
from dataclasses import replace
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

import audit
import crypto_envelope
import crypto_rowsig
import db
import keys
import metrics
import mirror as mirror_mod
import ratelimit
import tag_index as tag_index_mod
from errors import AppError
from services import counter as counter_svc
from services import verification
from services.verification import Binding, Decision, Verdict

log = logging.getLogger(__name__)

bp = Blueprint("verify", __name__, url_prefix="/api/v2")

_PRODUCT_COLS = (
    "id", "tag_index", "binding_token_hash", "product_id_ct", "batch_id_ct",
    "mfg_date_ct", "tag_uid_ct", "enc_dek", "shelf_life", "expiry_date",
    "crypto_version", "enrol_counter", "batch_ref", "device_id",
    "originality_status", "status", "binding_class", "enrolled_at",
    "row_sig", "row_sig_alg", "row_key_version",
)


def _load_product(cur, tag_index: str) -> dict | None:
    cur.execute(
        f"SELECT {', '.join(_PRODUCT_COLS)} FROM products WHERE tag_index = %s",  # noqa: S608 — interpolates a module-level column tuple, never user input
        (tag_index,))
    row = cur.fetchone()
    return dict(zip(_PRODUCT_COLS, row, strict=True)) if row else None


def _load_batch(cur, batch_ref: str) -> dict | None:
    cur.execute(
        "SELECT batch_ref, product_name, status, recall_notice FROM batches "
        " WHERE batch_ref = %s", (batch_ref,))
    row = cur.fetchone()
    cols = ("batch_ref", "product_name", "status", "recall_notice")
    return dict(zip(cols, row, strict=True)) if row else None


def _decrypt_product(row: dict) -> dict | None:
    """Product details for a verdict that displays them. Returns None on any
    failure — §15.3 rule 1: when uncertain, never upgrade the answer."""
    try:
        dek = crypto_envelope.unwrap_dek(row["enc_dek"],
                                         keys.field_recipient_private_key())
        expiry = row["expiry_date"]
        return {
            "name": crypto_envelope.open_field(row["product_id_ct"], dek, "product_id"),
            "batch": crypto_envelope.open_field(row["batch_id_ct"], dek, "batch_id"),
            "mfg_date": crypto_envelope.open_field(row["mfg_date_ct"], dek, "mfg_date"),
            "expiry": expiry.isoformat() if hasattr(expiry, "isoformat") else expiry,
        }
    except Exception as exc:
        log.warning("product_decrypt_failed", extra={"error": exc.__class__.__name__})
        return None


def _row_sig_valid(row: dict, cfg) -> bool:
    try:
        view = crypto_rowsig.signable_view(row)
        return crypto_rowsig.verify_row(view, row["row_sig"], cfg.row_signing_pubkey)
    except Exception:
        return False


@bp.get("/verify")
def verify():
    cfg = current_app.config["APP_CONFIG"]
    started = time.perf_counter()
    metrics.incr("verify_total")

    ip_hash = audit.hash_ip(request.remote_addr)
    ua_class = audit.classify_ua(request.headers.get("User-Agent"))

    try:
        # Duplicate parameters are rejected outright (B8). Flask's args.get
        # silently takes the first value, which is exactly what parameter
        # pollution relies on when a front layer takes the last.
        raw_m = mirror_mod.single_param(request.args, "m")
        raw_t = mirror_mod.single_param(request.args, "t")
        parsed, token = mirror_mod.parse_mirror(raw_m, raw_t)

        # `live=1` is a CLAIM by the page that it performed a Web NFC read. It
        # can only ever upgrade the reported binding LABEL; it never changes the
        # verdict, so a lying client gains nothing (C8).
        live = request.args.get("live") == "1"

        ratelimit.check("verify", ratelimit.ip_prefix(request.remote_addr))

        decision, product = _decide(parsed, token, cfg, live, ip_hash, ua_class)
    except AppError:
        metrics.incr("verify_errors_total")
        raise
    except Exception:
        # Any unexpected failure is an indeterminate verdict, never a positive
        # one and never a bare 500 to a worried patient (§15.3 rule 1).
        metrics.incr("verify_errors_total")
        log.exception("verify_unexpected_error")
        decision = Decision(
            verdict=Verdict.RECORD_INVALID, binding=Binding.NONE,
            checks={"record": "fail", "counter": "not_checked",
                    "recall": "not_checked", "expiry": "not_checked"})
        product = None

    metrics.incr(f"verify_verdict_{decision.verdict.value}")

    body = _serialise(decision, product)

    # Response-time floor (D22). Measured across the whole handler, not just the
    # database call, so the padding actually covers the difference it is hiding.
    elapsed_ms = (time.perf_counter() - started) * 1000
    if elapsed_ms < cfg.verify_time_floor_ms:
        time.sleep((cfg.verify_time_floor_ms - elapsed_ms) / 1000)

    response = jsonify(body)
    # Closes C9: a cached verdict is a verdict that outlives the counter check.
    response.headers["Cache-Control"] = "no-store"
    return response, 200


def _decide(parsed, token, cfg, live, ip_hash, ua_class):
    """Steps 0-11 of §9.7, plus the atomic counter advance and the concurrency
    re-check the advance can trigger. Returns (Decision, product_or_None)."""
    now = datetime.now(timezone.utc)

    def machine(row, state, batch, token_matches, row_sig_valid):
        return verification.decide(
            mirror=parsed, token=token, row=row, state=state, batch=batch, now=now,
            row_sig_valid=row_sig_valid, token_matches=token_matches,
            max_taps_per_day=cfg.max_taps_per_day,
            velocity_grace=cfg.velocity_grace, live_read=live)

    # Step 0 — the tag's mirror was never enabled. This is its own verdict and
    # its own incident kind: a tag whose mirror never turned on is a
    # manufacturing defect we want to hear about, not an UNKNOWN to shrug at.
    if parsed.placeholder:
        decision = machine(None, None, None, False, False)
        audit.log_audit(event_type="verify", actor="public",
                        result=Verdict.MIRROR_DISABLED.value,
                        source_ip_hash=ip_hash, user_agent_class=ua_class)
        return decision, None

    tag_index = tag_index_mod.tag_index(parsed.uid, cfg.tag_index_key)

    with db.connection() as conn, conn.cursor() as cur:
        row = _load_product(cur, tag_index)
        state = counter_svc.load_state(cur, tag_index) if row else None
        batch = _load_batch(cur, row["batch_ref"]) if row else None

    token_matches = bool(row) and tag_index_mod.binding_token_matches(
        token, row["binding_token_hash"])
    row_sig_valid = bool(row) and _row_sig_valid(row, cfg)
    if row is not None and token_matches and not row_sig_valid:
        metrics.incr("row_sig_invalid_total")

    decision = machine(row, state, batch, token_matches, row_sig_valid)

    if decision.advance_counter:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            advanced = counter_svc.advance(cur, tag_index, parsed.counter)
        if not advanced:
            # Another request already advanced past this counter while we were
            # deciding. That is itself a divergence: re-read the state and route
            # back through the machine, which now sees counter <= max_counter.
            with db.connection() as conn, conn.cursor() as cur:
                state = counter_svc.load_state(cur, tag_index)
            decision = machine(row, state, batch, token_matches, row_sig_valid)

    if decision.divergence is not None:
        incident_id = counter_svc.record_divergence(
            tag_index, decision.divergence,
            source_ip_hash=ip_hash, user_agent_class=ua_class)
        decision = replace(decision, advance_counter=False,
                           incident_id=incident_id)
    else:
        audit.log_audit(event_type="verify",
                        tag_index=tag_index if row else None, actor="public",
                        result=decision.verdict.value,
                        source_ip_hash=ip_hash, user_agent_class=ua_class,
                        detail={"binding": decision.binding.value,
                                "counter": parsed.counter})

    # Product details are decrypted ONLY for verdicts that display them. Nothing
    # decrypts data it is not about to show.
    product = None
    if row is not None and decision.verdict in (
            Verdict.AUTHENTIC, Verdict.EXPIRED, Verdict.RECALLED, Verdict.WITHDRAWN):
        product = _decrypt_product(row)

    return decision, product


def _serialise(decision, product) -> dict:
    """Uniform shape for every verdict (F23, F24).

    `product` is always present and null for negative verdicts, so an `unknown`
    response is not visibly shorter than an `authentic` one. The per-check
    breakdown is returned deliberately: it makes the system auditable from
    outside, it is honest about what was actually verified, it costs nothing —
    and it is the deployment metric for the paper, namely what fraction of real
    verifications received the strong guarantee.
    """
    return {
        "verdict": decision.verdict.value,
        "binding": decision.binding.value,
        "product": product,
        "checks": decision.checks,
        "incident": ({"id": decision.incident_id,
                      "kind": decision.divergence.kind.value}
                     if decision.divergence is not None else None),
        "recall_notice": decision.recall_notice,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
