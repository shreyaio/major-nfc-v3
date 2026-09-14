"""Enrolment business logic. ARCHITECTURE.md §9.5.

The order of operations below is NOT arbitrary and must not be reordered — each
step assumes the previous one passed. Most importantly, the signature is
verified over the raw body bytes BEFORE anything parses the body: unparsed
attacker data must never reach a parser (D1). v1 got this right; keep it.

Note what the client does NOT send: no tag_index, no shelf_life, no expiry_date,
no plaintext anything. The backend derives all three — shelf_life from the batch,
expiry_date from the decrypted mfg_date, tag_index from the decrypted UID. A
client that cannot state the expiry date cannot get the expiry date wrong (F8).
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

import psycopg2
from psycopg2 import errors as pg_errors

import audit
import crypto_envelope
import crypto_rowsig
import db
import keys
import metrics
import tag_index as tag_index_mod
from errors import (
    BadRequest,
    BatchNotOpen,
    BatchQuotaExhausted,
    DecryptFailed,
    IdempotencyConflict,
    MfgDateInvalid,
    TagAlreadyEnrolled,
)
from services import counter as counter_svc

log = logging.getLogger(__name__)

ENROL_SCHEMA = "nfcmed.enrol.v2"
ALLOWED_CRYPTO_VERSIONS = frozenset({"aes_gcm_v2"})
ALLOWED_ORIGINALITY = frozenset({"verified", "unverified", "failed"})
ALLOWED_BINDING_CLASS = frozenset({"counter", "none"})

MAX_MFG_AGE_DAYS = 3650          # 10 years — older than any plausible pack
MFG_BATCH_TOLERANCE_DAYS = 3     # the line may run a couple of days past the batch date
COUNTER_MAX = 0xFFFFFF


def calculate_expiry(mfg_date: date, shelf_life_days: int) -> date:
    """The one place expiry is derived. §15.3 rule 4: one source of truth per
    fact — never recomputed at verify time, never supplied by the client.
    (Carried over from v1's utils.calculate_expiry, which was the only function
    in that module worth keeping.)"""
    return mfg_date + timedelta(days=shelf_life_days)


# --------------------------------------------------------------- validation ---

def validate_body(body: dict) -> None:
    """Shape checks only. Raises BadRequest with a code, never a bare 500."""
    if not isinstance(body, dict):
        raise BadRequest("body is not a JSON object")
    if body.get("schema") != ENROL_SCHEMA:
        raise BadRequest(f"schema must be {ENROL_SCHEMA}")
    if body.get("crypto_version") not in ALLOWED_CRYPTO_VERSIONS:
        raise BadRequest("unsupported crypto_version")

    for field in ("batch_ref", "binding_token_hash"):
        if not isinstance(body.get(field), str) or not body[field].strip():
            raise BadRequest(f"missing or invalid {field}")

    counter = body.get("enrol_counter")
    if not isinstance(counter, int) or isinstance(counter, bool) \
            or not 0 <= counter <= COUNTER_MAX:
        raise BadRequest("enrol_counter must be an integer in 0..16777215")

    if body.get("originality_status") not in ALLOWED_ORIGINALITY:
        raise BadRequest("invalid originality_status")
    if body.get("binding_class", "counter") not in ALLOWED_BINDING_CLASS:
        raise BadRequest("invalid binding_class")

    sealed = body.get("sealed")
    if not isinstance(sealed, dict):
        raise BadRequest("missing sealed payload")
    if not isinstance(sealed.get("enc_dek"), str):
        raise BadRequest("missing enc_dek")
    for name in crypto_envelope.SEALED_FIELDS:
        part = sealed.get(name)
        if not isinstance(part, dict) or not isinstance(part.get("n"), str) \
                or not isinstance(part.get("c"), str):
            raise BadRequest(f"sealed.{name} is malformed")


def validate_mfg_date(raw: str, batch_mfg: date, now: datetime) -> date:
    """F8: a wrong expiry date on a medicine pack, signed and permanently
    recorded, is a patient-safety defect, not a data-quality one."""
    try:
        parsed = date.fromisoformat(raw.strip())
    except (ValueError, AttributeError) as exc:
        raise MfgDateInvalid(f"mfg_date is not an ISO date: {raw!r}") from exc

    today = now.date()
    if parsed > today:
        raise MfgDateInvalid("mfg_date is in the future")
    if (today - parsed).days > MAX_MFG_AGE_DAYS:
        raise MfgDateInvalid("mfg_date is more than 10 years old")
    if abs((parsed - batch_mfg).days) > MFG_BATCH_TOLERANCE_DAYS:
        raise MfgDateInvalid(
            f"mfg_date {parsed} does not match batch mfg_date {batch_mfg}")
    return parsed


# ------------------------------------------------------------- idempotency ---

def lookup_idempotency(cur, key: str, request_hash: str) -> tuple[int, dict] | None:
    """(status, body) to replay, or None to continue. Raises on a conflict."""
    cur.execute("SELECT request_hash, response_status, response_body "
                "  FROM idempotency_key WHERE key = %s", (key,))
    row = cur.fetchone()
    if row is None:
        return None
    stored_hash, status, body = row
    if stored_hash != request_hash:
        # Same key, different body: the client reused an idempotency key for a
        # different request. Replaying the old response would be wrong and
        # storing the new one would break the guarantee (D9).
        raise IdempotencyConflict("idempotency key reused with a different body")
    metrics.incr("enrol_idempotent_replays")
    return status, body


# ------------------------------------------------------------------ enrol ----

def enrol(*, body: dict, request_hash: str, idempotency_key: str, device_id: str,
          cfg, now: datetime | None = None) -> tuple[int, dict]:
    """Steps 7-16 of §9.5. Steps 1-6 (transport, signature, device, timestamp,
    idempotency lookup) happen in routes/enrol.py before this is called."""
    now = now or datetime.now(timezone.utc)

    # 7. Schema and crypto_version allow-list.
    validate_body(body)
    sealed = body["sealed"]

    with db.connection(write=True) as conn, conn.cursor() as cur:
        # 8. The batch must exist and be open, with quota left.
        batch = load_batch_for_update(cur, body["batch_ref"])
        if batch is None:
            raise BatchNotOpen(f"unknown batch {body['batch_ref']}")
        if batch["status"] != "open":
            raise BatchNotOpen(f"batch is {batch['status']}")
        if batch["enrolled_count"] >= batch["quota"]:
            raise BatchQuotaExhausted("batch quota reached")

        # 9. Unseal the DEK and decrypt ONLY tag_uid and mfg_date. Nothing needs
        #    product_id or batch_id at enrolment, so nothing decrypts them.
        try:
            opened = crypto_envelope.open_record(
                sealed, keys.field_recipient_private_key(),
                only=("tag_uid", "mfg_date"))
        except crypto_envelope.EnvelopeError as exc:
            raise DecryptFailed(str(exc)) from exc

        # 10-12. Derive everything the client was not allowed to state.
        mfg_date = validate_mfg_date(opened["mfg_date"], batch["mfg_date"], now)
        try:
            tag_index = tag_index_mod.tag_index(opened["tag_uid"], cfg.tag_index_key)
        except ValueError as exc:
            raise BadRequest(f"decrypted tag_uid is not a valid UID: {exc}") from exc
        shelf_life = batch["shelf_life_days"]
        expiry_date = calculate_expiry(mfg_date, shelf_life)

        # 13. Build the row and sign it.
        row = {
            "tag_index": tag_index,
            "binding_token_hash": body["binding_token_hash"].lower(),
            "product_id_ct": json.dumps(sealed["product_id"], sort_keys=True,
                                        separators=(",", ":")),
            "batch_id_ct": json.dumps(sealed["batch_id"], sort_keys=True,
                                      separators=(",", ":")),
            "mfg_date_ct": json.dumps(sealed["mfg_date"], sort_keys=True,
                                      separators=(",", ":")),
            "tag_uid_ct": json.dumps(sealed["tag_uid"], sort_keys=True,
                                     separators=(",", ":")),
            "enc_dek": sealed["enc_dek"],
            "shelf_life": shelf_life,
            "expiry_date": expiry_date.isoformat(),
            "crypto_version": body["crypto_version"],
            "enrol_counter": body["enrol_counter"],
            "batch_ref": batch["batch_ref"],
            "status": "active",
            "device_id": device_id,
            "originality_status": body["originality_status"],
            "enrolled_at": now.isoformat(),
            "row_sig_alg": "ed25519",
            "row_key_version": keys.row_key_version(),
        }
        row_sig = crypto_rowsig.sign_row(crypto_rowsig.signable_view(row),
                                         keys.row_signing_key())

        # 14. ONE transaction. An insert that succeeds while the quota increment
        #     fails would let the quota drift, and the quota is the mitigation
        #     for a stolen signing key (§12.6).
        try:
            cur.execute(
                "INSERT INTO products (tag_index, binding_token_hash, product_id_ct, "
                "  batch_id_ct, mfg_date_ct, tag_uid_ct, enc_dek, shelf_life, "
                "  expiry_date, crypto_version, enrol_counter, batch_ref, device_id, "
                "  originality_status, status, binding_class, enrolled_at, row_sig, "
                "  row_sig_alg, row_key_version) "
                "VALUES (%(tag_index)s, %(binding_token_hash)s, %(product_id_ct)s, "
                "  %(batch_id_ct)s, %(mfg_date_ct)s, %(tag_uid_ct)s, %(enc_dek)s, "
                "  %(shelf_life)s, %(expiry_date)s, %(crypto_version)s, "
                "  %(enrol_counter)s, %(batch_ref)s, %(device_id)s, "
                "  %(originality_status)s, %(status)s, %(binding_class)s, "
                "  %(enrolled_at)s, %(row_sig)s, %(row_sig_alg)s, %(row_key_version)s) "
                "RETURNING id",
                {**row, "row_sig": row_sig,
                 "binding_class": body.get("binding_class", "counter")})
            product_id = cur.fetchone()[0]

            cur.execute(
                "UPDATE batches SET enrolled_count = enrolled_count + 1 "
                " WHERE batch_ref = %s", (batch["batch_ref"],))

            counter_svc.create_initial_state(cur, tag_index, body["enrol_counter"])

            response = {"status": "enrolled", "tag_index": tag_index,
                        "expiry_date": expiry_date.isoformat()}
            cur.execute(
                "INSERT INTO idempotency_key (key, device_id, request_hash, "
                "  response_status, response_body) VALUES (%s, %s, %s, %s, %s)",
                (idempotency_key, device_id, request_hash, 201, json.dumps(response)))

        except pg_errors.UniqueViolation as exc:
            # products.tag_index UNIQUE (D10) or idempotency_key PRIMARY KEY (D9,
            # F11). Both mean "this already happened"; only the first is the
            # client's problem to fix.
            if "tag_index" in str(exc):
                raise TagAlreadyEnrolled("tag_index already present") from exc
            raise IdempotencyConflict("idempotency key already used") from exc
        except pg_errors.CheckViolation as exc:
            if "quota" in str(exc):
                raise BatchQuotaExhausted("batch quota CHECK violated") from exc
            raise BadRequest("a database constraint rejected this record") from exc
        except psycopg2.Error as exc:
            log.error("enrol_insert_failed", extra={"error": exc.__class__.__name__})
            raise

    # 15. Audit on every branch — including the failure branches, which the
    #     route handler logs from its except clauses.
    audit.log_audit(event_type="enrol", tag_index=tag_index, actor=device_id,
                    result="success",
                    detail={"batch_ref": batch["batch_ref"], "product_id": product_id,
                            "originality_status": body["originality_status"],
                            "binding_class": body.get("binding_class", "counter")})
    metrics.incr("enrol_total")
    return 201, response


def load_batch_for_update(cur, batch_ref: str) -> dict | None:
    """SELECT ... FOR UPDATE so two concurrent enrolments cannot both read the
    same enrolled_count and both pass the quota check in Python. The CHECK
    constraint is the real backstop; this just makes the error message better."""
    cur.execute(
        "SELECT batch_ref, product_name, mfg_date, shelf_life_days, quota, "
        "       enrolled_count, status, recall_notice "
        "  FROM batches WHERE batch_ref = %s FOR UPDATE", (batch_ref,))
    row = cur.fetchone()
    if row is None:
        return None
    cols = ("batch_ref", "product_name", "mfg_date", "shelf_life_days", "quota",
            "enrolled_count", "status", "recall_notice")
    return dict(zip(cols, row, strict=True))
