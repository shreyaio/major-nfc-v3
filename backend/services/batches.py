"""Batch lifecycle: open, close, list, recall. ARCHITECTURE.md §10.5, §12.6.

Two controls live here that v1 had no equivalent of:

  TWO-PERSON AUTHORISATION. `countersigned_by` must differ from `opened_by`, and
  that is a database CHECK, not a Python `if`. It closes F12 and it is half of
  the answer to G5 (an insider pre-enrolling blank tags against real batch
  numbers).

  ENROLMENT QUOTA. Also a database CHECK. The 5,001st enrolment into a batch of
  5,000 fails at the database whatever the client believes. This is the cheapest
  mitigation for a stolen Pi signing key (F1): it converts an unlimited
  compromise into a bounded one, for free.

RECALL RE-SIGNS EVERY AFFECTED ROW. `status` is inside the row signature (§7.4),
so changing it without re-signing would make every recalled pack return
RECORD_INVALID instead of RECALLED — technically safe, but it would mask a real
regulatory event behind a scary generic error, and a patient holding a recalled
pack would be told "we cannot confirm this" instead of "do not use this". The
re-sign happens inside the same transaction as the status change.
"""
from __future__ import annotations

import logging
from datetime import date

from psycopg2 import errors as pg_errors

import crypto_rowsig
import db
import keys
from errors import BadRequest, Conflict, CountersignatureRequired, NotFound

log = logging.getLogger(__name__)

BATCH_COLS = ("batch_ref", "product_name", "mfg_date", "shelf_life_days", "quota",
              "enrolled_count", "status", "opened_by", "countersigned_by",
              "opened_at", "closed_at", "recall_notice", "recalled_at")


def _row_to_batch(row) -> dict:
    return dict(zip(BATCH_COLS, row, strict=True))


def list_batches(status: str | None = None) -> list[dict]:
    sql = (f"SELECT {', '.join(BATCH_COLS)} FROM batches")  # noqa: S608 — interpolates a module-level column tuple, never user input
    params: tuple = ()
    if status:
        sql += " WHERE status = %s"
        params = (status,)
    sql += " ORDER BY opened_at DESC LIMIT 200"
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return [_row_to_batch(r) for r in cur.fetchall()]


def get_batch(batch_ref: str) -> dict | None:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {', '.join(BATCH_COLS)} FROM batches WHERE batch_ref = %s",  # noqa: S608 — interpolates a module-level column tuple, never user input
                    (batch_ref,))
        row = cur.fetchone()
        return _row_to_batch(row) if row else None


def open_batch(*, batch_ref: str, product_name: str, mfg_date: str,
               shelf_life_days: int, quota: int, opened_by: str,
               countersigned_by: str) -> dict:
    for name, value in (("batch_ref", batch_ref), ("product_name", product_name),
                        ("opened_by", opened_by),
                        ("countersigned_by", countersigned_by)):
        if not isinstance(value, str) or not value.strip():
            raise BadRequest(f"{name} is required")
    if opened_by.strip() == countersigned_by.strip():
        # Also a DB CHECK. Checked here only to return the specific code rather
        # than a generic constraint error.
        raise CountersignatureRequired("countersigned_by must be a different person")
    if not isinstance(quota, int) or quota <= 0:
        raise BadRequest("quota must be a positive integer")
    if not isinstance(shelf_life_days, int) or not 1 <= shelf_life_days <= 3650:
        raise BadRequest("shelf_life_days must be between 1 and 3650")
    try:
        parsed_mfg = date.fromisoformat(str(mfg_date))
    except ValueError as exc:
        raise BadRequest("mfg_date must be an ISO date") from exc

    try:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO batches (batch_ref, product_name, mfg_date, "
                "  shelf_life_days, quota, opened_by, countersigned_by) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (batch_ref.strip(), product_name.strip(), parsed_mfg, shelf_life_days,
                 quota, opened_by.strip(), countersigned_by.strip()))
    except pg_errors.UniqueViolation as exc:
        raise Conflict(f"batch {batch_ref} already exists") from exc
    except pg_errors.CheckViolation as exc:
        if "two_person" in str(exc):
            raise CountersignatureRequired("countersigned_by must differ") from exc
        raise BadRequest("a batch constraint rejected these values") from exc

    return get_batch(batch_ref)


def close_batch(batch_ref: str) -> dict:
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE batches SET status = 'closed', closed_at = NOW() "
            " WHERE batch_ref = %s AND status = 'open' RETURNING batch_ref",
            (batch_ref,))
        if cur.fetchone() is None:
            raise Conflict("batch does not exist or is not open")
    return get_batch(batch_ref)


# Columns needed to rebuild the signed view of a product row.
_PRODUCT_SIG_SELECT = ", ".join(crypto_rowsig.ROW_SIG_FIELDS)


def recall_batch(batch_ref: str, notice: str) -> int:
    """Set the batch to recalled, cascade to its products, and RE-SIGN each row.

    Returns the number of product rows updated. One transaction: a half-applied
    recall is a regulatory event that some packs report and others do not.
    """
    if not notice or not notice.strip():
        raise BadRequest("a recall notice is required — it is what the consumer reads")

    signing_key = keys.row_signing_key()
    updated = 0
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE batches SET status = 'recalled', recall_notice = %s, "
            "       recalled_at = NOW() "
            " WHERE batch_ref = %s AND status IN ('open','closed','recalled') "
            "RETURNING batch_ref",
            (notice.strip(), batch_ref))
        if cur.fetchone() is None:
            raise NotFound(f"no recallable batch {batch_ref}")

        cur.execute(
            f"SELECT id, {_PRODUCT_SIG_SELECT} FROM products "  # noqa: S608 — interpolates a module-level column tuple, never user input
            f" WHERE batch_ref = %s AND status = 'active' FOR UPDATE", (batch_ref,))
        rows = cur.fetchall()

        for row in rows:
            product_id = row[0]
            record = dict(zip(crypto_rowsig.ROW_SIG_FIELDS, row[1:], strict=True))
            record["status"] = "recalled"
            new_sig = crypto_rowsig.sign_row(crypto_rowsig.signable_view(record),
                                             signing_key)
            cur.execute(
                "UPDATE products SET status = 'recalled', row_sig = %s, "
                "       row_key_version = %s WHERE id = %s",
                (new_sig, keys.row_key_version(), product_id))
            updated += 1

    log.info("batch_recalled", extra={"batch_ref": batch_ref, "rows_resigned": updated})
    return updated
