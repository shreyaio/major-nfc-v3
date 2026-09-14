"""Batch session: two-person authorisation and the local quota view.
ARCHITECTURE.md §12.6.

    $ python enroller.py --batch AMX-2026-09-001
    Batch AMX-2026-09-001 — Amoxicillin 500mg
      mfg_date 2026-09-10   shelf_life 730 days   quota 5000   enrolled 0
    Opened by: shreya
    Countersigned by: ________     <- must differ from opened_by (DB CHECK)

Two things this module does NOT do, deliberately:

  It does not enforce the quota. That is a DATABASE CHECK CONSTRAINT. The 5,001st
  enrolment fails at the database whatever this process believes. An
  application-level count is a race; a CHECK is not. This is the cheapest
  mitigation for a stolen Pi signing key (F1) — it converts an unlimited
  compromise into a bounded one, for free — and it closes G5, because enrolments
  outside an open batch have nowhere to land.

  It does not ask the operator for mfg_date. That comes from the BATCH RECORD
  (F8). One typo would otherwise produce a wrong expiry date on a medicine pack,
  signed and permanently recorded.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import requests

log = logging.getLogger(__name__)


class BatchUnavailable(RuntimeError):
    """The batch does not exist, is not open, or the backend is unreachable."""


@dataclass(frozen=True)
class BatchSession:
    batch_ref: str
    product_name: str
    mfg_date: str
    shelf_life_days: int
    quota: int
    enrolled_count: int
    opened_by: str
    countersigned_by: str

    @property
    def remaining(self) -> int:
        return max(self.quota - self.enrolled_count, 0)

    def banner(self) -> str:
        return (f"Batch {self.batch_ref} — {self.product_name}\n"
                f"  mfg_date {self.mfg_date}   shelf_life {self.shelf_life_days} days"
                f"   quota {self.quota}   enrolled {self.enrolled_count}"
                f"   remaining {self.remaining}\n"
                f"  opened by {self.opened_by}, countersigned by {self.countersigned_by}")


def load(backend_url: str, batch_ref: str, admin_token: str,
         timeout: int = 20) -> BatchSession:
    """Fetch the batch from the backend. The Pi never invents batch metadata."""
    if not admin_token:
        raise BatchUnavailable(
            "a batch:read admin token is required to open a batch session. "
            "Mint one offline with backend/scripts/mint_admin_token.py.")
    try:
        resp = requests.get(f"{backend_url.rstrip('/')}/api/v2/admin/batches",
                            params={"status": "open"},
                            headers={"Authorization": f"Bearer {admin_token}"},
                            timeout=timeout)
    except requests.RequestException as exc:
        raise BatchUnavailable(f"cannot reach the backend: {exc}") from exc

    if resp.status_code != 200:
        raise BatchUnavailable(
            f"backend returned {resp.status_code} listing open batches")

    for batch in resp.json().get("batches", []):
        if batch.get("batch_ref") == batch_ref:
            if batch.get("status") != "open":
                raise BatchUnavailable(
                    f"batch {batch_ref} is {batch.get('status')}, not open")
            return BatchSession(
                batch_ref=batch["batch_ref"],
                product_name=batch["product_name"],
                mfg_date=batch["mfg_date"],
                shelf_life_days=batch["shelf_life_days"],
                quota=batch["quota"],
                enrolled_count=batch["enrolled_count"],
                opened_by=batch["opened_by"],
                countersigned_by=batch["countersigned_by"])

    raise BatchUnavailable(
        f"no open batch {batch_ref}. Open one first via the admin console "
        f"(it needs two different people: opened_by and countersigned_by).")


def confirm_countersignature(session: BatchSession, prompt=input) -> str:
    """Ask the second person to type their name at the console.

    The database CHECK already guarantees the two names differ on the batch
    record. This prompt is the operational half: a second real person has to be
    standing there. If one operator types two names, the control is theatre —
    that is open question 4 in §22 and it is a process problem, not a code one.
    """
    print(session.banner())
    who = prompt(f"Countersigned by [{session.countersigned_by}]: ").strip()
    who = who or session.countersigned_by
    if who == session.opened_by:
        raise BatchUnavailable(
            "the countersignature must come from a different person than "
            f"{session.opened_by}")
    return who
