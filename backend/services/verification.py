"""The verdict state machine. ARCHITECTURE.md §9.7.

This is the core of the system, and it is a PURE FUNCTION over
(mirror, product_row, counter_state, batch, now) returning a Decision. No Flask,
no database, no clock of its own. That is what lets
tests/unit/test_verdict_machine.py enumerate the whole state space and assert the
one property that matters:

    NO COMBINATION YIELDS `authentic` UNLESS EVERY CHECK PASSED.

The order below is not arbitrary — each step assumes the previous one passed:

 0. placeholder mirror                    -> MIRROR_DISABLED, binding "none"
 1. tag_index = HMAC(TAG_INDEX_KEY, uid)  (done by the caller)
 2. no row                                -> UNKNOWN
 3. binding token mismatch                -> UNKNOWN   (never "wrong token": an
                                             attacker must learn nothing from it)
 4. row signature invalid                 -> RECORD_INVALID
 5. counter state sticky-flagged          -> SUSPECT_DUPLICATE
 6. counter <= max_counter                -> SUSPECT_DUPLICATE (repeat/rollback)
 7. counter > velocity bound              -> SUSPECT_DUPLICATE (velocity)
 8. advance state (atomic, caller does it)
 9. recalled / withdrawn                  -> RECALLED / WITHDRAWN
10. today > expiry_date                   -> EXPIRED
11.                                       -> AUTHENTIC

NEVER RETURN "counterfeit" OR "fake". Attribution is genuinely ambiguous: an
attacker who pre-advances a clone's counter causes the GENUINE pack to trip the
alarm. The velocity bound handles the realistic version of that — a pack
manufactured eleven days ago cannot plausibly have been tapped 900,000 times, and
the counter cannot be written, only advanced by real reads at ~10 ms each. But
the honest response to divergence is to flag both readings, open an incident and
hand the decision to a human. Declaring the wrong pack counterfeit is a worse
failure than declaring an ambiguity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum

ALLOWED_CRYPTO_VERSIONS = frozenset({"aes_gcm_v2"})


class Verdict(str, Enum):
    AUTHENTIC = "authentic"
    EXPIRED = "expired"
    RECALLED = "recalled"
    WITHDRAWN = "withdrawn"
    SUSPECT_DUPLICATE = "suspect_duplicate"
    MIRROR_DISABLED = "mirror_disabled"
    RECORD_INVALID = "record_invalid"
    UNKNOWN = "unknown"


NEGATIVE_VERDICTS = frozenset(v for v in Verdict if v is not Verdict.AUTHENTIC)


class Binding(str, Enum):
    COUNTER_LIVEREAD = "counter+liveread"  # mirrored counter AND a Web NFC live read
    COUNTER = "counter"                    # mirrored counter — the normal, strong case
    NONE = "none"                          # no counter present


class DivergenceKind(str, Enum):
    ROLLBACK = "rollback"
    REPEAT = "repeat"
    VELOCITY = "velocity"
    GEO = "geo"
    MIRROR_DISABLED = "mirror_disabled"


CHECK_PASS = "pass"  # noqa: S105 — a check result, not a credential
CHECK_FAIL = "fail"
CHECK_SKIP = "not_checked"


@dataclass(frozen=True)
class Divergence:
    kind: DivergenceKind
    observed_counter: int
    expected_min: int
    velocity_bound: int | None = None


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    binding: Binding
    checks: dict[str, str] = field(default_factory=dict)
    divergence: Divergence | None = None
    # True only when steps 0-7 passed and the caller should now atomically
    # advance tag_counter_state. The advance is a database operation, so it
    # cannot live in a pure function — but the DECISION to advance can.
    advance_counter: bool = False
    recall_notice: str | None = None
    expiry_date: date | None = None
    # Filled in by the route once the incident row has actually been written,
    # so the consumer page can quote a reference when they report the pack.
    incident_id: int | None = None

    @property
    def is_authentic(self) -> bool:
        return self.verdict is Verdict.AUTHENTIC


def _checks(record=CHECK_SKIP, counter=CHECK_SKIP, recall=CHECK_SKIP,
            expiry=CHECK_SKIP) -> dict[str, str]:
    return {"record": record, "counter": counter, "recall": recall, "expiry": expiry}


def velocity_bound(enrol_counter: int, enrolled_at, now: datetime,
                   max_taps_per_day: int, grace: int) -> int:
    """The attribution fix (§9.7 step 7).

    A pack cannot have been tapped more times than its age allows. MAX_TAPS_PER_DAY
    defaults to 50 — generous for a medicine pack, and still catches an attacker
    who fast-forwards a clone's counter by roughly 1000x. VELOCITY_GRACE absorbs
    enrolment-time reads and honest repeat scans in the first days.
    """
    if isinstance(enrolled_at, str):
        enrolled_at = datetime.fromisoformat(enrolled_at)
    if enrolled_at.tzinfo is None:
        enrolled_at = enrolled_at.replace(tzinfo=timezone.utc)
    days = max((now - enrolled_at).days, 1)
    return enrol_counter + max_taps_per_day * days + grace


def decide(*, mirror, token: str, row: dict | None, state: dict | None,
           batch: dict | None, now: datetime, row_sig_valid: bool,
           token_matches: bool, max_taps_per_day: int, velocity_grace: int,
           live_read: bool = False) -> Decision:
    """The whole state machine. See the module docstring for the order.

    `row_sig_valid` and `token_matches` are passed in rather than computed here
    so this function stays free of key material and of crypto imports — the
    caller does the two comparisons, this decides what they mean.
    """
    # --- 0. The tag's mirror was never enabled -----------------------------
    if mirror.placeholder:
        return Decision(
            verdict=Verdict.MIRROR_DISABLED,
            binding=Binding.NONE,
            checks=_checks(counter=CHECK_FAIL),
            divergence=Divergence(DivergenceKind.MIRROR_DISABLED,
                                  observed_counter=0, expected_min=0),
        )

    binding = Binding.COUNTER_LIVEREAD if live_read else Binding.COUNTER

    # --- 2. Unknown tag ----------------------------------------------------
    if row is None:
        return Decision(verdict=Verdict.UNKNOWN, binding=binding, checks=_checks())

    # --- 3. Binding token mismatch -> UNKNOWN, not a distinct verdict -------
    # An attacker who guesses a UID but not the 128-bit token must get exactly
    # the same answer as someone who guessed a UID that was never enrolled.
    if not token_matches:
        return Decision(verdict=Verdict.UNKNOWN, binding=binding, checks=_checks())

    # --- 4. Row integrity --------------------------------------------------
    # crypto_version is checked here as well as by a DB CHECK and by the row
    # signature. Anything other than aes_gcm_v2 is a hard reject, never a
    # fallback (§7.2 — closes F14, D13 and E8 in one line of policy).
    if row.get("crypto_version") not in ALLOWED_CRYPTO_VERSIONS or not row_sig_valid:
        return Decision(verdict=Verdict.RECORD_INVALID, binding=binding,
                        checks=_checks(record=CHECK_FAIL))

    # --- 5. Sticky suspect state (G1) --------------------------------------
    # There is deliberately no path back to 'ok' except an audited admin action.
    # A counterfeiter must not be able to probe which stolen identifiers are
    # still good by waiting for a flag to clear.
    if state is not None and state.get("status") in ("suspect_duplicate", "frozen"):
        return Decision(verdict=Verdict.SUSPECT_DUPLICATE, binding=binding,
                        checks=_checks(record=CHECK_PASS, counter=CHECK_FAIL))

    max_counter = int(state["max_counter"]) if state is not None else -1

    # --- 6. THE MTA CORE ---------------------------------------------------
    if mirror.counter <= max_counter:
        kind = (DivergenceKind.REPEAT if mirror.counter == max_counter
                else DivergenceKind.ROLLBACK)
        return Decision(
            verdict=Verdict.SUSPECT_DUPLICATE, binding=binding,
            checks=_checks(record=CHECK_PASS, counter=CHECK_FAIL),
            divergence=Divergence(kind, observed_counter=mirror.counter,
                                  expected_min=max_counter + 1),
        )

    # --- 7. Velocity bound -------------------------------------------------
    bound = velocity_bound(int(row["enrol_counter"]), row["enrolled_at"], now,
                           max_taps_per_day, velocity_grace)
    if mirror.counter > bound:
        return Decision(
            verdict=Verdict.SUSPECT_DUPLICATE, binding=binding,
            checks=_checks(record=CHECK_PASS, counter=CHECK_FAIL),
            divergence=Divergence(DivergenceKind.VELOCITY,
                                  observed_counter=mirror.counter,
                                  expected_min=max_counter + 1,
                                  velocity_bound=bound),
        )

    # --- 8. The counter check passed. The caller advances state atomically. -
    counter_ok = _checks(record=CHECK_PASS, counter=CHECK_PASS)

    # --- 9. Recall and withdrawal (F20, G2) --------------------------------
    batch_status = (batch or {}).get("status")
    if row.get("status") == "recalled" or batch_status == "recalled":
        return Decision(
            verdict=Verdict.RECALLED, binding=binding, advance_counter=True,
            checks={**counter_ok, "recall": CHECK_FAIL},
            recall_notice=(batch or {}).get("recall_notice"),
            expiry_date=row.get("expiry_date"),
        )
    if row.get("status") in ("withdrawn", "destroyed") or batch_status == "withdrawn":
        return Decision(
            verdict=Verdict.WITHDRAWN, binding=binding, advance_counter=True,
            checks={**counter_ok, "recall": CHECK_FAIL},
            expiry_date=row.get("expiry_date"),
        )
    # A superseded row means the tag was explicitly re-enrolled. The old record
    # is no longer the truth about this object.
    if row.get("status") == "superseded":
        return Decision(verdict=Verdict.RECORD_INVALID, binding=binding,
                        checks=_checks(record=CHECK_FAIL))

    recall_ok = {**counter_ok, "recall": CHECK_PASS}

    # --- 10. Expiry --------------------------------------------------------
    expiry = row.get("expiry_date")
    if isinstance(expiry, str):
        expiry = date.fromisoformat(expiry)
    if expiry is not None and now.date() > expiry:
        return Decision(verdict=Verdict.EXPIRED, binding=binding,
                        advance_counter=True,
                        checks={**recall_ok, "expiry": CHECK_FAIL},
                        expiry_date=expiry)

    # --- 11. Everything passed ---------------------------------------------
    return Decision(verdict=Verdict.AUTHENTIC, binding=binding, advance_counter=True,
                    checks={**recall_ok, "expiry": CHECK_PASS}, expiry_date=expiry)
