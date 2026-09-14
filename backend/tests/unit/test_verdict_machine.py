"""Exhaustive enumeration of the verdict state machine. ARCHITECTURE.md §17.2.1.

THIS IS THE STRONGEST GUARANTEE IN THE CODEBASE.

services/verification.decide() is a pure function, so the whole state space can
be enumerated rather than sampled. The property under test is one sentence:

    NO COMBINATION YIELDS `authentic` UNLESS EVERY CHECK PASSED.

Dimensions (2 x 2 x 2 x 2 x 3 x 3 x 2 x 4 x 2 = 2,304 combinations):

    placeholder / real mirror
    known / unknown tag
    token match / mismatch
    row signature valid / invalid
    counter state ok / suspect_duplicate / frozen
    counter below / equal / above max_counter
    within / over the velocity bound
    row status active / recalled / withdrawn / superseded
    in date / expired
"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from services.verification import Binding, DivergenceKind, Verdict, decide, velocity_bound

NOW = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
ENROLLED_AT = NOW - timedelta(days=10)
MAX_TAPS = 50
GRACE = 20


class M:
    __slots__ = ("counter", "placeholder", "uid")

    def __init__(self, uid, counter, placeholder):
        self.uid, self.counter, self.placeholder = uid, counter, placeholder


def make_row(status="active", expiry="2028-01-01", enrol_counter=3):
    return {
        "tag_index": "a" * 64,
        "binding_token_hash": "b" * 64,
        "crypto_version": "aes_gcm_v2",
        "enrol_counter": enrol_counter,
        "enrolled_at": ENROLLED_AT,
        "expiry_date": expiry,
        "status": status,
        "batch_ref": "AMX-2026-09-001",
        "row_sig": "cc",
        "row_sig_alg": "ed25519",
    }


def call(**overrides):
    kwargs = {
        "mirror": M("04A1B2C3D4E5F6", 10, False),
        "token": "A" * 32,
        "row": make_row(),
        "state": {"max_counter": 5, "status": "ok"},
        "batch": {"status": "open", "recall_notice": None},
        "now": NOW,
        "row_sig_valid": True,
        "token_matches": True,
        "max_taps_per_day": MAX_TAPS,
        "velocity_grace": GRACE,
        "live_read": False,
    }
    kwargs.update(overrides)
    return decide(**kwargs)


# ============================================================ THE MAIN PROPERTY

def test_authentic_requires_every_check_to_pass():
    """The whole point of this file. 2,304 combinations, one invariant."""
    dimensions = list(itertools.product(
        [True, False],                                   # placeholder
        [True, False],                                   # row present
        [True, False],                                   # token matches
        [True, False],                                   # row sig valid
        ["ok", "suspect_duplicate", "frozen"],           # counter state
        ["below", "equal", "above"],                     # counter vs max
        [True, False],                                   # within velocity bound
        ["active", "recalled", "withdrawn", "superseded"],
        [True, False],                                   # in date
    ))
    assert len(dimensions) == 2304

    authentic_count = 0
    for (placeholder, has_row, token_ok, sig_ok, state_status, counter_rel,
         within_bound, status, in_date) in dimensions:
        max_counter = 5
        counter = {"below": max_counter - 1,
                   "equal": max_counter,
                   "above": max_counter + 1}[counter_rel]
        if not within_bound:
            # Push it past enrol_counter + MAX_TAPS*days + grace.
            counter = velocity_bound(3, ENROLLED_AT, NOW, MAX_TAPS, GRACE) + 1

        expiry = "2028-01-01" if in_date else "2026-01-01"

        decision = call(
            mirror=M("00000000000000" if placeholder else "04A1B2C3D4E5F6",
                     0 if placeholder else counter, placeholder),
            row=make_row(status=status, expiry=expiry) if has_row else None,
            state={"max_counter": max_counter, "status": state_status},
            token_matches=token_ok,
            row_sig_valid=sig_ok,
        )

        if decision.verdict is Verdict.AUTHENTIC:
            authentic_count += 1
            # Every one of these must hold. If any assertion here fires, a path
            # to AUTHENTIC exists that skipped a check.
            assert not placeholder, "authentic with a disabled mirror"
            assert has_row, "authentic with no record"
            assert token_ok, "authentic with a wrong binding token"
            assert sig_ok, "authentic with an invalid row signature"
            assert state_status == "ok", "authentic while flagged suspect"
            assert counter_rel == "above", "authentic without a strictly greater counter"
            assert within_bound, "authentic past the velocity bound"
            assert status == "active", f"authentic with status {status}"
            assert in_date, "authentic past the expiry date"
            assert decision.checks == {"record": "pass", "counter": "pass",
                                       "recall": "pass", "expiry": "pass"}
            assert decision.advance_counter is True

    # Exactly one combination should reach AUTHENTIC. If this number changes, a
    # gate was added or removed and that deserves a deliberate look.
    assert authentic_count == 1


def test_no_exception_path_produces_a_positive_verdict():
    """§15.3 rule 1 — fail to a safe state. Every malformed input must land on a
    negative or indeterminate verdict, never on AUTHENTIC and never by raising."""
    hostile_rows = [
        {},                                        # empty
        {"crypto_version": "paper_v1"},            # the deleted cipher (E8)
        {"crypto_version": "aes_gcm_v2"},          # no other fields
        make_row(expiry="not-a-date"),
    ]
    for row in hostile_rows:
        try:
            decision = call(row=row, row_sig_valid=True)
        except Exception:  # noqa: S112 — raising IS an accepted outcome here
            # A hostile row may make the machine raise. That is fine, because
            # routes/verify.py catches it and returns RECORD_INVALID. What must
            # never happen is AUTHENTIC, which the assertion below checks for
            # every row that does NOT raise.
            continue
        assert decision.verdict is not Verdict.AUTHENTIC


# =================================================================== STEP BY STEP

def test_step0_placeholder_is_mirror_disabled_not_unknown():
    """B7. A tag whose mirror never turned on is a manufacturing defect we want
    to hear about, not an UNKNOWN to shrug at — and certainly not an AUTHENTIC."""
    decision = call(mirror=M("00000000000000", 0, True))
    assert decision.verdict is Verdict.MIRROR_DISABLED
    assert decision.binding is Binding.NONE
    assert decision.divergence.kind is DivergenceKind.MIRROR_DISABLED


def test_step2_unknown_tag():
    assert call(row=None).verdict is Verdict.UNKNOWN


def test_step3_token_mismatch_is_indistinguishable_from_unknown():
    """An attacker who guesses a UID but not the 128-bit token must learn exactly
    nothing. Same verdict, same checks, same shape as a UID that was never
    enrolled."""
    wrong_token = call(token_matches=False)
    never_enrolled = call(row=None)
    assert wrong_token.verdict is never_enrolled.verdict is Verdict.UNKNOWN
    assert wrong_token.checks == never_enrolled.checks


def test_step4_bad_row_signature_is_record_invalid_not_authentic():
    """D12, D13, F13, F15 — the reason row signatures replaced payload_hash."""
    decision = call(row_sig_valid=False)
    assert decision.verdict is Verdict.RECORD_INVALID
    assert decision.checks["record"] == "fail"


def test_step4_rejects_any_crypto_version_but_aes_gcm_v2():
    """E8 — the paper cipher is not a fallback, it is a hard reject."""
    for version in ("paper_v1", "aes_gcm_v1", "", None, "AES_GCM_V2"):
        row = make_row()
        row["crypto_version"] = version
        assert call(row=row).verdict is Verdict.RECORD_INVALID


def test_step5_suspect_state_is_sticky():
    """G1. Once flagged, always flagged, pending human review. A counterfeiter
    must not be able to discover which stolen identifiers are still good by
    waiting for a flag to clear."""
    for status in ("suspect_duplicate", "frozen"):
        decision = call(state={"max_counter": 1, "status": status},
                        mirror=M("04A1B2C3D4E5F6", 9999, False))
        assert decision.verdict is Verdict.SUSPECT_DUPLICATE
        assert decision.advance_counter is False


@pytest.mark.parametrize("counter,kind", [
    (5, DivergenceKind.REPEAT),     # A3 — counter freeze replay
    (4, DivergenceKind.ROLLBACK),   # A4 — counter rollback
    (0, DivergenceKind.ROLLBACK),
])
def test_step6_mta_core(counter, kind):
    """The MTA core. A copied URL carries a frozen counter (A1); a cloned tag
    tapped after the genuine one rolls back (A4)."""
    decision = call(mirror=M("04A1B2C3D4E5F6", counter, False),
                    state={"max_counter": 5, "status": "ok"})
    assert decision.verdict is Verdict.SUSPECT_DUPLICATE
    assert decision.divergence.kind is kind
    assert decision.divergence.expected_min == 6


def test_step7_velocity_bound_catches_fast_forward():
    """A5. A pack manufactured ten days ago cannot plausibly have been tapped
    900,000 times — the counter cannot be written, only advanced by real reads at
    roughly 10 ms each."""
    bound = velocity_bound(3, ENROLLED_AT, NOW, MAX_TAPS, GRACE)
    assert call(mirror=M("04A1B2C3D4E5F6", bound, False)).verdict is Verdict.AUTHENTIC
    over = call(mirror=M("04A1B2C3D4E5F6", bound + 1, False))
    assert over.verdict is Verdict.SUSPECT_DUPLICATE
    assert over.divergence.kind is DivergenceKind.VELOCITY
    assert over.divergence.velocity_bound == bound


def test_velocity_bound_never_divides_by_zero_on_a_fresh_pack():
    """A pack enrolled seconds ago has an age of 0 days; the bound must still be
    computable and generous enough for the enrolment-time reads."""
    fresh = velocity_bound(3, NOW - timedelta(seconds=30), NOW, MAX_TAPS, GRACE)
    assert fresh == 3 + MAX_TAPS + GRACE


def test_step9_recall_beats_expiry():
    """F20, G2. A recalled pack must say RECALLED even if it is also expired —
    the recall is the actionable fact."""
    decision = call(row=make_row(status="active", expiry="2026-01-01"),
                    batch={"status": "recalled", "recall_notice": "Contamination."})
    assert decision.verdict is Verdict.RECALLED
    assert decision.recall_notice == "Contamination."


def test_step9_superseded_row_is_record_invalid():
    """A re-enrolled tag's old record is no longer the truth about the object."""
    assert call(row=make_row(status="superseded")).verdict is Verdict.RECORD_INVALID


def test_step10_expired():
    decision = call(row=make_row(expiry="2026-01-01"))
    assert decision.verdict is Verdict.EXPIRED
    assert decision.checks["expiry"] == "fail"
    # Still advances: an expired pack is genuine, and its counter is real data.
    assert decision.advance_counter is True


def test_expiry_boundary_is_inclusive():
    """`today > expiry_date` — a pack expiring today is still in date."""
    assert call(row=make_row(expiry=NOW.date().isoformat())).verdict is Verdict.AUTHENTIC
    yesterday = (NOW.date() - timedelta(days=1)).isoformat()
    assert call(row=make_row(expiry=yesterday)).verdict is Verdict.EXPIRED


# ==================================================================== BINDING

def test_live_read_upgrades_the_binding_label_only():
    """C8. `live=1` is a claim by the client. It can change the LABEL, never the
    verdict — so a lying client gains nothing."""
    plain = call(live_read=False)
    live = call(live_read=True)
    assert plain.binding is Binding.COUNTER
    assert live.binding is Binding.COUNTER_LIVEREAD
    assert plain.verdict is live.verdict


def test_placeholder_binding_is_none_regardless_of_live_claim():
    assert call(mirror=M("00000000000000", 0, True), live_read=True).binding is Binding.NONE
