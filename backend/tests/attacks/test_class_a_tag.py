"""Class A — tag and physical layer. ARCHITECTURE.md §16.1.

Every function here is named for its attack ID (A1..A14) and every function
writes one JSONL evidence record via the `evidence` fixture, so the §16.9
scoreboard can be filled with *measured* results rather than asserted ones.

The honest rule from §16.9 is enforced here literally: the known-open attacks
(A7, A8, A11) do NOT get a green test. They record `outcome="open"` and skip with
the reason. A reviewer trusts a suite more when the open items are visible as open
than when everything is a tick.

What this file can and cannot reach:

  * The MTA / counter-divergence attacks (A1, A3, A4, A5, A6, A14) are properties
    of the live verify path and are exercised end to end here.
  * The physical / silicon / config attacks (A2 originality, A9, A10, A12, A13)
    live in the Pi's enrolment pipeline and the NTAG216 hardware. They are
    exercised in `pi/` against a real chip (§18 phase 1); against the backend the
    only observable is the recorded `originality_status`, which is checked where
    it is observable and otherwise skipped with a reason.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


# ------------------------------------------------------------ counter core ----

def test_a1_blank_tag_link_copy_carries_a_frozen_counter(make_tag, enrol, verify,
                                                          evidence):
    """A1 — a URL copied off a genuine tag onto a blank one carries whatever
    counter it was captured at. That value is frozen: the blank tag has no live
    counter to advance it. The second use is no longer strictly greater."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 8, token).json()["verdict"] == "authentic"

    copied = verify(uid, 8, token).json()  # the blank clone replays the same URL
    assert copied["verdict"] == "suspect_duplicate"
    assert copied["checks"]["counter"] == "fail"
    assert copied["incident"]["kind"] == "repeat"

    evidence("A1", outcome="detected", expected="suspect_duplicate",
             detail={"kind": copied["incident"]["kind"]})


def test_a2_magic_tag_reports_a_zero_counter(make_tag, enrol, verify, evidence):
    """A2 — a UID-rewritable "magic" tag can spoof the UID but cannot fake a live
    NFC counter; it presents 000000. Against a tag the server has already seen
    advance, 000000 is a rollback below the recorded maximum.

    The originality half of A2 (the chip failing READ_SIG at enrolment) is a
    Pi-side gate and is exercised in pi/; here we prove the verify-side
    consequence, which is what a consumer's tap actually hits.
    """
    payload, uid, token = make_tag(enrol_counter=2)
    assert enrol(payload).status_code == 201
    assert verify(uid, 30, token).json()["verdict"] == "authentic"

    magic = verify(uid, 0, token).json()
    assert magic["verdict"] == "suspect_duplicate"
    assert magic["incident"]["kind"] == "rollback"

    evidence("A2", outcome="detected", expected="suspect_duplicate",
             detail={"observed_counter": 0, "kind": magic["incident"]["kind"]})


def test_a3_counter_freeze_replay_is_a_repeat(make_tag, enrol, verify, evidence):
    """A3 — the exact same counter value seen twice."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 7, token).json()["verdict"] == "authentic"

    replay = verify(uid, 7, token).json()
    assert replay["verdict"] == "suspect_duplicate"
    assert replay["incident"]["kind"] == "repeat"
    assert replay["incident"]["id"] is not None

    evidence("A3", outcome="detected", expected="suspect_duplicate",
             detail={"kind": "repeat", "incident_id": replay["incident"]["id"]})


def test_a4_counter_rollback_is_detected(make_tag, enrol, verify, evidence):
    """A4 — a counter lower than the recorded maximum."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 40, token).json()["verdict"] == "authentic"

    rolled = verify(uid, 9, token).json()
    assert rolled["verdict"] == "suspect_duplicate"
    assert rolled["incident"]["kind"] == "rollback"

    evidence("A4", outcome="detected", expected="suspect_duplicate",
             detail={"kind": "rollback"})


def test_a5_counter_fast_forward_trips_the_velocity_bound(make_tag, enrol, verify,
                                                          evidence):
    """A5 — a pack enrolled moments ago cannot have been tapped ~900k times. The
    counter cannot be written, only advanced by real reads at ~10 ms each."""
    payload, uid, token = make_tag(enrol_counter=3)
    assert enrol(payload).status_code == 201

    body = verify(uid, 900_000, token).json()
    assert body["verdict"] == "suspect_duplicate"
    assert body["incident"]["kind"] == "velocity"

    evidence("A5", outcome="detected", expected="suspect_duplicate",
             detail={"kind": "velocity", "observed_counter": 900_000})


def test_a6_counter_exhaustion_dos_raises_an_incident_for_triage(make_tag, enrol,
                                                                 verify, evidence):
    """A6 — an attacker who taps a genuine pack hard to burn its counter toward
    2^24 does not silently succeed: the abnormal advance is caught by the
    velocity bound, flagged, and an incident id is raised for human triage
    (§10.5). It is a detected, reviewable event, not an open failure.
    """
    payload, uid, token = make_tag(enrol_counter=5)
    assert enrol(payload).status_code == 201

    body = verify(uid, 16_000_000, token).json()  # near the 24-bit ceiling
    assert body["verdict"] == "suspect_duplicate"
    assert body["incident"]["id"] is not None

    evidence("A6", outcome="detected", expected="suspect_duplicate",
             detail={"incident_id": body["incident"]["id"],
                     "kind": body["incident"]["kind"]})


def test_a14_relay_advances_the_real_counter_so_the_holder_diverges(
        make_tag, enrol, verify, evidence):
    """A14 — a relay (NFCGate-style) must present a REAL tag to the reader, which
    advances that tag's real counter. The genuine holder's next tap then carries
    a value at or below what the relay already burned, and diverges. The attack
    is self-limiting and self-reporting: there is no separate mechanism to test,
    only the consequence of the shared monotonic counter.
    """
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    # The relayed session drives the counter up.
    assert verify(uid, 25, token).json()["verdict"] == "authentic"

    # The legitimate holder taps their pack next; its real counter is behind.
    holder = verify(uid, 18, token).json()
    assert holder["verdict"] == "suspect_duplicate"

    evidence("A14", outcome="detected", expected="suspect_duplicate",
             detail={"relayed_to": 25, "holder_saw": 18,
                     "kind": holder["incident"]["kind"]})


# --------------------------------------------------- known-open, by design ----
#
# §16.9: do NOT write a test that "passes" for these. Record them as open and
# skip with the reason. Saying so is worth more than a green tick.

def test_a7_field_ndef_rewrite_is_open_until_locking_is_enabled(server_config,
                                                                evidence):
    """A7 — static + dynamic lock bytes close this, but TAG_LOCK_ENABLED is off
    for this phase (D5). The system reports the posture honestly on /health; this
    test reads that posture rather than pretending the attack is closed."""
    locking = server_config.get("posture", {}).get("tag_locking")
    evidence("A7", outcome=("blocked" if locking == "enabled" else "open"),
             expected="open (TAG_LOCK_ENABLED=false)",
             detail={"tag_locking": locking})
    if locking != "enabled":
        pytest.skip("A7 is open by design while TAG_LOCK_ENABLED=false (§16.9, D5)")


def test_a8_config_rewrite_to_disable_counter_is_open_until_locking_is_enabled(
        server_config, evidence):
    """A8 — AUTH0=E3h + CFGLCK close this, but they only bite once locking is
    enabled. Open by design for this phase, and /health says so."""
    locking = server_config.get("posture", {}).get("tag_locking")
    evidence("A8", outcome=("blocked" if locking == "enabled" else "open"),
             expected="open (TAG_LOCK_ENABLED=false)",
             detail={"tag_locking": locking})
    if locking != "enabled":
        pytest.skip("A8 is open by design while TAG_LOCK_ENABLED=false (§16.9, D5)")


def test_a11_tag_transplant_refill_is_irreducibly_open(evidence):
    """A11 — moving a genuine, still-authentic tag onto a refilled/counterfeit
    pack cannot be detected in software: the tag, its counter and its record are
    all genuine. This needs tamper-evident packaging (§2 residual risk 1). It is
    recorded as open, permanently, by design."""
    evidence("A11", outcome="open",
             expected="open (requires tamper-evident packaging)",
             detail={"residual_risk": 1})
    pytest.skip("A11 is irreducible without tamper-evident packaging (§16.9)")


# ------------------------------------- hardware / Pi-side, not backend-visible -
#
# These are enforced in the NTAG216 silicon and the Pi enrolment pipeline
# (§6.5, §6.6, §6.8, §12.1). They are exercised in pi/ against a real chip in
# §18 phase 1; there is no backend-observable surface for them, so asserting a
# verdict here would be theatre. Recorded as inconclusive-from-backend and
# skipped with the pointer to where they are actually proven.

_PI_SIDE = {
    "A9": "tag PWD brute force — bounded by 2^32 at ~200/s (§6.5); physical, Pi/chip",
    "A10": "AUTHLIM=0 chosen precisely to prevent auth-based bricking (§6.5); chip",
    "A12": "counterfeit NXP silicon — GET_VERSION + READ_SIG gate (§6.6, §12.1); Pi",
    "A13": "tearing during enrolment — anti-tearing + read-back compare (§6.8); Pi",
}


@pytest.mark.parametrize("attack_id", sorted(_PI_SIDE))
def test_physical_and_silicon_gates_are_proven_pi_side(attack_id, evidence):
    reason = _PI_SIDE[attack_id]
    evidence(attack_id, outcome="inconclusive",
             expected="enforced in pi/ against real hardware",
             detail={"where": reason})
    pytest.skip(f"{attack_id}: {reason} — proven in pi/ §18 phase 1, not backend")
