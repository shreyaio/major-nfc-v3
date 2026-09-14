"""Enrol -> verify -> divergence, end to end. ARCHITECTURE.md §18 phase 3.

This is the file that proves Monotonic Tap Attestation actually works against a
live server: a counter that does not strictly increase raises an incident and
flips the tag to a sticky suspect state.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_enrol_then_verify_is_authentic(make_tag, enrol, verify):
    payload, uid, token = make_tag(enrol_counter=3)
    assert enrol(payload).status_code == 201

    # The first consumer tap is counter 4 — strictly greater than the value the
    # packaging line recorded.
    response = verify(uid, 4, token)
    assert response.status_code == 200
    body = response.json()

    assert body["verdict"] == "authentic"
    assert body["binding"] == "counter"
    assert body["checks"] == {"record": "pass", "counter": "pass",
                              "recall": "pass", "expiry": "pass"}
    assert body["incident"] is None
    assert body["product"]["batch"]


def test_counter_must_strictly_increase(make_tag, enrol, verify):
    """The MTA core. Three taps, increasing, all fine."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    for counter in (2, 3, 10, 11):
        assert verify(uid, counter, token).json()["verdict"] == "authentic"


def test_a3_replaying_the_same_counter_is_a_divergence(make_tag, enrol, verify):
    """A copied URL carries a FROZEN counter. The second time it is used, the
    value is no longer strictly greater than what the server has seen."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 7, token).json()["verdict"] == "authentic"

    replayed = verify(uid, 7, token).json()
    assert replayed["verdict"] == "suspect_duplicate"
    assert replayed["checks"]["counter"] == "fail"
    assert replayed["incident"]["kind"] == "repeat"
    assert replayed["incident"]["id"] is not None


def test_a4_a_lower_counter_is_a_rollback_divergence(make_tag, enrol, verify):
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 20, token).json()["verdict"] == "authentic"

    rolled_back = verify(uid, 5, token).json()
    assert rolled_back["verdict"] == "suspect_duplicate"
    assert rolled_back["incident"]["kind"] == "rollback"


def test_g1_suspect_duplicate_is_sticky(make_tag, enrol, verify):
    """Once flagged, always flagged, pending human review.

    This is the single most valuable business-logic control in the redesign: a
    counterfeiter must not be able to discover which stolen identifiers are
    still good by probing and watching a flag clear.
    """
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 10, token).json()["verdict"] == "authentic"
    assert verify(uid, 10, token).json()["verdict"] == "suspect_duplicate"

    # Even a perfectly valid, much higher counter stays flagged.
    for counter in (11, 50, 1000):
        assert verify(uid, counter, token).json()["verdict"] == "suspect_duplicate"


def test_a5_velocity_bound_catches_a_fast_forwarded_counter(make_tag, enrol, verify):
    """A pack enrolled moments ago cannot plausibly have been tapped 900,000
    times. The counter cannot be written — only advanced by real reads."""
    payload, uid, token = make_tag(enrol_counter=3)
    assert enrol(payload).status_code == 201

    body = verify(uid, 900_000, token).json()
    assert body["verdict"] == "suspect_duplicate"
    assert body["incident"]["kind"] == "velocity"


def test_unknown_tag(verify):
    body = verify("04FFFFFFFFFFFF", 5, "A" * 32).json()
    assert body["verdict"] == "unknown"
    assert body["product"] is None


def test_b7_placeholder_is_mirror_disabled(verify):
    """A tag whose mirror never turned on. Never UNKNOWN, never AUTHENTIC."""
    body = verify("00000000000000", 0, "A" * 32).json()
    assert body["verdict"] == "mirror_disabled"
    assert body["binding"] == "none"


def test_b6_wrong_binding_token_is_indistinguishable_from_unknown(
        make_tag, enrol, verify):
    """An attacker who reads a UID off a chip but does not have the 128-bit
    token must learn exactly nothing."""
    payload, uid, _token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    wrong = verify(uid, 5, "F" * 32).json()
    never_enrolled = verify("04AAAAAAAAAAAA", 5, "F" * 32).json()

    assert wrong["verdict"] == never_enrolled["verdict"] == "unknown"
    assert wrong["checks"] == never_enrolled["checks"]
    assert wrong["product"] is never_enrolled["product"] is None


def test_f23_status_code_is_never_a_second_oracle(make_tag, enrol, verify):
    """There is no 404 on this route. An unregistered tag returns 200 with
    verdict=unknown, so the status code cannot be used to enumerate."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 5, token).status_code == 200
    assert verify("04BBBBBBBBBBBB", 5, "A" * 32).status_code == 200
    assert verify("00000000000000", 0, "A" * 32).status_code == 200


def test_f24_every_verdict_has_the_same_response_shape(make_tag, enrol, verify):
    """`product` is always present as a key — null for negative verdicts — so an
    `unknown` is not visibly shorter than an `authentic`."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    bodies = [verify(uid, 9, token).json(),
              verify("04CCCCCCCCCCCC", 5, "A" * 32).json(),
              verify("00000000000000", 0, "A" * 32).json()]

    expected_keys = {"verdict", "binding", "product", "checks", "incident",
                     "recall_notice", "verified_at"}
    for body in bodies:
        assert set(body) == expected_keys, body


def test_c9_verdicts_are_never_cached(make_tag, enrol, verify):
    """A cached verdict is a verdict that outlives the counter check."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    response = verify(uid, 4, token)
    assert response.headers.get("Cache-Control") == "no-store"


def test_b8_duplicate_parameters_are_rejected(session, base_url):
    response = session.get(
        f"{base_url}/api/v2/verify?m=04A1B2C3D4E5F6x000001&m=04A1B2C3D4E5F6x000002"
        f"&t={'A' * 32}", timeout=30)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "malformed_parameters"


def test_b6_missing_token_is_a_400_not_a_verdict(session, base_url):
    """Fail closed. There is no UID-only path anywhere in this codebase."""
    response = session.get(f"{base_url}/api/v2/verify?m=04A1B2C3D4E5F6x000001",
                           timeout=30)
    assert response.status_code == 400


def test_live_read_flag_upgrades_the_binding_label_only(make_tag, enrol, verify):
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    plain = verify(uid, 4, token).json()
    live = verify(uid, 5, token, live=True).json()

    assert plain["binding"] == "counter"
    assert live["binding"] == "counter+liveread"
    assert plain["verdict"] == live["verdict"] == "authentic"


def test_d22_response_time_floor_hides_the_registration_oracle(
        make_tag, enrol, verify, server_config):
    """An `unknown` returns after one indexed lookup; an `authentic` does a
    lookup plus an X25519 unwrap plus four GCM decryptions. Without a floor the
    difference is measurable and leaks registration status even with identical
    bodies.

    This asserts the floor is applied at all rather than trying to measure
    statistical indistinguishability over a network, which a CI runner cannot do
    honestly.
    """
    import time

    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    def elapsed(fn):
        start = time.perf_counter()
        fn()
        return (time.perf_counter() - start) * 1000

    known = elapsed(lambda: verify(uid, 4, token))
    unknown = elapsed(lambda: verify("04DDDDDDDDDDDD", 4, "A" * 32))

    # Both must clear the configured floor. Network jitter dominates above it,
    # which is the point — the floor removes the deterministic component.
    assert known >= 100, f"known lookup returned in {known:.0f}ms, floor not applied"
    assert unknown >= 100, f"unknown lookup returned in {unknown:.0f}ms, floor not applied"
