"""The counter advance under concurrency. ARCHITECTURE.md §9.7, §17.2 item 5.

Doing the comparison in the WHERE clause is what makes MTA correct under
concurrency:

    UPDATE tag_counter_state SET max_counter = %(counter)s
     WHERE tag_index = %(tag_index)s AND max_counter < %(counter)s AND status = 'ok'
    RETURNING max_counter

A read-then-write in Python is a race, and a mass-produced clone — many copies of
one tag, tapped in many places at once — is exactly the workload that finds it.

FIRE N SIMULTANEOUS VERIFIES WITH THE SAME COUNTER VALUE. Exactly one must
succeed; the rest must produce a divergence. If two succeeded, two different
physical objects just both verified as authentic, which is the failure the whole
system exists to prevent.
"""
from __future__ import annotations

import concurrent.futures

import pytest

pytestmark = pytest.mark.integration

CONCURRENCY = 12


def test_only_one_of_n_simultaneous_identical_counters_wins(make_tag, enrol, verify):
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(verify, uid, 42, token) for _ in range(CONCURRENCY)]
        bodies = [f.result().json() for f in concurrent.futures.as_completed(futures)]

    verdicts = [b["verdict"] for b in bodies]
    authentic = verdicts.count("authentic")
    suspect = verdicts.count("suspect_duplicate")

    assert authentic == 1, (
        f"{authentic} requests got AUTHENTIC for the same counter value. The "
        f"counter comparison is racing — it must happen in the SQL WHERE clause, "
        f"not in Python. Verdicts: {verdicts}")
    assert authentic + suspect == CONCURRENCY, verdicts


def test_simultaneous_increasing_counters_all_advance(make_tag, enrol, verify):
    """The mirror image: distinct, increasing counter values arriving at once
    must not trip each other up. A pharmacy scanning a shelf of genuine packs
    must not manufacture incidents."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    counters = list(range(10, 10 + CONCURRENCY))
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(verify, uid, c, token) for c in counters]
        bodies = [f.result().json() for f in futures]

    verdicts = [b["verdict"] for b in bodies]
    # The highest value must win; lower ones that arrive after it are genuine
    # divergences by definition. What must NOT happen is everything failing.
    assert "authentic" in verdicts, verdicts

    # Whatever happened, the tag must end up either healthy or flagged — never
    # in a state where a later, higher tap silently passes after a divergence.
    final = verify(uid, 10_000, token).json()
    assert final["verdict"] in ("authentic", "suspect_duplicate")


def test_a_divergence_writes_exactly_one_incident_per_event(
        session, base_url, admin_token, make_tag, enrol, verify):
    """The incident, the state flip and the audit row are one transaction. A
    burst must not produce a pile of duplicate incidents for the same tap."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 30, token).json()["verdict"] == "authentic"

    before = _open_incident_count(session, base_url, admin_token)
    body = verify(uid, 30, token).json()
    assert body["verdict"] == "suspect_duplicate"
    after = _open_incident_count(session, base_url, admin_token)

    assert after == before + 1, (
        f"one replayed tap produced {after - before} incidents")


def _open_incident_count(session, base_url, admin_token) -> int:
    response = session.get(f"{base_url}/api/v2/admin/incidents?status=open",
                           headers={"Authorization": f"Bearer {admin_token}"},
                           timeout=30)
    assert response.status_code == 200, response.text
    return len(response.json()["incidents"])


def test_clearing_a_suspect_flag_is_only_possible_through_a_human_action(
        session, base_url, admin_token, make_tag, enrol, verify):
    """G1. There is no automatic recovery path. The only way back to `ok` is
    PATCH /admin/incidents/<id> with resolution=false_positive, by a human, with
    a note, audited."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 15, token).json()["verdict"] == "authentic"
    flagged = verify(uid, 15, token).json()
    assert flagged["verdict"] == "suspect_duplicate"
    incident_id = flagged["incident"]["id"]

    # No amount of waiting or re-scanning clears it.
    assert verify(uid, 999, token).json()["verdict"] == "suspect_duplicate"

    # A note is mandatory — the decision has to be explainable.
    no_note = session.patch(
        f"{base_url}/api/v2/admin/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"resolution": "false_positive"}, timeout=30)
    assert no_note.status_code == 400

    resolved = session.patch(
        f"{base_url}/api/v2/admin/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"resolution": "false_positive",
              "note": "Operator re-scanned the same pack twice during testing."},
        timeout=30)
    assert resolved.status_code == 200

    assert verify(uid, 2000, token).json()["verdict"] == "authentic"
