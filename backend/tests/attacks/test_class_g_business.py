"""Class G — business logic and abuse. ARCHITECTURE.md §16.7 (G1..G9).

This is the class v1's suite omitted entirely, and §16.7 calls it out as where the
most damaging real-world attacks live. The two to emphasise are exercised end to
end here:

  * G1 — SUSPECT_DUPLICATE is STICKY. Once flagged, always flagged, pending a
    human. This is what stops a counterfeiter probing the free public API to
    discover which stolen identifiers are still good.
  * G8 — the report channel is protected by PROOF-OF-WORK, not a CAPTCHA. A real
    submission solves a cheap challenge; a flood does not scale. We solve a live
    challenge and submit through it.

G4 (grey-market) and parts of G6/G7/G9 are partial by design (§16.9): the counter
still catches reused identifiers, but attribution and market-intelligence leakage
are bounded, not eliminated. Those are recorded honestly rather than ticked.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import date

import pytest

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------- G1 --------

def test_g1_suspect_duplicate_is_sticky(make_tag, enrol, verify, evidence):
    """G1 — the single most valuable business-logic control. Once a tag trips a
    divergence it stays SUSPECT_DUPLICATE for every later tap, even a perfectly
    valid much-higher counter. There is no automatic recovery path; only an
    audited admin action clears it. A counterfeiter cannot watch a flag clear."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    assert verify(uid, 10, token).json()["verdict"] == "authentic"
    assert verify(uid, 10, token).json()["verdict"] == "suspect_duplicate"  # trip

    for counter in (11, 50, 1000, 250_000):
        v = verify(uid, counter, token).json()["verdict"]
        assert v == "suspect_duplicate", f"flag cleared at counter {counter}"

    evidence("G1", outcome="detected",
             expected="suspect_duplicate is sticky, no auto-recovery")


# ------------------------------------------------------------------- G2 --------

def test_g2_recall_evasion_is_impossible_status_is_signed(session, base_url,
                                                          admin_token, enrol,
                                                          field_recipient_pub,
                                                          verify, evidence):
    """G2 — a recalled pack returns the RECALLED verdict with the notice a patient
    must read, not a generic error and not AUTHENTIC. status is inside the row
    signature and the recall re-signs every affected row, so the recall cannot be
    evaded by tampering and cannot be masked as RECORD_INVALID."""
    import crypto_envelope

    # A dedicated batch, so recalling it cannot disturb the shared test batch.
    batch_ref = f"GRECALL-{secrets.token_hex(4).upper()}"
    opened = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref, "product_name": "Recall Test 250mg",
              "mfg_date": date.today().isoformat(), "shelf_life_days": 365,
              "quota": 20, "opened_by": "operator-a", "countersigned_by": "operator-b"},
        timeout=30)
    assert opened.status_code == 201, opened.text

    uid = "04" + secrets.token_bytes(6).hex().upper()
    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": "RCL-1", "batch_id": batch_ref,
         "mfg_date": opened.json()["mfg_date"], "tag_uid": uid}, field_recipient_pub)
    payload = {"schema": "nfcmed.enrol.v2", "crypto_version": "aes_gcm_v2",
               "batch_ref": batch_ref,
               "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
               "enrol_counter": 2, "originality_status": "verified",
               "binding_class": "counter", "tag_version": "0004040201000F03",
               "sealed": sealed}
    assert enrol(payload, idempotency_key=str(uuid.uuid4())).status_code == 201
    assert verify(uid, 3, token_hex).json()["verdict"] == "authentic"

    notice = "Batch recalled: possible contamination. Return to pharmacist."
    recalled = session.post(
        f"{base_url}/api/v2/admin/recall",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref, "notice": notice}, timeout=30)
    assert recalled.status_code == 200, recalled.text

    body = verify(uid, 4, token_hex).json()
    assert body["verdict"] == "recalled"
    assert body["recall_notice"] == notice

    evidence("G2", outcome="detected", expected="recalled verdict + notice",
             detail={"rows_resigned": recalled.json().get("rows_resigned")})


# ------------------------------------------------------------------- G3 --------

def test_g3_expired_stock_relabelling_is_blocked_by_derived_signed_expiry(
        make_tag, enrol, test_batch, evidence):
    """G3 — relabelling old stock with a new expiry fails twice over: the client
    cannot state the expiry (the backend derives it from the batch mfg_date), and
    the derived expiry is inside the row signature so it cannot be edited in the
    database either. Here we prove the client cannot influence it."""
    payload, _, _ = make_tag()
    payload["expiry_date"] = "2099-01-01"   # attacker's extension attempt
    payload["shelf_life"] = 99_999
    r = enrol(payload)
    assert r.status_code == 201

    from datetime import timedelta
    expected = (date.fromisoformat(test_batch["mfg_date"])
                + timedelta(days=test_batch["shelf_life_days"])).isoformat()
    assert r.json()["expiry_date"] == expected, "client influenced the expiry date"

    evidence("G3", outcome="blocked",
             expected="expiry server-derived and signed; client value ignored")


# ------------------------------------------------------------------- G4 --------

def test_g4_grey_market_parallel_import_is_partial_and_open(evidence):
    """G4 — a genuine pack legitimately sold into another market is genuine; the
    system cannot call it a fake. Only coarse-region analytics on counter state
    can flag unusual distribution patterns, and that is advisory, not a verdict.
    Partial, known-open (§16.9)."""
    evidence("G4", outcome="open",
             expected="partial: coarse-region analytics only",
             detail={"where": "§9.11"})
    pytest.skip("G4 is partial/known-open: parallel import is not counterfeiting")


# ------------------------------------------------------------------- G5 --------

def test_g5_pre_enrolment_harvesting_requires_two_person_open_batch(
        session, base_url, admin_token, evidence):
    """G5 — harvesting identifiers before packaging is bounded by three things:
    a per-batch quota, an open-batch requirement, and two-person authorisation to
    open a batch. We prove the last: one operator cannot authorise their own
    batch, so a single compromised operator cannot open a batch to harvest from."""
    r = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": f"G5-{secrets.token_hex(3).upper()}",
              "product_name": "No Countersigner 100mg",
              "mfg_date": date.today().isoformat(), "shelf_life_days": 365,
              "quota": 10, "opened_by": "solo-operator",
              # The attack is ONE operator opening a batch alone, so they put
              # their own name in both fields. Omitting countersigned_by instead
              # only exercises required-field validation (malformed_request) and
              # never reaches the two-person rule, which is the control under
              # test: CountersignatureRequired fires when the two names MATCH
              # (services/batches.py::open_batch).
              "countersigned_by": "solo-operator"},
        timeout=30)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "countersignature_required"

    evidence("G5", outcome="blocked",
             expected="400 countersignature_required (two-person open)")


# ------------------------------------------------------------------- G6 --------

def test_g6_verdict_laundering_still_trips_the_counter(make_tag, enrol, verify,
                                                       evidence):
    """G6 — 'laundering' a known-good verdict by reusing the captured identifier
    still trips the monotonic counter: the reused value is not strictly greater
    and diverges. Attribution is partial (§16.9), but the reuse is caught."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 12, token).json()["verdict"] == "authentic"

    laundered = verify(uid, 12, token).json()
    assert laundered["verdict"] == "suspect_duplicate"

    evidence("G6", outcome="detected",
             expected="reused identifier diverges (attribution partial)")


# ------------------------------------------------------------------- G7 --------

def test_g7_denial_of_reputation_never_auto_publishes_counterfeit(make_tag, enrol,
                                                                  verify, evidence):
    """G7 — an attacker trying to smear a genuine product by forcing divergences
    cannot make the system PUBLICLY declare it counterfeit. The strongest negative
    verdict is SUSPECT_DUPLICATE, an incident is opened for human review, and the
    words 'counterfeit'/'fake' never appear as a verdict. Partial (§16.9): the
    human review is what prevents the reputational harm."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 5, token).json()["verdict"] == "authentic"

    forced = verify(uid, 5, token).json()  # attacker forces a divergence
    assert forced["verdict"] == "suspect_duplicate"
    assert forced["verdict"] not in ("counterfeit", "fake")
    assert forced["incident"]["id"] is not None  # queued for a human, not published

    evidence("G7", outcome="detected",
             expected="suspect_duplicate + human incident; never 'counterfeit'",
             detail={"incident_id": forced["incident"]["id"]})


# ------------------------------------------------------------------- G8 --------

def _leading_zero_bits(digest: bytes) -> int:
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


def _solve_pow(challenge: str, difficulty_bits: int) -> int:
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{challenge}{nonce}".encode()).digest()
        if _leading_zero_bits(digest) >= difficulty_bits:
            return nonce
        nonce += 1


def test_g8_report_channel_requires_proof_of_work(session, base_url, evidence):
    """G8 — the consumer report channel is gated by proof-of-work, not a CAPTCHA:
    no third-party dependency between a patient and a safety answer. A submission
    without valid PoW is refused; a submission that solved a live, server-signed
    challenge is accepted. The challenge is stateless (HMAC-signed), so there is
    no table to exhaust."""
    # No PoW at all -> refused.
    no_pow = session.post(f"{base_url}/api/v2/report",
                          json={"verdict_shown": "suspect_duplicate",
                                "note": "flooding attempt"}, timeout=30)
    assert no_pow.status_code in (400, 403)

    # A real submission: fetch a challenge, solve it, submit.
    ch = session.get(f"{base_url}/api/v2/report/challenge", timeout=30).json()
    challenge, bits = ch["challenge"], ch["difficulty_bits"]
    nonce = _solve_pow(challenge, bits)

    accepted = session.post(
        f"{base_url}/api/v2/report",
        json={"pow": {"challenge": challenge, "nonce": nonce},
              "verdict_shown": "suspect_duplicate",
              "note": "Pack looked tampered; bought at a market stall.",
              "city": "Test City"}, timeout=30)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["status"] == "received"

    # A forged/insufficient PoW (nonce 0 against the same challenge) is refused.
    bad = session.post(
        f"{base_url}/api/v2/report",
        json={"pow": {"challenge": challenge, "nonce": 0},
              "verdict_shown": "unknown"}, timeout=30)
    assert bad.status_code == 403

    evidence("G8", outcome="blocked",
             expected="valid PoW accepted; no/insufficient PoW refused",
             detail={"difficulty_bits": bits})


# ------------------------------------------------------------------- G9 --------

def test_g9_enumeration_returns_only_a_verdict_no_inventory(make_tag, enrol,
                                                            verify, evidence):
    """G9 — probing the public API for market intelligence yields only a verdict
    and per-check booleans. No counts, no stock levels, no raw counter, no batch
    quota — nothing an intelligence-gatherer could aggregate into inventory data.
    Partial (§16.9): a counter value is inherently informative, so the raw counter
    is deliberately never echoed back."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    body = verify(uid, 7, token).json()

    allowed = {"verdict", "binding", "product", "checks", "incident",
               "recall_notice", "verified_at"}
    assert set(body) == allowed, f"unexpected fields leak intel: {set(body) - allowed}"
    # The raw counter is never reflected back.
    assert "counter" not in body
    assert "max_counter" not in str(body)

    evidence("G9", outcome="blocked",
             expected="verdict + checks only; no inventory, no raw counter")
