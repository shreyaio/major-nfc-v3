"""Recall, and the row re-signing that has to come with it.
ARCHITECTURE.md §10.5, §9.7 step 9.

`status` is INSIDE the row signature (§7.4). So a recall that changed the status
without re-signing would make every recalled pack return RECORD_INVALID instead
of RECALLED — technically safe, but it would mask a real regulatory event behind
a scary generic error. A patient holding a recalled pack would be told "we cannot
confirm this" instead of "do not use this, return it to your pharmacist".

That is the difference this file tests.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import date

import pytest

pytestmark = pytest.mark.integration

NOTICE = "Batch recalled 2026-09-12: possible contamination. Return to pharmacist."


@pytest.fixture
def recallable_batch(session, base_url, admin_token):
    batch_ref = f"RECALL-{secrets.token_hex(4).upper()}"
    response = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref, "product_name": "Recall Test 250mg",
              "mfg_date": date.today().isoformat(), "shelf_life_days": 365,
              "quota": 20, "opened_by": "operator-a", "countersigned_by": "operator-b"},
        timeout=30)
    assert response.status_code == 201, response.text
    return response.json()


def _enrol_into(batch, enrol, field_recipient_pub, counter=2):
    import hashlib

    import crypto_envelope

    uid = "04" + secrets.token_bytes(6).hex().upper()
    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": f"R-{secrets.token_hex(3).upper()}",
         "batch_id": batch["batch_ref"], "mfg_date": batch["mfg_date"],
         "tag_uid": uid},
        field_recipient_pub)
    payload = {
        "schema": "nfcmed.enrol.v2", "crypto_version": "aes_gcm_v2",
        "batch_ref": batch["batch_ref"],
        "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
        "enrol_counter": counter, "originality_status": "verified",
        "binding_class": "counter", "tag_version": "0004040201000F03",
        "sealed": sealed,
    }
    response = enrol(payload, idempotency_key=str(uuid.uuid4()))
    assert response.status_code == 201, response.text
    return uid, token_hex


def test_g2_a_recalled_pack_says_recalled_not_record_invalid(
        session, base_url, admin_token, recallable_batch, enrol, verify,
        field_recipient_pub):
    """The whole point of re-signing inside the same transaction."""
    uid, token = _enrol_into(recallable_batch, enrol, field_recipient_pub)

    assert verify(uid, 5, token).json()["verdict"] == "authentic"

    response = session.post(
        f"{base_url}/api/v2/admin/recall",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": recallable_batch["batch_ref"], "notice": NOTICE},
        timeout=30)
    assert response.status_code == 200, response.text
    assert response.json()["rows_resigned"] >= 1

    body = verify(uid, 6, token).json()
    assert body["verdict"] == "recalled"
    assert body["verdict"] != "record_invalid"
    assert body["checks"]["record"] == "pass", (
        "the row signature must still verify after a recall — otherwise the "
        "recall is hidden behind a generic error")
    assert body["checks"]["recall"] == "fail"
    assert NOTICE in (body["recall_notice"] or "")


def test_the_recall_notice_reaches_the_consumer(
        session, base_url, admin_token, recallable_batch, enrol, verify,
        field_recipient_pub):
    """A recall with no explanation is a red screen with no instruction, which
    is worse than useless in a health context."""
    uid, token = _enrol_into(recallable_batch, enrol, field_recipient_pub)
    session.post(f"{base_url}/api/v2/admin/recall",
                 headers={"Authorization": f"Bearer {admin_token}",
                          "Content-Type": "application/json"},
                 json={"batch_ref": recallable_batch["batch_ref"], "notice": NOTICE},
                 timeout=30)

    assert verify(uid, 9, token).json()["recall_notice"] == NOTICE


def test_a_recall_without_a_notice_is_refused(session, base_url, admin_token,
                                              recallable_batch):
    for notice in ("", "   ", None):
        response = session.post(
            f"{base_url}/api/v2/admin/recall",
            headers={"Authorization": f"Bearer {admin_token}",
                     "Content-Type": "application/json"},
            json={"batch_ref": recallable_batch["batch_ref"], "notice": notice},
            timeout=30)
        assert response.status_code == 400, notice


def test_recall_requires_the_recall_scope(session, base_url, recallable_batch):
    response = session.post(
        f"{base_url}/api/v2/admin/recall",
        headers={"Content-Type": "application/json"},
        json={"batch_ref": recallable_batch["batch_ref"], "notice": NOTICE},
        timeout=30)
    assert response.status_code in (401, 403)


def test_a_recalled_batch_accepts_no_further_enrolments(
        session, base_url, admin_token, recallable_batch, enrol,
        field_recipient_pub):
    session.post(f"{base_url}/api/v2/admin/recall",
                 headers={"Authorization": f"Bearer {admin_token}",
                          "Content-Type": "application/json"},
                 json={"batch_ref": recallable_batch["batch_ref"], "notice": NOTICE},
                 timeout=30)

    import hashlib

    import crypto_envelope
    uid = "04" + secrets.token_bytes(6).hex().upper()
    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": "AFTER-RECALL", "batch_id": recallable_batch["batch_ref"],
         "mfg_date": recallable_batch["mfg_date"], "tag_uid": uid},
        field_recipient_pub)
    response = enrol({
        "schema": "nfcmed.enrol.v2", "crypto_version": "aes_gcm_v2",
        "batch_ref": recallable_batch["batch_ref"],
        "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
        "enrol_counter": 2, "originality_status": "verified",
        "binding_class": "counter", "tag_version": "0004040201000F03",
        "sealed": sealed}, idempotency_key=str(uuid.uuid4()))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "batch_not_open"
