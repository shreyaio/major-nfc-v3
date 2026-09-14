"""Batch quotas and two-person authorisation. ARCHITECTURE.md §8.3, §12.6.

The quota is the cheapest mitigation for a stolen Pi signing key (F1): it
converts an unlimited compromise into a bounded one, for free. It also closes G5
— an insider pre-enrolling blank tags against real batch numbers has nowhere to
put them once the quota is spent or the batch is closed.

Both controls are DATABASE CHECK CONSTRAINTS, not Python. The 5,001st enrolment
into a batch of 5,000 fails at the database whatever the client believes: an
application-level count is a race, a CHECK is not.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import date

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def tiny_batch(session, base_url, admin_token):
    """A batch with a quota of exactly 2, so exhaustion is cheap to reach."""
    batch_ref = f"QUOTA-{secrets.token_hex(4).upper()}"
    response = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref, "product_name": "Quota Test 10mg",
              "mfg_date": date.today().isoformat(), "shelf_life_days": 365,
              "quota": 2, "opened_by": "operator-a",
              "countersigned_by": "operator-b"},
        timeout=30)
    assert response.status_code == 201, response.text
    yield response.json()
    session.post(f"{base_url}/api/v2/admin/batches/{batch_ref}/close",
                 headers={"Authorization": f"Bearer {admin_token}"}, timeout=30)


def _payload_for(batch, field_recipient_pub):
    import hashlib

    import crypto_envelope

    uid = "04" + secrets.token_bytes(6).hex().upper()
    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": f"Q-{secrets.token_hex(3).upper()}",
         "batch_id": batch["batch_ref"], "mfg_date": batch["mfg_date"],
         "tag_uid": uid},
        field_recipient_pub)
    return {
        "schema": "nfcmed.enrol.v2",
        "crypto_version": "aes_gcm_v2",
        "batch_ref": batch["batch_ref"],
        "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
        "enrol_counter": 2,
        "originality_status": "verified",
        "binding_class": "counter",
        "tag_version": "0004040201000F03",
        "sealed": sealed,
    }


def test_f10a_the_quota_is_enforced_by_the_database(tiny_batch, enrol,
                                                    field_recipient_pub):
    """Fill the quota, then try once more. This is what bounds the damage from a
    stolen signing key."""
    for _ in range(tiny_batch["quota"]):
        response = enrol(_payload_for(tiny_batch, field_recipient_pub),
                         idempotency_key=str(uuid.uuid4()))
        assert response.status_code == 201, response.text

    over = enrol(_payload_for(tiny_batch, field_recipient_pub),
                 idempotency_key=str(uuid.uuid4()))
    assert over.status_code == 409
    assert over.json()["error"]["code"] == "batch_quota_exhausted"


def test_g5_a_closed_batch_accepts_nothing(session, base_url, admin_token,
                                           tiny_batch, enrol, field_recipient_pub):
    session.post(f"{base_url}/api/v2/admin/batches/{tiny_batch['batch_ref']}/close",
                 headers={"Authorization": f"Bearer {admin_token}"}, timeout=30)

    response = enrol(_payload_for(tiny_batch, field_recipient_pub),
                     idempotency_key=str(uuid.uuid4()))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "batch_not_open"


def test_enrolment_into_an_unknown_batch_is_refused(enrol, field_recipient_pub):
    fake = {"batch_ref": "NO-SUCH-BATCH-EVER", "mfg_date": date.today().isoformat()}
    response = enrol(_payload_for(fake, field_recipient_pub),
                     idempotency_key=str(uuid.uuid4()))
    assert response.status_code == 409


def test_f12_two_person_authorisation_is_required(session, base_url, admin_token):
    """countersigned_by must differ from opened_by. It is a DB CHECK, so no
    client can talk its way past it."""
    response = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": f"SOLO-{secrets.token_hex(4).upper()}",
              "product_name": "One Person Batch", "mfg_date": date.today().isoformat(),
              "shelf_life_days": 365, "quota": 10,
              "opened_by": "shreya", "countersigned_by": "shreya"},
        timeout=30)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "countersignature_required"


def test_the_enrolled_count_tracks_reality(session, base_url, admin_token,
                                           tiny_batch, enrol, field_recipient_pub):
    """The counter increment and the product insert are ONE transaction. An
    insert that succeeded while the increment failed would let the quota drift,
    and the quota is the mitigation for a stolen key."""
    assert enrol(_payload_for(tiny_batch, field_recipient_pub),
                 idempotency_key=str(uuid.uuid4())).status_code == 201

    batches = session.get(f"{base_url}/api/v2/admin/batches",
                          headers={"Authorization": f"Bearer {admin_token}"},
                          timeout=30).json()["batches"]
    this_batch = next(b for b in batches if b["batch_ref"] == tiny_batch["batch_ref"])
    assert this_batch["enrolled_count"] == 1


def test_an_invalid_shelf_life_is_refused(session, base_url, admin_token):
    for shelf_life in (0, -1, 4000):
        response = session.post(
            f"{base_url}/api/v2/admin/batches",
            headers={"Authorization": f"Bearer {admin_token}",
                     "Content-Type": "application/json"},
            json={"batch_ref": f"BAD-{secrets.token_hex(4).upper()}",
                  "product_name": "Bad Shelf Life", "mfg_date": date.today().isoformat(),
                  "shelf_life_days": shelf_life, "quota": 10,
                  "opened_by": "a", "countersigned_by": "b"},
            timeout=30)
        assert response.status_code == 400, shelf_life


def test_d14_admin_routes_reject_an_unsigned_token(session, base_url):
    """There is no admin secret on the server to brute-force — a forgery needs
    the private key, which never reaches the runtime backend."""
    for token in ["", "not-a-token", "a.b", "eyJzdWIiOiJhZG1pbiJ9.AAAA"]:
        response = session.get(f"{base_url}/api/v2/admin/batches",
                               headers={"Authorization": f"Bearer {token}"},
                               timeout=30)
        assert response.status_code in (401, 403), token
