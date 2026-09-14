"""Enrolment: idempotency, signatures, transport gates, derived fields.
ARCHITECTURE.md §9.5, §10.2.

The outbox retries until it gets a 2xx, which means the SAME request arrives
many times. Two things must hold: a replay must not enrol the tag twice (D5,
F11), and a key reused with a DIFFERENT body must be refused rather than
silently replaying the wrong stored response (D9).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import pytest

import crypto_envelope

pytestmark = pytest.mark.integration


# ============================================================== IDEMPOTENCY ====

def test_d5_a_verbatim_replay_returns_the_stored_response(make_tag, enrol):
    payload, _uid, _token = make_tag()
    key = str(uuid.uuid4())

    first = enrol(payload, idempotency_key=key)
    assert first.status_code == 201

    second = enrol(payload, idempotency_key=key)
    # 200, not 201: the caller can tell a replay from a fresh enrolment, which
    # is what makes the drainer's terminal/retryable split easy to get right.
    assert second.status_code == 200
    assert second.json() == first.json()


def test_d9_the_same_key_with_a_different_body_is_a_conflict(make_tag, enrol):
    """The idempotency key is INSIDE the signature so it cannot be swapped, and
    reusing it for different content is refused rather than replayed."""
    first_payload, _, _ = make_tag()
    second_payload, _, _ = make_tag()
    key = str(uuid.uuid4())

    assert enrol(first_payload, idempotency_key=key).status_code == 201

    conflict = enrol(second_payload, idempotency_key=key)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"


def test_d10_the_same_tag_under_a_new_key_is_rejected(make_tag, enrol,
                                                      field_recipient_pub,
                                                      test_batch):
    """products.tag_index is UNIQUE. Re-enrolment shadowing is a 409, never a
    quiet overwrite — there is no implicit supersede path in this codebase."""
    payload, uid, _token = make_tag()
    assert enrol(payload).status_code == 201

    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": "SECOND-ATTEMPT", "batch_id": test_batch["batch_ref"],
         "mfg_date": test_batch["mfg_date"], "tag_uid": uid},
        field_recipient_pub)
    duplicate = {**payload,
                 "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
                 "sealed": sealed}

    response = enrol(duplicate, idempotency_key=str(uuid.uuid4()))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "tag_already_enrolled"


# ================================================================ SIGNATURES ====

def test_d7_a_stale_timestamp_is_rejected(make_tag, enrol):
    payload, _, _ = make_tag()
    response = enrol(payload, timestamp=str(int(time.time()) - 120))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "bad_signature"


def test_d8_a_future_timestamp_is_rejected(make_tag, enrol):
    """v1 used abs(), which is already two-sided — but D8 was never tested. It
    is now: a clock ahead of the server is as much of a problem as one behind."""
    payload, _, _ = make_tag()
    assert enrol(payload, timestamp=str(int(time.time()) + 120)).status_code == 403


def test_d2_a_forged_signature_is_rejected(session, base_url, make_tag, sign_request):
    payload, _, _ = make_tag()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_request(raw)
    headers["X-Signature"] = "00" * 64

    response = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=30)
    assert response.status_code == 403


def test_d4_tampering_with_the_body_invalidates_the_signature(
        session, base_url, make_tag, sign_request):
    """The signature covers sha256(RAW BODY BYTES), so one changed byte breaks
    it — and the check happens before anything parses the body (D1)."""
    payload, _, _ = make_tag(enrol_counter=3)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_request(raw)

    tampered = raw.replace(b'"enrol_counter":3', b'"enrol_counter":0')
    assert tampered != raw, "payload shape changed; adjust the tamper"

    response = session.post(f"{base_url}/api/v2/enrol", data=tampered,
                            headers=headers, timeout=30)
    assert response.status_code == 403


def test_d3_an_unknown_device_is_rejected(session, base_url, make_tag, sign_request):
    payload, _, _ = make_tag()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_request(raw)
    headers["X-Device-Id"] = str(uuid.uuid4())  # valid uuid, not in the registry

    response = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=30)
    assert response.status_code == 403


# ============================================================ TRANSPORT GATES ====

def test_d18_wrong_content_type_is_415(session, base_url, make_tag, sign_request):
    payload, _, _ = make_tag()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_request(raw)
    headers["Content-Type"] = "text/plain"

    response = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=30)
    assert response.status_code == 415


def test_d19_an_oversized_body_is_413(session, base_url, sign_request):
    raw = json.dumps({"schema": "nfcmed.enrol.v2", "pad": "x" * 100_000}).encode()
    headers = sign_request(raw)
    response = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=30)
    assert response.status_code == 413


def test_d17_get_is_not_allowed_on_enrol(session, base_url):
    assert session.get(f"{base_url}/api/v2/enrol", timeout=30).status_code == 405


def test_d19_deeply_nested_json_is_rejected(session, base_url, sign_request):
    """Billion-laughs shaped input. Depth is bounded before anything walks the
    structure."""
    nested = {"schema": "nfcmed.enrol.v2"}
    cursor = nested
    for _ in range(40):
        cursor["next"] = {}
        cursor = cursor["next"]

    raw = json.dumps(nested).encode()
    headers = sign_request(raw)
    response = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=30)
    assert response.status_code == 400


# =========================================================== DERIVED FIELDS ====

def test_f8_the_client_cannot_state_the_expiry_date(make_tag, enrol, test_batch):
    """The backend derives shelf_life from the batch and expiry_date from the
    decrypted mfg_date. A client that cannot state the expiry date cannot get
    the expiry date wrong."""
    payload, _, _ = make_tag()
    payload["expiry_date"] = "2099-01-01"      # ignored
    payload["shelf_life"] = 99999              # ignored

    response = enrol(payload)
    assert response.status_code == 201

    from datetime import date, timedelta
    expected = (date.fromisoformat(test_batch["mfg_date"])
                + timedelta(days=test_batch["shelf_life_days"])).isoformat()
    assert response.json()["expiry_date"] == expected


def test_f8_an_mfg_date_that_disagrees_with_the_batch_is_rejected(make_tag, enrol):
    """One typo would otherwise produce a wrong expiry date on a medicine pack,
    signed and permanently recorded."""
    payload, _, _ = make_tag(mfg_date="2020-01-01")
    response = enrol(payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "mfg_date_invalid"


def test_a_future_mfg_date_is_rejected(make_tag, enrol):
    from datetime import date, timedelta
    future = (date.today() + timedelta(days=30)).isoformat()
    payload, _, _ = make_tag(mfg_date=future)
    assert enrol(payload).status_code == 400


def test_no_tag_index_is_accepted_from_the_client(make_tag, enrol):
    """The Pi never computes an index — TAG_INDEX_KEY lives only on the backend.
    Sending one must not influence anything (E5, D9)."""
    payload, _uid, _token = make_tag()
    payload["tag_index"] = "0" * 64

    response = enrol(payload)
    assert response.status_code == 201
    assert response.json()["tag_index"] != "0" * 64


# ============================================================ CRYPTO VERSION ====

def test_e8_the_paper_cipher_is_a_hard_reject_not_a_fallback(make_tag, enrol):
    for version in ("paper_v1", "aes_gcm_v1", "none", ""):
        payload, _, _ = make_tag()
        payload["crypto_version"] = version
        response = enrol(payload, idempotency_key=str(uuid.uuid4()))
        assert response.status_code == 400, version


def test_d11_a_corrupted_ciphertext_fails_authentication(make_tag, enrol):
    payload, _, _ = make_tag()
    corrupted = bytearray.fromhex(payload["sealed"]["tag_uid"]["c"])
    corrupted[0] ^= 0x01
    payload["sealed"]["tag_uid"]["c"] = corrupted.hex()

    response = enrol(payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "decrypt_failed"


def test_d11_swapping_two_sealed_fields_fails(make_tag, enrol):
    """Per-field AAD binds each ciphertext to its slot. Moving one is not a
    clever substitution, it is an authentication failure."""
    payload, _, _ = make_tag()
    sealed = payload["sealed"]
    sealed["tag_uid"], sealed["mfg_date"] = sealed["mfg_date"], sealed["tag_uid"]

    response = enrol(payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "decrypt_failed"
