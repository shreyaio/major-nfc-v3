"""Integration fixtures — a LIVE SERVER over real HTTP. ARCHITECTURE.md §17.3.

Not Flask's test client. A mock cannot catch a middleware ordering bug, a CORS
misconfiguration, a header the WSGI layer strips, or a rate limiter that counts
per worker instead of globally. v1 tested against a live server and was right to
(§5.2); this keeps that.

These tests run against a SEPARATE Supabase project, or against a batch reserved
for testing. They never mutate production data.

Everything here skips cleanly when TEST_BASE_URL is unset, so `pytest tests/unit`
stays the thing that runs everywhere.
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import date, datetime, timezone

import pytest
import requests

import crypto_envelope

pytestmark = pytest.mark.integration

TIMEOUT = 30


@pytest.fixture(scope="session")
def session():
    with requests.Session() as s:
        yield s


@pytest.fixture(scope="session")
def server_config(session, base_url):
    """Read the posture off /health so tests can assert against the deployment
    they are actually pointed at rather than against assumptions."""
    response = session.get(f"{base_url}/health", timeout=TIMEOUT)
    assert response.status_code in (200, 503), response.text
    return response.json()


@pytest.fixture(scope="session")
def field_recipient_pub():
    """The backend's X25519 public key. It is public by definition — the Pi
    carries it in plaintext — so reading it from the environment is fine."""
    import os
    value = os.getenv("TEST_FIELD_RECIPIENT_PUB")
    if not value:
        pytest.skip("TEST_FIELD_RECIPIENT_PUB is not set")
    return bytes.fromhex(value)


@pytest.fixture(scope="session")
def test_batch(session, base_url, admin_token):
    """An open batch with a generous quota, reserved for this test run."""
    batch_ref = f"TEST-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"
    response = session.post(
        f"{base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref,
              "product_name": "Integration Test Product 500mg",
              "mfg_date": date.today().isoformat(),
              "shelf_life_days": 730,
              "quota": 200,
              "opened_by": "integration-tests",
              "countersigned_by": "integration-tests-second-person"},
        timeout=TIMEOUT)
    assert response.status_code == 201, response.text
    yield response.json()

    # Close it on the way out so a test run cannot leave an open batch behind
    # for a stolen key to enrol into.
    session.post(f"{base_url}/api/v2/admin/batches/{batch_ref}/close",
                 headers={"Authorization": f"Bearer {admin_token}"},
                 timeout=TIMEOUT)


@pytest.fixture
def make_tag(field_recipient_pub, test_batch):
    """Build a plausible enrolment payload for a fresh, random tag.

    Returns (payload, uid, token_hex) — the caller needs the UID and the binding
    token to construct the verify URL afterwards, exactly as a consumer's phone
    would receive them from the chip.
    """
    def _make(*, enrol_counter: int = 3, product_id: str | None = None,
              mfg_date: str | None = None, binding_class: str = "counter",
              originality_status: str = "verified"):
        # A random 7-byte UID starting 04h, the way NXP assigns them.
        uid = "04" + secrets.token_bytes(6).hex().upper()
        token_hex = secrets.token_bytes(16).hex().upper()

        sealed = crypto_envelope.seal_record(
            {"product_id": product_id or f"TEST-{secrets.token_hex(4).upper()}",
             "batch_id": test_batch["batch_ref"],
             "mfg_date": mfg_date or test_batch["mfg_date"],
             "tag_uid": uid},
            field_recipient_pub)

        import hashlib
        payload = {
            "schema": "nfcmed.enrol.v2",
            "crypto_version": "aes_gcm_v2",
            "batch_ref": test_batch["batch_ref"],
            "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
            "enrol_counter": enrol_counter,
            "originality_status": originality_status,
            "binding_class": binding_class,
            "tag_version": "0004040201000F03",
            "sealed": sealed,
        }
        return payload, uid, token_hex

    return _make


@pytest.fixture
def enrol(session, base_url, sign_request):
    """POST one enrolment payload and return the response."""
    def _enrol(payload: dict, *, idempotency_key: str | None = None,
               timestamp: str | None = None, headers_override: dict | None = None):
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        headers = sign_request(raw, idempotency_key=idempotency_key,
                               timestamp=timestamp)
        headers.update(headers_override or {})
        return session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                            timeout=TIMEOUT)

    return _enrol


@pytest.fixture
def verify(session, base_url):
    """GET a verdict the way a phone would, with `m` and `t` from the chip."""
    def _verify(uid: str, counter: int, token_hex: str, *, live: bool = False):
        m = f"{uid}x{counter:06X}"
        params = {"m": m, "t": token_hex}
        if live:
            params["live"] = "1"
        return session.get(f"{base_url}/api/v2/verify", params=params, timeout=TIMEOUT)

    return _verify


def new_key() -> str:
    return str(uuid.uuid4())
