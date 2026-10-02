"""Shared fixtures. ARCHITECTURE.md §17.

Two kinds of test live here and they have very different needs:

  unit/        no database, no Flask, no network. These run everywhere, in CI,
               on a laptop, in a few hundred milliseconds. The verdict machine
               is a pure function precisely so it can be tested this way.

  integration/ a LIVE SERVER over real HTTP, not Flask's test client. v1 did
               this and was right to (§5.2): a mock cannot catch a middleware
               ordering bug, a CORS misconfiguration, a header the WSGI layer
               strips, or a rate limiter that counts per worker. They skip
               automatically when TEST_BASE_URL is unset.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
import requests

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
PI_DIR = REPO_ROOT / "pi"
VECTORS_DIR = Path(__file__).resolve().parent / "vectors"

# backend/ first so `import config` resolves there. pi/ is appended (not
# prepended) so the cross-device test can import the Pi's copies explicitly
# without shadowing the backend's modules of the same name.
sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture(scope="session")
def vectors_dir() -> Path:
    return VECTORS_DIR


def load_vector(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def uid_vectors() -> dict:
    return load_vector("uid.json")


@pytest.fixture(scope="session")
def mirror_vectors() -> dict:
    return load_vector("mirror.json")


@pytest.fixture(scope="session")
def envelope_vectors() -> dict:
    return load_vector("envelope.json")


@pytest.fixture(scope="session")
def rowsig_vectors() -> dict:
    return load_vector("rowsig.json")


@pytest.fixture(scope="session")
def reqsig_vectors() -> dict:
    return load_vector("reqsig.json")


# --------------------------------------------------------------- live server --

@pytest.fixture(scope="session")
def base_url() -> str:
    """The live server under test.

    Integration tests run against a SEPARATE Supabase project or a batch
    reserved for testing — never production data (§17.3). Nothing here will stop
    you pointing it at production; that is a discipline, and it is in the
    runbook.
    """
    url = os.getenv("TEST_BASE_URL")
    if not url:
        pytest.skip("TEST_BASE_URL is not set — integration tests need a live server")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def admin_token() -> str:
    token = os.getenv("TEST_ADMIN_TOKEN")
    if not token:
        pytest.skip("TEST_ADMIN_TOKEN is not set")
    return token


@pytest.fixture(scope="session")
def test_device():
    """A device identity for signing enrolment requests.

    The keypair is generated per session and its public half must be in
    device_registry for the integration tests to pass — see
    docs/OPERATOR_RUNBOOK.md. Generating it here rather than committing one keeps
    a usable private key out of the repository.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv_hex = os.getenv("TEST_DEVICE_PRIVATE_KEY")
    if priv_hex:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    else:
        sk = Ed25519PrivateKey.generate()

    return {
        "device_id": os.getenv("TEST_DEVICE_ID", str(uuid.uuid4())),
        "private_key": sk,
        "private_hex": sk.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        "public_hex": sk.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex(),
    }


@pytest.fixture
def sign_request(test_device):
    """Sign an enrolment request exactly as pi/drainer.py does."""
    import crypto_signing

    def _sign(raw_body: bytes, *, idempotency_key: str | None = None,
              timestamp: str | None = None):
        idempotency_key = idempotency_key or str(uuid.uuid4())
        timestamp = timestamp or str(int(datetime.now(timezone.utc).timestamp()))
        payload = crypto_signing.build_signed_payload(
            "ed25519", timestamp, idempotency_key, raw_body)
        return {
            "Content-Type": "application/json",
            "X-Device-Id": test_device["device_id"],
            "X-Timestamp": timestamp,
            "X-Sig-Alg": "ed25519",
            "X-Signature": test_device["private_key"].sign(payload).hex(),
            "X-Idempotency-Key": idempotency_key,
        }

    return _sign


# ------------------------------------------------------------------ helpers ---

class FakeMirror:
    """Stands in for backend.mirror.Mirror in unit tests, so the verdict machine
    can be exercised without importing Flask-adjacent code."""

    __slots__ = ("counter", "placeholder", "uid")

    def __init__(self, uid="04A1B2C3D4E5F6", counter=5, placeholder=False):
        self.uid = uid
        self.counter = counter
        self.placeholder = placeholder


@pytest.fixture
def fake_mirror():
    return FakeMirror


# ------------------------------------------------------- live-server requests --
#
# These drive a LIVE SERVER over real HTTP (§17.3). They used to live in
# integration/conftest.py, but the attack suite in attacks/ is a sibling
# directory and pytest only shares fixtures down a subtree — so they are lifted
# here, to the common ancestor, and both integration/ and attacks/ inherit them
# unchanged. Everything still skips cleanly when TEST_BASE_URL is unset, so
# `pytest tests/unit` stays the thing that runs everywhere.

HTTP_TIMEOUT = 30


@pytest.fixture(scope="session")
def session():
    with requests.Session() as s:
        yield s


@pytest.fixture(scope="session")
def server_config(session, base_url):
    """Read the posture off /health so tests can assert against the deployment
    they are actually pointed at rather than against assumptions."""
    response = session.get(f"{base_url}/health", timeout=HTTP_TIMEOUT)
    assert response.status_code in (200, 503), response.text
    return response.json()


@pytest.fixture(scope="session")
def field_recipient_pub():
    """The backend's X25519 public key. It is public by definition — the Pi
    carries it in plaintext — so reading it from the environment is fine."""
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
        timeout=HTTP_TIMEOUT)
    assert response.status_code == 201, response.text
    yield response.json()

    # Close it on the way out so a test run cannot leave an open batch behind
    # for a stolen key to enrol into.
    session.post(f"{base_url}/api/v2/admin/batches/{batch_ref}/close",
                 headers={"Authorization": f"Bearer {admin_token}"},
                 timeout=HTTP_TIMEOUT)


@pytest.fixture
def make_tag(field_recipient_pub, test_batch):
    """Build a plausible enrolment payload for a fresh, random tag.

    Returns (payload, uid, token_hex) — the caller needs the UID and the binding
    token to construct the verify URL afterwards, exactly as a consumer's phone
    would receive them from the chip.
    """
    import crypto_envelope

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
                            timeout=HTTP_TIMEOUT)

    return _enrol


@pytest.fixture
def verify(session, base_url):
    """GET a verdict the way a phone would, with `m` and `t` from the chip."""
    def _verify(uid: str, counter: int, token_hex: str, *, live: bool = False):
        m = f"{uid}x{counter:06X}"
        params = {"m": m, "t": token_hex}
        if live:
            params["live"] = "1"
        return session.get(f"{base_url}/api/v2/verify", params=params,
                           timeout=HTTP_TIMEOUT)

    return _verify


def new_key() -> str:
    return str(uuid.uuid4())
