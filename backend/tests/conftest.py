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
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

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
