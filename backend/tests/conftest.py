"""
Shared fixtures/helpers for the functional + attack-simulation suite.

These tests exercise a REAL, RUNNING server (not Flask's test client) because
several of them specifically need to observe live behavior: rate-limit counters,
actual DB-level nonce uniqueness under concurrent-ish requests, and timing.

Requires the test suite's own Ed25519 public key (see _TEST_DEVICE_PRIVATE_KEY_HEX
below) to be present in the server's PI_PUBLIC_KEYS env var, comma-joined with
the real Pi's public key -- otherwise every signed write in this suite gets a
403. Start the server first:

    cd backend
    venv\\Scripts\\python.exe app.py

Then, in another terminal:

    cd backend
    venv\\Scripts\\python.exe -m pytest tests/ -v

Every attack test also appends a structured JSON-line record to
backend/tests/evidence/<name>.jsonl documenting what was sent, what came back,
and whether it matched the expected defensive behavior. report.py turns that
(plus a look at the audit_log table) into evidence/report.md.
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Make backend/ modules importable regardless of the directory pytest is invoked from.
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from config import AES_MASTER_KEY                          # noqa: E402
from crypto_modern import derive_tag_key, aes_gcm_encrypt  # noqa: E402
from db import get_connection                              # noqa: E402

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:5000")
EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

# Dedicated test-suite device identity -- NOT a production secret, just a fixed
# Ed25519 keypair so these tests can simulate "a trusted device" writing
# without ever touching the real Pi's private key. Its public half must be
# added to the running server's PI_PUBLIC_KEYS (comma-joined with the real
# Pi's) for these tests to pass.
_TEST_DEVICE_PRIVATE_KEY_HEX = "d363692caaa69f161db30d22a8d479b470857d496400da83edaace883162ead8"
_test_signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_TEST_DEVICE_PRIVATE_KEY_HEX))


@pytest.fixture(scope="session", autouse=True)
def require_server_running():
    try:
        r = requests.get(BASE_URL + "/health", timeout=3)
        assert r.status_code == 200
    except Exception as e:
        pytest.exit(
            f"Backend not reachable at {BASE_URL} ({e}). "
            f"Start it first: cd backend && venv\\Scripts\\python.exe app.py"
        )


def sign_request(body: dict, ts: str = None):
    """Signs with the test suite's own fixed Ed25519 identity (see
    _test_signing_key above) -- not the real Pi's key."""
    ts = ts or str(int(time.time()))
    payload = ts + json.dumps(body, sort_keys=True, separators=(',', ':'))
    sig = _test_signing_key.sign(payload.encode('utf-8')).hex()
    return ts, sig


def build_valid_product_body(tag_uid: str = None, nonce: str = None,
                              product_id: str = "PROD-TEST", batch_id: str = "BATCH-TEST",
                              mfg_date: str = "2026-01-01", shelf_life: int = 365):
    """Builds a fully valid aes_gcm_v1 POST /api/products body, ready to sign and send."""
    import secrets as _secrets
    tag_uid = tag_uid or _secrets.token_hex(7).upper()
    tag_uid_hash = hashlib.sha256(tag_uid.encode('latin-1')).hexdigest()
    key = derive_tag_key(tag_uid_hash, AES_MASTER_KEY)

    pid_iv, pid_ct = aes_gcm_encrypt(product_id, key)
    bid_iv, bid_ct = aes_gcm_encrypt(batch_id, key)
    mfg_iv, mfg_ct = aes_gcm_encrypt(mfg_date, key)
    uid_iv, uid_ct = aes_gcm_encrypt(tag_uid, key)

    body = {
        "crypto_version": "aes_gcm_v1",
        "nonce": nonce or _secrets.token_hex(8),
        "tag_uid_hash": tag_uid_hash,
        "product_id": {"iv": pid_iv, "data": pid_ct},
        "batch_id": {"iv": bid_iv, "data": bid_ct},
        "mfg_date": {"iv": mfg_iv, "data": mfg_ct},
        "shelf_life": shelf_life,
        "tag_uid": {"iv": uid_iv, "data": uid_ct},
    }
    return body, tag_uid, tag_uid_hash


def post_signed_product(body: dict, ts: str = None):
    ts_, sig = sign_request(body, ts)
    headers = {"X-Timestamp": ts_, "X-Signature": sig}
    return requests.post(BASE_URL + "/api/products", json=body, headers=headers, timeout=5)


def register_valid_product(**kwargs):
    """Convenience: build + post a valid product, assert it succeeded, return (body, response)."""
    body, tag_uid, tag_uid_hash = build_valid_product_body(**kwargs)
    r = post_signed_product(body)
    assert r.status_code == 200, f"setup failed: {r.status_code} {r.text}"
    return body, tag_uid, tag_uid_hash, r


def log_evidence(name: str, record: dict):
    record["_logged_at"] = datetime.now(timezone.utc).isoformat()
    path = EVIDENCE_DIR / f"{name}.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def latest_audit_row(tag_uid_hash: str = None, event_type: str = None):
    conn = get_connection()
    if not conn:
        return None
    cur = conn.cursor()
    clauses, params = [], []
    if tag_uid_hash:
        clauses.append("tag_uid_hash = %s")
        params.append(tag_uid_hash)
    if event_type:
        clauses.append("event_type = %s")
        params.append(event_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT event_type, tag_uid_hash, result, source_ip, created_at "
                f"FROM audit_log {where} ORDER BY id DESC LIMIT 1", params)
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
