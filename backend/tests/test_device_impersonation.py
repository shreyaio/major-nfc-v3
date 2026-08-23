"""
Attack simulation: DEVICE IMPERSONATION (Ed25519-specific).

These demonstrate the specific security property the Ed25519 device-signing
scheme adds over the old shared-HMAC-secret model: verification only ever
needs a PUBLIC key. Knowing everything the server itself knows (its trusted
public keys) is still not enough to forge a write -- there is no secret value
whose leak would let an attacker sign as a trusted device, unlike HMAC where
the signing and verifying secret were identical.
"""

import secrets
import time

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import BASE_URL, build_valid_product_body, log_evidence


def _post_raw(body, ts, sig):
    return requests.post(
        BASE_URL + "/api/products", json=body,
        headers={"X-Timestamp": ts, "X-Signature": sig}, timeout=5,
    )


def test_untrusted_keypair_signature_rejected():
    """A well-formed, internally-consistent Ed25519 signature from a real
    keypair -- just not one the server has ever been told to trust -- is
    still rejected. Simulates a rogue/unregistered device trying to write."""
    rogue_key = Ed25519PrivateKey.generate()
    body, _, _ = build_valid_product_body()

    import json
    ts = str(int(time.time()))
    payload = ts + json.dumps(body, sort_keys=True, separators=(',', ':'))
    sig = rogue_key.sign(payload.encode('utf-8')).hex()

    r = _post_raw(body, ts, sig)

    log_evidence("device_impersonation", {
        "case": "untrusted_keypair",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
        "note": "Signature is cryptographically valid and internally consistent -- "
                "it's just not signed by a key in PI_PUBLIC_KEYS.",
    })
    assert r.status_code == 403


def test_signature_body_mismatch_rejected():
    """A signature that's valid for one body is sent alongside a DIFFERENT
    body -- simulates an attacker splicing a captured valid signature onto
    modified data."""
    from conftest import sign_request

    body_a, _, _ = build_valid_product_body(product_id="ORIGINAL")
    ts, sig = sign_request(body_a)

    body_b, _, _ = build_valid_product_body(product_id="SWAPPED")
    r = _post_raw(body_b, ts, sig)

    log_evidence("device_impersonation", {
        "case": "signature_body_mismatch",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
    })
    assert r.status_code == 403


def test_garbage_signature_with_knowledge_of_trusted_pubkeys_rejected():
    """Even a caller who knows the server's trusted public keys (they're not
    secret in this scheme -- knowing them is by design not enough to sign)
    cannot forge a signature. Simulated here with random bytes standing in
    for 'best guess without the private key'."""
    body, _, _ = build_valid_product_body()
    ts = str(int(time.time()))
    fake_sig = secrets.token_hex(64)  # 64 bytes -- correct length, wrong content

    r = _post_raw(body, ts, fake_sig)

    log_evidence("device_impersonation", {
        "case": "garbage_signature_correct_length",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
        "note": "Demonstrates the asymmetric property: PI_PUBLIC_KEYS can be fully "
                "known/leaked and still not usable to produce a valid signature -- "
                "unlike the old HMAC scheme where the verifying secret WAS the "
                "signing secret.",
    })
    assert r.status_code == 403
