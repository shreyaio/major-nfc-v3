"""
Attack simulation: CLONE.

An attacker tries to register a counterfeit tag against the backend without
possessing SHARED_SECRET, and separately we check what a blank/cloned physical
tag (whose UID was never registered) looks like to a consumer scanning it.

Known limitation (documented, not solved here): this system verifies by looking
up a server-side record keyed on tag_uid_hash. It cannot cryptographically prove
the *physical* NFC chip is genuine -- a cloned tag broadcasting a copied UID and
a copied NDEF URL would still resolve to the real record and show "authentic".
Closing that gap needs tag-side password protection (NTAG213 PWD_AUTH) or an
originality-signature chip family (e.g. NTAG 21x DNA) -- out of scope here.
"""

import requests

from conftest import (
    BASE_URL, build_valid_product_body, post_signed_product, log_evidence,
)


def test_write_without_shared_secret_is_rejected():
    body, _, _ = build_valid_product_body()
    # No X-Timestamp / X-Signature headers at all -- simulates an attacker who
    # doesn't know SHARED_SECRET trying to register a counterfeit product record.
    r = requests.post(BASE_URL + "/api/products", json=body, timeout=5)

    log_evidence("clone", {
        "case": "write_without_secret",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
    })
    assert r.status_code == 403


def test_write_with_wrong_signature_is_rejected():
    body, _, _ = build_valid_product_body()
    r = requests.post(BASE_URL + "/api/products", json=body,
                       headers={"X-Timestamp": "9999999999", "X-Signature": "0" * 64},
                       timeout=5)

    log_evidence("clone", {
        "case": "write_with_wrong_signature",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code in (403,),
    })
    assert r.status_code == 403


def test_verify_fabricated_uid_shows_unknown():
    """Simulates tapping a blank/cloned tag whose UID was never registered."""
    import secrets, hashlib
    fake_uid = secrets.token_hex(7).upper()
    fake_hash = hashlib.sha256(fake_uid.encode()).hexdigest()

    r = requests.get(BASE_URL + f"/api/verify/{fake_hash}", timeout=5)
    data = r.json()

    log_evidence("clone", {
        "case": "verify_fabricated_uid",
        "status": r.status_code,
        "result": data.get("status"),
        "expected": "unknown",
        "passed": data.get("status") == "unknown",
    })
    assert data["status"] == "unknown"
