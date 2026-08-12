"""
Attack simulation: MAN-IN-THE-MIDDLE (tamper detection).

Two angles: (1) an attacker intercepts a request in flight, flips a byte of
ciphertext, and tries to resubmit it -- without SHARED_SECRET they can't produce
a valid signature over the modified body, so it's rejected before it ever
reaches decryption or the database. (2) an attacker who reaches the database
directly (or a MITM who rewrote a stored value) mutates a ciphertext column --
the verify endpoint must flip to "tampered" via the payload_hash mismatch.

Explicitly flagged, not solved here: this proves INTEGRITY (tamper detection)
survives without TLS. It does not prove CONFIDENTIALITY without TLS -- a passive
eavesdropper on plain HTTP can still observe traffic patterns, tag hashes, and
timestamps. That's exactly why Phase 2 (HTTPS via Cloudflare Tunnel) still
matters and is not replaced by these results.
"""

import copy

import requests

from conftest import (
    BASE_URL, build_valid_product_body, post_signed_product, register_valid_product,
    log_evidence, get_connection,
)


def test_tampered_ciphertext_rejected_before_storage():
    """Flip a byte in the ciphertext and resubmit under an attacker-forged (invalid)
    signature -- rejected at the signature check, before decryption/DB write."""
    body, _, _ = build_valid_product_body()
    tampered = copy.deepcopy(body)
    ct = tampered["product_id"]["data"]
    flipped_char = "1" if ct[0] != "1" else "2"
    tampered["product_id"]["data"] = flipped_char + ct[1:]

    r = requests.post(BASE_URL + "/api/products", json=tampered,
                       headers={"X-Timestamp": "9999999999", "X-Signature": "0" * 64},
                       timeout=5)

    log_evidence("mitm", {
        "case": "tampered_ciphertext_forged_signature",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
    })
    assert r.status_code == 403


def test_db_level_tamper_detected_by_verify():
    """Simulates an attacker who reached the database directly (or a MITM who
    rewrote a stored ciphertext in transit to a replica) -- verify must catch it."""
    body, tag_uid, tag_uid_hash, r = register_valid_product()

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE products SET batch_id = %s WHERE tag_uid_hash = %s",
        ("00" * 20, tag_uid_hash),
    )
    conn.commit()
    cur.close()
    conn.close()

    vr = requests.get(BASE_URL + f"/api/verify/{tag_uid_hash}", timeout=5)
    data = vr.json()

    log_evidence("mitm", {
        "case": "db_level_ciphertext_tamper",
        "status": vr.status_code,
        "result": data.get("status"),
        "expected": "tampered",
        "passed": data.get("status") == "tampered",
        "note": "Proves integrity/tamper detection without TLS. Does NOT substitute "
                "for TLS -- confidentiality still requires Phase 2 HTTPS.",
    })
    assert data["status"] == "tampered"
