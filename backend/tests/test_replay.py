"""
Attack simulation: REPLAY.

An attacker who captures a single valid signed POST /api/products request tries
to resend it to create a duplicate/ambiguous record for a tag that's already
registered. Two independent defenses are exercised: the 30-second timestamp
window, and the nonce UNIQUE constraint (which holds even if the attacker can
forge a fresh, currently-valid signature over the same nonce).
"""

from conftest import (
    build_valid_product_body, post_signed_product, sign_request, log_evidence,
)


def test_replay_verbatim_request_is_rejected_by_nonce_uniqueness():
    body, _, _ = build_valid_product_body()
    r1 = post_signed_product(body)
    assert r1.status_code == 200, "setup: first write should succeed"

    # Replay the exact same request (same body, same nonce) immediately.
    r2 = post_signed_product(body)

    log_evidence("replay", {
        "case": "verbatim_replay",
        "first_status": r1.status_code,
        "replay_status": r2.status_code,
        "replay_body": r2.json() if r2.headers.get("content-type", "").startswith("application/json") else r2.text,
        "expected": 409,
        "passed": r2.status_code == 409,
    })
    assert r2.status_code == 409, "replayed nonce must be rejected even within the timestamp window"


def test_replay_stale_timestamp_is_rejected():
    import time
    body, _, _ = build_valid_product_body()
    stale_ts = str(int(time.time()) - 60)  # outside the 30s window
    r = post_signed_product(body, ts=stale_ts)

    log_evidence("replay", {
        "case": "stale_timestamp",
        "status": r.status_code,
        "expected": 403,
        "passed": r.status_code == 403,
    })
    assert r.status_code == 403


def test_replay_with_freshly_forged_signature_same_nonce_still_rejected():
    """
    Even a legitimately-signed, brand-new, currently-valid request over the
    identical body/nonce (simulated here via the test fixture's own trusted
    Ed25519 key) is still stopped -- because nonce uniqueness is enforced at
    the database level, independent of signature validity or timestamp
    freshness. This holds even for a fully trusted signer, so it necessarily
    also holds against anyone who isn't.
    """
    body, _, _ = build_valid_product_body()
    r1 = post_signed_product(body)
    assert r1.status_code == 200

    # Re-sign the same body/nonce with a brand-new, currently-valid signature.
    ts2, sig2 = sign_request(body)
    import requests
    from conftest import BASE_URL
    r2 = requests.post(BASE_URL + "/api/products", json=body,
                        headers={"X-Timestamp": ts2, "X-Signature": sig2}, timeout=5)

    log_evidence("replay", {
        "case": "fresh_signature_same_nonce",
        "status": r2.status_code,
        "expected": 409,
        "passed": r2.status_code == 409,
    })
    assert r2.status_code == 409
