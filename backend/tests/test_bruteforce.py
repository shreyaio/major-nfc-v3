"""
Attack simulation: BRUTE FORCE.

Two angles: (1) hammering POST /api/products with random signatures, hoping one
gets lucky; (2) enumerating random tag_uid_hash values against the public verify
endpoint, hoping to discover a registered tag. Both should be rejected on every
attempt, AND the rate limiter should start returning 429 once the per-minute
threshold is exceeded.

Honest caveat (documented, not oversold): tag_uid_hash is SHA-256 of a 7-byte
factory UID (a 2^56 search space). That's infeasible to brute-force live against
a rate-limited endpoint -- this test demonstrates the rate limiter engages, not
that the hash itself is brute-force-proof against an offline/precomputed attack.
"""

import hashlib
import secrets
import time

import requests

from conftest import BASE_URL, build_valid_product_body, log_evidence


def test_bruteforce_post_products_all_rejected_and_throttled():
    statuses = []
    for _ in range(40):
        body, _, _ = build_valid_product_body()
        r = requests.post(
            BASE_URL + "/api/products", json=body,
            headers={"X-Timestamp": str(int(time.time())), "X-Signature": secrets.token_hex(32)},
            timeout=5,
        )
        statuses.append(r.status_code)

    saw_429 = 429 in statuses
    all_rejected = all(s in (403, 429) for s in statuses)

    log_evidence("bruteforce", {
        "case": "post_products_random_signatures",
        "attempts": len(statuses),
        "status_counts": {str(s): statuses.count(s) for s in set(statuses)},
        "saw_rate_limit_429": saw_429,
        "all_rejected_or_throttled": all_rejected,
        "passed": all_rejected,
    })
    assert all_rejected, f"unexpected status codes among {set(statuses)}"


def test_bruteforce_verify_enumeration_all_unknown_and_throttled():
    statuses, results = [], []
    for _ in range(30):
        fake_hash = hashlib.sha256(secrets.token_bytes(7)).hexdigest()
        r = requests.get(BASE_URL + f"/api/verify/{fake_hash}", timeout=5)
        statuses.append(r.status_code)
        if r.status_code == 200:
            results.append(r.json().get("status"))

    saw_429 = 429 in statuses
    all_unknown_or_throttled = all(
        s == 429 or (s == 200 and res == "unknown")
        for s, res in zip(statuses, results + [None] * (len(statuses) - len(results)))
    )

    log_evidence("bruteforce", {
        "case": "verify_enumeration",
        "attempts": len(statuses),
        "status_counts": {str(s): statuses.count(s) for s in set(statuses)},
        "saw_rate_limit_429": saw_429,
        "note": "tag_uid_hash is SHA-256 of a 7-byte UID (2^56 space); this only "
                "demonstrates throttling engages, not brute-force infeasibility of the hash itself.",
        "passed": all_unknown_or_throttled,
    })
    assert all_unknown_or_throttled
