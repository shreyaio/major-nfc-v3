"""
Attack simulation: BIRTHDAY ATTACK (nonce collision).

A real birthday attack against this system's nonce (secrets.token_hex(8) --
64 bits of randomness) would need on the order of 1.25*sqrt(2**64) ~= 4.3
billion requests for a 50% chance of a collision. That's not something we can
or should actually run live. Instead this file does the honest version:

1. Empirically validates the birthday-paradox math on a small, tractable hash
   space (pure local computation, no network requests) -- proving the
   methodology is sound.
2. Applies that same formula to this system's real parameters (64-bit nonce,
   256-bit SHA-256 hashes) to compute and state the real attack cost.
3. Runs exactly one live check: deliberately submits two requests sharing the
   same nonce (which is what a successful birthday attack would eventually
   produce) and confirms the UNIQUE constraint rejects the second one
   regardless of *how* the duplicate arose -- proving the defense holds even
   in the hypothetical case an attacker beat the odds.
"""

import math
import random
import time

import requests

from conftest import BASE_URL, build_valid_product_body, sign_request, log_evidence


def _expected_draws_for_collision(space_size: int) -> float:
    """Classic birthday-paradox approximation: expected number of random draws
    from a space of size N before the first collision is ~1.2533*sqrt(N)."""
    return 1.2533 * math.sqrt(space_size)


def test_birthday_paradox_empirical_validation():
    """No network requests -- pure local simulation on a small (16-bit) space
    where collisions are cheap to actually find, confirming the birthday
    formula's prediction matches reality before we rely on it below."""
    space_size = 2 ** 16
    trials = 300
    draw_counts = []

    for _ in range(trials):
        seen = set()
        draws = 0
        while True:
            draws += 1
            val = random.randrange(space_size)
            if val in seen:
                break
            seen.add(val)
        draw_counts.append(draws)

    empirical_avg = sum(draw_counts) / len(draw_counts)
    theoretical = _expected_draws_for_collision(space_size)
    ratio = empirical_avg / theoretical

    log_evidence("birthday", {
        "case": "empirical_validation_16bit_space",
        "trials": trials,
        "empirical_avg_draws": round(empirical_avg, 1),
        "theoretical_avg_draws": round(theoretical, 1),
        "ratio": round(ratio, 3),
        "passed": 0.7 <= ratio <= 1.4,
    })
    # Empirical average should land close to the theoretical prediction --
    # wide-ish tolerance since this is a probabilistic process, not exact.
    assert 0.7 <= ratio <= 1.4, (
        f"empirical avg {empirical_avg:.1f} vs theoretical {theoretical:.1f} "
        f"(ratio {ratio:.3f}) is further off than expected -- formula or "
        f"simulation logic may be wrong"
    )


def test_birthday_bound_analysis_for_real_system():
    """No network requests -- computes the real attack cost for this system's
    actual parameters and documents it as evidence for the report."""
    nonce_bits = 64          # secrets.token_hex(8) == 8 random bytes
    hash_bits = 256          # SHA-256 (tag_uid_hash, payload_hash)

    nonce_draws = _expected_draws_for_collision(2 ** nonce_bits)
    hash_draws = _expected_draws_for_collision(2 ** hash_bits)

    log_evidence("birthday", {
        "case": "real_system_bound_analysis",
        "nonce_bits": nonce_bits,
        "nonce_expected_draws_for_collision": f"{nonce_draws:.3e}",
        "hash_bits": hash_bits,
        "hash_expected_draws_for_collision": f"{hash_draws:.3e}",
        "conclusion": (
            "~5.4e9 requests needed for a 50% chance of a nonce collision; "
            "even at a sustained 1000 req/s with no rate limiting at all, "
            "that's ~62 days of continuous requests against a single "
            "endpoint. With the deployed rate limit (30/min on writes), "
            "it would take over 340 years. The SHA-256 birthday bound "
            "(~4.3e38 draws -- the square root of the full 2**256 keyspace, "
            "not the keyspace itself) is even further out of reach; a full "
            "brute-force preimage search (~1.2e77 draws) is the only other "
            "reference point and is not a practical concern at any "
            "achievable scale either way."
        ),
        "passed": True,
    })
    assert nonce_draws > 1e9  # sanity-check the math actually ran
    assert hash_draws > 1e35  # birthday bound for a 256-bit hash is ~2**128 ~= 3.4e38


def test_duplicate_nonce_rejected_regardless_of_how_it_arose():
    """Simulates the hypothetical outcome of a successful birthday attack: two
    genuinely different, validly-signed requests that happen to share a
    nonce. The database-level UNIQUE constraint doesn't care how the
    duplicate came about -- collision, replay, or coincidence -- it's
    rejected either way."""
    shared_nonce = "birthday" + str(int(time.time()))[-8:]

    body_a, _, _ = build_valid_product_body(nonce=shared_nonce, product_id="BDAY-A")
    ts_a, sig_a = sign_request(body_a)
    r1 = requests.post(BASE_URL + "/api/products", json=body_a,
                        headers={"X-Timestamp": ts_a, "X-Signature": sig_a}, timeout=5)

    body_b, _, _ = build_valid_product_body(nonce=shared_nonce, product_id="BDAY-B")
    ts_b, sig_b = sign_request(body_b)
    r2 = requests.post(BASE_URL + "/api/products", json=body_b,
                        headers={"X-Timestamp": ts_b, "X-Signature": sig_b}, timeout=5)

    log_evidence("birthday", {
        "case": "duplicate_nonce_two_different_bodies",
        "first_status": r1.status_code,
        "second_status": r2.status_code,
        "expected_second": 409,
        "passed": r1.status_code == 200 and r2.status_code == 409,
    })
    assert r1.status_code == 200, "setup: first write should succeed"
    assert r2.status_code == 409, "second write sharing a nonce must be rejected"
