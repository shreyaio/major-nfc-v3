"""Monte-Carlo validation of MTA clone-detection probabilities.

Reproduces Section VI ("Detection analysis") / Table III of the paper —
*Low-Cost Authentication of Medicine Packaging Using NFC Tags, Standard
Cryptography and Live Physical-Tag Binding* — against THIS repository's own
decision logic.

Why this belongs in unit/, not attacks/: it is a property of the pure
services.verification.decide() function, exactly like test_verdict_machine.py
(which enumerates it exhaustively). This file samples it statistically instead
of enumerating it, because detection PROBABILITY under random interleaving —
not just reachability of a verdict — is the thing being checked. Like the rest
of unit/, it needs no database, no Flask process and no network, so it runs
everywhere test_verdict_machine.py does, including plain `pytest` on a laptop
with no TEST_BASE_URL set.

The paper's own methodology (quoted in clone_detection_mc.py) is explicit that
this validation "contains no radio, tag, phone or network behaviour" — i.e.
the authors themselves ran it as pure software, driving the deployed decision
function. That is exactly what this file does, against the actual function
rather than a reimplementation of it.

Fast tests below use a MODERATE, fixed-seed trial count so the suite stays
fast and deterministic in CI. The full paper-scale reproduction (10^5
trials/cell, ~30-60s) is a separate, opt-in slow test — see
test_full_table_iii_reproduction_matches_paper below and
tests/simulation/reproduce_table_iii.py for a standalone CLI version of the
same thing.
"""
from __future__ import annotations

import os
import random

import pytest
from simulation.clone_detection_mc import (
    PAPER_TABLE_III,
    SimParams,
    closed_form_distinct_forged,
    closed_form_single_use_clone,
    format_table_iii_markdown,
    run_table_iii,
    simulate_distinct_forged,
    simulate_reused_url,
    simulate_single_use_clone,
    write_table_iii_csv,
)

# A fixed seed makes every assertion below deterministic — not flaky,
# reproducible, and re-runnable bit-for-bit by anyone who checks this out.
SEED = 1337
FAST_TRIALS = 6000


@pytest.fixture(scope="module")
def rng() -> random.Random:
    return random.Random(SEED)


@pytest.fixture(scope="module")
def params() -> SimParams:
    # c0 = 3, pack age 30 days -> B = 1523, exactly the paper's own
    # validation parameters, which are themselves this project's
    # MAX_TAPS_PER_DAY=50 / VELOCITY_GRACE=20 defaults (backend/config.py).
    return SimParams(enrol_counter=3, pack_age_days=30)


# =========================================================== PROPOSITION 1 ===
# Reused URL (m >= 2): certain detection no later than the second clone
# verification.

@pytest.mark.parametrize("m", [2, 3, 5, 10])
def test_proposition1_reused_url_is_certain_detection(m, rng, params):
    result = simulate_reused_url(m=m, trials=FAST_TRIALS, rng=rng, params=params)
    assert result.pdet.estimate == 1.0, (
        f"m={m}: expected certain detection (Pdet=1.0), got {result.pdet.estimate}")


def test_proposition1_detection_lands_on_the_second_presentation(rng, params):
    """Not just "eventually detected" — the paper is specific that detection
    cannot be later than the second clone use."""
    result = simulate_reused_url(m=2, trials=FAST_TRIALS, rng=rng, params=params)
    assert result.first_detected_at.estimate == 1.0


# =========================================================== PROPOSITION 2 ===
# Single-use clone (m == 1): Pdet = g/(g+1) for static-copy and
# forged-at-bound; Pgen = 0 for static-copy, Pgen = Pdet for forged-at-bound.

@pytest.mark.parametrize("g", [1, 2, 5])
def test_proposition2_static_copy_pdet_matches_g_over_g_plus_1(g, rng, params):
    result = simulate_single_use_clone(g=g, strategy="static", trials=FAST_TRIALS,
                                       rng=rng, params=params)
    theory = closed_form_single_use_clone(g)
    assert result.pdet.within(theory), (
        f"g={g} static: simulated Pdet={result.pdet.estimate:.4f} "
        f"(se={result.pdet.standard_error:.4f}) vs theory={theory:.4f}")


@pytest.mark.parametrize("g", [1, 2, 5])
def test_proposition2_static_copy_never_flags_the_genuine_pack_first(g, rng, params):
    """The alarm always lands on the clone for a static captured counter — the
    genuine pack's counter is always ahead of the frozen k once any genuine
    verification has happened. Pgen = 0.000 in the paper, every row."""
    result = simulate_single_use_clone(g=g, strategy="static", trials=FAST_TRIALS,
                                       rng=rng, params=params)
    assert result.pgen.estimate == 0.0, (
        f"g={g} static: expected Pgen=0 (clone always takes the flag), "
        f"got {result.pgen.estimate}")


@pytest.mark.parametrize("g", [1, 2, 5])
def test_proposition2_forged_at_bound_pdet_matches_g_over_g_plus_1(g, rng, params):
    result = simulate_single_use_clone(g=g, strategy="forged_at_bound", trials=FAST_TRIALS,
                                       rng=rng, params=params)
    theory = closed_form_single_use_clone(g)
    assert result.pdet.within(theory), (
        f"g={g} forged_at_bound: simulated Pdet={result.pdet.estimate:.4f} "
        f"(se={result.pdet.standard_error:.4f}) vs theory={theory:.4f}")


@pytest.mark.parametrize("g", [1, 2, 5])
def test_proposition2_forged_at_bound_misattributes_to_the_genuine_pack(g, rng, params):
    """§VI "Attribution is not a corner case": for a clone forged at the
    velocity bound, EVERY detected trial flags the genuine pack, never the
    clone — Pgen == Pdet exactly, in every row of the paper's table. This is
    the single most important empirical property MTA's design has to be
    honest about (sticky SUSPECT_DUPLICATE, routed to a human, never
    "counterfeit")."""
    result = simulate_single_use_clone(g=g, strategy="forged_at_bound", trials=FAST_TRIALS,
                                       rng=rng, params=params)
    assert result.pgen.estimate == pytest.approx(result.pdet.estimate, abs=1e-9), (
        f"g={g} forged_at_bound: Pgen ({result.pgen.estimate}) should equal "
        f"Pdet ({result.pdet.estimate}) — every detection should be the genuine pack")


@pytest.mark.parametrize("g", [1, 2, 5])
def test_proposition2_random_offset_matches_published_table_iii(g, rng, params):
    """No closed form exists for this strategy (the paper reports it only
    empirically) — so cross-validate against the paper's own published
    figures instead of a formula, and sanity-check 0 < Pgen < Pdet (the
    genuine pack is flagged sometimes, not always, and not never)."""
    result = simulate_single_use_clone(g=g, strategy="random_1_20", trials=FAST_TRIALS,
                                       rng=rng, params=params)
    published = PAPER_TABLE_III["single_use_clone"][("random_1_20", g)]
    # Generous tolerance: this cell's SE from a ~6k-trial run, or 0.03, whichever
    # is larger — the published figure is itself a single 10^5-trial sample.
    tol = max(4 * result.pdet.standard_error, 0.03)
    assert abs(result.pdet.estimate - published["pdet"]) <= tol, (
        f"g={g} random_1_20: simulated Pdet={result.pdet.estimate:.4f} vs "
        f"paper={published['pdet']}")
    tol_gen = max(4 * result.pgen.standard_error, 0.04)
    assert abs(result.pgen.estimate - published["pgen"]) <= tol_gen, (
        f"g={g} random_1_20: simulated Pgen={result.pgen.estimate:.4f} vs "
        f"paper={published['pgen']}")
    assert 0.0 < result.pgen.estimate < result.pdet.estimate


# =========================================================== PROPOSITION 3 ===
# Distinct forged counters (n >= 2, g = 0): Pdet = 1 - 1/n!.

@pytest.mark.parametrize("n", [2, 3, 4, 5])
def test_proposition3_distinct_forged_counters_matches_1_minus_1_over_n_factorial(
        n, rng, params):
    result = simulate_distinct_forged(n=n, trials=FAST_TRIALS, rng=rng, params=params)
    theory = closed_form_distinct_forged(n)
    assert result.pdet.within(theory), (
        f"n={n}: simulated Pdet={result.pdet.estimate:.4f} "
        f"(se={result.pdet.standard_error:.4f}) vs theory={theory:.4f}")


def test_proposition3_detection_probability_increases_with_n(rng, params):
    """More distinct forged clones in circulation -> harder for the
    counterfeiter to get lucky with the scan order."""
    pdets = [
        simulate_distinct_forged(n=n, trials=FAST_TRIALS, rng=rng, params=params).pdet.estimate
        for n in (2, 3, 4, 5)
    ]
    assert pdets == sorted(pdets)


# ================================================================ IRREDUCIBLE
# GAP (Remark 1): a strictly increasing forged sequence is indistinguishable
# from one honest tag's history. This is not a bug to fix — the paper is
# explicit that MTA converts cloning into a statistical risk, not a
# certainty, and the suite should say so rather than imply perfect detection.

def test_remark1_the_irreducible_gap_is_real_not_simulated_away():
    """If n distinct forged counters happen to be presented in ascending
    order, decide() must accept every one of them as AUTHENTIC — anything
    else would mean the simulation (or the decision function) is cheating by
    using information a real verifier does not have access to."""
    params = SimParams(enrol_counter=3, pack_age_days=30)
    from simulation.clone_detection_mc import Verdict, _TagTimeline

    timeline = _TagTimeline(params)
    ascending = [10, 25, 40, 55, 70]
    for counter in ascending:
        verdict = timeline.scan(counter)
        assert verdict is Verdict.AUTHENTIC, (
            f"counter={counter}: an ascending forged sequence must be "
            f"indistinguishable from a genuine one, got {verdict}")


# ========================================================= FULL TABLE III ====
# Opt-in, paper-scale (10^5 trials/cell) reproduction. Skipped by default
# because it takes tens of seconds; set RUN_SLOW_MC=1 to run it, exactly the
# way TEST_BASE_URL gates the live-server attack suite. Writes the same
# evidence files tests/simulation/reproduce_table_iii.py would.

pytestmark_slow = pytest.mark.slow


@pytest.mark.slow
@pytest.mark.skipif(not os.getenv("RUN_SLOW_MC"),
                    reason="paper-scale (10^5 trials/cell) reproduction; "
                           "set RUN_SLOW_MC=1 to run it (takes ~30-60s)")
def test_full_table_iii_reproduction_matches_paper(tmp_path):
    result = run_table_iii(trials=100_000, seed=20260914)

    for row in result["single_use_clone"]:
        published = PAPER_TABLE_III["single_use_clone"][(row["strategy"], row["g"])]
        assert abs(row["pdet_sim"] - published["pdet"]) < 0.01, row
        assert abs(row["pgen_sim"] - published["pgen"]) < 0.01, row

    for row in result["distinct_forged_counters"]:
        published = PAPER_TABLE_III["distinct_forged_counters"][row["n"]]
        assert abs(row["pdet_sim"] - published) < 0.01, row

    for row in result["reused_url"]:
        assert row["pdet_sim"] == 1.0

    evidence_dir = tmp_path / "evidence"
    write_table_iii_csv(result, evidence_dir / "montecarlo_table_iii.csv")
    (evidence_dir / "montecarlo_table_iii.md").write_text(
        format_table_iii_markdown(result), encoding="utf-8")
    assert (evidence_dir / "montecarlo_table_iii.csv").exists()
