"""Monte-Carlo validation of MTA clone-detection probabilities.

This reproduces Section VI ("Detection analysis") of the paper
*Low-Cost Authentication of Medicine Packaging Using NFC Tags, Standard
Cryptography and Live Physical-Tag Binding* — specifically Propositions 1-3
and Table III.

The paper's own methodology is explicit about what the simulation is and is
not (quote): "We validated these results by driving the deployed pure verdict
function with randomly interleaved scans (10^5 trials per cell; c0 = 3, pack
age 30 days, so B = 1523; genuine taps advance by 1 + Poisson(1) per
verification) ... The simulation is of the decision logic only: it contains
no radio, tag, phone or network behaviour."

That "deployed pure verdict function" is services/verification.decide() in
THIS repository — not a reimplementation of the state machine. Everything
below threads state through decide() exactly the way services/counter.py
does against a real database (advance max_counter only when
decision.advance_counter is True; flip to the sticky "suspect_duplicate"
status on the first counter divergence), so the simulation exercises the
actual shipped decision logic, not an abstract model of it. This is why it
can be done entirely in software: decide() takes no DB/Flask/network
dependency, by design (see its module docstring).

Three adversary clone strategies, matching the paper 1:1:

  * Reused URL (m >= 2)        -- Proposition 1. Certain detection.
  * Single-use clone (m == 1)  -- Proposition 2. Pdet = Pgen = g / (g + 1)
                                   for a clone frozen at the velocity bound;
                                   Pdet = g / (g + 1), Pgen = 0 for a static
                                   captured counter; an empirical in-between
                                   case for a small random forged offset.
  * Distinct forged counters   -- Proposition 3. Pdet = 1 - 1/n! (g = 0).
    (n >= 2)

"g" is the number of genuine-pack verifications and "m" the number of clone
verifications, interleaved uniformly at random — exactly the paper's model.
"""
from __future__ import annotations

import math
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from services.verification import Verdict, decide  # noqa: E402
from services.verification import velocity_bound as _velocity_bound  # noqa: E402

# --------------------------------------------------------------------------- #
# Paper defaults — c0 = 3, pack age 30 days, so B = 1523. These are not
# arbitrary: max_taps_per_day=50 and velocity_grace=20 are this project's own
# MAX_TAPS_PER_DAY / VELOCITY_GRACE defaults (backend/config.py), so the paper's
# simulation parameters already ARE this project's parameters.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SimParams:
    enrol_counter: int = 3
    pack_age_days: int = 30
    max_taps_per_day: int = 50
    velocity_grace: int = 20
    token: str = "A" * 32
    anchor: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))

    @property
    def now(self) -> datetime:
        return self.anchor

    @property
    def enrolled_at(self) -> datetime:
        return self.anchor - timedelta(days=self.pack_age_days)

    @property
    def velocity_bound(self) -> int:
        return _velocity_bound(self.enrol_counter, self.enrolled_at, self.now,
                                self.max_taps_per_day, self.velocity_grace)

    def row(self) -> dict:
        return {
            "tag_index": "sim" + "0" * 61,
            "binding_token_hash": "simulated-binding-token-hash",
            "crypto_version": "aes_gcm_v2",
            "enrol_counter": self.enrol_counter,
            "enrolled_at": self.enrolled_at,
            "expiry_date": "2099-01-01",
            "status": "active",
            "batch_ref": "SIM-BATCH-MONTECARLO",
            "row_sig": "simulated",
            "row_sig_alg": "ed25519",
        }


class _Mirror:
    """Stands in for backend.mirror.Mirror — the only attributes decide() reads."""

    __slots__ = ("counter", "placeholder", "uid")

    def __init__(self, counter: int, uid: str = "04A1B2C3D4E5F6"):
        self.uid = uid
        self.counter = counter
        self.placeholder = False


class _TagTimeline:
    """Threads (mirror, state) through decide() exactly as services/counter.py
    drives it against a real database row: advance max_counter only when
    decision.advance_counter is True, and flip the state sticky to
    "suspect_duplicate" the first time a counter divergence fires — never
    cleared inside a trial, matching the project's sticky-flag design (G1).
    """

    def __init__(self, params: SimParams):
        self._params = params
        self._state = {"max_counter": params.enrol_counter, "status": "ok"}
        self._row = params.row()
        self._batch = {"status": "open", "recall_notice": None}

    def scan(self, counter: int) -> Verdict:
        decision = decide(
            mirror=_Mirror(counter),
            token=self._params.token,
            row=self._row,
            state=dict(self._state),
            batch=self._batch,
            now=self._params.now,
            row_sig_valid=True,
            token_matches=True,
            max_taps_per_day=self._params.max_taps_per_day,
            velocity_grace=self._params.velocity_grace,
        )
        if decision.advance_counter:
            self._state["max_counter"] = counter
        if decision.verdict is Verdict.SUSPECT_DUPLICATE and decision.divergence is not None:
            self._state["status"] = "suspect_duplicate"
        return decision.verdict


# --------------------------------------------------------------------------- #
# Synthetic scan-sequence generators. "Genuine taps advance by 1 + Poisson(1)
# per verification" — sampled with random.Random so a trial is reproducible
# from its seed.
# --------------------------------------------------------------------------- #


def _poisson1(rng: random.Random) -> int:
    """Knuth's algorithm for Poisson(lambda=1), good enough for lambda=1."""
    threshold = math.exp(-1.0)
    k, p = 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= threshold:
            return k - 1


def _genuine_sequence(start: int, count: int, rng: random.Random) -> list[int]:
    """`count` strictly increasing counters, each at least 1 above the last —
    the real hardware counter can only ever go up."""
    out = []
    counter = start
    for _ in range(count):
        counter += 1 + _poisson1(rng)
        out.append(counter)
    return out


# --------------------------------------------------------------------------- #
# Statistics helpers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Proportion:
    """A simulated probability with its sampling error, for comparison against
    a closed-form or published value."""

    estimate: float
    n_trials: int
    successes: int

    @property
    def standard_error(self) -> float:
        p = self.estimate
        return math.sqrt(max(p * (1 - p), 1e-12) / self.n_trials)

    def within(self, target: float, *, z: float = 4.0, floor: float = 0.004) -> bool:
        """True if `target` is within `z` standard errors of the estimate (plus
        a small floor so a near-zero/near-one cell with a tiny SE is not held
        to an unreasonably tight absolute tolerance)."""
        tolerance = max(z * self.standard_error, floor)
        return abs(self.estimate - target) <= tolerance


def _proportion(successes: int, n_trials: int) -> Proportion:
    return Proportion(estimate=successes / n_trials, n_trials=n_trials, successes=successes)


# --------------------------------------------------------------------------- #
# Closed forms — Propositions 1-3
# --------------------------------------------------------------------------- #


def closed_form_single_use_clone(g: int) -> float:
    """Proposition 2. Pdetect = g / (g + 1), for both the static-copy and the
    forged-at-bound strategies (they share the same combinatorial argument —
    see the module docstring and the paper's proof)."""
    return g / (g + 1)


def closed_form_distinct_forged(n: int) -> float:
    """Proposition 3. Pdetect = 1 - 1/n! — only the single ascending permutation
    among n! equally likely scan orders evades detection."""
    return 1 - 1 / math.factorial(n)


# --------------------------------------------------------------------------- #
# Simulation 1 — Reused URL (Proposition 1): same captured counter k used m>=2
# times. Detection is certain no later than the second clone presentation,
# regardless of order, because both presentations carry the identical counter.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ReusedUrlResult:
    m: int
    pdet: Proportion
    first_detected_at: Proportion  # P(detected on exactly the 2nd presentation)


def simulate_reused_url(*, m: int, trials: int, rng: random.Random,
                        params: SimParams | None = None) -> ReusedUrlResult:
    if m < 2:
        raise ValueError("reused-URL only applies for m >= 2 (Proposition 1)")
    params = params or SimParams()
    detected = 0
    detected_on_second = 0
    for _ in range(trials):
        timeline = _TagTimeline(params)
        k = params.enrol_counter + 1 + _poisson1(rng)
        was_detected = False
        for i in range(m):
            verdict = timeline.scan(k)
            if verdict is Verdict.SUSPECT_DUPLICATE:
                was_detected = True
                if i == 1:  # zero-indexed: the SECOND presentation
                    detected_on_second += 1
                break
        if was_detected:
            detected += 1
    return ReusedUrlResult(
        m=m,
        pdet=_proportion(detected, trials),
        first_detected_at=_proportion(detected_on_second, trials),
    )


# --------------------------------------------------------------------------- #
# Simulation 2 — Single-use clone (Proposition 2): g genuine verifications + 1
# clone verification, interleaved uniformly at random.
#
# "Interleaved" here means the lone clone tap is inserted at a uniformly
# random point among the g genuine taps — NOT that the g genuine taps are
# themselves reshuffled. The g genuine verifications are one real object's
# chronological history (each one the pack's hardware counter actually
# advancing before the next tap can happen), so they keep their natural
# counter-increasing order; only the attacker's single clone presentation can
# land anywhere in that timeline. This gives g + 1 equally likely insertion
# points, matching the paper's closed-form combinatorics exactly (shuffling
# the genuine events against each other instead would create impossible
# "later tap has an earlier counter" orderings and silently inflate Pdet).
# --------------------------------------------------------------------------- #

STRATEGIES = ("static", "random_1_20", "forged_at_bound")


@dataclass(frozen=True)
class SingleUseCloneResult:
    g: int
    strategy: str
    pdet: Proportion
    pgen: Proportion  # P(the genuine pack, not the clone, is the first flagged)


def simulate_single_use_clone(*, g: int, strategy: str, trials: int,
                              rng: random.Random,
                              params: SimParams | None = None) -> SingleUseCloneResult:
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {STRATEGIES}, got {strategy!r}")
    params = params or SimParams()
    detected = 0
    genuine_first_flagged = 0

    for _ in range(trials):
        timeline = _TagTimeline(params)

        # The attacker's own single tap, capturing counter k — not itself a
        # consumer verification.
        k = params.enrol_counter + 1 + _poisson1(rng)

        # g genuine consumer verifications, all strictly after the capture, the
        # real hardware counter only ever increasing.
        genuine_counters = _genuine_sequence(k, g, rng)

        if strategy == "static":
            clone_counter = k
        elif strategy == "random_1_20":
            clone_counter = k + rng.randint(1, 20)
        else:  # forged_at_bound
            clone_counter = params.velocity_bound

        # Insert the single clone tap at a uniformly random point in the
        # genuine timeline — g + 1 equally likely positions (index 0..g).
        insert_at = rng.randint(0, g)
        events: list[tuple[str, int]] = [("genuine", c) for c in genuine_counters]
        events.insert(insert_at, ("clone", clone_counter))

        for kind, counter in events:
            verdict = timeline.scan(counter)
            if verdict is Verdict.SUSPECT_DUPLICATE:
                detected += 1
                if kind == "genuine":
                    genuine_first_flagged += 1
                break  # only the FIRST flagged event matters for Pdet/Pgen

    return SingleUseCloneResult(
        g=g, strategy=strategy,
        pdet=_proportion(detected, trials),
        pgen=_proportion(genuine_first_flagged, trials),
    )


# --------------------------------------------------------------------------- #
# Simulation 3 — Distinct forged counters (Proposition 3): n clones, n
# distinct increasing counters, g = 0 genuine scans, scanned in uniformly
# random order.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DistinctForgedResult:
    n: int
    pdet: Proportion


def simulate_distinct_forged(*, n: int, trials: int, rng: random.Random,
                             params: SimParams | None = None) -> DistinctForgedResult:
    if n < 2:
        raise ValueError("distinct-forged-counters only applies for n >= 2 (Proposition 3)")
    params = params or SimParams()
    detected = 0
    for _ in range(trials):
        timeline = _TagTimeline(params)
        counters = _genuine_sequence(params.enrol_counter, n, rng)  # n distinct, increasing
        order = list(counters)
        rng.shuffle(order)
        for counter in order:
            verdict = timeline.scan(counter)
            if verdict is Verdict.SUSPECT_DUPLICATE:
                detected += 1
                break
    return DistinctForgedResult(n=n, pdet=_proportion(detected, trials))


# --------------------------------------------------------------------------- #
# Table III reproduction
# --------------------------------------------------------------------------- #

TABLE_III_G_VALUES = (1, 2, 5)
TABLE_III_N_VALUES = (2, 3, 4, 5)


def run_table_iii(*, trials: int, seed: int, params: SimParams | None = None) -> dict:
    """Reproduces every cell of paper Table III. Returns a JSON-serialisable
    dict with raw simulated values, closed forms where one exists, and the
    paper's own published figures (for a reader comparing all three)."""
    params = params or SimParams()
    rng = random.Random(seed)

    single_use_rows = []
    for strategy in STRATEGIES:
        for g in TABLE_III_G_VALUES:
            result = simulate_single_use_clone(
                g=g, strategy=strategy, trials=trials, rng=rng, params=params)
            single_use_rows.append({
                "g": g,
                "strategy": strategy,
                "pdet_sim": result.pdet.estimate,
                "pdet_se": result.pdet.standard_error,
                "pgen_sim": result.pgen.estimate,
                "pgen_se": result.pgen.standard_error,
                "pdet_closed_form": (closed_form_single_use_clone(g)
                                     if strategy != "random_1_20" else None),
            })

    distinct_forged_rows = []
    for n in TABLE_III_N_VALUES:
        result = simulate_distinct_forged(n=n, trials=trials, rng=rng, params=params)
        distinct_forged_rows.append({
            "n": n,
            "pdet_sim": result.pdet.estimate,
            "pdet_se": result.pdet.standard_error,
            "pdet_closed_form": closed_form_distinct_forged(n),
        })

    reused_url_rows = []
    for m in (2, 3, 5):
        result = simulate_reused_url(m=m, trials=trials, rng=rng, params=params)
        reused_url_rows.append({
            "m": m,
            "pdet_sim": result.pdet.estimate,
            "pdet_closed_form": 1.0,
        })

    return {
        "trials_per_cell": trials,
        "seed": seed,
        "params": {
            "enrol_counter": params.enrol_counter,
            "pack_age_days": params.pack_age_days,
            "max_taps_per_day": params.max_taps_per_day,
            "velocity_grace": params.velocity_grace,
            "velocity_bound": params.velocity_bound,
        },
        "single_use_clone": single_use_rows,
        "distinct_forged_counters": distinct_forged_rows,
        "reused_url": reused_url_rows,
    }


# Table III as published in the paper (Sec. VI), for a reader who wants to
# compare this repository's reproduction against the printed figures directly
# rather than against the closed forms alone. Keyed the same way as the rows
# `run_table_iii` returns.
PAPER_TABLE_III = {
    "single_use_clone": {
        ("static", 1): {"pdet": 0.503, "pgen": 0.000},
        ("static", 2): {"pdet": 0.666, "pgen": 0.000},
        ("static", 5): {"pdet": 0.835, "pgen": 0.000},
        ("random_1_20", 1): {"pdet": 0.526, "pgen": 0.475},
        ("random_1_20", 2): {"pdet": 0.702, "pgen": 0.601},
        ("random_1_20", 5): {"pdet": 0.875, "pgen": 0.626},
        ("forged_at_bound", 1): {"pdet": 0.501, "pgen": 0.501},
        ("forged_at_bound", 2): {"pdet": 0.665, "pgen": 0.665},
        ("forged_at_bound", 5): {"pdet": 0.833, "pgen": 0.833},
    },
    "distinct_forged_counters": {
        2: 0.501,
        3: 0.831,
        4: 0.958,
        5: 0.991,
    },
}


def write_table_iii_csv(result: dict, path: Path) -> None:
    """Per-cell raw CSV: one row per simulated cell, with the closed form and
    the paper's published figure alongside the simulated estimate — the same
    "preserve every raw number, don't just assert pass/fail" discipline the
    rest of this repository's evidence files follow."""
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["family", "g_or_n_or_m", "strategy", "trials",
                         "pdet_sim", "pdet_se", "pdet_closed_form", "pdet_paper",
                         "pgen_sim", "pgen_se", "pgen_paper"])
        for row in result["single_use_clone"]:
            paper = PAPER_TABLE_III["single_use_clone"].get((row["strategy"], row["g"]), {})
            writer.writerow([
                "single_use_clone", row["g"], row["strategy"], result["trials_per_cell"],
                f"{row['pdet_sim']:.6f}", f"{row['pdet_se']:.6f}",
                row["pdet_closed_form"] if row["pdet_closed_form"] is not None else "",
                paper.get("pdet", ""),
                f"{row['pgen_sim']:.6f}", f"{row['pgen_se']:.6f}", paper.get("pgen", ""),
            ])
        for row in result["distinct_forged_counters"]:
            paper_pdet = PAPER_TABLE_III["distinct_forged_counters"].get(row["n"], "")
            writer.writerow([
                "distinct_forged_counters", row["n"], "", result["trials_per_cell"],
                f"{row['pdet_sim']:.6f}", f"{row['pdet_se']:.6f}",
                f"{row['pdet_closed_form']:.6f}", paper_pdet, "", "", "",
            ])
        for row in result["reused_url"]:
            writer.writerow([
                "reused_url", row["m"], "", result["trials_per_cell"],
                f"{row['pdet_sim']:.6f}", "0", f"{row['pdet_closed_form']:.6f}", 1.0,
                "", "", "",
            ])


def format_table_iii_markdown(result: dict) -> str:
    """A paper-ready Markdown rendering of the reproduction, laid out the same
    way as Table III so it can be diffed against the printed table by eye."""
    lines = [
        f"Monte-Carlo reproduction of Table III "
        f"({result['trials_per_cell']} trials/cell, seed={result['seed']})",
        "",
        f"c0={result['params']['enrol_counter']}, "
        f"pack_age_days={result['params']['pack_age_days']}, "
        f"B={result['params']['velocity_bound']}",
        "",
        "| g | static Pdet | static Pgen | random+1..20 Pdet | random+1..20 Pgen "
        "| forged-at-B Pdet | forged-at-B Pgen |",
        "|---|---|---|---|---|---|---|",
    ]
    by_g: dict[int, dict] = {}
    for row in result["single_use_clone"]:
        by_g.setdefault(row["g"], {})[row["strategy"]] = row
    for g in TABLE_III_G_VALUES:
        cells = by_g[g]
        lines.append(
            f"| {g} "
            f"| {cells['static']['pdet_sim']:.3f} | {cells['static']['pgen_sim']:.3f} "
            f"| {cells['random_1_20']['pdet_sim']:.3f} | {cells['random_1_20']['pgen_sim']:.3f} "
            f"| {cells['forged_at_bound']['pdet_sim']:.3f} "
            f"| {cells['forged_at_bound']['pgen_sim']:.3f} |")
    lines += [
        "",
        f"Theory g/(g+1): {', '.join(f'{closed_form_single_use_clone(g):.3f}' for g in TABLE_III_G_VALUES)}",
        "",
        "Distinct forged counters (g=0):",
        "",
        "| n | Pdet (sim) | Pdet (theory 1-1/n!) |",
        "|---|---|---|",
    ]
    for row in result["distinct_forged_counters"]:
        lines.append(f"| {row['n']} | {row['pdet_sim']:.3f} | {row['pdet_closed_form']:.3f} |")
    lines += [
        "",
        "Reused URL (m >= 2): Pdet = " +
        ", ".join(f"m={row['m']}:{row['pdet_sim']:.4f}" for row in result["reused_url"]) +
        " (theory: 1.0000 in every cell)",
        "",
    ]
    return "\n".join(lines)


__all__ = [
    "PAPER_TABLE_III",
    "STRATEGIES",
    "DistinctForgedResult",
    "Proportion",
    "ReusedUrlResult",
    "SimParams",
    "SingleUseCloneResult",
    "closed_form_distinct_forged",
    "closed_form_single_use_clone",
    "format_table_iii_markdown",
    "run_table_iii",
    "simulate_distinct_forged",
    "simulate_reused_url",
    "simulate_single_use_clone",
    "write_table_iii_csv",
]
