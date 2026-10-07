#!/usr/bin/env python3
"""Standalone reproduction of paper Table III. No server, no database, no
hardware — this drives services/verification.decide() directly (see
clone_detection_mc.py's module docstring for why that is a legitimate,
faithful way to validate the paper's detection-probability claims).

Usage (from backend/):

    python tests/simulation/reproduce_table_iii.py
    python tests/simulation/reproduce_table_iii.py --trials 100000 --seed 42
    python tests/simulation/reproduce_table_iii.py --out-dir tests/evidence

With no arguments this runs the paper's own trial count (10^5 per cell),
which takes roughly 30-60s on a laptop, and writes:

    <out-dir>/montecarlo_table_iii.csv        -- one row per simulated cell
    <out-dir>/montecarlo_table_iii.md         -- paper-ready Markdown table

and prints the Markdown table to stdout.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/tests/
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # backend/

from simulation.clone_detection_mc import (
    SimParams,
    format_table_iii_markdown,
    run_table_iii,
    write_table_iii_csv,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=100_000,
                        help="trials per cell (paper used 10^5; default: 100000)")
    parser.add_argument("--seed", type=int, default=20260914,
                        help="RNG seed, for a reproducible run (default: 20260914)")
    parser.add_argument("--out-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "evidence",
                        help="where to write the CSV/Markdown (default: tests/evidence)")
    parser.add_argument("--enrol-counter", type=int, default=3, dest="enrol_counter")
    parser.add_argument("--pack-age-days", type=int, default=30, dest="pack_age_days")
    args = parser.parse_args()

    params = SimParams(enrol_counter=args.enrol_counter, pack_age_days=args.pack_age_days)

    print(f"Running {args.trials} trials/cell (seed={args.seed}) ... "
         "this drives the real services.verification.decide(), no server needed",
         file=sys.stderr)
    t0 = time.perf_counter()
    result = run_table_iii(trials=args.trials, seed=args.seed, params=params)
    elapsed = time.perf_counter() - t0
    print(f"done in {elapsed:.1f}s", file=sys.stderr)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "montecarlo_table_iii.csv"
    md_path = args.out_dir / "montecarlo_table_iii.md"
    write_table_iii_csv(result, csv_path)
    markdown = format_table_iii_markdown(result)
    md_path.write_text(markdown, encoding="utf-8")

    print(markdown)
    print(f"\nwrote {csv_path}", file=sys.stderr)
    print(f"wrote {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
