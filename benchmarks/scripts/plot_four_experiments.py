#!/usr/bin/env python3
"""Regenerates every figure from the saved raw/summary CSVs — handoff §6.4,
§11, §14. Never plots anything that wasn't written to disk first, so every
point on every figure is auditable back to a raw CSV row.

Usage (from the repo root, after running run_four_experiments.py):

    python benchmarks/scripts/plot_four_experiments.py

Requires matplotlib (not in requirements-dev.txt — this is a report-generation
tool, not a test dependency):

    pip install matplotlib
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parents[1]

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib is required: pip install matplotlib", file=sys.stderr)
    raise SystemExit(1) from None

DPI = 300


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        print(f"skip: {path} does not exist (run that experiment first)", file=sys.stderr)
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _f(row: dict, key: str, default: float = float("nan")) -> float:
    value = row.get(key, "")
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# =============================================================== FIG 1 ===== #
# RPS vs p50/p95/p99 latency.

def plot_fig1(out_dir: Path) -> None:
    rows = _read_csv(BENCH_DIR / "summaries" / "exp1_summary.csv")
    if not rows:
        return
    by_tier: dict[float, list[dict]] = {}
    for row in rows:
        by_tier.setdefault(_f(row, "tier_value"), []).append(row)

    tiers = sorted(by_tier)
    p50 = [sum(_f(r, "p50_ms") for r in by_tier[t]) / len(by_tier[t]) for t in tiers]
    p95 = [sum(_f(r, "p95_ms") for r in by_tier[t]) / len(by_tier[t]) for t in tiers]
    p99 = [sum(_f(r, "p99_ms") for r in by_tier[t]) / len(by_tier[t]) for t in tiers]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(tiers, p50, marker="o", label="p50")
    ax.plot(tiers, p95, marker="s", label="p95")
    ax.plot(tiers, p99, marker="^", label="p99")
    ax.set_xlabel("Request rate (RPS)")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Fig. 1 — Request rate vs latency")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    path = out_dir / "fig1_request_rate_vs_latency.png"
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"wrote {path}")


# =============================================================== FIG 2 ===== #
# RPS vs response percentage breakdown.

def plot_fig2(out_dir: Path) -> None:
    rows = _read_csv(BENCH_DIR / "summaries" / "exp2_summary.csv")
    if not rows:
        return
    rows = sorted(rows, key=lambda r: _f(r, "tier_value"))
    tiers = [_f(r, "tier_value") for r in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    ax1.plot(tiers, [_f(r, "success_pct") for r in rows], marker="o", label="2xx success")
    ax1.plot(tiers, [_f(r, "rate_limit_pct") for r in rows], marker="s",
             label="429 (rate limited)")
    ax1.plot(tiers, [_f(r, "other_4xx_pct") for r in rows], marker="d", label="other 4xx")
    ax1.plot(tiers, [_f(r, "server_5xx_pct") for r in rows], marker="^",
             label="5xx (server failure)", color="red")
    ax1.plot(tiers, [_f(r, "timeout_pct") for r in rows], marker="x",
             label="timeout/transport", color="darkred")
    ax1.set_xlabel("Request rate (RPS)")
    ax1.set_ylabel("Response share (%)")
    ax1.set_title("Fig. 2a — Response-code distribution")
    ax1.legend(fontsize=8)
    ax1.grid(True, alpha=0.3)

    throughput_rows = _read_csv(BENCH_DIR / "summaries" / "exp1_summary.csv")
    if throughput_rows:
        by_tier: dict[float, list[dict]] = {}
        for row in throughput_rows:
            by_tier.setdefault(_f(row, "tier_value"), []).append(row)
        t_tiers = sorted(by_tier)
        achieved = [sum(_f(r, "achieved_rps") for r in by_tier[t]) / len(by_tier[t])
                   for t in t_tiers]
        ax2.plot(t_tiers, t_tiers, "--", color="gray", label="ideal (achieved == requested)")
        ax2.plot(t_tiers, achieved, marker="o", label="achieved RPS")
        ax2.set_xlabel("Requested rate (RPS)")
        ax2.set_ylabel("Achieved throughput (RPS)")
        ax2.set_title("Fig. 2b — Achieved throughput")
        ax2.legend()
        ax2.grid(True, alpha=0.3)
    else:
        ax2.axis("off")
        ax2.text(0.5, 0.5, "run exp1 for throughput data", ha="center", va="center")

    fig.tight_layout()
    path = out_dir / "fig2_request_rate_vs_errors.png"
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"wrote {path}")


# =============================================================== FIG 3 ===== #
# DB record count vs p95 (and p50) verification latency.

def plot_fig3(out_dir: Path) -> None:
    rows = _read_csv(BENCH_DIR / "summaries" / "exp3_summary.csv")
    if not rows:
        return
    rows = sorted(rows, key=lambda r: _f(r, "tier_value"))
    sizes = [_f(r, "db_row_count_confirmed") or _f(r, "tier_value") for r in rows]
    p50 = [_f(r, "p50_ms") for r in rows]
    p95 = [_f(r, "p95_ms") for r in rows]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(sizes, p95, marker="o", label="p95", color="firebrick")
    ax.plot(sizes, p50, marker="s", label="p50", color="steelblue")
    ax.set_xscale("log")
    ax.set_xlabel("Database record count (log scale)")
    ax.set_ylabel("Verification latency (ms)")
    ax.set_title("Fig. 3 — Database size vs verification latency")
    ax.legend()
    ax.grid(True, alpha=0.3, which="both")
    fig.tight_layout()
    path = out_dir / "fig3_db_size_vs_latency.png"
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"wrote {path}")


# =============================================================== FIG 4 ===== #
# Replay attempt number vs detection state / probability.

def plot_fig4(out_dir: Path) -> None:
    raw_rows = _read_csv(BENCH_DIR / "raw" / "exp4_replay_storm.csv")
    summary_rows = _read_csv(BENCH_DIR / "summaries" / "exp4_summary.csv")
    if not raw_rows and not summary_rows:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    if summary_rows:
        summary_rows = sorted(summary_rows, key=lambda r: _f(r, "tier_value"))
        ns = [_f(r, "tier_value") for r in summary_rows]
        rates = [_f(r, "detection_rate") for r in summary_rows]
        ax1.plot(ns, rates, marker="o", color="darkgreen")
        ax1.set_xscale("log")
        ax1.set_ylim(-0.05, 1.05)
        ax1.set_xlabel("Replay count N (log scale)")
        ax1.set_ylabel("Detection probability across trials")
        ax1.set_title("Fig. 4a — Replay count vs detection rate")
        ax1.grid(True, alpha=0.3, which="both")
    else:
        ax1.axis("off")

    if raw_rows:
        detected_latencies, flagged_latencies = [], []
        for row in raw_rows:
            latency = _f(row, "elapsed_ms")
            if row.get("logical_verdict") == "suspect_duplicate":
                flagged_latencies.append(latency)
            elif row.get("logical_verdict") == "authentic":
                detected_latencies.append(latency)
        if detected_latencies:
            ax2.hist(detected_latencies, bins=30, alpha=0.6, label="authentic",
                     color="steelblue")
        if flagged_latencies:
            ax2.hist(flagged_latencies, bins=30, alpha=0.6, label="suspect_duplicate",
                     color="firebrick")
        ax2.set_xlabel("Response latency (ms)")
        ax2.set_ylabel("Request count")
        ax2.set_title("Fig. 4b — Latency by verdict")
        ax2.legend()
        ax2.grid(True, alpha=0.3)
    else:
        ax2.axis("off")

    fig.tight_layout()
    path = out_dir / "fig4_replay_attempts_vs_detection.png"
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"wrote {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, default=BENCH_DIR / "figures")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    plot_fig1(args.out_dir)
    plot_fig2(args.out_dir)
    plot_fig3(args.out_dir)
    plot_fig4(args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
