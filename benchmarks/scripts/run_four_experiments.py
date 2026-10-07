#!/usr/bin/env python3
"""The four quantitative experiments from the handoff
(NFC_System_Quantitative_Attack_Test_Handoff).

    exp1  request-rate / latency saturation      (open-loop RPS sweep)
    exp2  request-rate / error behavior           (ANALYSIS of exp1's raw CSV —
                                                    no network traffic of its own,
                                                    per the handoff's efficiency rule)
    exp3  database growth / verification scaling  (enrol synthetic records at
                                                    increasing DB-size tiers, then
                                                    measure verify latency)
    exp4  replay-storm / repeated-request attack   (scale A3 from one replay to
                                                    many, across independent trials)

Every experiment is isolated to ONE test/staging deployment via TEST_BASE_URL
and writes raw, per-request CSV rows plus a per-tier summary CSV — nothing is
dropped, nothing is averaged away before being saved (handoff §5, §12).

    NEVER POINT THIS AT PRODUCTION.

Examples (run from the repo root; backend/requirements-dev.txt must be
installed):

    export TEST_BASE_URL=https://your-staging-host
    export TEST_ADMIN_TOKEN=...          # exp3, exp4 only (they enrol records)
    export TEST_FIELD_RECIPIENT_PUB=...  # exp3, exp4 only
    export TEST_DEVICE_PRIVATE_KEY=...   # exp3, exp4 only, must be registered
    export TEST_WORKER_COUNT=2           # record it — rate-limit results are
                                          # meaningless without it (§17.3)

    # Baseline sanity check FIRST (the handoff's non-negotiable gate):
    cd backend && python -m pytest tests/attacks/test_class_a_tag.py -k "test_a3 or test_a4" -v -rs

    # Experiment 1 — needs one already-enrolled record to verify repeatedly.
    # Point it at ANY known-good (uid, counter, token) on the staging deployment,
    # or let --self-enrol create one (needs the exp3/exp4 env vars too).
    python benchmarks/scripts/run_four_experiments.py exp1 \\
        --rps 1 2 5 10 20 40 80 --warmup-s 10 --measure-s 30 --cooldown-s 10 \\
        --repetitions 3 --self-enrol

    # Experiment 2 — pure analysis, no new traffic:
    python benchmarks/scripts/run_four_experiments.py exp2 \\
        --from-exp1-raw benchmarks/raw/exp1_request_latency.csv

    # Experiment 3 — needs enrolment env vars:
    python benchmarks/scripts/run_four_experiments.py exp3 \\
        --tiers 1000 5000 10000 25000 --measured-requests 30

    # Experiment 4:
    python benchmarks/scripts/run_four_experiments.py exp4 \\
        --replay-counts 1 5 10 50 100 500 1000 --trials-per-n 5
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = REPO_ROOT / "benchmarks"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402
from common import (  # noqa: E402
    BenchConfig,
    ConfigError,
    RawEvidenceWriter,
    RequestResult,
    close_batch,
    enrol,
    get_batch_enrolled_count,
    iso_now,
    make_tag_payload,
    new_run_id,
    open_batch,
    summarise,
    timed_verify,
)

log = logging.getLogger("run_four_experiments")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ============================================================ MANIFEST ===== #

def write_run_manifest(extra: dict) -> None:
    """Appends/refreshes benchmarks/run_manifest.json — handoff §10.3. Not a
    template filled in by hand: every run merges its own record in, so the
    manifest always reflects what was actually executed."""
    import platform
    import shutil
    import subprocess

    path = BENCH_DIR / "run_manifest.json"
    manifest = {"runs": []}
    if path.exists():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("run_manifest.json was not valid JSON — starting a new one")

    git = shutil.which("git")
    try:
        commit = (subprocess.check_output(  # noqa: S603
            [git, "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
            if git else "unknown")
    except Exception:
        commit = "unknown"

    entry = {
        "recorded_at_utc": iso_now(),
        "commit": commit,
        "python": platform.python_version(),
        "platform": platform.platform(),
        **extra,
    }
    manifest.setdefault("runs", []).append(entry)
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    log.info("updated %s", path)


# =============================================================== EXP 1 ===== #
# Open-loop RPS scheduler: requests are paced against wall-clock time, not
# fired back-to-back. Each scheduled tick submits a request without waiting
# for the previous one's response.

def _open_loop_tier(session: requests.Session, cfg: BenchConfig, *,
                    rps: float, duration_s: float, run_id: str, rep: int,
                    uid: str, counter_start: int, token_hex: str,
                    writer: RawEvidenceWriter, is_warmup: bool) -> list[RequestResult]:
    from concurrent.futures import ThreadPoolExecutor

    interval = 1.0 / rps
    n_requests = int(duration_s * rps)
    results: list[RequestResult] = []
    max_workers = min(64, max(4, int(rps * 2)))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = []
        t_start = time.perf_counter()
        for seq in range(n_requests):
            target_time = t_start + seq * interval
            now = time.perf_counter()
            if target_time > now:
                time.sleep(target_time - now)
            # Verify an ALREADY-accepted counter repeatedly (counter_start -
            # 1) — exp1/exp2 are about server load under a VALID verification
            # path (handoff §6.1 "the request itself should be valid"), not
            # about the counter machinery, so this intentionally reproduces
            # the EVR-absorbed repeat path (Sec. V-D) rather than tripping
            # suspect_duplicate on every request, which would confound
            # latency with incident-write overhead.
            futures.append(pool.submit(
                timed_verify, session, cfg, experiment_id="exp1", run_id=run_id,
                sequence_number=seq, uid=uid, counter=counter_start, token_hex=token_hex,
                tier_value=f"{rps}"))
        for fut in futures:
            result = fut.result()
            if not is_warmup:
                writer.write(result, target_env=cfg.base_url)
                results.append(result)
    return results


def cmd_exp1(args: argparse.Namespace) -> None:
    cfg = BenchConfig.from_env(need_admin=args.self_enrol, need_field_recipient=args.self_enrol)
    session = requests.Session()
    run_id = new_run_id()

    if args.self_enrol:
        batch = open_batch(session, cfg, quota=10, batch_ref_prefix="EXP1")
        payload, uid, token_hex = make_tag_payload(cfg, batch["batch_ref"], batch["mfg_date"])
        resp = enrol(session, cfg, payload)
        resp.raise_for_status()
        counter = 7
        first = timed_verify(session, cfg, experiment_id="exp1-setup", run_id=run_id,
                             sequence_number=0, uid=uid, counter=counter, token_hex=token_hex)
        assert first.logical_verdict == "authentic", (
            f"exp1 setup verification did not come back authentic: {first}")
        log.info("exp1: self-enrolled a fresh record, baseline verify OK")
    else:
        if not (args.uid and args.token and args.counter is not None):
            raise SystemExit(
                "exp1 needs --uid/--token/--counter for an already-enrolled "
                "record, or --self-enrol to create one (needs admin env vars)")
        uid, token_hex, counter = args.uid, args.token, args.counter

    raw_path = BENCH_DIR / "raw" / "exp1_request_latency.csv"
    summary_path = BENCH_DIR / "summaries" / "exp1_summary.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_rows = []

    with RawEvidenceWriter(raw_path) as writer:
        for rps in args.rps:
            tier_runs = []
            for rep in range(1, args.repetitions + 1):
                log.info("exp1: RPS=%s rep=%d/%d — warmup %ss", rps, rep,
                        args.repetitions, args.warmup_s)
                _open_loop_tier(session, cfg, rps=rps, duration_s=args.warmup_s,
                                run_id=run_id, rep=rep, uid=uid, counter_start=counter,
                                token_hex=token_hex, writer=writer, is_warmup=True)

                log.info("exp1: RPS=%s rep=%d/%d — measuring %ss", rps, rep,
                        args.repetitions, args.measure_s)
                t0 = time.perf_counter()
                results = _open_loop_tier(
                    session, cfg, rps=rps, duration_s=args.measure_s, run_id=run_id,
                    rep=rep, uid=uid, counter_start=counter, token_hex=token_hex,
                    writer=writer, is_warmup=False)
                wall_elapsed = time.perf_counter() - t0
                achieved_rps = len(results) / wall_elapsed if wall_elapsed else 0.0

                stats = summarise(results)
                stats.update({"experiment_id": "exp1", "run_id": run_id,
                             "tier_value": rps, "repetition": rep,
                             "achieved_rps": achieved_rps})
                summary_rows.append(stats)
                tier_runs.append(stats)

                unhealthy = stats["server_5xx_pct"] + stats["timeout_pct"]
                log.info("exp1: RPS=%s rep=%d -> p50=%.1fms p95=%.1fms p99=%.1fms "
                        "success=%.1f%% 429=%.1f%% 5xx+timeout=%.1f%%",
                        rps, rep, stats["p50_ms"], stats["p95_ms"], stats["p99_ms"],
                        stats["success_pct"], stats["rate_limit_pct"], unhealthy)

                log.info("exp1: cooling down %ss", args.cooldown_s)
                time.sleep(args.cooldown_s)

                if unhealthy > args.unhealthy_threshold_pct and not args.ignore_unhealthy:
                    log.warning(
                        "exp1: RPS=%s crossed the %.1f%% 5xx+timeout threshold "
                        "(%.1f%%) — stopping the sweep here per the handoff's "
                        "'do not intentionally destabilise the host' rule. "
                        "This tier IS the saturation region, not a bug.",
                        rps, args.unhealthy_threshold_pct, unhealthy)
                    _write_exp1_summary(summary_path, summary_rows)
                    write_run_manifest({"experiment": "exp1", "stopped_early": True,
                                        "stop_reason": f"5xx+timeout {unhealthy:.1f}% "
                                                       f"at RPS={rps}",
                                        "tiers_completed": [r["tier_value"]
                                                            for r in summary_rows]})
                    return

    _write_exp1_summary(summary_path, summary_rows)
    write_run_manifest({"experiment": "exp1", "rps_tiers": list(args.rps),
                        "warmup_s": args.warmup_s, "measure_s": args.measure_s,
                        "cooldown_s": args.cooldown_s, "repetitions": args.repetitions,
                        "stopped_early": False})
    log.info("exp1: done. raw=%s summary=%s", raw_path, summary_path)


def _write_exp1_summary(path: Path, rows: list[dict]) -> None:
    fieldnames = ["experiment_id", "run_id", "tier_value", "repetition", "request_count",
                 "achieved_rps", "p50_ms", "p95_ms", "p99_ms", "success_pct",
                 "rate_limit_pct", "other_4xx_pct", "server_5xx_pct", "timeout_pct"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


# =============================================================== EXP 2 ===== #
# Pure analysis of exp1's raw CSV. No network traffic — "Prefer to reuse the
# raw dataset from Experiment 1" (handoff §7.1).

def cmd_exp2(args: argparse.Namespace) -> None:
    src = Path(args.from_exp1_raw)
    if not src.exists():
        raise SystemExit(f"{src} does not exist — run exp1 first")

    by_tier: dict[str, list[dict]] = {}
    with src.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            by_tier.setdefault(row["tier_value"], []).append(row)

    out_raw = BENCH_DIR / "raw" / "exp2_error_behavior.csv"
    out_summary = BENCH_DIR / "summaries" / "exp2_summary.csv"
    out_raw.parent.mkdir(parents=True, exist_ok=True)
    out_summary.parent.mkdir(parents=True, exist_ok=True)

    # The raw file is the same per-request data, relabelled experiment_id —
    # exp2 adds no new fields exp1 didn't already record (handoff §5 says to
    # record logical_verdict alongside, not instead of, the HTTP class).
    with out_raw.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = list(next(iter(by_tier.values()))[0].keys()) if by_tier else []
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rows in by_tier.values():
            for row in rows:
                row = dict(row)
                row["experiment_id"] = "exp2"
                writer.writerow(row)

    summary_fields = ["tier_value", "request_count", "success_pct", "rate_limit_pct",
                      "other_4xx_pct", "server_5xx_pct", "timeout_pct",
                      "protection_vs_failure"]
    summary_rows = []
    for tier, rows in sorted(by_tier.items(), key=lambda kv: float(kv[0])):
        n = len(rows)
        counts = {"2xx": 0, "429": 0, "4xx_other": 0, "5xx": 0, "timeout": 0,
                 "transport_error": 0}
        for row in rows:
            counts[row["response_class"]] = counts.get(row["response_class"], 0) + 1
        server_fail_pct = 100.0 * (counts["5xx"] + counts["timeout"]
                                   + counts["transport_error"]) / n if n else 0.0
        summary_rows.append({
            "tier_value": tier, "request_count": n,
            "success_pct": 100.0 * counts["2xx"] / n if n else 0.0,
            "rate_limit_pct": 100.0 * counts["429"] / n if n else 0.0,
            "other_4xx_pct": 100.0 * counts["4xx_other"] / n if n else 0.0,
            "server_5xx_pct": 100.0 * counts["5xx"] / n if n else 0.0,
            "timeout_pct": 100.0 * (counts["timeout"] + counts["transport_error"]) / n
                          if n else 0.0,
            # §7.2 rule 4 — 429 is NOT a failure signal, kept in a separate column.
            "protection_vs_failure": ("protection (429-dominant)"
                                      if counts["429"] > counts["5xx"] + counts["timeout"]
                                      else "failure (5xx/timeout-dominant)"
                                      if server_fail_pct > args.threshold_pct else "healthy"),
        })

    with out_summary.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(summary_rows)

    first_unhealthy = next(
        (r["tier_value"] for r in summary_rows
         if r["server_5xx_pct"] + r["timeout_pct"] > args.threshold_pct), None)

    log.info("exp2: wrote %s and %s", out_raw, out_summary)
    log.info("exp2: first tier exceeding %.1f%% 5xx+timeout: %s",
            args.threshold_pct, first_unhealthy or "none observed")
    write_run_manifest({"experiment": "exp2", "source_raw": str(src),
                        "threshold_pct": args.threshold_pct,
                        "first_tier_over_threshold": first_unhealthy})


# =============================================================== EXP 3 ===== #

def cmd_exp3(args: argparse.Namespace) -> None:
    cfg = BenchConfig.from_env()
    session = requests.Session()
    run_id = new_run_id()
    raw_path = BENCH_DIR / "raw" / "exp3_db_scaling.csv"
    summary_path = BENCH_DIR / "summaries" / "exp3_summary.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    tiers = sorted(args.tiers)
    max_tier = tiers[-1]
    batch = open_batch(session, cfg, quota=max_tier + 10, batch_ref_prefix="EXP3")
    batch_ref, mfg_date = batch["batch_ref"], batch["mfg_date"]
    log.info("exp3: opened batch %s with quota %d", batch_ref, max_tier + 10)

    # One fixed record, enrolled first, verified at every tier so the
    # independent variable is DB size, not WHICH record is being looked up
    # (handoff §8.2 step 2/4).
    fixed_payload, fixed_uid, fixed_token = make_tag_payload(
        cfg, batch_ref, mfg_date, product_id="EXP3-FIXED-PROBE")
    enrol(session, cfg, fixed_payload).raise_for_status()
    fixed_counter = 7
    probe = timed_verify(session, cfg, experiment_id="exp3-setup", run_id=run_id,
                         sequence_number=0, uid=fixed_uid, counter=fixed_counter,
                         token_hex=fixed_token)
    assert probe.logical_verdict == "authentic", f"exp3 fixed-probe setup failed: {probe}"

    enrolled_so_far = 1
    summary_rows = []

    with RawEvidenceWriter(raw_path) as writer:
        for tier in tiers:
            need = tier - enrolled_so_far
            if need > 0:
                log.info("exp3: enrolling %d more records to reach tier=%d "
                        "(%d already in batch)", need, tier, enrolled_so_far)
                from concurrent.futures import ThreadPoolExecutor

                def _one_enrol(i, tier=tier):
                    p, _, _ = make_tag_payload(cfg, batch_ref, mfg_date,
                                               product_id=f"EXP3-FILL-{tier}-{i}")
                    resp = enrol(session, cfg, p)
                    return resp.status_code

                with ThreadPoolExecutor(max_workers=args.enrol_concurrency) as pool:
                    statuses = list(pool.map(_one_enrol, range(need)))
                failures = [s for s in statuses if s != 201]
                if failures:
                    log.warning("exp3: %d/%d fill enrolments at tier=%d did not "
                               "return 201 (status codes: %s)", len(failures),
                               need, tier, sorted(set(failures)))
                enrolled_so_far = tier

            confirmed = get_batch_enrolled_count(session, cfg, batch_ref)
            log.info("exp3: tier=%d requested, batch reports enrolled_count=%d",
                    tier, confirmed)

            # Warm-up against the fixed probe record.
            for seq in range(args.warmup_requests):
                timed_verify(session, cfg, experiment_id="exp3-warmup", run_id=run_id,
                            sequence_number=seq, uid=fixed_uid, counter=fixed_counter,
                            token_hex=fixed_token, tier_value=tier)

            results = []
            for seq in range(args.measured_requests):
                result = timed_verify(session, cfg, experiment_id="exp3", run_id=run_id,
                                      sequence_number=seq, uid=fixed_uid,
                                      counter=fixed_counter, token_hex=fixed_token,
                                      tier_value=tier)
                writer.write(result, target_env=cfg.base_url)
                results.append(result)
                time.sleep(args.inter_request_delay_s)  # fixed low concurrency (1 client)

            stats = summarise(results)
            stats.update({"experiment_id": "exp3", "run_id": run_id, "tier_value": tier,
                         "db_row_count_confirmed": confirmed})
            summary_rows.append(stats)
            log.info("exp3: tier=%d -> p50=%.1fms p95=%.1fms p99=%.1fms",
                    tier, stats["p50_ms"], stats["p95_ms"], stats["p99_ms"])

    fieldnames = ["experiment_id", "run_id", "tier_value", "db_row_count_confirmed",
                 "request_count", "p50_ms", "p95_ms", "p99_ms", "success_pct",
                 "rate_limit_pct", "other_4xx_pct", "server_5xx_pct", "timeout_pct"]
    with summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary_rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    if args.cleanup:
        log.info("exp3: closing benchmark batch %s", batch_ref)
        close_batch(session, cfg, batch_ref)

    log.info("exp3: done. raw=%s summary=%s", raw_path, summary_path)
    write_run_manifest({"experiment": "exp3", "tiers": tiers, "batch_ref": batch_ref,
                        "measured_requests_per_tier": args.measured_requests,
                        "cleaned_up": args.cleanup})


# =============================================================== EXP 4 ===== #

def cmd_exp4(args: argparse.Namespace) -> None:
    cfg = BenchConfig.from_env()
    session = requests.Session()
    run_id = new_run_id()
    raw_path = BENCH_DIR / "raw" / "exp4_replay_storm.csv"
    summary_path = BENCH_DIR / "summaries" / "exp4_summary.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    batch = open_batch(session, cfg, quota=len(args.replay_counts) * args.trials_per_n + 10,
                       batch_ref_prefix="EXP4")
    batch_ref, mfg_date = batch["batch_ref"], batch["mfg_date"]

    summary_rows = []
    with RawEvidenceWriter(raw_path) as writer:
        for n in args.replay_counts:
            detected_trials = 0
            first_detect_attempts = []
            for trial in range(1, args.trials_per_n + 1):
                # Fresh synthetic record per independent trial (handoff §9.2
                # step 1) — never reuse a dirty record across trials.
                payload, uid, token_hex = make_tag_payload(
                    cfg, batch_ref, mfg_date, product_id=f"EXP4-N{n}-T{trial}")
                enrol(session, cfg, payload).raise_for_status()

                baseline_counter = 7
                baseline = timed_verify(
                    session, cfg, experiment_id="exp4", run_id=run_id, sequence_number=0,
                    uid=uid, counter=baseline_counter, token_hex=token_hex,
                    tier_value=f"n={n}")
                writer.write(baseline, target_env=cfg.base_url)
                assert baseline.logical_verdict == "authentic", (
                    f"exp4 n={n} trial={trial}: baseline verification was not "
                    f"authentic ({baseline.logical_verdict}) — environment is "
                    f"not in the state this experiment needs")

                first_detected_at = None
                for attempt in range(1, n + 1):
                    result = timed_verify(
                        session, cfg, experiment_id="exp4", run_id=run_id,
                        sequence_number=attempt, uid=uid, counter=baseline_counter,
                        token_hex=token_hex, tier_value=f"n={n}")
                    writer.write(result, target_env=cfg.base_url)
                    if (result.logical_verdict == "suspect_duplicate"
                            and first_detected_at is None):
                        first_detected_at = attempt
                        # Sticky by design — the handoff explicitly says not to
                        # clear it inside a trial, so we keep replaying rather
                        # than stopping, to also observe "do later replays stay
                        # flagged" (handoff §9.2 step 8).

                if first_detected_at is not None:
                    detected_trials += 1
                    first_detect_attempts.append(first_detected_at)

                log.info("exp4: n=%d trial=%d/%d first_detected_at=%s", n, trial,
                        args.trials_per_n, first_detected_at)

            detection_rate = detected_trials / args.trials_per_n if args.trials_per_n else 0.0
            summary_rows.append({
                "experiment_id": "exp4", "run_id": run_id, "tier_value": n,
                "trials": args.trials_per_n, "detected_trials": detected_trials,
                "detection_rate": detection_rate,
                "min_first_detect_attempt": min(first_detect_attempts)
                                            if first_detect_attempts else "",
                "median_first_detect_attempt": (sorted(first_detect_attempts)
                                                [len(first_detect_attempts) // 2]
                                                if first_detect_attempts else ""),
            })
            log.info("exp4: n=%d detection_rate=%.2f (%d/%d)", n, detection_rate,
                    detected_trials, args.trials_per_n)

    fieldnames = ["experiment_id", "run_id", "tier_value", "trials", "detected_trials",
                 "detection_rate", "min_first_detect_attempt", "median_first_detect_attempt"]
    with summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    if args.cleanup:
        close_batch(session, cfg, batch_ref)

    log.info("exp4: done. raw=%s summary=%s", raw_path, summary_path)
    write_run_manifest({"experiment": "exp4", "replay_counts": args.replay_counts,
                        "trials_per_n": args.trials_per_n, "batch_ref": batch_ref,
                        "cleaned_up": args.cleanup})


# ================================================================== CLI ===== #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("exp1", help="request-rate vs latency saturation")
    p1.add_argument("--rps", type=float, nargs="+", default=[1, 2, 5, 10, 20, 40, 80])
    p1.add_argument("--warmup-s", type=float, default=10.0)
    p1.add_argument("--measure-s", type=float, default=30.0)
    p1.add_argument("--cooldown-s", type=float, default=12.0)
    p1.add_argument("--repetitions", type=int, default=3)
    p1.add_argument("--unhealthy-threshold-pct", type=float, default=1.0)
    p1.add_argument("--ignore-unhealthy", action="store_true",
                    help="keep sweeping past the stopping criterion (debugging only)")
    p1.add_argument("--self-enrol", action="store_true",
                    help="enrol a fresh record to verify against (needs admin env vars)")
    p1.add_argument("--uid", help="an already-enrolled tag UID, if not --self-enrol")
    p1.add_argument("--token", help="that tag's binding token hex")
    p1.add_argument("--counter", type=int, help="an already-accepted counter for it")
    p1.set_defaults(func=cmd_exp1)

    p2 = sub.add_parser("exp2", help="request-rate vs error behavior (analysis only)")
    p2.add_argument("--from-exp1-raw", default=str(BENCH_DIR / "raw" / "exp1_request_latency.csv"))
    p2.add_argument("--threshold-pct", type=float, default=1.0,
                    help="5xx+timeout threshold that defines 'first unhealthy tier'")
    p2.set_defaults(func=cmd_exp2)

    p3 = sub.add_parser("exp3", help="database growth vs verification latency")
    p3.add_argument("--tiers", type=int, nargs="+", default=[1000, 5000, 10000, 25000])
    p3.add_argument("--measured-requests", type=int, default=30)
    p3.add_argument("--warmup-requests", type=int, default=5)
    p3.add_argument("--inter-request-delay-s", type=float, default=0.05,
                    help="keeps concurrency at ~1 client, per handoff §8.2 step 5")
    p3.add_argument("--enrol-concurrency", type=int, default=8)
    p3.add_argument("--cleanup", action="store_true", default=True)
    p3.add_argument("--no-cleanup", dest="cleanup", action="store_false")
    p3.set_defaults(func=cmd_exp3)

    p4 = sub.add_parser("exp4", help="replay-storm / repeated-request detection")
    p4.add_argument("--replay-counts", type=int, nargs="+",
                    default=[1, 5, 10, 50, 100, 500, 1000])
    p4.add_argument("--trials-per-n", type=int, default=5)
    p4.add_argument("--cleanup", action="store_true", default=True)
    p4.add_argument("--no-cleanup", dest="cleanup", action="store_false")
    p4.set_defaults(func=cmd_exp4)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except ConfigError as exc:
        log.error(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
