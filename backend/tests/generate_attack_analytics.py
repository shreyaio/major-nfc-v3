#!/usr/bin/env python3
"""Compute the five quantitative analytics from an attack-suite evidence run.

    python tests/generate_attack_analytics.py --evidence-dir tests/evidence

Writes `analytics_summary.json` next to the evidence and prints a Markdown
summary to stdout. Both are inputs to the paper's results section; the point of
the exercise is to replace narrated outcomes ("returned 403") with figures.

## Which evidence format this reads

The §16 suite (classes A–H) emits one JSONL row per attack ID:

    {"attack_id", "outcome", "expected", "detail", "recorded_at",
     "target", "worker_count"}

This is NOT the v1 seven-category format, which had a per-category file
(`injection.jsonl`, `birthday.jsonl`, ...) and a `passed` boolean per row. v1's
files were removed in 7e06ce2 along with the suite that wrote them. Rows in the
old shape are counted and reported as skipped rather than silently averaged in
with the new ones, because the two disagree about what a row means: v1 logged
one row per *request*, this logs one row per *attack*.

## What "success rate" means here

v1 computed `passed` over every row. There is no `passed` field now, and the
replacement is deliberately not a single boolean, because `outcome` carries four
states and flattening them is how a known-open item turns into a green tick:

    blocked       the attack was stopped
    detected      it was not stopped, but it was caught and recorded
    open          known-open by design or constraint (§16.9)
    inconclusive  not honestly measurable from this runner

The headline malicious-success rate counts `blocked` and `detected` as defended
and reports `open` / `inconclusive` separately, next to the rate, rather than
inside it. A reader who wants the harsher number can compute it from the counts;
a reader who is handed only the harsher number cannot recover the breakdown.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

DEFENDED = {"blocked", "detected"}
KNOWN_OPEN = {"open"}
NOT_MEASURED = {"inconclusive"}

CLASS_NAMES = {
    "A": "Tag and physical layer",
    "B": "NDEF and URL layer",
    "C": "Client and browser layer",
    "D": "API and protocol layer",
    "E": "Cryptographic layer",
    "F": "Infrastructure and supply chain",
    "G": "Business logic and abuse",
    "H": "Forward-looking and quantum",
}

# The §16 matrix, one entry per attack id (tests/attacks/README.md). Used only
# to report which ids produced no evidence row; it is not a pass/fail gate.
EXPECTED_IDS = frozenset(
    [f"A{n}" for n in range(1, 15)]        # A1-A14
    + [f"B{n}" for n in range(1, 11)]      # B1-B10
    + [f"C{n}" for n in range(1, 11)]      # C1-C10
    + [f"D{n}" for n in range(1, 33)]      # D1-D32
    + [f"E{n}" for n in range(1, 14)]      # E1-E13
    + [f"F{n}a" for n in range(1, 11)]     # F1a-F10a
    + ["F2a-pins"]                         # supporting row, its own id
    + [f"G{n}" for n in range(1, 10)]      # G1-G9
    + [f"H{n}" for n in range(1, 7)]       # H1-H6
)


def _id_sort_key(attack_id: str):
    """Sort A2 before A10 — plain string order puts A10 first."""
    head = attack_id[0]
    digits = "".join(c for c in attack_id[1:] if c.isdigit())
    return (head, int(digits) if digits else 0, attack_id)


INJECTION_IDS = {"D25", "D26", "D27", "D28", "D29", "D30"}
FLOOD_IDS = {"D31", "D32"}


# ------------------------------------------------------------------ loading ---

def load_rows(evidence_dir: Path) -> tuple[list[dict], dict]:
    """Return (rows, provenance). Provenance records what was read, so a figure
    can always be traced back to the files behind it."""
    files = sorted(evidence_dir.glob("attacks-*.jsonl"))
    if not files:
        sys.exit(f"no attacks-*.jsonl found in {evidence_dir}")

    rows: list[dict] = []
    legacy = 0
    malformed = 0
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if "attack_id" not in row or "outcome" not in row:
                legacy += 1          # v1-shaped row; see the module docstring
                continue
            row["_source_file"] = path.name
            rows.append(row)

    # Append-only logging means a stale file silently mixes runs. Say so loudly
    # rather than averaging two runs into one number.
    seen = Counter(r["attack_id"] for r in rows)
    duplicated = sorted(aid for aid, n in seen.items() if n > 1)

    # A test that fails BEFORE its evidence() call writes no row at all, so the
    # id vanishes from the denominator and "0 of N attacks succeeded" silently
    # excludes it. §16.9 requires a known-open to stay visible rather than be
    # curated away; an attack that did not report is the same problem wearing a
    # different hat. Compare against the §16 matrix and name the absent ones.
    missing = sorted(EXPECTED_IDS - set(seen), key=_id_sort_key)

    provenance = {
        "evidence_dir": str(evidence_dir),
        "files": [p.name for p in files],
        "file_count": len(files),
        "rows_loaded": len(rows),
        "legacy_v1_rows_skipped": legacy,
        "malformed_lines_skipped": malformed,
        "duplicate_attack_ids": duplicated,
        "missing_attack_ids": missing,
        "expected_id_count": len(EXPECTED_IDS),
        "recorded_id_count": len(set(seen)),
        "targets": sorted({r.get("target", "") for r in rows if r.get("target")}),
        "worker_counts": sorted({str(r.get("worker_count", "unknown"))
                                 for r in rows}),
    }
    return rows, provenance


def _class_of(attack_id: str) -> str:
    match = re.match(r"([A-H])", attack_id.upper())
    return match.group(1) if match else "?"


def _statuses(row: dict) -> Counter:
    """Every HTTP status this row observed.

    A single-request attack records `detail.status`. A flood records
    `detail.status_counts` as {status: n}. Both are folded into one counter so
    the aggregate distribution is per-REQUEST, not per-attack — otherwise a
    40-request flood would weigh the same as one signature check.
    """
    detail = row.get("detail") or {}
    counter: Counter = Counter()

    counts = detail.get("status_counts")
    if isinstance(counts, dict):
        for status, n in counts.items():
            try:
                counter[int(status)] += int(n)
            except (TypeError, ValueError):
                continue

    status = detail.get("status")
    if isinstance(status, int):
        counter[status] += 1

    return counter


# ---------------------------------------------------------------- analytics ---

def malicious_success_rate(rows: list[dict]) -> dict:
    """Analytic 1 — the headline number."""
    outcomes = Counter(r["outcome"] for r in rows)
    total = len(rows)
    defended = sum(outcomes[o] for o in DEFENDED)
    open_items = sum(outcomes[o] for o in KNOWN_OPEN)
    not_measured = sum(outcomes[o] for o in NOT_MEASURED)
    succeeded = total - defended - open_items - not_measured

    requests = sum(sum(_statuses(r).values()) for r in rows)
    # A malicious write that landed: any attack row reporting an accepted
    # enrolment. The flood cases record this explicitly.
    accepted = sum(int((r.get("detail") or {}).get("accepted", 0) or 0)
                   for r in rows)

    return {
        "attacks_total": total,
        "attacks_defended": defended,
        "attacks_succeeded": succeeded,
        "attacks_known_open": open_items,
        "attacks_not_measured": not_measured,
        "success_rate_pct": round(100 * succeeded / total, 3) if total else 0.0,
        "defended_rate_pct": round(100 * defended / total, 3) if total else 0.0,
        "requests_total": requests,
        "malicious_requests_accepted": accepted,
        "request_success_rate_pct": (round(100 * accepted / requests, 4)
                                     if requests else 0.0),
        "outcome_counts": dict(sorted(outcomes.items())),
    }


def status_distribution(rows: list[dict]) -> dict:
    """Analytic 2 — the aggregate HTTP status split across the whole run."""
    counter: Counter = Counter()
    for row in rows:
        counter.update(_statuses(row))
    total = sum(counter.values())
    return {
        "requests_total": total,
        "by_status": {
            str(status): {
                "count": n,
                "pct": round(100 * n / total, 2) if total else 0.0,
            }
            for status, n in sorted(counter.items())
        },
    }


def per_category(rows: list[dict]) -> dict:
    """Analytic 3 — the same fields, grouped by §16 class.

    This is what shows each class leaning on a different mechanism: D is where
    the 403s and the 409 live, the floods are the only place 429 does real work,
    and E/F/H are offline property checks that make no HTTP requests at all.
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[_class_of(row["attack_id"])].append(row)

    out = {}
    for letter in sorted(grouped):
        group = grouped[letter]
        counter: Counter = Counter()
        for row in group:
            counter.update(_statuses(row))
        outcomes = Counter(r["outcome"] for r in group)
        out[letter] = {
            "name": CLASS_NAMES.get(letter, "unknown"),
            "attacks": len(group),
            "attack_ids": sorted({r["attack_id"] for r in group}),
            "outcome_counts": dict(sorted(outcomes.items())),
            "requests": sum(counter.values()),
            "status_counts": {str(k): v for k, v in sorted(counter.items())},
        }
    return out


def injection_defense_layers(rows: list[dict]) -> dict:
    """Analytic 4 — edge vs app attribution for the injection payloads.

    The claim this supports is specific: most payloads never reach the
    application, and the one that does is neutralised by a parameterised query
    rather than by a filter. Without the per-payload layer, "the WAF caught it"
    and "the query was parameterised" are indistinguishable in the evidence.
    """
    relevant = [r for r in rows
                if r["attack_id"] in INJECTION_IDS
                or "defense_layer" in (r.get("detail") or {})]
    if not relevant:
        return {"available": False,
                "note": "no rows carried detail.defense_layer "
                        "(D25-D30 did not run)"}

    layers = Counter((r["detail"] or {}).get("defense_layer", "unrecorded")
                     for r in relevant)
    total = len(relevant)
    return {
        "available": True,
        "payloads_total": total,
        "by_layer": {
            layer: {"count": n, "pct": round(100 * n / total, 1)}
            for layer, n in sorted(layers.items())
        },
        "per_payload": sorted(
            ({
                "attack_id": r["attack_id"],
                "payload": (r["detail"] or {}).get("payload"),
                "status": (r["detail"] or {}).get("status"),
                "defense_layer": (r["detail"] or {}).get("defense_layer"),
            } for r in relevant),
            key=lambda d: d["attack_id"]),
    }


def birthday_validation(rows: list[dict]) -> dict:
    """Analytic 5 — the empirical validation, then the extrapolation."""
    by_id = {r["attack_id"]: (r.get("detail") or {}) for r in rows}
    empirical = by_id.get("E12")
    bounds = by_id.get("E13")
    if not empirical and not bounds:
        return {"available": False,
                "note": "E12/E13 did not run — no birthday evidence"}
    return {
        "available": True,
        "empirical": empirical or {"note": "E12 did not run"},
        "real_system_bounds": bounds or {"note": "E13 did not run"},
    }


# ------------------------------------------------------------------ output ----

def render_markdown(summary: dict) -> str:
    prov = summary["provenance"]
    rate = summary["malicious_success_rate"]
    dist = summary["status_distribution"]
    cats = summary["per_category"]
    inj = summary["injection_defense_layers"]
    bday = summary["birthday_validation"]

    lines: list[str] = []
    add = lines.append

    add("# Attack suite analytics")
    add("")
    add(f"Computed from {prov['file_count']} evidence file(s) in "
        f"`{prov['evidence_dir']}` — {prov['rows_loaded']} attack rows.")
    if prov["duplicate_attack_ids"]:
        add("")
        add(f"> **Warning — stale evidence.** These IDs appear more than once: "
            f"`{', '.join(prov['duplicate_attack_ids'])}`. Evidence logging is "
            f"append-only; clear the directory and re-run, or the figures below "
            f"mix two runs.")
    if prov.get("missing_attack_ids"):
        add("")
        add(f"> **Warning — incomplete coverage.** "
            f"{prov['recorded_id_count']} of {prov['expected_id_count']} §16 "
            f"attack ids produced an evidence row. No row was written for: "
            f"`{', '.join(prov['missing_attack_ids'])}`. A test that fails "
            f"before its `evidence()` call records nothing, so these are "
            f"EXCLUDED from every figure below, the success rate included. "
            f"Resolve them and re-run before citing these numbers.")
    if prov["legacy_v1_rows_skipped"]:
        add("")
        add(f"> {prov['legacy_v1_rows_skipped']} row(s) in the retired v1 format "
            f"were skipped (see the module docstring).")
    if prov["worker_counts"] == ["unknown"]:
        add("")
        add("> **Rate-limit figures are not defensible in this run.** "
            "`TEST_WORKER_COUNT` was not set, so any 429 count reflects a "
            "per-worker limit, not the configured one (§17.3, F16).")
    add("")

    add("## 1. Malicious success rate")
    add("")
    add(f"**{rate['attacks_succeeded']} / {rate['attacks_total']} attacks "
        f"succeeded ({rate['success_rate_pct']}%).**")
    add("")
    add(f"- Defended: {rate['attacks_defended']} "
        f"({rate['defended_rate_pct']}%)")
    add(f"- Known-open by design (§16.9): {rate['attacks_known_open']}")
    add(f"- Not measurable from this runner: {rate['attacks_not_measured']}")
    add(f"- Malicious requests sent: {rate['requests_total']}; "
        f"accepted: {rate['malicious_requests_accepted']} "
        f"({rate['request_success_rate_pct']}%)")
    add("")

    add("## 2. HTTP status distribution")
    add("")
    if dist["requests_total"]:
        add("| Status | Count | % of requests |")
        add("|---|---:|---:|")
        for status, info in dist["by_status"].items():
            add(f"| {status} | {info['count']} | {info['pct']}% |")
        add(f"| **Total** | **{dist['requests_total']}** | 100% |")
    else:
        add("No HTTP requests recorded — only offline property checks ran.")
    add("")

    add("## 3. Per-category breakdown")
    add("")
    add("| Class | Attacks | Requests | Status split | Outcomes |")
    add("|---|---:|---:|---|---|")
    for letter, info in cats.items():
        statuses = (", ".join(f"{k}×{v}" for k, v in info["status_counts"].items())
                    or "—")
        outcomes = ", ".join(f"{k}×{v}" for k, v in info["outcome_counts"].items())
        add(f"| {letter} — {info['name']} | {info['attacks']} | "
            f"{info['requests']} | {statuses} | {outcomes} |")
    add("")

    add("## 4. Injection defense-layer attribution")
    add("")
    if inj.get("available"):
        add(f"{inj['payloads_total']} payload(s):")
        add("")
        for layer, info in inj["by_layer"].items():
            add(f"- **{layer}**: {info['count']} ({info['pct']}%)")
        add("")
        add("| ID | Payload | Status | Stopped at |")
        add("|---|---|---:|---|")
        for row in inj["per_payload"]:
            add(f"| {row['attack_id']} | {row['payload']} | "
                f"{row['status']} | {row['defense_layer']} |")
    else:
        add(inj.get("note", "unavailable"))
    add("")

    add("## 5. Birthday-paradox validation")
    add("")
    if bday.get("available"):
        emp = bday["empirical"]
        if "empirical_mean_draws" in emp:
            add(f"Validated on a {emp.get('bits')}-bit space over "
                f"{emp.get('trials')} trials (seed `{emp.get('seed')}`):")
            add("")
            add(f"- Empirical mean draws to first collision: "
                f"**{emp['empirical_mean_draws']}** "
                f"(± {emp.get('std_error')} s.e.)")
            add(f"- Theoretical √(πN/2): **{emp['theoretical_mean_draws']}**")
            add(f"- Deviation: **{emp['deviation_pct']}%**")
            add("")
        spaces = (bday["real_system_bounds"] or {}).get("spaces")
        if spaces:
            add("Formula applied to the deployed key spaces:")
            add("")
            add("| Space | Bits | log₂ draws for p=1e-9 | log₂ draws for p=0.5 |")
            add("|---|---:|---:|---:|")
            for name, info in spaces.items():
                add(f"| {name} | {info['bits']} | "
                    f"{info.get('draws_for_1_in_1e9_log2')} | "
                    f"{info.get('draws_for_50pct_log2')} |")
            retired = (bday["real_system_bounds"] or {}).get(
                "v1_retired_write_nonce")
            if retired:
                add("")
                add(f"> The v1 paper extrapolated to a {retired['bits']}-bit "
                    f"write nonce (50% collision at 2^"
                    f"{retired.get('draws_for_50pct_log2')} draws). "
                    f"{retired.get('status')}")
    else:
        add(bday.get("note", "unavailable"))
    add("")

    return "\n".join(lines)


def _force_utf8_stdio() -> None:
    """Windows' default console codepage is cp1252, which cannot encode the §,
    ×, ± and √ in the summary — `print` raises UnicodeEncodeError and the real
    output is lost behind a traceback. This is the same failure mode that once
    masked every DB connection error in db.py; fix it at the stream rather than
    flattening the text.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main() -> int:
    _force_utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--evidence-dir", type=Path,
                        default=Path(__file__).resolve().parent / "evidence",
                        help="directory holding attacks-*.jsonl")
    parser.add_argument("--out", type=Path, default=None,
                        help="where to write analytics_summary.json "
                             "(default: <evidence-dir>/analytics_summary.json)")
    parser.add_argument("--markdown-out", type=Path, default=None,
                        help="also write the Markdown summary to this path")
    args = parser.parse_args()

    rows, provenance = load_rows(args.evidence_dir)

    summary = {
        "provenance": provenance,
        "malicious_success_rate": malicious_success_rate(rows),
        "status_distribution": status_distribution(rows),
        "per_category": per_category(rows),
        "injection_defense_layers": injection_defense_layers(rows),
        "birthday_validation": birthday_validation(rows),
    }

    out_path = args.out or (args.evidence_dir / "analytics_summary.json")
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    markdown = render_markdown(summary)
    if args.markdown_out:
        args.markdown_out.write_text(markdown + "\n", encoding="utf-8")

    print(markdown)
    print(f"\n[written] {out_path}", file=sys.stderr)
    if args.markdown_out:
        print(f"[written] {args.markdown_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
