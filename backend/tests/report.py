#!/usr/bin/env python3
"""Cross-reference the attack evidence against the server's own audit log.

    python tests/report.py

Writes `tests/evidence/report.md`. This is the companion to
`generate_attack_analytics.py`: that script reports what the ATTACKER observed,
this one checks the server independently recorded the same events. An evidence
file is the test runner's word for what happened; the audit chain is the
server's, and a claim that rests on only one of them is weaker than one where
the two agree.

Carried over in spirit from v1's `tests/report.py` (deleted in 7e06ce2 with the
rest of the seven-category suite). The v1 version assumed the old per-category
evidence files and a `nonce` column; this reads the §16 `attacks-*.jsonl` format
and the v2 `audit_log` schema.

## Requires DATABASE_URL

The audit log is deliberately not exposed over HTTP — there is no admin route
that returns audit rows, because an endpoint that dumps the tamper-evidence
chain is itself a target. So the cross-reference needs a direct connection, the
same way `tests/integration/test_audit_chain.py` does.

Without `DATABASE_URL` the script still runs and still writes a report; the
cross-reference section records that it was unavailable rather than being
silently omitted. A missing section a reader cannot see is worse than a stated
gap.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
REPORT_PATH = EVIDENCE_DIR / "report.md"

AUDIT_COLS = ("seq", "event_type", "tag_index", "actor", "result",
              "source_ip_hash", "user_agent_class", "detail", "prev_hash",
              "entry_hash")

# Attack classes that drive the live server. E, F and H are offline property
# checks, so the absence of an audit row for them is correct, not a finding.
LIVE_CLASSES = {"A", "B", "C", "D", "G"}


def _force_utf8_stdio() -> None:
    """cp1252 cannot encode the section marks and arrows below; reconfigure
    rather than flatten (see generate_attack_analytics.py for the same note)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


# ----------------------------------------------------------------- evidence --

def load_evidence() -> tuple[list[dict], list[str]]:
    files = sorted(EVIDENCE_DIR.glob("attacks-*.jsonl"))
    rows: list[dict] = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "attack_id" in row:
                row["_source_file"] = path.name
                rows.append(row)
    return rows, [p.name for p in files]


def evidence_window(rows: list[dict]) -> tuple[str | None, str | None]:
    """The first and last `recorded_at` across the run — the window the audit
    rows are compared against, so an unrelated earlier run's rows are not
    counted as corroboration."""
    stamps = sorted(r["recorded_at"] for r in rows if r.get("recorded_at"))
    return (stamps[0], stamps[-1]) if stamps else (None, None)


# -------------------------------------------------------------------- audit --

def load_audit(since: str | None, until: str | None) -> dict:
    """Read the audit rows written during the evidence window and verify the
    chain over them. Returns a result dict that always has `available`."""
    url = os.getenv("DATABASE_URL")
    if not url:
        return {"available": False,
                "reason": "DATABASE_URL is not set — the audit log has no HTTP "
                          "surface, so the cross-reference needs a direct "
                          "connection (see the module docstring)"}

    try:
        import psycopg2

        import audit as audit_mod
        from db import _with_sslmode
    except ImportError as exc:
        return {"available": False,
                "reason": f"could not import the backend modules: {exc}"}

    try:
        conn = psycopg2.connect(_with_sslmode(url))
    except Exception as exc:
        return {"available": False, "reason": f"could not connect: {exc}"}

    try:
        with conn, conn.cursor() as cur:
            # The chain is verified over the WHOLE log, not just the window:
            # a break anywhere invalidates every hash after it, so a window-only
            # walk could report "intact" over a chain that is already broken.
            cur.execute(f"SELECT {', '.join(AUDIT_COLS)} FROM audit_log "  # noqa: S608 — interpolates a module-level column tuple, never user input
                        f"ORDER BY seq ASC")
            all_rows = [dict(zip(AUDIT_COLS, r, strict=True))
                        for r in cur.fetchall()]

        first_break = audit_mod.verify_chain(all_rows)

        window_rows = all_rows
        if since and until:
            def in_window(row) -> bool:
                detail = row.get("detail") or {}
                stamp = detail.get("at") if isinstance(detail, dict) else None
                return stamp is None or since <= str(stamp) <= until
            window_rows = [r for r in all_rows if in_window(r)]

        return {
            "available": True,
            "rows_total": len(all_rows),
            "rows_in_window": len(window_rows),
            "chain_intact": first_break is None,
            "first_break_seq": first_break,
            "event_types": dict(sorted(
                Counter(r["event_type"] for r in window_rows).items())),
            "results": dict(sorted(
                Counter(str(r["result"]) for r in window_rows).items())),
        }
    except Exception as exc:
        return {"available": False, "reason": f"query failed: {exc}"}
    finally:
        conn.close()


# ------------------------------------------------------------------ report ---

def render(evidence: list[dict], files: list[str], audit: dict,
           since: str | None, until: str | None) -> str:
    outcomes = Counter(r["outcome"] for r in evidence)
    live = [r for r in evidence if r["attack_id"][:1].upper() in LIVE_CLASSES]
    offline = [r for r in evidence if r["attack_id"][:1].upper() not in LIVE_CLASSES]

    lines: list[str] = []
    add = lines.append

    add("# Attack evidence — audit cross-reference")
    add("")
    add(f"Generated {datetime.now(timezone.utc).isoformat()}")
    add("")
    add(f"- Evidence files: {len(files)} (`{'`, `'.join(files)}`)")
    add(f"- Attack rows: {len(evidence)}")
    add(f"- Window: `{since}` → `{until}`")
    add("")

    add("## Outcomes recorded by the suite")
    add("")
    add("| Outcome | Count |")
    add("|---|---:|")
    for outcome, n in sorted(outcomes.items()):
        add(f"| {outcome} | {n} |")
    add("")
    add(f"{len(live)} row(s) from server-driving classes (A, B, C, D, G); "
        f"{len(offline)} from offline property checks (E, F, H), which "
        f"correctly write no audit rows.")
    add("")

    add("## Server-side audit log")
    add("")
    if not audit.get("available"):
        add(f"**Unavailable.** {audit.get('reason')}")
        add("")
        add("The suite's own evidence above still stands on its own; what is "
            "missing is the independent confirmation that the server recorded "
            "the same events. Re-run with `DATABASE_URL` set to complete it.")
    else:
        add(f"- Audit rows in the log: **{audit['rows_total']}**")
        add(f"- Rows within the evidence window: **{audit['rows_in_window']}**")
        if audit["chain_intact"]:
            add("- Hash chain: **intact** over the whole log")
        else:
            add(f"- Hash chain: **BROKEN — first break at seq "
                f"{audit['first_break_seq']}**")
        add("")
        add("### Events recorded")
        add("")
        add("| Event type | Count |")
        add("|---|---:|")
        for event, n in audit["event_types"].items():
            add(f"| {event} | {n} |")
        add("")
        add("### Results recorded")
        add("")
        add("| Result | Count |")
        add("|---|---:|")
        for result, n in audit["results"].items():
            add(f"| {result} | {n} |")
        add("")
        if live and audit["rows_in_window"] == 0:
            add("> **Finding.** The suite drove the live server "
                f"({len(live)} attack rows) but the audit log recorded nothing "
                "in the window. Either the suite ran against a different "
                "deployment than `DATABASE_URL` points at, or audit writes are "
                "failing silently (they are best-effort by design and must not "
                "raise — check the `audit_write_failures` metric).")
            add("")

    add("## How to read this with the analytics")
    add("")
    add("`generate_attack_analytics.py` reports what the attacker saw: status "
        "codes, success rate, defense-layer attribution. This file reports what "
        "the server independently wrote down. The two are only worth citing "
        "together — matching counts mean the defence both rejected the attack "
        "and noticed it.")
    add("")

    return "\n".join(lines)


def main() -> int:
    _force_utf8_stdio()
    evidence, files = load_evidence()
    if not evidence:
        sys.exit(f"no attack evidence found in {EVIDENCE_DIR}")

    since, until = evidence_window(evidence)
    audit = load_audit(since, until)
    report = render(evidence, files, audit, since, until)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report + "\n", encoding="utf-8")

    print(report)
    print(f"\n[written] {REPORT_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
