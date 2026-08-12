"""
Generates evidence/report.md from the JSON-line evidence files written by the
attack-simulation tests, cross-referenced against the audit_log table so the
report shows the *server's own record* of each attack, not just what the client
script printed.

Run after the test suite:
    venv\\Scripts\\python.exe -m pytest tests/ -v
    venv\\Scripts\\python.exe tests/report.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import get_connection  # noqa: E402

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
OUTPUT = EVIDENCE_DIR / "report.md"

CATEGORIES = ["replay", "clone", "bruteforce", "mitm"]


def load_evidence(name):
    path = EVIDENCE_DIR / f"{name}.jsonl"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def recent_audit_rows(limit=25):
    conn = get_connection()
    if not conn:
        return []
    cur = conn.cursor()
    cur.execute(
        "SELECT event_type, tag_uid_hash, result, source_ip, created_at "
        "FROM audit_log ORDER BY id DESC LIMIT %s", (limit,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def main():
    lines = ["# Attack Simulation Evidence Report", ""]
    total, passed = 0, 0

    for category in CATEGORIES:
        records = load_evidence(category)
        if not records:
            continue
        lines.append(f"## {category.upper()}")
        lines.append("")
        lines.append("| Case | Result | Pass |")
        lines.append("|---|---|---|")
        for rec in records:
            total += 1
            ok = rec.get("passed", False)
            passed += 1 if ok else 0
            case = rec.get("case", "?")
            summary = rec.get("result", rec.get("status", ""))
            lines.append(f"| {case} | {summary} | {'YES' if ok else 'NO'} |")
        lines.append("")
        # Include any explicit caveat/note fields verbatim.
        for rec in records:
            if rec.get("note"):
                lines.append(f"> **Note ({rec['case']}):** {rec['note']}")
                lines.append("")

    lines.append(f"## Summary: {passed}/{total} checks passed")
    lines.append("")

    lines.append("## Recent server-side audit_log entries (independent evidence)")
    lines.append("")
    rows = recent_audit_rows()
    if rows:
        lines.append("| event_type | tag_uid_hash | result | source_ip | created_at |")
        lines.append("|---|---|---|---|---|")
        for event_type, tag_uid_hash, result, source_ip, created_at in rows:
            short_hash = (tag_uid_hash or "")[:12]
            lines.append(f"| {event_type} | {short_hash} | {result} | {source_ip} | {created_at} |")
    else:
        lines.append("_No audit_log rows found -- was the database reachable?_")
    lines.append("")

    lines.append("## Known limitations (documented, not solved by this suite)")
    lines.append("")
    lines.append("- **Physical clone resistance**: verification is by server-side lookup, "
                  "not by cryptographically proving physical tag authenticity. A cloned tag "
                  "broadcasting a copied UID/NDEF link would still show \"authentic\".")
    lines.append("- **MITM confidentiality**: tamper *detection* is proven without TLS; "
                  "eavesdropping on plaintext HTTP traffic is still possible until Phase 2 "
                  "(HTTPS via Cloudflare Tunnel) is deployed.")
    lines.append("- **Brute force**: tag_uid_hash is SHA-256 of a 7-byte UID (2^56 space) -- "
                  "infeasible live against the rate limiter, not proven infeasible offline.")
    lines.append("")

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Wrote {OUTPUT} ({passed}/{total} checks passed)")


if __name__ == "__main__":
    main()
