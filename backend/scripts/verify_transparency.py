#!/usr/bin/env python3
"""Third-party verifier for the transparency log. ARCHITECTURE.md §14.3, §9.9.

This is the tool that makes the transparency claim mean something. Ship it,
document it, and reference it in the paper — a log nobody can check is just a
file.

Three things it does, none of which require any access to our systems:

    # 1. Is a published root correctly signed?
    python verify_transparency.py --log-dir log --latest

    # 2. Is a specific record in the tree under that root?
    python verify_transparency.py --log-dir log --date 2026-09-11 \
        --prove <row_sig> --proof proof.json

    # 3. Is the audit log's hash chain intact? (needs DATABASE_URL)
    python verify_transparency.py --check-audit-chain

A verifier with only the published log directory and the public key can do (1)
and (2). Only (3) needs database access, and it is what CI runs nightly.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGN_DOMAIN = b"nfcmed/v2/transparency:"
SIGNED_FIELDS = ("as_of_date", "merkle_root", "record_count", "audit_head")


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(document: dict, expected_pubkey: str | None = None) -> bool:
    """Check the Ed25519 signature over the four signed fields.

    If you have the publisher's public key from somewhere other than this file —
    the paper, a pinned copy, the README — pass it as `expected_pubkey`. A
    document that carries its own key and signs itself proves only internal
    consistency, not authorship.
    """
    pubkey_hex = document.get("pubkey", "")
    if expected_pubkey and pubkey_hex != expected_pubkey:
        print(f"  ! pubkey mismatch: document says {pubkey_hex[:16]}…, "
              f"you expected {expected_pubkey[:16]}…", file=sys.stderr)
        return False
    try:
        payload = {k: document[k] for k in SIGNED_FIELDS}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(document["signature"]), SIGN_DOMAIN + canonical(payload))
        return True
    except (KeyError, ValueError, InvalidSignature):
        return False


def check_roots(log_dir: Path, latest_only: bool, expected_pubkey: str | None) -> int:
    files = sorted(log_dir.glob("*.json"))
    if not files:
        print(f"no roots found in {log_dir}", file=sys.stderr)
        return 1
    if latest_only:
        files = files[-1:]

    failures = 0
    previous_count = None
    for path in files:
        document = json.loads(path.read_text(encoding="utf-8"))
        ok = verify_signature(document, expected_pubkey)
        status = "OK  " if ok else "BAD "
        print(f"{status} {path.name}  records={document.get('record_count')} "
              f"root={document.get('merkle_root', '')[:16]}…")
        if not ok:
            failures += 1

        # The register only grows. A root with fewer records than the day before
        # means rows were deleted — which is exactly the thing a transparency log
        # exists to make visible.
        count = document.get("record_count")
        if previous_count is not None and isinstance(count, int) and count < previous_count:
            print(f"  ! record_count went backwards: {previous_count} -> {count}. "
                  f"Records were deleted from the register.", file=sys.stderr)
            failures += 1
        previous_count = count if isinstance(count, int) else previous_count

    return 1 if failures else 0


def check_inclusion(log_dir: Path, as_of: str, leaf: str, proof_path: Path) -> int:
    from services import transparency as transparency_svc

    document = json.loads((log_dir / f"{as_of}.json").read_text(encoding="utf-8"))
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    ok = transparency_svc.verify_inclusion(leaf, proof, document["merkle_root"])
    print(f"{'OK  ' if ok else 'BAD '} inclusion of {leaf[:16]}… under "
          f"{document['merkle_root'][:16]}… ({as_of})")
    return 0 if ok else 1


def check_audit_chain() -> int:
    """Walk the audit hash chain and report the FIRST break. §9.9."""
    import os

    import audit
    import db

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 1

    class _Cfg:
        def __init__(self, url):
            self.database_url = url
            self.db_pool_max = 2

    db.init_pool(_Cfg(database_url))
    cols = ("seq", "event_type", "tag_index", "actor", "result", "source_ip_hash",
            "user_agent_class", "detail", "prev_hash", "entry_hash")
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {', '.join(cols)} FROM audit_log ORDER BY seq")  # noqa: S608 — interpolates a module-level column tuple, never user input
        rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]

    break_at = audit.verify_chain(rows)
    if break_at is None:
        print(f"OK   audit chain intact across {len(rows)} entries")
        return 0
    print(f"BAD  audit chain breaks at seq {break_at}. An entry was deleted or "
          f"altered after it was written.", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log-dir", type=Path, default=Path("log"))
    ap.add_argument("--latest", action="store_true", help="check only the newest root")
    ap.add_argument("--pubkey", help="the publisher's key, from a source you trust")
    ap.add_argument("--date", help="as-of date for an inclusion check")
    ap.add_argument("--prove", help="a row_sig to prove membership for")
    ap.add_argument("--proof", type=Path, help="the inclusion proof JSON")
    ap.add_argument("--check-audit-chain", action="store_true")
    args = ap.parse_args()

    if args.check_audit_chain:
        return check_audit_chain()
    if args.prove:
        if not (args.date and args.proof):
            ap.error("--prove needs --date and --proof")
        return check_inclusion(args.log_dir, args.date, args.prove, args.proof)
    return check_roots(args.log_dir, args.latest, args.pubkey)


if __name__ == "__main__":
    raise SystemExit(main())
