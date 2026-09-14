#!/usr/bin/env python3
"""Build, sign and publish the daily transparency root. ARCHITECTURE.md §14.3.

Run from .github/workflows/transparency.yml:

    python backend/scripts/publish_transparency.py --out log

Steps:
  1. SELECT id, row_sig FROM products ORDER BY id -> Merkle tree over row_sig.
  2. Read the latest audit_log.entry_hash (the chain head).
  3. Sign {as_of_date, merkle_root, record_count, audit_head} with
     TRANSPARENCY_KEY — a GitHub Actions secret, NEVER on the runtime backend.
  4. Write log/<date>.json for committing to the public repository.
  5. Store the same object in transparency_root so
     /.well-known/transparency/latest can serve it.

The audit head is in the signed object for a reason: an attacker with database
access who deletes their own trace breaks the hash chain, and because the head
was published yesterday, the break becomes PUBLICLY PROVABLE (F25). Without it
the audit log is not independent evidence — it can be edited by exactly the
adversary it exists to catch.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import db
from services import transparency as transparency_svc

SIGN_DOMAIN = b"nfcmed/v2/transparency:"


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _MinimalConfig:
    """publish_transparency runs in CI, not in the web process, so it needs the
    database URL and nothing else. Loading the full app config would demand KEK
    and the wrapped keys — which must NOT be available to this job."""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self.db_pool_max = 2


def audit_head() -> str:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
    return row[0] if row else "0" * 64


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="log", help="directory for log/<date>.json")
    ap.add_argument("--date", default=None, help="override the as-of date (testing)")
    args = ap.parse_args()

    database_url = os.getenv("DATABASE_URL")
    signing_key_hex = os.getenv("TRANSPARENCY_KEY")
    if not database_url:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 1
    if not signing_key_hex:
        print("TRANSPARENCY_KEY is not set. This job signs the root; without the "
              "key there is nothing to publish and a root must NEVER be published "
              "unsigned.", file=sys.stderr)
        return 1

    db.init_pool(_MinimalConfig(database_url))

    row_sigs = transparency_svc.collect_row_sigs()
    root = transparency_svc.merkle_root(row_sigs)
    as_of = args.date or date.today().isoformat()

    payload = {
        "as_of_date": as_of,
        "merkle_root": root,
        "record_count": len(row_sigs),
        "audit_head": audit_head(),
    }

    signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
    signature = signing_key.sign(SIGN_DOMAIN + canonical(payload)).hex()
    pubkey = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    repo = os.getenv("GITHUB_REPOSITORY", "")
    published_url = (f"https://github.com/{repo}/blob/main/log/{as_of}.json"
                     if repo else None)

    document = {**payload, "signature": signature, "pubkey": pubkey,
                "published_url": published_url,
                "generated_at": datetime.now(timezone.utc).isoformat()}

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{as_of}.json"
    out_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    transparency_svc.store_root(
        as_of_date=as_of, merkle_root_hex=root, record_count=len(row_sigs),
        audit_head=payload["audit_head"], signature=signature,
        published_url=published_url)

    print(f"published {out_path}: {len(row_sigs)} records, root {root[:16]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
