#!/usr/bin/env python3
"""Mint a scoped, short-lived admin token. ARCHITECTURE.md §9.10.

    python backend/scripts/mint_admin_token.py \
        --key <ADMIN_TOKEN_KEY_HEX> --sub shreya \
        --scopes recall incident:write --ttl 3600

Run this OFFLINE. `ADMIN_TOKEN_KEY` must never reach the runtime backend — the
backend holds only `ADMIN_TOKEN_PUBKEY` and verifies signatures with it. That is
what removes the v1 problem of a single static `X-Admin-Key` string with no
scoping, no expiry and no rotation path (F18), and it means there is no secret on
the server for D14 to brute-force.

Token format:
    base64url(payload_json) + "." + base64url(ed25519_sig(payload_json))
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Kept in sync with backend/auth_admin.py::VALID_SCOPES.
VALID_SCOPES = frozenset({
    "batch:read", "batch:write",
    "recall",
    "incident:read", "incident:write",
    "report:read", "report:write",
    "metrics:read",
})

MAX_TTL_SECONDS = 12 * 3600  # enforced again at verification time


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def mint(privkey_hex: str, sub: str, scopes: list[str], ttl: int) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
    now = int(time.time())
    payload = {
        "sub": sub,
        "scopes": sorted(scopes),
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{b64u(body)}.{b64u(sk.sign(body))}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", required=True, help="ADMIN_TOKEN_KEY, 64 hex chars")
    ap.add_argument("--sub", required=True, help="who this token is for, e.g. 'shreya'")
    ap.add_argument("--scopes", nargs="+", required=True,
                    help=f"one or more of: {' '.join(sorted(VALID_SCOPES))}")
    ap.add_argument("--ttl", type=int, default=3600, help="seconds, max 43200 (12h)")
    args = ap.parse_args()

    bad = set(args.scopes) - VALID_SCOPES
    if bad:
        print(f"unknown scopes: {', '.join(sorted(bad))}", file=sys.stderr)
        return 1
    if not 0 < args.ttl <= MAX_TTL_SECONDS:
        print(f"--ttl must be between 1 and {MAX_TTL_SECONDS} seconds", file=sys.stderr)
        return 1

    print(mint(args.key, args.sub, args.scopes, args.ttl))
    print(f"\nvalid for {args.ttl}s, scopes: {' '.join(sorted(args.scopes))}",
          file=sys.stderr)
    print("Paste into the admin console's session-only token field. Never store it "
          "in localStorage.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
