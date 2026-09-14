#!/usr/bin/env python3
"""Generate every keypair and secret the v2 system needs. ARCHITECTURE.md §20.2.

Run once, offline, on a machine you trust:

    python backend/scripts/gen_keys.py --out keys.local.json

The output file contains PRIVATE KEY MATERIAL. It is in .gitignore. Never commit
it, never paste it into a chat, never put it in an issue.

Key separation (§7.1) is the whole point: no single compromise breaks more than
one property. Specifically:
  - the Pi gets DEVICE_PRIVATE_KEY and FIELD_RECIPIENT_PUB only — it can write
    records, it cannot read the register;
  - the backend gets the two wrapped private keys plus KEK, and never the admin
    or transparency signing keys;
  - ADMIN_TOKEN_KEY and TRANSPARENCY_KEY stay offline / in CI.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _ed25519() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub


def _x25519() -> tuple[str, str]:
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub


def generate() -> dict:
    device_priv, device_pub = _ed25519()
    field_priv, field_pub = _x25519()
    row_priv, row_pub = _ed25519()
    admin_priv, admin_pub = _ed25519()
    transp_priv, transp_pub = _ed25519()
    return {
        "_warning": "PRIVATE KEY MATERIAL. Never commit. Never share.",
        "device": {
            "DEVICE_ID": str(uuid.uuid4()),
            "DEVICE_PRIVATE_KEY": device_priv,  # -> pi/.env
            "DEVICE_PUBLIC_KEY": device_pub,    # -> device_registry row
        },
        "field_recipient": {
            "FIELD_RECIPIENT_KEY": field_priv,  # -> wrap under KEK, backend only
            "FIELD_RECIPIENT_PUB": field_pub,   # -> pi/.env AND backend/.env
        },
        "row_signing": {
            "ROW_SIGNING_KEY": row_priv,        # -> wrap under KEK, backend only
            "ROW_SIGNING_PUBKEY": row_pub,      # -> backend/.env (external verification)
        },
        "admin_token": {
            "ADMIN_TOKEN_KEY": admin_priv,      # -> OFFLINE ONLY. Never on the backend.
            "ADMIN_TOKEN_PUBKEY": admin_pub,    # -> backend/.env
        },
        "transparency": {
            "TRANSPARENCY_KEY": transp_priv,    # -> GitHub Actions secret only
            "TRANSPARENCY_PUBKEY": transp_pub,  # -> published alongside the roots
        },
        "symmetric": {
            "TAG_INDEX_KEY": secrets.token_hex(32),  # backend only, never the Pi
            "IP_HASH_SEED": secrets.token_hex(32),
            "KEK": secrets.token_hex(32),            # store SEPARATELY from the wrapped blobs
            "TAG_PWD_MASTER": secrets.token_hex(32), # Pi only, used when locking is enabled
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="keys.local.json", help="output path (gitignored)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = ap.parse_args()

    if os.path.exists(args.out) and not args.force:
        print(f"refusing to overwrite existing {args.out} (pass --force if you mean it)",
              file=sys.stderr)
        return 1

    keys = generate()
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(keys, fh, indent=2)
    try:
        os.chmod(args.out, 0o600)
    except OSError:
        pass  # Windows; the .gitignore entry is the real control here

    print(f"wrote {args.out}")
    print()
    print("Next steps (§20.2):")
    print("  1. Wrap the two backend private keys:")
    print("       python backend/scripts/wrap_secret.py --kek <KEK> --secret <FIELD_RECIPIENT_KEY>")
    print("       python backend/scripts/wrap_secret.py --kek <KEK> --secret <ROW_SIGNING_KEY>")
    print("  2. Put KEK, ADMIN_TOKEN_KEY and TRANSPARENCY_KEY somewhere with DIFFERENT")
    print("     access control from the Render dashboard. A password manager, not a")
    print("     second env var next to the wrapped blobs — otherwise the envelope")
    print("     buys nothing and §19 capability (v) is not answered.")
    print("  3. Insert the device row into device_registry (§20.3 step 3).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
