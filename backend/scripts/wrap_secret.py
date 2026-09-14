#!/usr/bin/env python3
"""Envelope-wrap a secret under the KEK so it can be pasted into Render's env.
ARCHITECTURE.md §7.6, §20.2.

    python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <PRIVKEY_HEX>

Output format (hex):  nonce(12) || AESGCM(KEK).encrypt(nonce, secret, aad)

This does not make key theft impossible. It means reading the backend's
environment variables is no longer sufficient — which is exactly what threat-model
capability (v) requires. The point only holds if KEK lives somewhere with
genuinely different access control from the Render dashboard. If you paste KEK in
next to the wrapped blob, you have gained nothing.
"""
from __future__ import annotations

import argparse
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

WRAP_AAD = b"nfcmed/v2/kek-wrap"


def wrap(kek: bytes, secret: bytes) -> str:
    nonce = os.urandom(12)
    return (nonce + AESGCM(kek).encrypt(nonce, secret, WRAP_AAD)).hex()


def unwrap(kek: bytes, wrapped_hex: str) -> bytes:
    blob = bytes.fromhex(wrapped_hex)
    if len(blob) < 12 + 16:
        raise ValueError("wrapped blob too short")
    return AESGCM(kek).decrypt(blob[:12], blob[12:], WRAP_AAD)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kek", required=True, help="64 hex chars")
    ap.add_argument("--secret", help="the secret to wrap, hex")
    ap.add_argument("--unwrap", help="a wrapped blob to unwrap (round-trip check)")
    args = ap.parse_args()

    try:
        kek = bytes.fromhex(args.kek)
    except ValueError:
        print("KEK must be hex", file=sys.stderr)
        return 1
    if len(kek) != 32:
        print(f"KEK must be 32 bytes (64 hex chars), got {len(kek)}", file=sys.stderr)
        return 1

    if args.unwrap:
        print(unwrap(kek, args.unwrap).hex())
        return 0

    if not args.secret:
        print("pass --secret or --unwrap", file=sys.stderr)
        return 1

    try:
        secret = bytes.fromhex(args.secret)
    except ValueError:
        print("secret must be hex", file=sys.stderr)
        return 1

    wrapped = wrap(kek, secret)
    assert unwrap(kek, wrapped) == secret, "round-trip failed"
    print(wrapped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
