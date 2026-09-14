"""Merkle tree construction for the public transparency log.
ARCHITECTURE.md §14.3.

This is the answer to "shouldn't this be on a blockchain?", and it costs nothing.

A ledger is usually proposed to remove the need to trust a single custodian of
the database. A daily signed Merkle root over every row signature, published to a
public repository, delivers that property directly: anyone can prove a record
existed on a given date via an inclusion proof, and the custodian cannot silently
rewrite history. No consortium, no tokens, no per-transaction fee.

Domain separation on leaves and nodes is not decoration — without distinct
prefixes, a second-preimage attack can present an internal node as a leaf.
"""
from __future__ import annotations

import hashlib

import db

LEAF_PREFIX = b"nfcmed/v2/leaf:"
NODE_PREFIX = b"nfcmed/v2/node:"

EMPTY_ROOT = hashlib.sha256(b"nfcmed/v2/empty").hexdigest()


def leaf_hash(row_sig: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + row_sig.encode("ascii")).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_root(row_sigs: list[str]) -> str:
    if not row_sigs:
        return EMPTY_ROOT
    level = [leaf_hash(s) for s in row_sigs]
    while len(level) > 1:
        # An odd node is PROMOTED unchanged rather than duplicated. Duplicating
        # it is the CVE-2012-2459 shape, where two different leaf sets produce
        # the same root.
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def inclusion_proof(row_sigs: list[str], index: int) -> list[dict]:
    """Sibling path for `index`, as [{"side": "left"|"right", "hash": hex}, ...].
    scripts/verify_transparency.py replays this against a published root."""
    if not 0 <= index < len(row_sigs):
        raise IndexError("index out of range")
    level = [leaf_hash(s) for s in row_sigs]
    path: list[dict] = []
    pos = index
    while len(level) > 1:
        if pos % 2 == 1:
            path.append({"side": "left", "hash": level[pos - 1].hex()})
        elif pos + 1 < len(level):
            path.append({"side": "right", "hash": level[pos + 1].hex()})
        # else: pos is the last node of an odd level and gets promoted unchanged,
        # so it has no sibling at this level and contributes nothing to the path.

        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        pos //= 2
        level = nxt
    return path


def verify_inclusion(leaf: str, path: list[dict], root_hex: str) -> bool:
    current = leaf_hash(leaf)
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        current = (node_hash(current, sibling) if step["side"] == "right"
                   else node_hash(sibling, current))
    return current.hex() == root_hex


def collect_row_sigs() -> list[str]:
    """All row signatures in id order. Order is part of the commitment."""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT row_sig FROM products ORDER BY id")
        return [r[0] for r in cur.fetchall()]


def latest_root() -> dict | None:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT as_of_date, merkle_root, record_count, audit_head, signature, "
            "       published_url FROM transparency_root "
            " ORDER BY as_of_date DESC LIMIT 1")
        row = cur.fetchone()
    if row is None:
        return None
    cols = ("as_of_date", "merkle_root", "record_count", "audit_head", "signature",
            "published_url")
    out = dict(zip(cols, row, strict=True))
    out["as_of_date"] = out["as_of_date"].isoformat()
    return out


def store_root(*, as_of_date: str, merkle_root_hex: str, record_count: int,
               audit_head: str, signature: str, published_url: str | None) -> None:
    with db.connection(write=True) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO transparency_root (as_of_date, merkle_root, record_count, "
            "  audit_head, signature, published_url) VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (as_of_date) DO UPDATE SET merkle_root = EXCLUDED.merkle_root, "
            "  record_count = EXCLUDED.record_count, audit_head = EXCLUDED.audit_head, "
            "  signature = EXCLUDED.signature, published_url = EXCLUDED.published_url",
            (as_of_date, merkle_root_hex, record_count, audit_head, signature,
             published_url))
