"""Strict parser for the `m` mirror parameter. ARCHITECTURE.md §6.3, §9.6.

What the chip puts in the URL on a consumer tap:

    https://<HOST>/c?m=04A1B2C3D4E5F6x0001A7&t=9f3c...
                      |------------| |----|
                        UID 14 hex   counter 6 hex

Normalisation rules, applied identically here and on the Pi, pinned by
tests/vectors/mirror.json:

 1. `m` must match ^[0-9A-Fa-f]{14}x[0-9A-Fa-f]{6}$ exactly, then uppercase. Any
    other shape is a 400, not a verdict (B3, B5).
 2. UID is the 14 hex chars, uppercase, no separators — the same string form the
    Pi hashes. "04A1B2C3D4E5F6", never "04:a1:b2:...".
 3. Counter is int(m[15:21], 16).
 4. If uid == "00000000000000" and counter == 0, the mirror is not enabled on
    this tag -> verdict MIRROR_DISABLED, never UNKNOWN and never AUTHENTIC (B7).

The edge Worker canonicalises first and the origin re-validates here. Two
independent parsers that must agree is the defence against B9 (edge/origin
differential smuggling); the origin never trusts the edge's parse.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from errors import MalformedParameters

M_PATTERN = re.compile(r"^[0-9A-F]{14}X[0-9A-F]{6}$")
T_PATTERN = re.compile(r"^[0-9A-F]{32}$")
PLACEHOLDER_UID = "00000000000000"

# Length cap applied BEFORE the regex, so an oversized parameter is rejected
# without running a regex over it (B4 — and it keeps the regex off the DoS
# surface entirely).
MAX_PARAM_LEN = 64

COUNTER_MAX = 0xFFFFFF  # 24-bit counter


@dataclass(frozen=True)
class Mirror:
    uid: str
    counter: int
    placeholder: bool


def _canonical(raw: str, name: str) -> str:
    if raw is None:
        raise MalformedParameters(f"missing parameter {name}")
    if not isinstance(raw, str):
        raise MalformedParameters(f"parameter {name} is not a string")
    if len(raw) > MAX_PARAM_LEN:
        raise MalformedParameters(f"parameter {name} too long")
    # NFKC-normalise then uppercase BEFORE matching, so full-width and mixed-case
    # inputs are rejected by the pattern rather than sneaking past it (B5).
    return unicodedata.normalize("NFKC", raw).strip().upper()


def parse_mirror(raw_m: str, raw_t: str) -> tuple[Mirror, str]:
    """Returns (Mirror, canonical_token). Raises MalformedParameters (a 400).

    `t` is MANDATORY. There is no UID-only fallback path anywhere in this
    codebase — fail closed (B6). A UID is printed on the outside of every chip;
    a 128-bit token is not.
    """
    m = _canonical(raw_m, "m")
    t = _canonical(raw_t, "t")

    if not M_PATTERN.fullmatch(m) or not T_PATTERN.fullmatch(t):
        raise MalformedParameters("m or t failed the strict pattern")

    uid, counter = m[:14], int(m[15:21], 16)
    if counter > COUNTER_MAX:  # unreachable given 6 hex chars, asserted anyway
        raise MalformedParameters("counter out of range")

    if uid == PLACEHOLDER_UID and counter == 0:
        return Mirror(uid=uid, counter=counter, placeholder=True), t
    return Mirror(uid=uid, counter=counter, placeholder=False), t


def single_param(args, name: str) -> str:
    """Reject duplicate query parameters outright (B8).

    Flask's request.args.get silently takes the first value, which is exactly the
    behaviour parameter-pollution attacks rely on when a front layer takes the
    last. Use getlist and require exactly one.
    """
    values = args.getlist(name)
    if len(values) != 1:
        raise MalformedParameters(
            f"parameter {name} appeared {len(values)} times, expected exactly 1")
    return values[0]
