"""Typed, validated, fail-fast configuration. ARCHITECTURE.md §9.2, §21.1.

If a required secret is missing or malformed, this raises with the variable
name and the process does not start.

NEVER `os.getenv("SECRET", "")`. A secret that defaults to empty string turns a
misconfiguration into a silent security hole — v1 did exactly this for
SHARED_SECRET, AES_MASTER_KEY and ADMIN_API_KEY.

Two settings are startup failures rather than runtime warnings because getting
them wrong destroys data integrity silently (§15.4):
  - CNT_BYTE_ORDER unset  -> refuse to start. Never guess (§6.4).
  - TAG_INDEX_KEY unset   -> refuse to start. Never fall back to plain SHA-256.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from dotenv import load_dotenv

from errors import ConfigError

load_dotenv()

VERSION = "2.0.0"

REQUIRED = ["DATABASE_URL", "KEK", "FIELD_RECIPIENT_KEY_WRAPPED",
            "ROW_SIGNING_KEY_WRAPPED", "TAG_INDEX_KEY", "ADMIN_TOKEN_PUBKEY",
            "IP_HASH_SEED", "CNT_BYTE_ORDER", "PUBLIC_HOST"]

# Variables removed in v2 (§21.4). If any of these is still set, the deployment
# is half-migrated and something is reading a key that no longer means anything.
REMOVED_V1_VARS = ["SHARED_SECRET", "AES_MASTER_KEY", "PI_PUBLIC_KEYS",
                   "ADMIN_API_KEY", "FRONTEND_VERIFY_BASE_URL", "QR_FALLBACK_DIR"]

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class Config:
    database_url: str
    kek: bytes
    field_recipient_key_wrapped: str
    field_recipient_pub: bytes
    row_signing_key_wrapped: str
    row_signing_pubkey: bytes
    row_key_version: int
    tag_index_key: bytes
    admin_token_pubkey: bytes
    ip_hash_seed: bytes
    cnt_byte_order: str
    public_host: str
    allowed_origins: list[str] = field(default_factory=list)
    # Public half only, and optional: it is served alongside the transparency
    # root as a convenience. The private half is a GitHub Actions secret and
    # never reaches this process.
    transparency_pubkey: str = ""

    max_taps_per_day: int = 50
    velocity_grace: int = 20
    verify_time_floor_ms: int = 120
    neg_cache_ttl: int = 300
    pow_difficulty_bits: int = 18
    db_pool_max: int = 6
    audit_retention_days: int = 90

    tag_locking_enabled: bool = False
    originality_policy: str = "reject"
    edge_expected: bool = True
    log_level: str = "INFO"

    # Request-signing window, two-sided (§7.7).
    timestamp_window_s: int = 30
    max_body_bytes: int = 64 * 1024
    max_json_depth: int = 8


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value or not value.strip():
        raise ConfigError(f"missing required env var: {name}")
    return value.strip()


def _hex_bytes(name: str, value: str, *, expect_len: int | None = None) -> bytes:
    if not _HEX.fullmatch(value) or len(value) % 2:
        raise ConfigError(f"{name} must be hex")
    raw = bytes.fromhex(value)
    if expect_len is not None and len(raw) != expect_len:
        raise ConfigError(
            f"{name} must be {expect_len} bytes ({expect_len * 2} hex chars), "
            f"got {len(raw)}")
    return raw


def _int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_config() -> Config:
    missing = [k for k in REQUIRED if not (os.getenv(k) or "").strip()]
    if missing:
        raise ConfigError(f"missing required env vars: {', '.join(missing)}")

    stale = [k for k in REMOVED_V1_VARS if (os.getenv(k) or "").strip()]
    if stale:
        raise ConfigError(
            f"v1 env vars are still set and mean nothing in v2: {', '.join(stale)}. "
            f"Remove them (§21.4) — leaving them set hides a half-finished migration.")

    database_url = _require("DATABASE_URL")
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise ConfigError("DATABASE_URL must be a postgresql:// connection string")

    cnt_byte_order = _require("CNT_BYTE_ORDER").lower()
    if cnt_byte_order not in ("msb", "lsb"):
        raise ConfigError(
            "CNT_BYTE_ORDER must be 'msb' or 'lsb'. It has no default on purpose: "
            "guessing it silently corrupts every enrol_counter and makes the "
            "velocity bound nonsense. Calibrate it on a scrap tag (§6.4, §20.7).")

    originality_policy = (os.getenv("ORIGINALITY_POLICY") or "reject").strip().lower()
    if originality_policy not in ("reject", "warn"):
        raise ConfigError("ORIGINALITY_POLICY must be 'reject' or 'warn'")

    public_host = _require("PUBLIC_HOST")
    if "/" in public_host or public_host.startswith("http"):
        raise ConfigError("PUBLIC_HOST must be a bare hostname, not a URL")

    origins = [o.strip() for o in (os.getenv("ALLOWED_ORIGINS") or "").split(",") if o.strip()]
    for origin in origins:
        if not origin.startswith(("http://", "https://")):
            raise ConfigError(f"ALLOWED_ORIGINS entry must include a scheme: {origin!r}")

    return Config(
        database_url=database_url,
        kek=_hex_bytes("KEK", _require("KEK"), expect_len=32),
        field_recipient_key_wrapped=_require("FIELD_RECIPIENT_KEY_WRAPPED"),
        field_recipient_pub=_hex_bytes("FIELD_RECIPIENT_PUB",
                                       _require("FIELD_RECIPIENT_PUB"), expect_len=32),
        row_signing_key_wrapped=_require("ROW_SIGNING_KEY_WRAPPED"),
        row_signing_pubkey=_hex_bytes("ROW_SIGNING_PUBKEY",
                                      _require("ROW_SIGNING_PUBKEY"), expect_len=32),
        row_key_version=_int_env("ROW_KEY_VERSION", 1, minimum=1),
        tag_index_key=_hex_bytes("TAG_INDEX_KEY", _require("TAG_INDEX_KEY"), expect_len=32),
        admin_token_pubkey=_hex_bytes("ADMIN_TOKEN_PUBKEY",
                                      _require("ADMIN_TOKEN_PUBKEY"), expect_len=32),
        ip_hash_seed=_hex_bytes("IP_HASH_SEED", _require("IP_HASH_SEED"), expect_len=32),
        cnt_byte_order=cnt_byte_order,
        public_host=public_host,
        allowed_origins=origins,
        transparency_pubkey=(os.getenv("TRANSPARENCY_PUBKEY") or "").strip(),
        max_taps_per_day=_int_env("MAX_TAPS_PER_DAY", 50, minimum=1),
        velocity_grace=_int_env("VELOCITY_GRACE", 20, minimum=0),
        verify_time_floor_ms=_int_env("VERIFY_TIME_FLOOR_MS", 120, minimum=0),
        neg_cache_ttl=_int_env("NEG_CACHE_TTL", 300, minimum=0),
        pow_difficulty_bits=_int_env("POW_DIFFICULTY_BITS", 18, minimum=0),
        db_pool_max=_int_env("DB_POOL_MAX", 6, minimum=1),
        audit_retention_days=_int_env("AUDIT_RETENTION_DAYS", 90, minimum=1),
        tag_locking_enabled=_bool_env("TAG_LOCK_ENABLED", False),
        originality_policy=originality_policy,
        edge_expected=_bool_env("EDGE_EXPECTED", True),
        log_level=(os.getenv("LOG_LEVEL") or "INFO").upper(),
    )


# Names whose VALUES must never be emitted in a log line or an error message.
# logging_setup.py builds its redaction filter from this list (F6a).
SECRET_ENV_NAMES = (
    "DATABASE_URL", "KEK", "FIELD_RECIPIENT_KEY_WRAPPED", "ROW_SIGNING_KEY_WRAPPED",
    "TAG_INDEX_KEY", "IP_HASH_SEED", "ADMIN_TOKEN_KEY", "TRANSPARENCY_KEY",
    "DEVICE_PRIVATE_KEY", "TAG_PWD_MASTER",
)
