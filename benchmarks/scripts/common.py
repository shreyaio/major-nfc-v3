"""Shared request plumbing for the four quantitative experiments.

Per the handoff's golden rule — "Claude must inspect before coding ... reuse
the project implementation wherever possible" — every request this module
builds reuses the SAME construction logic as
backend/tests/conftest.py::sign_request / make_tag / enrol / verify, just
outside pytest (these scripts are standalone CLI tools, not pytest tests: they
drive sustained load/scale over minutes, which is not what a test suite is
for). Nothing here invents a route, a header, or a payload shape.

Every function that performs a live HTTP call returns a RequestResult with
start_time_utc + elapsed_ms recorded with time.perf_counter(), per the
handoff's measurement standard (§5): every attempt is recorded, not just
pass/fail, and nothing is dropped from the raw stream — timeouts and
transport exceptions get their own response_class, they are never discarded.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import secrets
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import crypto_envelope  # noqa: E402
import crypto_signing  # noqa: E402

log = logging.getLogger("benchmarks")

HTTP_TIMEOUT = float(os.getenv("BENCH_HTTP_TIMEOUT", "15"))


# =============================================================== CONFIG ===== #

class ConfigError(RuntimeError):
    """A required TEST_* environment variable is missing. Raised, never
    guessed around — the handoff is explicit: "If a required variable is
    missing, stop and tell me exactly which variable is missing and why."""


@dataclass(frozen=True)
class BenchConfig:
    base_url: str
    admin_token: str
    field_recipient_pub: bytes
    device_id: str
    device_private_hex: str
    worker_count: str

    @classmethod
    def from_env(cls, *, need_admin: bool = True,
                 need_field_recipient: bool = True) -> "BenchConfig":
        base_url = os.getenv("TEST_BASE_URL")
        if not base_url:
            raise ConfigError(
                "TEST_BASE_URL is not set. Point it at your TEST/STAGING "
                "deployment, e.g. TEST_BASE_URL=https://your-staging-host")
        admin_token = os.getenv("TEST_ADMIN_TOKEN", "")
        if need_admin and not admin_token:
            raise ConfigError(
                "TEST_ADMIN_TOKEN is not set. This experiment opens a test "
                "batch via /api/v2/admin/batches, which needs an admin token "
                "— see docs/OPERATOR_RUNBOOK.md for how to mint one "
                "(backend/scripts/mint_admin_token.py) for your TEST/STAGING "
                "deployment specifically. Never reuse a production token here.")
        field_recipient_hex = os.getenv("TEST_FIELD_RECIPIENT_PUB", "")
        if need_field_recipient and not field_recipient_hex:
            raise ConfigError(
                "TEST_FIELD_RECIPIENT_PUB is not set. This is the backend's "
                "public X25519 key (public by definition — see "
                "backend/tests/conftest.py::field_recipient_pub) — read it "
                "off your TEST/STAGING deployment's config/environment.")
        device_id = os.getenv("TEST_DEVICE_ID", str(uuid.uuid4()))
        device_priv_hex = os.getenv("TEST_DEVICE_PRIVATE_KEY", "")
        if not device_priv_hex:
            # Generated fresh is fine for a benchmark run, exactly like
            # tests/conftest.py::test_device — but it must ALREADY be
            # registered in device_registry on the target, or enrolment
            # (exp3, exp4) will 403. Exp1/exp2 against pre-existing records
            # do not need this at all.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
            )
            sk = Ed25519PrivateKey.generate()
            device_priv_hex = sk.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
            public_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            log.warning(
                "TEST_DEVICE_PRIVATE_KEY not set — generated an ephemeral "
                "device key (public half: %s). It must be registered as "
                "'active' in device_registry on %s before enrolment will "
                "succeed. See docs/OPERATOR_RUNBOOK.md.",
                public_hex, base_url)

        return cls(
            base_url=base_url.rstrip("/"),
            admin_token=admin_token,
            field_recipient_pub=(bytes.fromhex(field_recipient_hex)
                                 if field_recipient_hex else b""),
            device_id=device_id,
            device_private_hex=device_priv_hex,
            worker_count=os.getenv("TEST_WORKER_COUNT", "unknown"),
        )


# ======================================================= REQUEST RESULT ===== #

RESPONSE_CLASSES = ("2xx", "429", "4xx_other", "5xx", "timeout", "transport_error")


@dataclass
class RequestResult:
    experiment_id: str
    run_id: str
    sequence_number: int
    target: str
    start_time_utc: str
    elapsed_ms: float
    status_code: int | None
    response_class: str
    logical_verdict: str | None = None
    incident_kind: str | None = None
    incident_id_present: bool = False
    timeout: bool = False
    exception_type: str | None = None
    tier_value: str = ""

    def as_csv_row(self) -> dict:
        return asdict(self)


RAW_FIELDNAMES = [
    "experiment_id", "run_id", "target_env", "tier_value", "sequence_number",
    "start_time_utc", "elapsed_ms", "status_code", "response_class",
    "logical_verdict", "incident_kind", "incident_id_present", "timeout",
    "exception_type",
]


def classify_response(status_code: int | None, *, timed_out: bool,
                      transport_error: bool) -> str:
    if timed_out:
        return "timeout"
    if transport_error:
        return "transport_error"
    if status_code is None:
        return "transport_error"
    if status_code == 429:
        return "429"
    if 200 <= status_code < 300:
        return "2xx"
    if 400 <= status_code < 500:
        return "4xx_other"
    if 500 <= status_code < 600:
        return "5xx"
    return "4xx_other"


class RawEvidenceWriter:
    """Append-only CSV, one row per HTTP attempt — never drop a row, per the
    handoff's "Do not 'massage' data, drop timeouts, or remove failed
    requests" rule."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not path.exists()
        self._fh = path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=RAW_FIELDNAMES)
        if is_new:
            self._writer.writeheader()
            self._fh.flush()

    def write(self, result: RequestResult, target_env: str) -> None:
        row = {
            "experiment_id": result.experiment_id,
            "run_id": result.run_id,
            "target_env": target_env,
            "tier_value": result.tier_value,
            "sequence_number": result.sequence_number,
            "start_time_utc": result.start_time_utc,
            "elapsed_ms": f"{result.elapsed_ms:.3f}",
            "status_code": result.status_code if result.status_code is not None else "",
            "response_class": result.response_class,
            "logical_verdict": result.logical_verdict or "",
            "incident_kind": result.incident_kind or "",
            "incident_id_present": result.incident_id_present,
            "timeout": result.timeout,
            "exception_type": result.exception_type or "",
        }
        self._writer.writerow(row)
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "RawEvidenceWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# =================================================== SIGNED ENROLMENT ======= #
# Mirrors tests/conftest.py::sign_request / make_tag / enrol byte for byte —
# this is not a second implementation, it is the same construction used
# standalone.

def sign_request_headers(cfg: BenchConfig, raw_body: bytes, *,
                         idempotency_key: str | None = None,
                         timestamp: str | None = None) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(cfg.device_private_hex))
    idempotency_key = idempotency_key or str(uuid.uuid4())
    timestamp = timestamp or str(int(datetime.now(timezone.utc).timestamp()))
    payload = crypto_signing.build_signed_payload(
        "ed25519", timestamp, idempotency_key, raw_body)
    return {
        "Content-Type": "application/json",
        "X-Device-Id": cfg.device_id,
        "X-Timestamp": timestamp,
        "X-Sig-Alg": "ed25519",
        "X-Signature": sk.sign(payload).hex(),
        "X-Idempotency-Key": idempotency_key,
    }


def make_tag_payload(cfg: BenchConfig, batch_ref: str, mfg_date: str, *,
                     enrol_counter: int = 3, product_id: str | None = None) -> tuple:
    """Returns (payload, uid, token_hex) exactly like
    tests/conftest.py::make_tag."""
    uid = "04" + secrets.token_bytes(6).hex().upper()
    token_hex = secrets.token_bytes(16).hex().upper()

    sealed = crypto_envelope.seal_record(
        {"product_id": product_id or f"BENCH-{secrets.token_hex(4).upper()}",
         "batch_id": batch_ref, "mfg_date": mfg_date, "tag_uid": uid},
        cfg.field_recipient_pub)

    payload = {
        "schema": "nfcmed.enrol.v2",
        "crypto_version": "aes_gcm_v2",
        "batch_ref": batch_ref,
        "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
        "enrol_counter": enrol_counter,
        "originality_status": "verified",
        "binding_class": "counter",
        "tag_version": "0004040201000F03",
        "sealed": sealed,
    }
    return payload, uid, token_hex


def enrol(session: requests.Session, cfg: BenchConfig, payload: dict,
         *, timeout: float = HTTP_TIMEOUT) -> requests.Response:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_request_headers(cfg, raw)
    return session.post(f"{cfg.base_url}/api/v2/enrol", data=raw, headers=headers,
                        timeout=timeout)


def open_batch(session: requests.Session, cfg: BenchConfig, *, quota: int,
               batch_ref_prefix: str = "BENCH") -> dict:
    batch_ref = f"{batch_ref_prefix}-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"
    response = session.post(
        f"{cfg.base_url}/api/v2/admin/batches",
        headers={"Authorization": f"Bearer {cfg.admin_token}",
                 "Content-Type": "application/json"},
        json={"batch_ref": batch_ref,
              "product_name": "Quantitative Benchmark Product",
              "mfg_date": date.today().isoformat(),
              "shelf_life_days": 730,
              "quota": quota,
              "opened_by": "benchmarks/run_four_experiments.py",
              "countersigned_by": "benchmarks-second-signer"},
        timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json()


def close_batch(session: requests.Session, cfg: BenchConfig, batch_ref: str) -> dict:
    response = session.post(f"{cfg.base_url}/api/v2/admin/batches/{batch_ref}/close",
                            headers={"Authorization": f"Bearer {cfg.admin_token}"},
                            timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_batch_enrolled_count(session: requests.Session, cfg: BenchConfig,
                             batch_ref: str) -> int:
    """The project-supported way to confirm row count without a direct DB
    connection — GET /api/v2/admin/batches is what close_batch itself reads
    enrolled_count off of (routes/admin.py)."""
    response = session.get(f"{cfg.base_url}/api/v2/admin/batches",
                           headers={"Authorization": f"Bearer {cfg.admin_token}"},
                           timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    for batch in response.json().get("batches", []):
        if batch.get("batch_ref") == batch_ref:
            return int(batch.get("enrolled_count", 0))
    raise RuntimeError(f"batch {batch_ref} not found in /api/v2/admin/batches")


# =================================================== VERIFY (the one GET) === #

def verify_url_params(uid: str, counter: int, token_hex: str, *,
                      live: bool = False) -> dict:
    m = f"{uid}x{counter:06X}"
    params = {"m": m, "t": token_hex}
    if live:
        params["live"] = "1"
    return params


def timed_verify(session: requests.Session, cfg: BenchConfig, *,
                 experiment_id: str, run_id: str, sequence_number: int,
                 uid: str, counter: int, token_hex: str, tier_value: str = "",
                 timeout: float = HTTP_TIMEOUT) -> RequestResult:
    """The one function every experiment calls to hit /api/v2/verify. Uses
    the SAME request shape as tests/conftest.py::verify. Returns a fully
    populated RequestResult — this is the "reuse the existing helper or HTTP
    request construction rather than duplicating authentication logic" the
    handoff asks for; verify needs no authentication at all (it is the public
    consumer-facing endpoint), so there is nothing to duplicate beyond the
    URL/param shape, which is reused byte for byte.
    """
    params = verify_url_params(uid, counter, token_hex)
    start = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    status_code = None
    verdict = incident_kind = exception_type = None
    incident_id_present = False
    timed_out = transport_error = False
    try:
        response = session.get(f"{cfg.base_url}/api/v2/verify", params=params,
                               timeout=timeout)
        status_code = response.status_code
        try:
            body = response.json()
            verdict = body.get("verdict")
            incident = body.get("incident") or {}
            incident_kind = incident.get("kind")
            incident_id_present = incident.get("id") is not None
        except ValueError:
            pass  # non-JSON body (e.g. an edge 403/502 HTML page) — status still recorded
    except requests.exceptions.Timeout:
        timed_out = True
        exception_type = "Timeout"
    except requests.exceptions.RequestException as exc:
        transport_error = True
        exception_type = type(exc).__name__
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    return RequestResult(
        experiment_id=experiment_id, run_id=run_id, sequence_number=sequence_number,
        target=cfg.base_url, start_time_utc=start.isoformat(),
        elapsed_ms=elapsed_ms, status_code=status_code,
        response_class=classify_response(status_code, timed_out=timed_out,
                                         transport_error=transport_error),
        logical_verdict=verdict, incident_kind=incident_kind,
        incident_id_present=incident_id_present, timeout=timed_out,
        exception_type=exception_type, tier_value=str(tier_value),
    )


# =============================================================== STATS ===== #

def percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile over an already-sorted list. pct in [0, 100]."""
    if not sorted_values:
        return float("nan")
    n = len(sorted_values)
    rank = max(1, min(n, round(pct / 100.0 * n + 0.5)))
    return sorted_values[rank - 1]


def summarise(results: list[RequestResult]) -> dict:
    latencies = sorted(r.elapsed_ms for r in results)
    n = len(results)
    counts = {cls: 0 for cls in RESPONSE_CLASSES}
    for r in results:
        counts[r.response_class] = counts.get(r.response_class, 0) + 1
    return {
        "request_count": n,
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "success_pct": 100.0 * counts["2xx"] / n if n else 0.0,
        "rate_limit_pct": 100.0 * counts["429"] / n if n else 0.0,
        "other_4xx_pct": 100.0 * counts["4xx_other"] / n if n else 0.0,
        "server_5xx_pct": 100.0 * counts["5xx"] / n if n else 0.0,
        "timeout_pct": 100.0 * (counts["timeout"] + counts["transport_error"]) / n if n else 0.0,
    }


def new_run_id() -> str:
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{secrets.token_hex(3)}"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "RAW_FIELDNAMES",
    "RESPONSE_CLASSES",
    "BenchConfig",
    "ConfigError",
    "RawEvidenceWriter",
    "RequestResult",
    "classify_response",
    "close_batch",
    "enrol",
    "get_batch_enrolled_count",
    "iso_now",
    "make_tag_payload",
    "new_run_id",
    "open_batch",
    "percentile",
    "sign_request_headers",
    "summarise",
    "timed_verify",
    "verify_url_params",
]
