"""Error envelope and secret redaction. ARCHITECTURE.md §15.2, §14.5.

Two properties, both of which v1 got wrong:

  1. THE ENVELOPE NEVER LEAKS INTERNALS. v1 returned jsonify({"error": str(e)})
     in a dozen places, which hands the client whatever psycopg2 felt like
     saying — table names, column names, sometimes the connection string (D23).

  2. SECRETS NEVER REACH A LOG LINE. §14.5 asks for exactly this test: force an
     exception containing DATABASE_URL and assert it is redacted (F6a). A
     credential in a log aggregator is a credential shared with everyone who can
     read logs, which is usually far more people than can read the environment.
"""
from __future__ import annotations

import json
import logging
import os

import pytest

from errors import (
    TERMINAL_STATUSES,
    AppError,
    BadRequest,
    Conflict,
    MalformedParameters,
    RateLimited,
    RecordInvalid,
    ServiceUnavailable,
)
from logging_setup import REDACTED, JsonFormatter, SecretRedactor, request_id_var

# ================================================================= ENVELOPE ====

def test_envelope_shape_is_exactly_the_contract():
    exc = MalformedParameters("m failed the strict pattern")
    envelope = exc.to_envelope("01J8TESTREQUESTID")
    assert envelope == {
        "error": {
            "code": "malformed_parameters",
            "message": "The verification link is not valid.",
            "request_id": "01J8TESTREQUESTID",
            "retry_after": None,
        }
    }


def test_detail_is_for_the_log_and_never_for_the_client():
    """The whole reason `detail` and `public_message` are separate arguments."""
    secret_ish = "relation \"products\" does not exist at /opt/render/app.py:214"
    exc = BadRequest(secret_ish)
    envelope = exc.to_envelope("rid")

    assert exc.detail == secret_ish
    assert secret_ish not in json.dumps(envelope)
    assert envelope["error"]["message"] == "The request was not valid."


def test_retry_after_is_carried_on_429_and_503():
    """The Pi's drainer backs off on this rather than guessing (§12.3)."""
    limited = RateLimited("verify limit exceeded", retry_after=37)
    assert limited.to_envelope("rid")["error"]["retry_after"] == 37

    unavailable = ServiceUnavailable("pool exhausted", retry_after=2)
    assert unavailable.to_envelope("rid")["error"]["retry_after"] == 2

    # Everything else leaves it null rather than inventing a number.
    assert BadRequest("x").to_envelope("rid")["error"]["retry_after"] is None


@pytest.mark.parametrize("exc,status,code", [
    (BadRequest("x"), 400, "malformed_request"),
    (Conflict("x"), 409, "conflict"),
    (RateLimited("x"), 429, "rate_limited"),
    (ServiceUnavailable("x"), 503, "service_unavailable"),
    (AppError("x"), 500, "internal_error"),
])
def test_status_and_code_pairs(exc, status, code):
    assert exc.status == status
    assert exc.code == code


def test_record_invalid_is_a_verdict_not_an_http_error():
    """§15.3 rule 8. A tampered row must produce a calm negative answer to the
    consumer, not a server error. It carries no HTTP status of its own beyond
    the inherited default because it is never raised to a client."""
    exc = RecordInvalid("row signature failed")
    assert exc.code == "record_invalid"
    assert "could not confirm" in exc.public_message.lower()


def test_terminal_statuses_are_the_ones_the_drainer_must_not_retry():
    """§10.2. 400/403/409/413/415 will never succeed as-is; everything else
    (429, 5xx, network) is worth retrying forever."""
    assert TERMINAL_STATUSES == {400, 403, 409, 413, 415}
    assert 429 not in TERMINAL_STATUSES   # rate limiting is temporary
    assert 500 not in TERMINAL_STATUSES
    assert 503 not in TERMINAL_STATUSES


def test_public_messages_carry_no_internals():
    """Scan every error class's default message for anything that smells like
    infrastructure."""
    forbidden = ["psycopg", "postgres", "traceback", "sql", "/opt/", "select ",
                 "relation", "0x", "None"]
    for cls in (BadRequest, Conflict, RateLimited, ServiceUnavailable, AppError,
                RecordInvalid, MalformedParameters):
        message = cls.public_message.lower()
        for token in forbidden:
            assert token not in message, f"{cls.__name__}: {message}"


# ================================================================ REDACTION ====

def _capture(record_factory, env=None):
    """Run one log record through the real filter + formatter and return the
    emitted line."""
    previous = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        redactor = SecretRedactor()
        formatter = JsonFormatter(redactor)
        record = record_factory()
        redactor.filter(record)
        return formatter.format(record)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_f6a_database_url_is_redacted_from_an_exception():
    """THE test §14.5 asks for by name."""
    dsn = "postgresql://postgres.abcdefgh:sup3rs3cr3t@aws-0-ap-south-1.pooler.supabase.com:5432/postgres"

    def factory():
        try:
            raise RuntimeError(f"could not connect to {dsn}")
        except RuntimeError:
            import sys
            return logging.LogRecord(
                "test", logging.ERROR, __file__, 1, "connection failed", (),
                sys.exc_info())

    line = _capture(factory, env={"DATABASE_URL": dsn})

    assert dsn not in line
    assert "sup3rs3cr3t" not in line
    assert REDACTED in line


def test_secret_values_are_redacted_wherever_they_appear():
    secret = "a1b2c3d4" * 8

    def factory():
        return logging.LogRecord("test", logging.WARNING, __file__, 1,
                                 "unwrap failed for %s", (secret,), None)

    line = _capture(factory, env={"KEK": secret})
    assert secret not in line
    assert REDACTED in line


def test_keys_that_look_like_secrets_are_redacted_by_name():
    """Even a value we have never seen before: if it arrives under a key called
    *_key or *_secret or authorization, it does not get printed."""
    def factory():
        record = logging.LogRecord("test", logging.INFO, __file__, 1, "admin", (), None)
        record.tag_index_key = "never-seen-this-before"
        record.authorization = "Bearer eyJhb..."
        record.batch_ref = "AMX-2026-09-001"
        return record

    line = _capture(factory)
    payload = json.loads(line)
    assert payload["tag_index_key"] == REDACTED
    assert payload["authorization"] == REDACTED
    # Non-secret context still comes through — redaction that ate everything
    # would make the logs useless and get switched off.
    assert payload["batch_ref"] == "AMX-2026-09-001"


def test_short_values_are_not_treated_as_secrets():
    """A secret of 'ok' would turn every log line into asterisks. The floor is
    8 characters."""
    def factory():
        return logging.LogRecord("test", logging.INFO, __file__, 1,
                                 "status is ok and fine", (), None)

    line = _capture(factory, env={"KEK": "ok"})
    assert "status is ok and fine" in line


def test_log_line_is_valid_json_with_a_request_id():
    request_id_var.set("01J8ABCDEF")

    def factory():
        record = logging.LogRecord("test", logging.INFO, __file__, 1,
                                   "verify_complete", (), None)
        record.verdict = "authentic"
        return record

    payload = json.loads(_capture(factory))
    assert payload["level"] == "INFO"
    assert payload["msg"] == "verify_complete"
    assert payload["verdict"] == "authentic"
    assert payload["request_id"] == "01J8ABCDEF"
    assert "ts" in payload
