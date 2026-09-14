"""Structured JSON logs to stdout, with secret redaction. ARCHITECTURE.md §14.5.

Render captures stdout, so that is where logs go — one JSON object per line.

The redaction filter is the load-bearing part (F6a). Any value matching a known
secret, and any key that looks like a secret, is replaced with *** before
emission. A database URL that ends up in an exception string is a credential leak
into a log aggregator that many people can read.

backend/tests/unit/test_errors.py forces an exception containing DATABASE_URL and
asserts *** appears in the emitted line.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import uuid
from contextvars import ContextVar

from config import SECRET_ENV_NAMES

REDACTED = "***"

# Keys whose values are redacted regardless of content.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(_key$|_secret$|^secret|password|passwd|token|^kek$|database_url|"
    r"authorization|x-signature|private)")

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    return uuid.uuid4().hex[:26]


class SecretRedactor(logging.Filter):
    """Replaces known secret values anywhere in the formatted record."""

    def __init__(self):
        super().__init__()
        self._values: list[str] = []
        for name in SECRET_ENV_NAMES:
            value = (os.getenv(name) or "").strip()
            # Short values would cause absurd false positives ("ok" -> "***").
            if len(value) >= 8:
                self._values.append(value)
        # Longest first, so a substring never masks the longer match.
        self._values.sort(key=len, reverse=True)

    def scrub(self, text: str) -> str:
        for secret in self._values:
            if secret in text:
                text = text.replace(secret, REDACTED)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.scrub(record.msg)
        if record.args:
            try:
                record.args = tuple(
                    self.scrub(a) if isinstance(a, str) else a for a in record.args)
            except TypeError:  # dict-style args
                pass
        if record.exc_info:
            # Format now so the traceback text passes through the scrubber below
            # rather than being rendered later, unfiltered, by the formatter.
            record.exc_text = self.scrub(
                logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


class JsonFormatter(logging.Formatter):
    RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
        "message", "asctime", "exc_text", "taskName"}

    def __init__(self, redactor: SecretRedactor):
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        for key, value in record.__dict__.items():
            if key in self.RESERVED or key.startswith("_"):
                continue
            payload[key] = REDACTED if _SECRET_KEY_PATTERN.search(key) else value
        if getattr(record, "exc_text", None):
            payload["exception"] = record.exc_text

        line = json.dumps(payload, default=str, ensure_ascii=False)
        return self._redactor.scrub(line)


def setup_logging(cfg) -> None:
    redactor = SecretRedactor()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(redactor))
    handler.addFilter(redactor)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(getattr(logging, getattr(cfg, "log_level", "INFO"), logging.INFO))

    # gunicorn installs its own handlers; route them through ours so access logs
    # are redacted too.
    for name in ("gunicorn.error", "gunicorn.access", "werkzeug"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
