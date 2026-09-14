"""Exception hierarchy and the single error envelope. ARCHITECTURE.md §15.

Binding on every module. There is no `jsonify({"error": str(e)})` anywhere in
this codebase — v1 had that in a dozen places, which leaks whatever psycopg2 felt
like saying (D23).

Envelope:

    {"error": {"code": "malformed_parameters",
               "message": "The verification link is not valid.",
               "request_id": "01J8...",
               "retry_after": null}}

Rules enforced by the global handler in app.py:

  - `message` is consumer-safe. No stack traces, no SQL, no exception repr, no
    file paths.
  - `detail` and full context go to the structured log, keyed by request_id.
    request_id is how you correlate a user report to a log line.
  - Any unhandled exception is a 500 with code "internal_error" and a logged
    traceback. No route may return an ad-hoc error dict.
  - retry_after is set on 429 and 503 and mirrored in the Retry-After header, so
    the Pi's drainer backs off correctly instead of guessing.
"""
from __future__ import annotations


class AppError(Exception):
    """Base for every error this application raises deliberately."""

    status = 500
    code = "internal_error"
    public_message = "Something went wrong. Please try again."

    def __init__(self, detail: str | None = None, *, code: str | None = None,
                 public_message: str | None = None, retry_after: int | None = None,
                 **context):
        # `detail` is for the log. `public_message` is for the client. Keeping
        # them as separate arguments is what makes the leak hard to reintroduce.
        super().__init__(detail or self.public_message)
        self.detail = detail
        self.context = context
        self.retry_after = retry_after
        if code is not None:
            self.code = code
        if public_message is not None:
            self.public_message = public_message

    def to_envelope(self, request_id: str) -> dict:
        return {"error": {"code": self.code,
                          "message": self.public_message,
                          "request_id": request_id,
                          "retry_after": self.retry_after}}


class BadRequest(AppError):
    status, code = 400, "malformed_request"
    public_message = "The request was not valid."


class Unauthorized(AppError):
    status, code = 401, "unauthorized"
    public_message = "Authentication is required."


class Forbidden(AppError):
    status, code = 403, "forbidden"
    public_message = "Not permitted."


class NotFound(AppError):
    status, code = 404, "not_found"
    public_message = "Not found."


class Conflict(AppError):
    status, code = 409, "conflict"
    public_message = "That conflicts with the current state."


class PayloadTooLarge(AppError):
    status, code = 413, "payload_too_large"
    public_message = "The request body is too large."


class UnsupportedMedia(AppError):
    status, code = 415, "unsupported_media_type"
    public_message = "Content-Type must be application/json."


class RateLimited(AppError):
    status, code = 429, "rate_limited"
    public_message = "Too many requests. Please wait and try again."


class ServiceUnavailable(AppError):
    status, code = 503, "service_unavailable"
    public_message = "The service is temporarily unavailable."


class ConfigError(AppError):
    """Raised at import/boot time. Never reaches a client — the process dies."""

    code = "config_error"


class RecordInvalid(AppError):
    """The stored row failed its Ed25519 signature check, or its ciphertext
    failed GCM authentication.

    NOT an HTTP error. It is caught by the verification service and turned into
    the `record_invalid` VERDICT, never a 500 (§15.3 rule 8). A tampered row must
    produce a calm negative answer to the consumer, not a server error.
    """

    code = "record_invalid"
    public_message = "We could not confirm this pack's record."


# --------------------------------------------------------------------------
# Named sub-errors for the enrol contract in §10.2. Each maps to exactly one
# (status, code) pair so the Pi's drainer can split terminal from retryable.
# --------------------------------------------------------------------------

class MfgDateInvalid(BadRequest):
    code = "mfg_date_invalid"
    public_message = "The manufacture date is not valid for this batch."


class DecryptFailed(BadRequest):
    code = "decrypt_failed"
    public_message = "The sealed payload failed authentication."


class BadSignature(Forbidden):
    code = "bad_signature"
    public_message = "Request signature, timestamp or device is not valid."


class TagAlreadyEnrolled(Conflict):
    code = "tag_already_enrolled"
    public_message = "This tag is already in the register."


class BatchQuotaExhausted(Conflict):
    code = "batch_quota_exhausted"
    public_message = "This batch has reached its enrolment quota."


class BatchNotOpen(Conflict):
    code = "batch_not_open"
    public_message = "This batch is not open for enrolment."


class IdempotencyConflict(Conflict):
    code = "idempotency_conflict"
    public_message = "That idempotency key was used with a different body."


class CountersignatureRequired(BadRequest):
    code = "countersignature_required"
    public_message = "A second, different person must countersign this batch."


class MalformedParameters(BadRequest):
    code = "malformed_parameters"
    public_message = "The verification link is not valid."


# Terminal for the Pi's outbox: the record will never succeed as-is, so retrying
# forever is wrong. Everything else (429, 5xx, network) is retryable. Getting
# this split wrong is how an outbox either spins forever on a permanently bad
# record or silently drops a good one (§12.3).
TERMINAL_STATUSES = frozenset({400, 403, 409, 413, 415})
