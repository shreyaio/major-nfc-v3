"""Scoped, short-lived admin tokens. ARCHITECTURE.md §9.10.

v1 used one static string in X-Admin-Key with no scoping, no expiry and no
rotation path (F18). v2 uses Ed25519-signed tokens minted OFFLINE by
scripts/mint_admin_token.py:

    token   = base64url(payload) + "." + base64url(ed25519_sign(payload))
    payload = {"sub": "...", "scopes": [...], "iat": ..., "exp": ..., "jti": "..."}

ADMIN_TOKEN_KEY never reaches the runtime backend — it holds only
ADMIN_TOKEN_PUBKEY. So there is no admin secret on the server to steal and none
to brute-force (D14): a forgery requires the private key, not a lucky guess.

Every admin action writes an audit row including `sub` and `jti` — who did it —
and that row is inside the hash chain.
"""
from __future__ import annotations

import base64
import functools
import json
import logging
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import g, request

import audit
from errors import Forbidden, Unauthorized

log = logging.getLogger(__name__)

# Kept in sync with scripts/mint_admin_token.py::VALID_SCOPES.
VALID_SCOPES = frozenset({
    "batch:read", "batch:write",
    "recall",
    "incident:read", "incident:write",
    "report:read", "report:write",
    "metrics:read",
})

MAX_LIFETIME_SECONDS = 12 * 3600

_pubkey: bytes = b""


def configure(cfg) -> None:
    global _pubkey
    _pubkey = cfg.admin_token_pubkey


def _b64u_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def parse_token(token: str) -> dict:
    """Verify signature, expiry and lifetime. Raises Unauthorized on any failure
    with a message that distinguishes nothing an attacker could use."""
    if not _pubkey:
        raise Unauthorized("admin token public key not configured")
    if not token or token.count(".") != 1:
        raise Unauthorized("malformed admin token")

    body_b64, sig_b64 = token.split(".", 1)
    try:
        body = _b64u_decode(body_b64)
        signature = _b64u_decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise Unauthorized("malformed admin token") from exc

    try:
        Ed25519PublicKey.from_public_bytes(_pubkey).verify(signature, body)
    except (InvalidSignature, ValueError) as exc:
        raise Unauthorized("admin token signature invalid") from exc

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise Unauthorized("admin token payload is not JSON") from exc

    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise Unauthorized("admin token is missing iat/exp")
    # Lifetime is capped at verification time as well as at minting time. A
    # minting script is a file someone can edit; this check is the one that
    # actually binds.
    if exp - iat > MAX_LIFETIME_SECONDS:
        raise Unauthorized("admin token lifetime exceeds the 12 hour maximum")
    now = time.time()
    if now >= exp:
        raise Unauthorized("admin token has expired")
    if iat - now > 60:
        raise Unauthorized("admin token is not yet valid")

    scopes = payload.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise Unauthorized("admin token has no usable scopes")
    payload["scopes"] = [s for s in scopes if s in VALID_SCOPES]
    return payload


def _token_from_request() -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("X-Admin-Token", "").strip()


def require_scope(*required: str):
    """Route decorator. Attaches the verified claims to flask.g.admin."""
    for scope in required:
        if scope not in VALID_SCOPES:
            raise ValueError(f"unknown scope in require_scope: {scope}")

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            claims = parse_token(_token_from_request())
            if not any(scope in claims["scopes"] for scope in required):
                audit.log_audit(event_type="admin", actor=claims.get("sub"),
                                result="scope_denied",
                                detail={"needed": list(required),
                                        "had": claims["scopes"],
                                        "jti": claims.get("jti")})
                raise Forbidden(f"token lacks scope: {' or '.join(required)}")
            g.admin = claims
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_subject() -> str:
    return (getattr(g, "admin", None) or {}).get("sub", "unknown")


def current_jti() -> str:
    return (getattr(g, "admin", None) or {}).get("jti", "")


def audit_admin(action: str, result: str, **detail) -> None:
    audit.log_audit(event_type="admin", actor=current_subject(), result=result,
                    detail={"action": action, "jti": current_jti(), **detail})
