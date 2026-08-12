"""
Admin authentication: a static API key checked via constant-time comparison,
sent as the X-Admin-Key header. Appropriate for a small, single-operator admin
surface — not a general auth system.
"""

import hmac
from functools import wraps
from flask import request, jsonify
from config import ADMIN_API_KEY
from audit import log_audit


def require_admin_key(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        supplied = request.headers.get("X-Admin-Key", "")
        if not ADMIN_API_KEY or not hmac.compare_digest(supplied, ADMIN_API_KEY):
            log_audit(
                event_type="auth_failure",
                result="bad_admin_key",
                source_ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                detail={"path": request.path},
            )
            return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped
