"""Application factory. ARCHITECTURE.md §9.1.

v1 was 418 lines with every route inline. This file now does five things and no
business logic whatsoever: validate config, set up logging, load keys, open the
database pool, register blueprints and error handlers.

NO ROUTE LOGIC IN THIS FILE. Every handler lives in routes/, every decision in
services/. Route modules validate and serialise; service modules decide. The
verdict state machine must stay unit-testable without Flask.

Start command is pinned in render.yaml:

    gunicorn "app:create_app()" --bind 0.0.0.0:$PORT --workers 2 --threads 4 \
             --timeout 30 --graceful-timeout 10 --access-logfile - --error-logfile -

Workers are pinned at 2 deliberately. v1 left this to Render's default, which
meant the in-process rate limiter kept a separate counter per worker and its
configured limits were silently N times looser than reported (F16).
"""
from __future__ import annotations

import logging
import os

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

import audit
import auth_admin
import db
import keys
import logging_setup
from config import VERSION, load_config
from errors import AppError, NotFound, PayloadTooLarge
from routes import register_blueprints

log = logging.getLogger(__name__)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")


def create_app() -> Flask:
    cfg = load_config()            # raises on any missing/malformed secret
    logging_setup.setup_logging(cfg)
    keys.load(cfg)                 # unwrap FIELD_RECIPIENT_KEY + ROW_SIGNING_KEY
    db.init_pool(cfg)              # ThreadedConnectionPool
    audit.configure(cfg)
    auth_admin.configure(cfg)

    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
    app.config["APP_CONFIG"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_body_bytes  # D19: body size cap
    app.url_map.strict_slashes = False

    # CORS is scoped to our own origins. v1 used origins:"*" on verify, which was
    # defensible — no secrets are returned — but it also means anyone can build a
    # convincing verification page against this API, including a counterfeiter
    # running a look-alike site that always says "authentic" (F28).
    if cfg.allowed_origins:
        CORS(app, resources={r"/api/v2/*": {"origins": cfg.allowed_origins}})

    register_blueprints(app)
    register_error_handlers(app)
    register_security_headers(app)
    register_static_pages(app)

    log.info("app_started", extra={"version": VERSION,
                                   "tag_locking": cfg.tag_locking_enabled,
                                   "public_host": cfg.public_host})
    return app


# --------------------------------------------------------------- middleware ---

def register_security_headers(app: Flask) -> None:
    """§9.12. Applied to every response, not just the HTML ones.

    frame-ancestors 'none' closes C3 (clickjacking the verification page under a
    fake "authentic" overlay). No inline scripts anywhere in the frontend — the
    CSP forbids them, and that is what makes C4 (XSS via a hostile product name)
    unexploitable even if output encoding were missed somewhere.
    """
    csp = ("default-src 'none'; script-src 'self'; style-src 'self'; "
           "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
           "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

    @app.before_request
    def _assign_request_id():
        rid = logging_setup.new_request_id()
        logging_setup.request_id_var.set(rid)
        g.request_id = rid

    @app.after_request
    def _headers(response):
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), camera=(), microphone=()")
        response.headers["X-Request-Id"] = getattr(g, "request_id", "-")
        return response


def register_error_handlers(app: Flask) -> None:
    """§15.2. Every error, without exception, leaves through here."""

    @app.errorhandler(AppError)
    def _app_error(exc: AppError):
        request_id = getattr(g, "request_id", "-")
        # detail and context go to the LOG, never to the client (D23).
        log.warning("app_error", extra={"code": exc.code, "status": exc.status,
                                        "detail": exc.detail, **exc.context})
        response = jsonify(exc.to_envelope(request_id))
        if exc.retry_after is not None:
            response.headers["Retry-After"] = str(exc.retry_after)
        return response, exc.status

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_exc):
        return _app_error(PayloadTooLarge("body exceeded MAX_CONTENT_LENGTH"))

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        # Werkzeug's own 404/405/etc, normalised into our envelope so there is
        # exactly one error shape on the wire.
        mapped = AppError(exc.description, code=_code_for(exc.code or 500),
                          public_message=_public_for(exc.code or 500))
        mapped.status = exc.code or 500
        return _app_error(mapped)

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        request_id = getattr(g, "request_id", "-")
        # Any unhandled exception is a 500 with code "internal_error" and a
        # logged traceback. No route may return an ad-hoc error dict.
        log.exception("unhandled_exception", extra={"path": request.path})
        return jsonify(AppError().to_envelope(request_id)), 500


def _code_for(status: int) -> str:
    return {400: "malformed_request", 401: "unauthorized", 403: "forbidden",
            404: "not_found", 405: "method_not_allowed", 409: "conflict",
            413: "payload_too_large", 415: "unsupported_media_type",
            429: "rate_limited", 503: "service_unavailable"}.get(status, "internal_error")


def _public_for(status: int) -> str:
    return {400: "The request was not valid.",
            401: "Authentication is required.",
            403: "Not permitted.",
            404: "Not found.",
            405: "That method is not allowed here.",
            413: "The request body is too large.",
            415: "Content-Type must be application/json.",
            429: "Too many requests. Please wait and try again.",
            503: "The service is temporarily unavailable."}.get(
                status, "Something went wrong. Please try again.")


def register_static_pages(app: Flask) -> None:
    """The frontend is served same-origin so the CSP above can say 'self'."""

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/c")
    def landing():
        """The tag landing page. The edge Worker normally serves its own instant
        shell here; the origin serves the same route so that removing the Worker
        is a config change and not a redeployment of every tag in the field
        (§11.2 mitigation 1)."""
        return send_from_directory(app.static_folder, "verify.html")

    @app.get("/report")
    def report_page():
        return send_from_directory(app.static_folder, "report.html")

    @app.get("/admin")
    def admin_page():
        return send_from_directory(app.static_folder, "admin.html")

    # Every v1 route is GONE, not disabled (D15, D16). These explicit handlers
    # exist so the 404 is our envelope rather than Werkzeug's HTML, and so
    # tests/integration/test_dead_routes.py has something deterministic to
    # assert against.
    @app.route("/api/products", methods=["GET", "POST", "PUT", "DELETE"])
    @app.route("/api/verify/<path:_rest>", methods=["GET", "POST"])
    @app.route("/api/admin/products", methods=["GET", "POST"])
    @app.route("/api/admin/keys/<path:_rest>", methods=["GET", "POST"])
    @app.route("/test-db", methods=["GET", "POST"])
    def _dead_v1_route(_rest=None):
        raise NotFound("this endpoint was removed in v2")


# Local development only. Production runs gunicorn against create_app().
if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
