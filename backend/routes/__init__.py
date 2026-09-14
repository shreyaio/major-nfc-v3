"""Blueprint registration. ARCHITECTURE.md §9.4.

Route modules validate and serialise. Service modules decide. No business logic
in here and none in app.py.
"""
from __future__ import annotations

from flask import Flask

from routes.admin import bp as admin_bp
from routes.enrol import bp as enrol_bp
from routes.health import bp as health_bp
from routes.report import bp as report_bp
from routes.transparency import bp as transparency_bp
from routes.verify import bp as verify_bp

# Every v1 route returns 404 (D15, D16). Deleted, not disabled — a disabled route
# that still exists is a route someone re-enables. tests/integration/
# test_dead_routes.py asserts each of these.
DEAD_V1_ROUTES = (
    "/api/products",
    "/api/verify/<path:anything>",
    "/api/admin/products",
    "/api/admin/keys/<path:anything>",
    "/test-db",
)


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(health_bp)
    app.register_blueprint(enrol_bp)
    app.register_blueprint(verify_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(transparency_bp)
