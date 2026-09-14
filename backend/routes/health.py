"""/health and /metrics. ARCHITECTURE.md §10.1, §14.5."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

import db
import keys
import metrics
import ratelimit
from auth_admin import require_scope
from config import VERSION
from services.verification import ALLOWED_CRYPTO_VERSIONS

bp = Blueprint("health", __name__)


@bp.get("/health")
def health():
    """Liveness, server time, and the operating posture.

    `server_time` exists so the Pi can measure clock drift before it starts a run
    (§12.5). `posture` exists so the operating configuration is never ambiguous —
    if tag locking is off or originality checks are unavailable, that is visible
    without reading the code, and the admin console shows it as a banner.

    No database detail, no dependency versions, no connection string. v1's
    separate /test-db route was an unauthenticated database reachability oracle;
    it is folded in here as one boolean with no detail (§5.1).
    """
    cfg = current_app.config["APP_CONFIG"]
    db_ok = db.healthcheck()
    keys_ok = keys.loaded()
    status = "ok" if (db_ok and keys_ok) else "degraded"
    return jsonify({
        "status": status,
        "version": VERSION,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "posture": {
            "tag_locking": "enabled" if cfg.tag_locking_enabled else "disabled",
            "originality_policy": cfg.originality_policy,
            "crypto_versions": sorted(ALLOWED_CRYPTO_VERSIONS),
            "edge_expected": cfg.edge_expected,
            "row_signing": "ready" if keys_ok else "unavailable",
            "database": "ok" if db_ok else "unavailable",
        },
    }), (200 if status == "ok" else 503)


@bp.get("/metrics")
@require_scope("metrics:read")
def metrics_endpoint():
    ratelimit.check("metrics", ratelimit.ip_prefix(request.remote_addr))
    return jsonify({"counters": metrics.snapshot()})
