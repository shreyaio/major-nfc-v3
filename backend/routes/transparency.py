"""GET /.well-known/transparency/latest. ARCHITECTURE.md §10.6, §14.3.

Public and unauthenticated on purpose. The whole value of a transparency log is
that a third party who trusts nobody here can fetch the signed root, fetch the
published log from GitHub, and check them against each other.

The signature is made by TRANSPARENCY_KEY, which is a GitHub Actions secret and
NEVER on the runtime backend. This route serves a signed object it cannot itself
have produced — that is the point.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from errors import NotFound
from services import transparency as transparency_svc

bp = Blueprint("transparency", __name__)


@bp.get("/.well-known/transparency/latest")
def latest():
    root = transparency_svc.latest_root()
    if root is None:
        raise NotFound("no transparency root has been published yet")
    cfg = current_app.config["APP_CONFIG"]
    root["pubkey"] = getattr(cfg, "transparency_pubkey", "") or ""
    return jsonify(root)
