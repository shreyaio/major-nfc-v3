"""
Basic end-to-end functional checks. Supersedes the old ad hoc scripts
(final_checklist.py, verify_hardening.py, verify_section2.py) as real asserts.
"""

import requests

from conftest import (
    BASE_URL, build_valid_product_body, post_signed_product,
    register_valid_product, sign_request,
)


def test_health():
    r = requests.get(BASE_URL + "/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_post_products_requires_signature():
    r = requests.post(BASE_URL + "/api/products", json={"test": "data"})
    assert r.status_code == 403


def test_post_products_rejects_stale_timestamp():
    body, _, _ = build_valid_product_body()
    stale_ts = str(int(__import__("time").time()) - 60)
    r = post_signed_product(body, ts=stale_ts)
    assert r.status_code == 403


def test_post_products_valid_aes_gcm_write():
    body, tag_uid, tag_uid_hash, r = register_valid_product()
    data = r.json()
    assert data["status"] == "success"
    assert "expiry_date" in data


def test_verify_authentic_after_write():
    _, _, tag_uid_hash, _ = register_valid_product()
    r = requests.get(BASE_URL + f"/api/verify/{tag_uid_hash}")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "authentic"
    assert data["product_id"] == "PROD-TEST"


def test_verify_unknown_tag():
    r = requests.get(BASE_URL + "/api/verify/" + "0" * 64)
    assert r.status_code == 200
    assert r.json()["status"] == "unknown"


def test_admin_products_requires_key():
    r = requests.get(BASE_URL + "/api/admin/products")
    assert r.status_code == 401


def test_old_anonymous_products_route_is_gone():
    r = requests.get(BASE_URL + "/api/products")
    assert r.status_code == 404
