"""
Attack simulation: INJECTION (SQL injection).

Every database query in this codebase uses psycopg2 parameterized queries
(%s placeholders) rather than string-built SQL, so injection payloads should
be treated as inert literal text everywhere they can reach the database:
the tag_uid_hash path/query parameter (GET /api/verify, GET /api/admin/*),
and the nonce/tag_uid_hash fields in a POST /api/products body.

Real finding from running these against the live deployment: Render serves
traffic through Cloudflare, and Cloudflare's own managed WAF intercepts and
blocks several of these payloads (a 403 "Blocked" HTML page, "Server:
cloudflare") before they ever reach this Flask app at all. That's a genuine,
separate defense layer neither designed nor controlled by this codebase --
worth reporting honestly as-is rather than claiming the app-level
parameterized-query defense was what stopped it when it wasn't the layer
that actually fired. Each test below accepts EITHER outcome as safe (the
app handling it correctly, or Cloudflare blocking it earlier) and records
which one actually happened.
"""

import time

import requests

from conftest import BASE_URL, build_valid_product_body, post_signed_product, log_evidence, get_connection
from config import ADMIN_API_KEY

BASIC_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT product_id, batch_id, mfg_date FROM products --",
]

DROP_TABLE_PAYLOAD = "x'; DROP TABLE products; --"
TIME_BASED_PAYLOAD = "x'; SELECT pg_sleep(5); --"


def _products_row_count():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM products;")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count


def _table_exists(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = %s);",
        (name,),
    )
    exists = cur.fetchone()[0]
    cur.close()
    conn.close()
    return exists


def _classify_response(r):
    """Returns ('app', data) if this app's own JSON API handled the request,
    ('cloudflare_waf', None) if Cloudflare's edge blocked it first, or
    ('other', None) for anything else (e.g. our own 403/429)."""
    if r.headers.get("Server", "").lower() == "cloudflare" and r.status_code == 403 \
            and "text/html" in r.headers.get("Content-Type", ""):
        return "cloudflare_waf", None
    if r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            return "app", r.json()
        except ValueError:
            return "other", None
    return "other", None


def test_sqli_basic_payloads_return_unknown_or_are_waf_blocked():
    for payload in BASIC_PAYLOADS:
        r = requests.get(BASE_URL + "/api/verify/" + requests.utils.quote(payload, safe=""), timeout=10)
        layer, data = _classify_response(r)

        app_handled_safely = layer == "app" and r.status_code == 200 and data.get("status") == "unknown"
        waf_blocked = layer == "cloudflare_waf"

        log_evidence("injection", {
            "case": "basic_sqli_verify",
            "payload": payload,
            "status": r.status_code,
            "defense_layer": layer,
            "result": data.get("status") if data else None,
            "expected": "app returns 'unknown', OR Cloudflare WAF blocks it -- either is safe",
            "passed": app_handled_safely or waf_blocked,
        })
        assert app_handled_safely or waf_blocked, (
            f"payload {payload!r} was neither safely handled by the app nor blocked by the WAF "
            f"(got status={r.status_code}, layer={layer})"
        )


def test_sqli_drop_table_payload_does_not_drop_table():
    assert _table_exists("products"), "setup: products table should exist before this test"
    count_before = _products_row_count()

    r = requests.get(
        BASE_URL + "/api/verify/" + requests.utils.quote(DROP_TABLE_PAYLOAD, safe=""), timeout=10
    )
    layer, data = _classify_response(r)

    table_survived = _table_exists("products")
    count_after = _products_row_count() if table_survived else None

    app_handled_safely = layer == "app" and r.status_code == 200 and data.get("status") == "unknown"
    waf_blocked = layer == "cloudflare_waf"

    log_evidence("injection", {
        "case": "drop_table_payload",
        "payload": DROP_TABLE_PAYLOAD,
        "status": r.status_code,
        "defense_layer": layer,
        "table_exists_after": table_survived,
        "row_count_before": count_before,
        "row_count_after": count_after,
        "passed": table_survived and count_after is not None and count_after >= count_before
                  and (app_handled_safely or waf_blocked),
    })
    assert table_survived, "products table must still exist after the injection attempt"
    assert count_after >= count_before, "row count must not have decreased"
    assert app_handled_safely or waf_blocked


def test_sqli_time_based_blind_payload_not_executed():
    """Whichever layer handles this (app or WAF), it must not take ~5s -- that
    would mean pg_sleep(5) actually ran against the database."""
    start = time.time()
    r = requests.get(
        BASE_URL + "/api/verify/" + requests.utils.quote(TIME_BASED_PAYLOAD, safe=""), timeout=15
    )
    elapsed = time.time() - start
    layer, _ = _classify_response(r)

    log_evidence("injection", {
        "case": "time_based_blind_pg_sleep",
        "payload": TIME_BASED_PAYLOAD,
        "status": r.status_code,
        "defense_layer": layer,
        "elapsed_seconds": round(elapsed, 2),
        "expected": "well under 5s (pg_sleep(5) must not execute)",
        "passed": elapsed < 4.0,
    })
    assert elapsed < 4.0, f"response took {elapsed:.2f}s -- suggests pg_sleep(5) actually executed"


def test_sqli_payload_in_admin_products_filter_handled_safely():
    r = requests.get(
        BASE_URL + "/api/admin/products",
        params={"tag_uid_hash": "' OR '1'='1"},
        headers={"X-Admin-Key": ADMIN_API_KEY},
        timeout=10,
    )
    layer, data = _classify_response(r)

    app_handled_safely = layer == "app" and r.status_code == 200 and data.get("count") == 0
    waf_blocked = layer == "cloudflare_waf"

    log_evidence("injection", {
        "case": "admin_products_filter_sqli",
        "status": r.status_code,
        "defense_layer": layer,
        "count_returned": data.get("count") if data else None,
        "expected": "app returns 200 with zero rows, OR Cloudflare WAF blocks it",
        "passed": app_handled_safely or waf_blocked,
    })
    assert app_handled_safely or waf_blocked


def test_sqli_payload_in_write_nonce_field_stored_safely_as_text():
    """The nonce column is also reached via a parameterized INSERT. A payload
    submitted as the nonce value should either be stored as inert text by the
    app, or be blocked by Cloudflare's WAF before it gets that far -- either
    way the table must survive intact."""
    injected_nonce = "x'; DROP TABLE products; --" + str(int(time.time()))
    body, _, tag_uid_hash = build_valid_product_body(nonce=injected_nonce, product_id="INJECT-NONCE")
    r = post_signed_product(body)
    layer, data = _classify_response(r)

    table_survived = _table_exists("products")
    app_stored_safely = layer == "app" and r.status_code == 200
    waf_blocked = layer == "cloudflare_waf"

    log_evidence("injection", {
        "case": "write_nonce_field_sqli",
        "nonce_payload": injected_nonce,
        "status": r.status_code,
        "defense_layer": layer,
        "table_exists_after": table_survived,
        "expected": "app stores it safely as text (200), OR Cloudflare WAF blocks it",
        "passed": table_survived and (app_stored_safely or waf_blocked),
    })
    assert table_survived, "products table must still exist after a malicious nonce value"
    assert app_stored_safely or waf_blocked
