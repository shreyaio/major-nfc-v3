"""Every v1 route is GONE. ARCHITECTURE.md §9.4, §17.2 item 4.

Deleted, not disabled. A disabled route that still exists is a route somebody
re-enables during a debugging session and forgets about.

The one that matters most is /api/admin/keys/<hash>. It served KEY MATERIAL OVER
HTTP (F19, D16). There is no version of that endpoint which is acceptable, so
there is no version of it in this codebase and this test says so.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

DEAD_ROUTES = [
    ("GET", "/api/products"),
    ("POST", "/api/products"),
    ("GET", "/api/verify/abc123"),
    ("GET", "/api/verify/" + "a" * 64),
    ("GET", "/api/admin/products"),
    ("GET", "/api/admin/keys/" + "a" * 64),
    ("GET", "/test-db"),
    ("GET", "/api/v1/verify"),
    ("GET", "/.env"),
    ("GET", "/backend/.env"),
    ("GET", "/keys.local.json"),
]


@pytest.mark.parametrize("method,path", DEAD_ROUTES)
def test_v1_routes_are_404(session, base_url, method, path):
    response = session.request(method, f"{base_url}{path}", timeout=30)
    assert response.status_code == 404, f"{method} {path} returned {response.status_code}"


def test_the_key_endpoint_returns_nothing_that_looks_like_a_key(session, base_url):
    """Belt and braces: even the 404 body must not contain key material, which
    it obviously would not — but this is the endpoint whose entire history is
    leaking keys, so it gets the explicit assertion."""
    response = session.get(f"{base_url}/api/admin/keys/" + "a" * 64, timeout=30)
    assert response.status_code == 404
    body = response.text.lower()
    for token in ("key_chars", "-----begin", "aes", "private"):
        assert token not in body


def test_dead_routes_use_the_standard_error_envelope(session, base_url):
    """§15.2 — one error shape on the wire, whichever layer produced it."""
    response = session.get(f"{base_url}/api/products", timeout=30)
    body = response.json()
    assert set(body["error"]) == {"code", "message", "request_id", "retry_after"}
    assert body["error"]["code"] == "not_found"


def test_no_open_redirect_endpoints_exist(session, base_url):
    """B2. Nothing in this application redirects to a caller-supplied URL."""
    for path in ["/redirect?url=https://example.com",
                 "/r?to=https://example.com",
                 "/c?next=https://example.com&m=04A1B2C3D4E5F6x000001&t=" + "A" * 32]:
        response = session.get(f"{base_url}{path}", timeout=30, allow_redirects=False)
        assert response.status_code not in (301, 302, 303, 307, 308), path


def test_security_headers_are_present_on_every_response(session, base_url):
    """§9.12. frame-ancestors 'none' closes C3; nosniff and no-referrer are
    cheap and unconditional."""
    response = session.get(f"{base_url}/health", timeout=30)
    csp = response.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert "max-age=" in response.headers.get("Strict-Transport-Security", "")


def test_health_leaks_no_infrastructure_detail(session, base_url):
    """v1's separate /test-db route was an unauthenticated database reachability
    oracle. It is folded in here as one word with no detail (§5.1, §10.1)."""
    body = session.get(f"{base_url}/health", timeout=30).json()
    text = str(body).lower()
    for token in ("postgres://", "postgresql://", "supabase.com", "password",
                  "traceback", "psycopg"):
        assert token not in text
    assert set(body) == {"status", "version", "server_time", "posture"}
