"""Class C — client and browser layer. ARCHITECTURE.md §16.3.

The client is untrusted by definition (§9.7): the server-side incident record is
authoritative and no claim the page makes can upgrade a verdict. That single
principle covers most of this class. The parts that are genuinely client-side —
the service worker's cache scope (C5), the "no app to impersonate" posture (C6),
and the offline blank-state copy (C10) — live in `frontend/` and are signed off
on a real Android phone and a real iPhone in §18 phase 6; they are recorded here
with that pointer rather than asserted against HTTP.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

TOKEN = "A" * 32


def test_c1_url_trust_works_on_ios_with_no_app(session, base_url, make_tag,
                                               enrol, verify, evidence):
    """C1 — the counter is inside the URL itself (the chip's ASCII mirror), so a
    verdict needs only a plain GET with `m` and `t`. No Web NFC, no app, no
    custom header — which is exactly what makes it work on iOS. We prove the
    route yields a full verdict from nothing but the two query parameters."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    # A bare GET, no User-Agent games, no Web NFC — an iPhone's Safari tap.
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": f"{uid}x{4:06X}", "t": token}, timeout=30)
    body = r.json()
    assert body["verdict"] == "authentic"
    assert body["binding"] == "counter"

    evidence("C1", outcome="blocked",
             expected="verdict from URL alone, no app",
             detail={"binding": body["binding"]})


def test_c2_shared_link_carries_a_stale_counter(make_tag, enrol, verify, evidence):
    """C2 — a screenshotted or forwarded link freezes the counter at capture
    time. Re-use is no longer strictly greater and diverges."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 20, token).json()["verdict"] == "authentic"

    shared_again = verify(uid, 20, token).json()
    assert shared_again["verdict"] == "suspect_duplicate"

    evidence("C2", outcome="detected", expected="suspect_duplicate",
             detail={"kind": shared_again["incident"]["kind"]})


def test_c3_clickjacking_is_blocked_by_frame_ancestors(session, base_url, evidence):
    """C3 — frame-ancestors 'none' means the verdict page cannot be framed and
    overlaid."""
    r = session.get(f"{base_url}/health", timeout=30)
    csp = r.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in csp

    evidence("C3", outcome="blocked", expected="frame-ancestors 'none'",
             detail={"csp_present": bool(csp)})


def test_c4_xss_via_product_fields_is_neutralised(session, base_url, make_tag,
                                                  enrol, verify, evidence):
    """C4 — a product field carrying a script payload is (a) returned as a JSON
    string, not HTML, under a strict CSP with no inline scripts, so it cannot
    execute even if a naive client injected it, and (b) round-trips byte-for-byte
    rather than being silently mangled. The API contract is JSON; rendering is
    the client's job and the CSP is its backstop."""
    marker = "<script>alert('xss')</script>"
    payload, uid, token = make_tag(enrol_counter=1, product_id=marker)
    assert enrol(payload).status_code == 201

    r = verify(uid, 4, token)
    assert r.headers["Content-Type"].split(";")[0] == "application/json"
    csp = r.headers.get("Content-Security-Policy", "")
    assert "script-src 'self'" in csp

    body = r.json()
    assert body["verdict"] == "authentic"
    # The dangerous string is data, carried safely inside JSON, not interpreted.
    assert body["product"]["name"] == marker

    evidence("C4", outcome="blocked",
             expected="JSON string under strict CSP, not executable HTML",
             detail={"content_type": "application/json",
                     "csp_script_src": "self"})


def test_c5_verdicts_are_never_cacheable_by_a_service_worker(session, base_url,
                                                             make_tag, enrol,
                                                             verify, evidence):
    """C5 — the server marks every verdict no-store, so even a misbehaving or
    poisoned service worker has nothing cacheable to replay. The SW's own narrow
    scope is a frontend property signed off in §18 phase 6."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    r = verify(uid, 4, token)
    assert r.headers.get("Cache-Control") == "no-store"

    evidence("C5", outcome="blocked", expected="Cache-Control: no-store on verdicts",
             detail={"frontend_scope": "SW cache scope proven §18 phase 6"})


def test_c6_no_verification_app_exists_to_impersonate(evidence):
    """C6 — there is no first-party app whose look and feel a fake could clone;
    verification is a plain web page at a canonical, published host. This is a
    design posture (no attack surface), recorded as such."""
    evidence("C6", outcome="blocked",
             expected="no app to impersonate; canonical host published",
             detail={"where": "§13.3"})
    pytest.skip("C6 is a no-app design posture; canonical host published (§13.3)")


def test_c7_web_nfc_permission_denial_never_blocks_a_verdict(make_tag, enrol,
                                                             verify, evidence):
    """C7 — a verdict is never gated on the Web NFC permission. Whether or not the
    page performed a live read, the counter-in-URL path still returns a full
    verdict; the live read only ever *upgrades the reported binding label*."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    no_permission = verify(uid, 4, token).json()          # permission denied
    with_live_read = verify(uid, 5, token, live=True).json()

    assert no_permission["verdict"] == with_live_read["verdict"] == "authentic"
    assert no_permission["binding"] == "counter"
    assert with_live_read["binding"] == "counter+liveread"

    evidence("C7", outcome="blocked",
             expected="verdict independent of Web NFC permission",
             detail={"no_perm_binding": no_permission["binding"],
                     "live_binding": with_live_read["binding"]})


def test_c8_a_lying_live_flag_cannot_upgrade_the_verdict(make_tag, enrol, verify,
                                                         evidence):
    """C8 — the client is untrusted. `live=1` is only a claim; it can move the
    binding LABEL but never the verdict. A tampering extension that forges the
    flag gains nothing, because the counter check is server-side and
    authoritative."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 10, token).json()["verdict"] == "authentic"

    # Client LIES that it did a live read while replaying a stale counter.
    lied = verify(uid, 10, token, live=True).json()
    assert lied["verdict"] == "suspect_duplicate", "live flag upgraded a divergence"

    evidence("C8", outcome="blocked",
             expected="server-side verdict overrides client claim",
             detail={"verdict": lied["verdict"]})


def test_c9_verdicts_are_never_cached(make_tag, enrol, verify, evidence):
    """C9 — a cached verdict is a verdict that outlives the counter check."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    r = verify(uid, 4, token)
    assert r.headers.get("Cache-Control") == "no-store"

    evidence("C9", outcome="blocked", expected="Cache-Control: no-store")


def test_c10_offline_blank_state_is_an_explicit_client_verdict(evidence):
    """C10 — when the phone is offline the page shows an explicit "cannot verify"
    state, never a blank screen that reads as either pass or fail. The `offline`
    value is even accepted by the report channel so a consumer can report from
    that state. The rendering is a frontend property signed off on real devices
    in §18 phase 6."""
    evidence("C10", outcome="blocked",
             expected="explicit cannot-verify state (client)",
             detail={"proven_in": "frontend/, §13.5, §18 phase 6"})
    pytest.skip("C10 is a client offline-state property; proven §18 phase 6")
