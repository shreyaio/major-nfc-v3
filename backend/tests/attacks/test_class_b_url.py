"""Class B — NDEF and URL layer. ARCHITECTURE.md §16.2.

The `m`/`t` parser (backend/mirror.py) is the single choke point for most of this
class: a strict `^[0-9A-F]{14}X[0-9A-F]{6}$` after NFKC + uppercase, a length cap
applied *before* the regex, mandatory `t`, and `getlist`-based duplicate
rejection. These are exercised here from the attacker's side against the live
route, and each writes a JSONL evidence record.

B1 is known-open (no custom domain under the free-only constraint, D6) and is
recorded as open, not ticked. B10 (NDEF record-type confusion) is a tag-layout
property proven byte-for-byte in unit/test_tag_layout.py and at enrolment
read-back; it has no backend-verify surface, so it is recorded with that pointer.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

TOKEN = "A" * 32
# 14 hex + X + 6 hex. This was "...X00001A7" (7 digits after X), which never
# matched the pattern, so B8 would have passed even with the duplicate check
# removed — the pattern would have rejected it anyway.
GOOD_M = "04A1B2C3D4E5F6X00001A"


def _verify_raw(session, base_url, query: str):
    return session.get(f"{base_url}/api/v2/verify?{query}", timeout=30)


# The edge and the origin both reject these, which is the B9 defence, but they
# label the reject differently: edge/canonicalise.js returns a specific code per
# cause, while backend/mirror.py::_canonical returns one coarse
# `malformed_parameters` for every cause. TEST_BASE_URL may legitimately be
# either layer, so the assertions accept either label and the evidence record
# carries the one actually returned. Narrowing these to a single code made the
# result a property of which URL the suite was pointed at.
OVERSIZE_CODES = frozenset({"parameter_too_long", "malformed_parameters"})
DUPLICATE_CODES = frozenset({"duplicate_parameter", "malformed_parameters"})


# ------------------------------------------------------------- known-open ------

def test_b1_homograph_lookalike_domain_is_open(evidence):
    """B1 — with no custom domain, the host is a *.workers.dev / *.onrender.com
    name that a look-alike can imitate. The only mitigation is the host printed
    on the pack (D6). Recorded as open, honestly; there is no server check that
    closes it."""
    evidence("B1", outcome="open",
             expected="open (no custom domain, D6)",
             detail={"mitigation": "printed host on pack only"})
    pytest.skip("B1 is open under the free-only, no-custom-domain constraint (§16.9)")


# ------------------------------------------------------------- redirects -------

def test_b2_no_open_redirect_endpoint_exists(session, base_url, evidence):
    """B2 — nothing in this application redirects to a caller-supplied URL, so
    there is no endpoint to abuse as an open redirect."""
    hostile = [
        "/redirect?url=https://evil.example",
        "/r?to=https://evil.example",
        f"/c?next=https://evil.example&m={GOOD_M}&t={TOKEN}",
        f"/api/v2/verify?m={GOOD_M}&t={TOKEN}&redirect=https://evil.example",
    ]
    redirected = []
    for path in hostile:
        r = session.get(f"{base_url}{path}", timeout=30, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            redirected.append((path, r.status_code, r.headers.get("Location")))
    assert not redirected, redirected

    evidence("B2", outcome="blocked", expected="no 3xx to attacker URL",
             detail={"probes": len(hostile)})


# --------------------------------------------------------------- parsing -------

def test_b3_url_parameter_injection_is_rejected(session, base_url, evidence):
    """B3 — strict charset before any use. Separators, SQL/again-shaped payloads,
    NUL, path traversal and CRLF all fail the pattern with a 400."""
    injections = [
        "04:A1:B2:C3:D4:E5:F6x00001A7",   # colon separators
        "04A1B2C3D4E5F6x00001A7' OR '1",  # sql-shaped
        "04A1B2C3D4E5F6x00001A7%00",      # NUL
        "../../etc/passwd",               # traversal
        "04A1B2C3D4E5F6x00001A7%0d%0aSet-Cookie:x=1",  # CRLF
    ]
    for bad_m in injections:
        r = session.get(f"{base_url}/api/v2/verify",
                        params={"m": bad_m, "t": TOKEN}, timeout=30)
        assert r.status_code == 400, bad_m
        assert r.json()["error"]["code"] == "malformed_parameters", bad_m

    evidence("B3", outcome="blocked", expected="400 malformed_parameters",
             detail={"variants": len(injections)})


def test_b4_oversized_parameter_is_capped_before_the_regex(session, base_url,
                                                           evidence):
    """B4 — a length cap (MAX_PARAM_LEN=64) is applied before the regex so an
    oversized value is rejected without ever running a pattern over it."""
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": "0" * 5000, "t": TOKEN}, timeout=30)
    assert r.status_code == 400
    code = r.json()["error"]["code"]
    assert code in OVERSIZE_CODES, code

    evidence("B4", outcome="blocked", expected="400, capped before the regex",
             detail={"sent_len": 5000, "code": code})


def test_b5_unicode_and_mixed_case_do_not_bypass_the_pattern(session, base_url,
                                                             make_tag, enrol,
                                                             verify, evidence):
    """B5 — NFKC-normalise then uppercase before matching. Two consequences:

      * A lowercase-hex UID is normalised to the same tag, not treated as a
        different one (so an attacker cannot dodge the counter check by changing
        case).
      * A full-width digit look-alike (e.g. U+FF10) normalises under NFKC and is
        then held to the strict ASCII-hex pattern — it does not sneak past.
    """
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    # Lowercase the whole mirror; it must resolve to the SAME tag and advance the
    # SAME counter, i.e. a replay at equal counter still diverges.
    assert verify(uid, 12, token).json()["verdict"] == "authentic"
    lower_m = f"{uid.lower()}x{12:06x}"
    replayed = _verify_raw(session, base_url, f"m={lower_m}&t={token}").json()
    assert replayed["verdict"] == "suspect_duplicate", "case-folding changed identity"

    # Full-width digits: NFKC folds them, then the pattern still governs. Either
    # it normalises to valid hex (accepted, same tag) or it is a 400 — never a
    # third, unnormalised identity.
    fullwidth = "０４" + uid[2:] + "x00000C"  # ０４....
    r = _verify_raw(session, base_url, f"m={fullwidth}&t={token}")
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.json()["verdict"] in ("suspect_duplicate", "unknown")

    evidence("B5", outcome="blocked",
             expected="normalised-then-strict; no third identity",
             detail={"lowercase_verdict": replayed["verdict"],
                     "fullwidth_status": r.status_code})


def test_b6_missing_token_fails_closed(session, base_url, evidence):
    """B6 — `t` is mandatory. There is no UID-only path; a UID is printed on the
    outside of every chip and cannot be a credential."""
    r = _verify_raw(session, base_url, f"m={GOOD_M}")
    assert r.status_code == 400
    # Deliberately strict: a MISSING parameter is not a duplicate one. The edge
    # used to report this as `duplicate_parameter`, which disagreed with the
    # origin and was misleading in logs; this assertion is what holds that fix.
    code = r.json()["error"]["code"]
    assert code == "malformed_parameters", code

    evidence("B6", outcome="blocked", expected="400, no UID-only fallback",
             detail={"code": code})


def test_b7_placeholder_passthrough_is_mirror_disabled(verify, evidence):
    """B7 — a tag whose mirror never turned on presents 00000000000000x000000.
    That is its own verdict, never UNKNOWN (which would invite a retry) and never
    AUTHENTIC."""
    body = verify("00000000000000", 0, TOKEN).json()
    assert body["verdict"] == "mirror_disabled"
    assert body["binding"] == "none"

    evidence("B7", outcome="detected", expected="mirror_disabled",
             detail={"binding": body["binding"]})


def test_b8_parameter_pollution_is_rejected(session, base_url, evidence):
    """B8 — duplicate parameters are rejected via getlist rather than silently
    resolved. This is the differential a front layer taking the last value and an
    origin taking the first would otherwise open up."""
    codes = []
    for dup in (f"m={GOOD_M}&m=04FFFFFFFFFFFFX000002&t={TOKEN}",
                f"m={GOOD_M}&t={TOKEN}&t={'B' * 32}"):
        r = _verify_raw(session, base_url, dup)
        assert r.status_code == 400, dup
        code = r.json()["error"]["code"]
        assert code in DUPLICATE_CODES, (dup, code)
        codes.append(code)

    evidence("B8", outcome="blocked", expected="400, duplicates rejected",
             detail={"codes": codes})


def test_b9_fragment_and_query_smuggling_does_not_bypass_the_origin(
        session, base_url, make_tag, enrol, verify, evidence):
    """B9 — the origin re-validates independently and never trusts an upstream
    parse. A fragment is not sent to the server at all; a smuggled extra segment
    or an encoded separator inside `m` must not produce a different identity than
    the strict parser sees. We assert the origin's own parse is authoritative:
    junk appended to a valid mirror is rejected, not silently trimmed to the
    valid prefix.
    """
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 15, token).json()["verdict"] == "authentic"

    # A smuggled second mirror hidden behind an encoded separator must NOT be
    # trimmed down to a valid prefix and accepted.
    smuggled = f"{uid}x00000F%00{uid}x000001"
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": smuggled, "t": token}, timeout=30)
    assert r.status_code == 400, "origin accepted a smuggled/oversized mirror"
    assert r.json()["error"]["code"] == "malformed_parameters"

    evidence("B9", outcome="blocked",
             expected="origin re-validates; no differential",
             detail={"note": "origin never trusts an upstream parse"})


def test_b10_ndef_record_type_confusion_is_a_tag_layout_property(evidence):
    """B10 — a single URI record, byte-compared against the intended layout at
    enrolment read-back (§12.1 step 8). This is proven exhaustively in
    unit/test_tag_layout.py; there is no backend-verify surface for it, so it is
    recorded here with that pointer rather than re-asserted against HTTP."""
    evidence("B10", outcome="blocked",
             expected="single URI record, byte-compared at enrolment",
             detail={"proven_in": "unit/test_tag_layout.py, §12.1 step 8"})
    pytest.skip("B10 is a tag-layout property; proven in unit/test_tag_layout.py")
