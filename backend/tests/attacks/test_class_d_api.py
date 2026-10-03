"""Class D — API and protocol layer. ARCHITECTURE.md §16.4 (D1..D32).

The enrolment contract is signature-before-parse: transport gates, a
device_registry lookup, an Ed25519 signature over the RAW body bytes, a two-sided
timestamp window and idempotency all run before a single field is parsed (§9.5).
The verify contract adds an anti-oracle layer: one response shape, no 404, and a
response-time floor. This file drives both from the attacker's side.

Two items are not honestly testable from a CI runner and are recorded as such
with a pointer, rather than faked:
  * D20 (slowloris / slow POST) is an edge-timeout + gunicorn --timeout property.
  * D21 (verify enumeration) depends on the edge KV limiter and a PINNED worker
    count (§17.3); the origin limiter is only the backstop and a flood from one
    runner is not a defensible measurement.

D25..D32 were carried back from the v1 seven-category suite (SQL injection and
the two brute-force floods), which was deleted in 7e06ce2 when this matrix
replaced it. They are re-expressed against the v2 routes rather than restored
verbatim — the surfaces they targeted (a `nonce` body field, a UID-only verify
lookup) no longer exist. The floods carry `@pytest.mark.flood` and must run
last; see README.md.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

import pytest

pytestmark = pytest.mark.integration

TOKEN = "A" * 32


def _raw(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# =============================================================== SIGNATURES ====

def test_d1_unsigned_enrolment_is_rejected_before_parsing(session, base_url,
                                                          make_tag, evidence):
    """D1 — no signature headers at all. The body never reaches a parser: the
    device lookup / signature gate fails first."""
    payload, _, _ = make_tag()
    r = session.post(f"{base_url}/api/v2/enrol", data=_raw(payload),
                    headers={"Content-Type": "application/json"}, timeout=30)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "bad_signature"

    evidence("D1", outcome="blocked", expected="403 bad_signature")


def test_d2_a_forged_signature_is_rejected(session, base_url, make_tag,
                                           sign_request, evidence):
    """D2 — a syntactically valid but wrong signature."""
    payload, _, _ = make_tag()
    raw = _raw(payload)
    headers = sign_request(raw)
    headers["X-Signature"] = "00" * 64
    r = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers, timeout=30)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "bad_signature"

    evidence("D2", outcome="blocked", expected="403 bad_signature")


def test_d3_a_valid_signature_from_an_untrusted_key_is_rejected(
        session, base_url, make_tag, sign_request, evidence):
    """D3 — a well-formed request signed by a device that is not in the registry
    (or is not `active`) is refused. A good signature is necessary, not
    sufficient."""
    payload, _, _ = make_tag()
    raw = _raw(payload)
    headers = sign_request(raw)
    headers["X-Device-Id"] = str(uuid.uuid4())  # valid uuid, not registered
    r = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers, timeout=30)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "bad_signature"

    evidence("D3", outcome="blocked", expected="403 bad_signature")


def test_d4_signature_splicing_body_tamper_is_rejected(session, base_url,
                                                       make_tag, sign_request,
                                                       evidence):
    """D4 — the signature covers sha256(raw body) + timestamp + idempotency key,
    so one changed body byte breaks it, and the check happens before the parse."""
    payload, _, _ = make_tag(enrol_counter=3)
    raw = _raw(payload)
    headers = sign_request(raw)
    tampered = raw.replace(b'"enrol_counter":3', b'"enrol_counter":0')
    assert tampered != raw, "payload shape changed; adjust the tamper"
    r = session.post(f"{base_url}/api/v2/enrol", data=tampered, headers=headers,
                    timeout=30)
    assert r.status_code == 403

    evidence("D4", outcome="blocked", expected="403 (signature covers the body)")


def test_d5_a_verbatim_replay_returns_the_stored_response(make_tag, enrol,
                                                          evidence):
    """D5 — the outbox retries until a 2xx, so the same request arrives many
    times. A replay returns the stored response with 200 (not a second 201) and
    does not enrol twice."""
    payload, _, _ = make_tag()
    key = str(uuid.uuid4())
    first = enrol(payload, idempotency_key=key)
    assert first.status_code == 201
    second = enrol(payload, idempotency_key=key)
    assert second.status_code == 200
    assert second.json() == first.json()

    evidence("D5", outcome="blocked", expected="200 replay of stored response",
             detail={"first": 201, "replay": 200})


def test_d6_a_fresh_signature_over_a_used_key_still_replays(make_tag, enrol,
                                                            evidence):
    """D6 — re-signing the same body under the same idempotency key (a fresh
    timestamp, a fresh signature) does not create a second enrolment: the
    request_hash matches, so the stored response is returned again."""
    payload, _, _ = make_tag()
    key = str(uuid.uuid4())
    first = enrol(payload, idempotency_key=key)
    assert first.status_code == 201

    # New timestamp -> new signature bytes, same key, same body.
    resigned = enrol(payload, idempotency_key=key,
                     timestamp=str(int(time.time())))
    assert resigned.status_code == 200
    assert resigned.json() == first.json()

    evidence("D6", outcome="blocked", expected="200 replay; request_hash matches")


def test_d7_a_stale_timestamp_is_rejected(make_tag, enrol, evidence):
    """D7 — a timestamp behind the two-sided ±window."""
    payload, _, _ = make_tag()
    r = enrol(payload, timestamp=str(int(time.time()) - 120))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "bad_signature"

    evidence("D7", outcome="blocked", expected="403 bad_signature (stale ts)")


def test_d8_a_future_timestamp_is_rejected(make_tag, enrol, evidence):
    """D8 — the window is two-sided: a clock ahead of the server is as much of a
    problem as one behind, and it is explicitly tested this time."""
    payload, _, _ = make_tag()
    r = enrol(payload, timestamp=str(int(time.time()) + 120))
    assert r.status_code == 403

    evidence("D8", outcome="blocked", expected="403 (future ts)")


# ============================================================== IDEMPOTENCY ====

def test_d9_same_key_different_body_is_a_conflict(make_tag, enrol, evidence):
    """D9 — the idempotency key is inside the signature so it cannot be swapped,
    and reusing it for different content is a 409, never a silent replay of the
    wrong stored response."""
    first_payload, _, _ = make_tag()
    second_payload, _, _ = make_tag()
    key = str(uuid.uuid4())
    assert enrol(first_payload, idempotency_key=key).status_code == 201
    conflict = enrol(second_payload, idempotency_key=key)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"

    evidence("D9", outcome="blocked", expected="409 idempotency_conflict")


def test_d10_re_enrolment_shadowing_is_rejected(make_tag, enrol,
                                                field_recipient_pub, test_batch,
                                                evidence):
    """D10 — products.tag_index is UNIQUE. A second enrolment of the same tag
    under a NEW idempotency key is a 409, never a quiet overwrite."""
    import crypto_envelope
    payload, uid, _ = make_tag()
    assert enrol(payload).status_code == 201

    token_hex = secrets.token_bytes(16).hex().upper()
    sealed = crypto_envelope.seal_record(
        {"product_id": "SECOND-ATTEMPT", "batch_id": test_batch["batch_ref"],
         "mfg_date": test_batch["mfg_date"], "tag_uid": uid},
        field_recipient_pub)
    duplicate = {**payload,
                 "binding_token_hash": hashlib.sha256(token_hex.encode()).hexdigest(),
                 "sealed": sealed}
    r = enrol(duplicate, idempotency_key=str(uuid.uuid4()))
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "tag_already_enrolled"

    evidence("D10", outcome="blocked", expected="409 tag_already_enrolled")


# ================================================================== CRYPTO =====

def test_d11_cross_tag_ciphertext_substitution_fails(make_tag, enrol, evidence):
    """D11 — per-record DEK + per-field AAD. Swapping two sealed fields, or
    corrupting one, is an authentication failure, not a clever substitution."""
    payload, _, _ = make_tag()
    sealed = payload["sealed"]
    sealed["tag_uid"], sealed["mfg_date"] = sealed["mfg_date"], sealed["tag_uid"]
    r = enrol(payload)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "decrypt_failed"

    evidence("D11", outcome="blocked", expected="400 decrypt_failed (per-field AAD)")


def test_d12_expiry_extension_via_the_database_is_a_rowsig_property(evidence):
    """D12 — expiry_date is inside the Ed25519 row signature, so editing it
    directly in the database breaks the signature and the row reads as
    RECORD_INVALID. This is proven in unit/test_rowsig.py (a DB-write attack has
    no HTTP surface); recorded here with that pointer."""
    evidence("D12", outcome="blocked",
             expected="expiry_date inside row signature",
             detail={"proven_in": "unit/test_rowsig.py, §7.4"})
    pytest.skip("D12 is a row-signature property; proven in unit/test_rowsig.py")


def test_d13_crypto_downgrade_is_a_hard_reject(make_tag, enrol, evidence):
    """D13 — the crypto_version allow-list is of exactly one. Anything else is a
    hard reject at enrolment, never a fallback (and the same value is pinned by
    the row signature and a DB CHECK for the DB-write path)."""
    rejected = []
    for version in ("paper_v1", "aes_gcm_v1", "none", ""):
        payload, _, _ = make_tag()
        payload["crypto_version"] = version
        r = enrol(payload, idempotency_key=str(uuid.uuid4()))
        rejected.append((version, r.status_code))
        assert r.status_code == 400, version

    evidence("D13", outcome="blocked", expected="400 for any non-allow-listed version",
             detail={"rejected": rejected})


# ================================================================== ADMIN ======

def test_d14_admin_tokens_have_no_secret_to_brute_force(session, base_url, evidence):
    """D14 — admin auth is Ed25519-signed tokens verified against a PUBLIC key.
    There is no shared secret on the server to guess. Garbage and well-shaped
    forgeries are both refused."""
    forgeries = [
        "not-a-token",
        "a.b",
        secrets.token_urlsafe(32) + "." + secrets.token_urlsafe(64),
        "e30." + secrets.token_urlsafe(64),  # base64url("{}") . junk sig
    ]
    statuses = []
    for tok in forgeries:
        r = session.get(f"{base_url}/api/v2/admin/batches",
                       headers={"Authorization": f"Bearer {tok}"}, timeout=30)
        statuses.append(r.status_code)
        assert r.status_code in (401, 403), tok

    evidence("D14", outcome="blocked", expected="401/403; no secret to guess",
             detail={"statuses": statuses})


def test_d15_admin_route_enumeration_yields_nothing(session, base_url, evidence):
    """D15 — admin paths are all under one prefix and all require a scoped token;
    an unknown admin path is a 404 and a known one without a token is 401. Neither
    leaks structure."""
    no_token = session.get(f"{base_url}/api/v2/admin/batches", timeout=30)
    assert no_token.status_code == 401
    unknown = session.get(f"{base_url}/api/v2/admin/does-not-exist", timeout=30)
    assert unknown.status_code in (401, 404)

    evidence("D15", outcome="blocked", expected="401 without token, 404 unknown",
             detail={"no_token": no_token.status_code, "unknown": unknown.status_code})


def test_d16_legacy_key_endpoint_is_deleted(session, base_url, evidence):
    """D16 — /api/admin/keys/* served key material over HTTP in v1. It is deleted,
    not disabled, and even the 404 body carries nothing key-shaped."""
    r = session.get(f"{base_url}/api/admin/keys/" + "a" * 64, timeout=30)
    assert r.status_code == 404
    body = r.text.lower()
    for token in ("key_chars", "-----begin", "private", "aes"):
        assert token not in body

    evidence("D16", outcome="blocked", expected="404, no key material")


# ============================================================ TRANSPORT GATES ==

def test_d17_http_method_confusion_is_rejected(session, base_url, evidence):
    """D17 — an explicit method allow-list. GET on the enrol route never reaches
    the handler.

    The two layers answer differently and both are correct. The edge states the
    allow-list and returns 405. The ORIGIN cannot: app.py builds Flask with
    static_url_path="", so a catch-all `/<path:filename>` GET rule exists and
    Werkzeug prefers it over the POST-only enrol rule, giving 404 from the static
    handler. Asserting 405 alone made this a test of which URL the suite was
    pointed at; 404 is in fact the quieter answer, since it does not confirm the
    route exists."""
    r = session.get(f"{base_url}/api/v2/enrol", timeout=30)
    assert r.status_code in (405, 404), r.status_code
    layer = "edge" if r.status_code == 405 else "origin_static_shadow"

    evidence("D17", outcome="blocked", expected="GET /enrol never reaches the handler",
             detail={"status": r.status_code, "answered_by": layer})


def test_d18_content_type_confusion_is_415(session, base_url, make_tag,
                                           sign_request, evidence):
    """D18 — a strict application/json check returns 415 for anything else."""
    payload, _, _ = make_tag()
    raw = _raw(payload)
    headers = sign_request(raw)
    headers["Content-Type"] = "text/plain"
    r = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers, timeout=30)
    assert r.status_code == 415

    evidence("D18", outcome="blocked", expected="415 unsupported_media_type")


def test_d19_json_bomb_and_oversize_are_rejected(session, base_url, sign_request,
                                                 evidence):
    """D19 — depth is bounded before anything walks the structure (billion-laughs
    shape), and an oversized body is a 413 before it is parsed."""
    # Deeply nested.
    nested = {"schema": "nfcmed.enrol.v2"}
    cursor = nested
    for _ in range(60):
        cursor["next"] = {}
        cursor = cursor["next"]
    raw = _raw(nested)
    headers = sign_request(raw)
    deep = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                       timeout=30)
    assert deep.status_code == 400

    # Oversized.
    big = json.dumps({"schema": "nfcmed.enrol.v2", "pad": "x" * 200_000}).encode()
    big_headers = sign_request(big)
    oversize = session.post(f"{base_url}/api/v2/enrol", data=big, headers=big_headers,
                           timeout=30)
    assert oversize.status_code == 413

    evidence("D19", outcome="blocked", expected="400 deep, 413 oversize",
             detail={"deep": deep.status_code, "oversize": oversize.status_code})


def test_d20_slowloris_slow_post_is_an_edge_and_timeout_property(evidence):
    """D20 — slow-body attacks are absorbed by the edge Worker's timeouts and the
    gunicorn --timeout 30 backstop (§11.1). Holding a socket open slowly from a CI
    runner does not measure that honestly and would be flaky; recorded with the
    pointer instead of faked."""
    evidence("D20", outcome="inconclusive",
             expected="edge timeout + gunicorn --timeout 30",
             detail={"where": "§9, §11.1"})
    pytest.skip("D20 is a timeout property (edge + gunicorn); not CI-measurable")


def test_d21_verify_enumeration_needs_the_edge_limiter_and_a_pinned_worker_count(
        server_config, evidence):
    """D21 — per-tag rate limiting lives in the edge KV limiter (global across
    edge locations); the Postgres origin limiter is only the backstop for a direct
    origin hit. A defensible enumeration measurement requires the edge deployed
    AND a pinned worker count (§17.3, F16). We record the posture and defer the
    measurement to the phase-8 run that has both."""
    edge = server_config.get("posture", {}).get("edge_expected")
    evidence("D21", outcome=("blocked" if edge else "inconclusive"),
             expected="edge KV per-tag limit + negative-lookup cache",
             detail={"edge_expected": edge,
                     "note": "needs pinned worker count (§17.3)"})
    pytest.skip("D21 needs the edge limiter + a pinned worker count (§17.3)")


def test_d22_response_time_floor_hides_the_registration_oracle(make_tag, enrol,
                                                               verify, evidence):
    """D22 — an `unknown` costs one indexed lookup; an `authentic` adds an X25519
    unwrap plus four GCM decryptions. A response-time floor removes the
    deterministic difference. We assert the floor is APPLIED (both clear it),
    which is testable, rather than trying to measure statistical
    indistinguishability over a network, which a CI runner cannot do honestly."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    def elapsed_ms(fn):
        start = time.perf_counter()
        fn()
        return (time.perf_counter() - start) * 1000

    known = elapsed_ms(lambda: verify(uid, 4, token))
    unknown = elapsed_ms(lambda: verify("04DDDDDDDDDDDD", 4, TOKEN))
    assert known >= 100, f"known returned in {known:.0f}ms; floor not applied"
    assert unknown >= 100, f"unknown returned in {unknown:.0f}ms; floor not applied"

    evidence("D22", outcome="blocked", expected="both clear the response-time floor",
             detail={"known_ms": round(known), "unknown_ms": round(unknown)})


def test_d23_error_messages_do_not_leak_internals(session, base_url, evidence):
    """D23 — every error is the §15.2 envelope: a consumer-safe message, a
    request_id for correlation, and nothing else. No stack trace, no SQL, no
    connection string, no exception repr."""
    # Force a few different error paths.
    responses = [
        session.get(f"{base_url}/api/v2/verify?m=zzz&t={TOKEN}", timeout=30),
        session.get(f"{base_url}/api/products", timeout=30),
        session.post(f"{base_url}/api/v2/enrol", data=b"not json",
                     headers={"Content-Type": "application/json"}, timeout=30),
    ]
    for r in responses:
        body = r.json()
        assert set(body["error"]) == {"code", "message", "request_id", "retry_after"}
        text = json.dumps(body).lower()
        for leak in ("traceback", "psycopg", "postgres", "select ", "  file \"",
                     "line ", "0x7f"):
            assert leak not in text, (r.url, leak)

    evidence("D23", outcome="blocked", expected="envelope only; no internals",
             detail={"paths_checked": len(responses)})


def test_d24_connection_pool_is_not_exhausted_by_sequential_load(make_tag, enrol,
                                                                 verify, evidence):
    """D24 — the pooled context manager always returns its connection, even on the
    error path. A burst of requests that each open and use a connection must not
    leak the pool dry.

    A leaked pool shows up as 5xx (service_unavailable once no connection can be
    acquired), NEVER as 429. So the assertion is on the absence of 5xx, not on
    every request returning 200: through the edge, 40 verifies of ONE tag crosses
    the per-tag KV bound (LIMITS.tag = 30/hour, edge/src/ratelimit.js) and the
    tail is legitimately rate-limited. Demanding 200 forty times made this test
    pass only when pointed at the origin, and it measured the limiter rather than
    the pool."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    served, limited = 0, 0
    counter = 2
    for _ in range(40):
        counter += 1
        r = verify(uid, counter, token)
        assert r.status_code < 500, f"pool leak: {r.status_code} {r.text}"
        assert r.status_code in (200, 429), r.status_code
        if r.status_code == 200:
            served += 1
        else:
            limited += 1
    assert served + limited == 40
    assert served > 0, "every request was rate-limited; the pool was not exercised"

    evidence("D24", outcome="blocked", expected="no pool leak under a burst",
             detail={"requests": 40, "served": served, "rate_limited": limited})


# =============================================================== INJECTION =====
#
# D25..D30 — SQL injection, carried over from the v1 seven-category suite
# (tests/test_injection.py, deleted in 7e06ce2) and re-expressed against the v2
# routes. The v1 cases targeted a `nonce` body field and an admin filter that no
# longer exist, so the equivalent surfaces are used instead: the strict `m`/`t`
# mirror parameters, the admin `?status=` filter, and the `X-Idempotency-Key`
# header.
#
# Every case records `defense_layer` in its evidence detail. That attribution is
# the point of the category: it separates payloads stopped at the edge from
# payloads that reach the app and are neutralised by a parameterised query, and
# a claim that "the WAF caught it" is not citable without it.

SQLI_PAYLOADS = {
    "tautology": "' OR '1'='1",
    "union": "' UNION SELECT NULL,NULL,NULL--",
    "drop": "'; DROP TABLE products;--",
    "sleep": "'; SELECT pg_sleep(5);--",
}


def _defense_layer(response) -> str:
    """Which layer rejected this request.

    The app answers every error with the §15.2 JSON envelope. The edge does not:
    a WAF block is HTML (or an empty body) with a `cf-ray` / `server: cloudflare`
    header and no envelope. Anything 2xx reached the app and was answered
    normally — for an injection payload that means the query was parameterised
    and simply matched nothing.
    """
    server = response.headers.get("server", "").lower()
    edge_marked = "cloudflare" in server or "cf-ray" in response.headers

    try:
        code = response.json()["error"]["code"]
    except (ValueError, KeyError, TypeError):
        code = None

    if response.ok:
        return "app"
    if code is not None:
        return "app"
    return "edge" if edge_marked else "edge_or_proxy"


def test_d25_tautology_payload_in_verify_is_rejected(session, base_url, evidence):
    """D25 — the classic `' OR '1'='1` against the verify parameters.

    v1 expected `unknown` here, because `m` reached a lookup more or less as
    given. v2 never gets that far: `m` must match M_PATTERN (14 hex, `x`, 6 hex)
    before anything touches the database, so the payload dies in the parser with
    `malformed_parameters`. Either a 400 from the app or a block at the edge is a
    pass; a 200 with a verdict would mean the pattern gate had been removed.
    """
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": SQLI_PAYLOADS["tautology"], "t": "0" * 32},
                    timeout=30)
    layer = _defense_layer(r)
    assert r.status_code in (400, 403), r.text
    if layer == "app":
        assert r.json()["error"]["code"] == "malformed_parameters"

    evidence("D25", outcome="blocked",
             expected="400 malformed_parameters, or an edge block",
             detail={"payload": "tautology", "status": r.status_code,
                     "defense_layer": layer})


def test_d26_union_extraction_payload_in_verify_is_rejected(session, base_url,
                                                            evidence):
    """D26 — UNION-based column extraction. Same gate as D25; recorded as its own
    ID because the WAF rule that catches a UNION is not the one that catches a
    tautology, and the defense_layer split is the thing being measured."""
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": SQLI_PAYLOADS["union"], "t": "0" * 32},
                    timeout=30)
    layer = _defense_layer(r)
    assert r.status_code in (400, 403), r.text

    evidence("D26", outcome="blocked",
             expected="400 malformed_parameters, or an edge block",
             detail={"payload": "union", "status": r.status_code,
                     "defense_layer": layer})


def test_d27_drop_table_payload_leaves_the_schema_intact(session, base_url,
                                                         admin_token, make_tag,
                                                         enrol, verify, evidence):
    """D27 — the destructive one. Rejection alone is not the assertion; the
    assertion is that the schema and the data are still there afterwards.

    There is no DB handle in this suite by design (§17.3 — black box over HTTP),
    so "unchanged" is established through the API: a batch count taken before and
    after, plus a live enrol+verify round trip that would fail outright if
    `products` had been dropped.
    """
    def batch_count() -> int:
        r = session.get(f"{base_url}/api/v2/admin/batches",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        timeout=30)
        assert r.status_code == 200, r.text
        return len(r.json()["batches"])

    before = batch_count()

    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": SQLI_PAYLOADS["drop"], "t": "0" * 32},
                    timeout=30)
    layer = _defense_layer(r)
    assert r.status_code in (400, 403), r.text

    after = batch_count()
    assert after == before, "batch rows changed across a DROP TABLE payload"

    # The strongest available proof that `products` survived: write one and read
    # it back.
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    assert verify(uid, 2, token).status_code == 200

    evidence("D27", outcome="blocked",
             expected="rejected; batch count and enrol/verify round trip intact",
             detail={"payload": "drop_table", "status": r.status_code,
                     "defense_layer": layer,
                     "batches_before": before, "batches_after": after})


def test_d28_time_based_blind_payload_does_not_execute(session, base_url,
                                                       server_config, evidence):
    """D28 — `pg_sleep(5)`. A blind-injection payload proves itself by the clock,
    so the measurement is elapsed time, not the status code.

    The verify handler has a deliberate response-time floor (D22), so the budget
    is the floor plus slack, not zero. It still has to land nowhere near 5s.
    """
    floor_ms = server_config.get("config", {}).get("verify_time_floor_ms", 0)
    budget_s = (floor_ms / 1000) + 2.0

    started = time.perf_counter()
    r = session.get(f"{base_url}/api/v2/verify",
                    params={"m": SQLI_PAYLOADS["sleep"], "t": "0" * 32},
                    timeout=30)
    elapsed = time.perf_counter() - started

    layer = _defense_layer(r)
    assert r.status_code in (400, 403), r.text
    assert elapsed < budget_s, f"took {elapsed:.2f}s - pg_sleep may have executed"

    evidence("D28", outcome="blocked",
             expected=f"rejected in well under 5s (budget {budget_s:.1f}s)",
             detail={"payload": "pg_sleep", "status": r.status_code,
                     "defense_layer": layer,
                     "elapsed_s": round(elapsed, 3),
                     "budget_s": round(budget_s, 3),
                     "time_floor_ms": floor_ms})


def test_d29_payload_in_the_admin_status_filter_matches_nothing(session, base_url,
                                                                admin_token,
                                                                evidence):
    """D29 — the one payload that is *supposed* to reach the app.

    `GET /api/v2/admin/batches?status=` goes to `batch_svc.list_batches`, which
    appends `WHERE status = %s` and passes the value as a bound parameter. The
    payload is neither blocked nor escaped — it is simply a string that no row's
    status equals. 200 with zero batches is the correct defended outcome, and it
    is a different mechanism from the five above.
    """
    r = session.get(f"{base_url}/api/v2/admin/batches",
                    params={"status": SQLI_PAYLOADS["tautology"]},
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=30)
    layer = _defense_layer(r)

    if r.status_code == 403 and layer != "app":
        # The edge got there first. Still defended, but it did not demonstrate
        # the parameterised query, so say that rather than claiming it did.
        evidence("D29", outcome="blocked",
                 expected="200 with zero rows (parameterised)",
                 detail={"payload": "tautology", "status": 403,
                         "defense_layer": layer,
                         "note": "blocked at the edge; app layer not exercised"})
        pytest.skip("edge blocked the payload before the parameterised query ran")

    assert r.status_code == 200, r.text
    assert r.json()["batches"] == [], "a SQLi payload matched rows"

    evidence("D29", outcome="blocked",
             expected="200 with zero rows (parameterised query)",
             detail={"payload": "tautology", "status": 200,
                     "defense_layer": "app", "rows": 0})


def test_d30_payload_in_the_idempotency_key_is_rejected(session, base_url,
                                                        make_tag, sign_request,
                                                        evidence):
    """D30 — v1 put this payload in the write body's `nonce` field. There is no
    nonce field now; the per-request uniqueness token is the `X-Idempotency-Key`
    header, which must parse as a UUID (§9.5 step 5). Because the key is inside
    the signed payload, substituting a payload for it breaks the signature first
    — so this is a 403 bad_signature, or a 400 from the uuid check if the caller
    signed the payload itself. Either way it is never a stored string.
    """
    payload, _, _ = make_tag()
    raw = _raw(payload)
    headers = sign_request(raw)
    headers["X-Idempotency-Key"] = SQLI_PAYLOADS["tautology"]

    r = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                     timeout=30)
    layer = _defense_layer(r)
    assert r.status_code in (400, 403), r.text
    if layer == "app":
        assert r.json()["error"]["code"] in ("malformed_request", "bad_signature")

    evidence("D30", outcome="blocked",
             expected="400 malformed_request (key must be a uuid)",
             detail={"payload": "tautology", "status": r.status_code,
                     "defense_layer": layer})


# ============================================================== BRUTE FORCE ====
#
# D31..D32 — the two flood cases from v1's test_zz_bruteforce.py. The `zz` prefix
# was load-bearing: a flood exhausts the limiter, so it has to run last or it
# poisons every test after it with spurious 429s. Pytest runs files in
# alphabetical order and functions in file order, so being at the bottom of
# class D is NOT sufficient on its own — these carry `@pytest.mark.flood` and
# the runbook orders them last (see README).
#
# Both are honest about D21's caveat: a flood from one runner against an unknown
# worker count measures the per-worker limit, not the configured one. The
# evidence row records `worker_count` (the conftest recorder always does) so the
# number is interpretable rather than just large.

FLOOD_WRITES = 40
FLOOD_VERIFIES = 30


@pytest.mark.flood
def test_d31_write_flood_with_random_signatures_is_fully_rejected(
        session, base_url, make_tag, sign_request, evidence):
    """D31 — 40 enrolment attempts carrying random signatures. Every one must be
    rejected (403) or rate-limited (429). A single 201 is a total failure of the
    signature gate, so the assertion is on the absence of any success, not on the
    ratio between the two rejection modes."""
    payload, _, _ = make_tag()
    raw = _raw(payload)

    statuses: list[int] = []
    for _ in range(FLOOD_WRITES):
        headers = sign_request(raw)
        headers["X-Signature"] = secrets.token_hex(64)
        headers["X-Idempotency-Key"] = str(uuid.uuid4())
        r = session.post(f"{base_url}/api/v2/enrol", data=raw, headers=headers,
                         timeout=30)
        statuses.append(r.status_code)

    counts = {str(s): statuses.count(s) for s in sorted(set(statuses))}
    assert set(statuses) <= {403, 429}, counts
    assert 201 not in statuses

    evidence("D31", outcome="blocked",
             expected="all 40 rejected (403) or rate-limited (429)",
             detail={"requests": FLOOD_WRITES, "status_counts": counts,
                     "accepted": 0})


@pytest.mark.flood
def test_d32_verify_enumeration_flood_returns_only_unknown(session, base_url,
                                                           evidence):
    """D32 — 30 verify attempts against randomly generated UIDs that were never
    enrolled. Each must come back either as a well-formed `unknown` verdict (200)
    or rate-limited (429) — never a 404, never an error, and never a verdict that
    distinguishes "not registered" from "registered but failed a check" (D22).

    This is the measurable companion to D21, which records the posture and defers
    the measurement. Read the two together: D21 says what a defensible number
    needs, D32 produces the number under whatever worker count was pinned.
    """
    statuses: list[int] = []
    verdicts: list[str] = []
    for _ in range(FLOOD_VERIFIES):
        uid = secrets.token_hex(7).upper()
        r = session.get(f"{base_url}/api/v2/verify",
                        params={"m": f"{uid}x000005", "t": secrets.token_hex(16)},
                        timeout=30)
        statuses.append(r.status_code)
        if r.status_code == 200:
            verdicts.append(r.json().get("verdict", ""))

    counts = {str(s): statuses.count(s) for s in sorted(set(statuses))}
    assert set(statuses) <= {200, 429}, counts
    assert set(verdicts) <= {"unknown"}, set(verdicts)

    evidence("D32", outcome="blocked",
             expected="all 30 unknown (200) or rate-limited (429)",
             detail={"requests": FLOOD_VERIFIES, "status_counts": counts,
                     "verdicts": {v: verdicts.count(v) for v in set(verdicts)},
                     "note": "per-worker limit unless TEST_WORKER_COUNT is pinned"})
