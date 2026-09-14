"""The hash-chained audit log. ARCHITECTURE.md §9.9, §17.2 item 3.

Each entry commits to the previous entry's hash, and the daily transparency job
publishes the head. An attacker with database access who deletes their own trace
breaks the chain — and because yesterday's head was published to a public
repository, the break becomes PUBLICLY PROVABLE (F25).

Without this, the audit log is not independent evidence for the paper. It can be
edited by exactly the adversary it exists to catch.

The destructive part of this file needs DATABASE_URL and will not run without
it. It writes to whatever database you point it at, so point it at a scratch
project (§17.3).
"""
from __future__ import annotations

import itertools
import os
import secrets

import pytest

pytestmark = pytest.mark.integration

AUDIT_COLS = ("seq", "event_type", "tag_index", "actor", "result",
              "source_ip_hash", "user_agent_class", "detail", "prev_hash",
              "entry_hash")


@pytest.fixture
def direct_db():
    """A direct connection, for the tamper this test has to perform.

    Nothing in the application ever does this — it exists to play the adversary
    from threat-model capability (vi), who has full read/write on the register.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL is not set — the chain-break test needs one")

    import psycopg2

    from db import _with_sslmode
    conn = psycopg2.connect(_with_sslmode(url))
    yield conn
    conn.close()


def _read_chain(conn, limit=500):
    with conn.cursor() as cur:
        cur.execute(f"SELECT {', '.join(AUDIT_COLS)} FROM audit_log "  # noqa: S608 — interpolates a module-level column tuple, never user input
                    f" ORDER BY seq DESC LIMIT %s", (limit,))
        rows = [dict(zip(AUDIT_COLS, r, strict=True)) for r in cur.fetchall()]
    return list(reversed(rows))


def test_every_verify_writes_an_audit_row(make_tag, enrol, verify, direct_db):
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    before = _count_audit(direct_db)
    verify(uid, 5, token)
    after = _count_audit(direct_db)
    assert after > before


def _count_audit(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM audit_log")
        return cur.fetchone()[0]


def test_the_chain_links_every_entry(direct_db):
    """Walk what is there and confirm each prev_hash matches the entry before."""

    rows = _read_chain(direct_db)
    if len(rows) < 2:
        pytest.skip("not enough audit history to verify a chain")

    # Verify links rather than recomputing from genesis: the retention job
    # deletes rows older than 90 days, so a full walk from the start would
    # legitimately fail on a long-lived database (see the note in backup.yml).
    for previous, current in itertools.pairwise(rows):
        assert current["prev_hash"] == previous["entry_hash"], (
            f"chain break between seq {previous['seq']} and {current['seq']}")


def test_f25_deleting_a_row_breaks_the_chain_detectably(direct_db):
    """Play the adversary: delete an entry and confirm the break is found at the
    right place. This is the property that makes the audit log evidence rather
    than a file the attacker can edit."""
    import audit

    # Write three rows we own, so the tamper touches nothing else.
    marker = f"chaintest-{secrets.token_hex(4)}"
    for index in range(3):
        audit.log_audit(event_type="test", actor=marker, result=f"entry-{index}")

    rows = _read_chain(direct_db)
    ours = [r for r in rows if r["actor"] == marker]
    assert len(ours) == 3, "audit writes did not land"

    # Take a window starting at a known-good link so verify_chain has a genesis.
    start = rows.index(ours[0])
    window = rows[start:]

    # Intact: every link holds.
    for previous, current in itertools.pairwise(window):
        assert current["prev_hash"] == previous["entry_hash"]

    # Now delete the middle one, exactly as an attacker covering their tracks
    # would, and confirm the link no longer holds.
    victim = ours[1]
    with direct_db.cursor() as cur:
        cur.execute("DELETE FROM audit_log WHERE seq = %s", (victim["seq"],))
    direct_db.commit()

    after = _read_chain(direct_db)
    remaining = [r for r in after if r["actor"] == marker]
    assert len(remaining) == 2

    # The survivor after the deleted row points at a hash that is no longer in
    # the table. That dangling link IS the detection.
    hashes = {r["entry_hash"] for r in after}
    assert remaining[1]["prev_hash"] not in hashes, (
        "deleting a row did not leave a detectable gap — the chain is not doing "
        "its job")


def test_audit_never_stores_a_raw_ip_or_user_agent(direct_db, make_tag, enrol, verify):
    """F30 and India's DPDP Act 2023. Consumer scan records tied to a time and a
    source are personal data."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201
    verify(uid, 4, token)

    with direct_db.cursor() as cur:
        cur.execute("SELECT source_ip_hash, user_agent_class FROM audit_log "
                    " WHERE event_type = 'verify' ORDER BY seq DESC LIMIT 20")
        rows = cur.fetchall()

    import re
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    for ip_hash, ua_class in rows:
        if ip_hash is not None:
            assert not ipv4.match(ip_hash), f"a raw IPv4 address was stored: {ip_hash}"
            assert ":" not in ip_hash, f"a raw IPv6 address was stored: {ip_hash}"
            assert len(ip_hash) == 32
        if ua_class is not None:
            assert len(ua_class) < 32, f"this looks like a raw User-Agent: {ua_class}"
            assert "mozilla" not in ua_class.lower()


def test_an_audit_failure_never_breaks_its_caller(make_tag, enrol, verify):
    """The contract v1 got right and v2 keeps: log_audit MUST NOT raise. There is
    no way to induce a logging failure from outside, so this asserts the shape
    of the contract — a verify still returns a verdict under load, when audit
    contention is at its highest."""
    payload, uid, token = make_tag(enrol_counter=1)
    assert enrol(payload).status_code == 201

    for counter in range(5, 15):
        response = verify(uid, counter, token)
        assert response.status_code == 200
        assert "verdict" in response.json()
