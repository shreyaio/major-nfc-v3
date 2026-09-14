"""NDEF TLV construction and mirror offset arithmetic. ARCHITECTURE.md §6.1, §6.2.

Every number here is load-bearing. If MIRROR_PAGE / MIRROR_BYTE do not line up
with where the `m=` placeholder actually landed in the record, enabling the
mirror CORRUPTS THE URL and every consumer scan opens a broken link — on a tag
that may already be locked and on a pack that may already have shipped.

These are pure arithmetic, so they can be tested exhaustively on a laptop with no
PN532 anywhere near it.
"""
from __future__ import annotations

import pytest

from tag_layout import (
    BINDING_TOKEN_HEX_LEN,
    MAX_NDEF_BYTES,
    MIRROR_LEN,
    MIRROR_PLACEHOLDER,
    NDEF_START_PAGE,
    USER_MEM_BYTES,
    TagLayoutError,
    build_ndef_tlv,
    build_verify_url,
    extract_placeholder,
    mirror_position,
    placeholder_offset,
)

HOST = "nfc-med-edge.example.workers.dev"
TOKEN = "A" * BINDING_TOKEN_HEX_LEN

# Fixed overhead around the host, derived rather than guessed:
#   2  NDEF Message TLV tag + length
#   4  record header (D1 01 <len> 55)
#   1  URI abbreviation code
#   5  "/c?m="
#  21  the mirror placeholder
#   3  "&t="
#  32  the binding token
#   1  terminator TLV
TLV_OVERHEAD = 2 + 4 + 1 + len("/c?m=") + MIRROR_LEN + len("&t=") + BINDING_TOKEN_HEX_LEN + 1
MAX_HOST_LEN = MAX_NDEF_BYTES - TLV_OVERHEAD


def test_placeholder_is_exactly_21_characters():
    """MIRROR_CONF = 11b mirrors 14 hex of UID + the chip's automatic 'x'
    separator + 6 hex of counter. Not 20, not 22."""
    assert MIRROR_LEN == 21
    assert len(MIRROR_PLACEHOLDER) == 21
    assert MIRROR_PLACEHOLDER == "00000000000000x000000"


def test_url_shape():
    url = build_verify_url(HOST, TOKEN)
    assert url == f"https://{HOST}/c?m={MIRROR_PLACEHOLDER}&t={TOKEN}"


def test_token_length_is_enforced():
    for bad in ["", "A" * 31, "A" * 33]:
        with pytest.raises(TagLayoutError):
            build_verify_url(HOST, bad)


def test_host_must_be_a_bare_hostname():
    """A URL here would silently shift every mirror offset by the length of the
    scheme, which is exactly the class of bug this module exists to prevent."""
    for bad in ["https://example.com", "example.com/path", "example.com:8443"]:
        with pytest.raises(TagLayoutError):
            build_verify_url(bad, TOKEN)


# ======================================================== THE ROUND TRIP ======

def test_placeholder_lands_exactly_where_the_mirror_config_points():
    """THE test in this file. Build the TLV, compute the mirror position from the
    host alone, and confirm the 21 bytes there are the placeholder.

    pi/enroller.py runs this same check against the bytes it READ BACK FROM THE
    TAG, before it writes the config pages (§6.2).
    """
    for host in ["a.workers.dev",
                 "nfc-med.workers.dev",
                 "nfc-med-edge.example.workers.dev",
                 "nfc-med-backend.onrender.com",
                 "x" * (MAX_HOST_LEN - 4) + ".dev"]:
        tlv = build_ndef_tlv(build_verify_url(host, TOKEN))
        assert extract_placeholder(tlv, host) == MIRROR_PLACEHOLDER.encode("ascii"), host


def test_mirror_position_derives_from_the_offset():
    offset = placeholder_offset(HOST)
    page, byte = mirror_position(HOST)
    assert page == NDEF_START_PAGE + offset // 4
    assert byte == offset % 4
    assert 0 <= byte <= 3
    assert 0x04 <= page <= 0x27


def test_offset_accounts_for_the_full_tlv_header():
    """7 bytes of TLV + record header + type + abbreviation, then the host, then
    '/c?m='. Getting any one of those wrong shifts the mirror."""
    assert placeholder_offset("abc") == 7 + 3 + len("/c?m=")


# ============================================================ THE 137 LIMIT ===

def test_the_host_budget_is_what_section_6_1_says():
    """§6.1's budget table, checked against the code rather than trusted.

    A workers.dev host is ~24 characters against a budget of MAX_HOST_LEN, which
    is why decision D6 (no custom domain) does not cost anything on the tag —
    the URL fits comfortably. It is the B1 homograph defence that D6 weakens,
    not the memory budget.
    """
    assert TLV_OVERHEAD == 69
    assert MAX_HOST_LEN == 68
    assert len("nfc-med.workers.dev") < MAX_HOST_LEN

    longest = "x" * (MAX_HOST_LEN - 4) + ".dev"
    tlv = build_ndef_tlv(build_verify_url(longest, TOKEN))
    # The 137-byte cap is on the NDEF MESSAGE. The returned buffer is padded up
    # to whole 4-byte pages, so it can be a few bytes larger — and it must still
    # fit the 144 bytes of user memory, because page 28h onward is configuration.
    assert len(tlv) <= USER_MEM_BYTES
    with pytest.raises(TagLayoutError):
        build_ndef_tlv(build_verify_url(longest + "x", TOKEN))


def test_ndef_fits_comfortably_for_a_realistic_host():
    """§6.1's budget check: ~93 of 137 bytes for a workers.dev host."""
    tlv = build_ndef_tlv(build_verify_url("nfc-med.workers.dev", TOKEN))
    assert len(tlv) <= MAX_NDEF_BYTES
    assert len(tlv) < 100   # ~93 of 137, as the §6.1 table says


def test_oversized_host_is_refused_rather_than_truncated():
    """F10. A truncated NDEF is a tag that opens a broken URL — and once locked,
    it can never be fixed. Refuse to write it instead."""
    with pytest.raises(TagLayoutError) as excinfo:
        build_ndef_tlv(build_verify_url("x" * 120 + ".example.com", TOKEN))
    assert "137" in str(excinfo.value)


def test_mirror_refuses_to_overrun_user_memory():
    long_host = "x" * 110 + ".com"
    with pytest.raises(TagLayoutError):
        mirror_position(long_host)


# ================================================================ TLV BYTES ===

def test_tlv_structure_is_a_single_well_known_uri_record():
    """B10 — one URI record, byte-compared at enrolment. Anything else is record
    type confusion waiting to happen."""
    tlv = build_ndef_tlv(build_verify_url(HOST, TOKEN))
    assert tlv[0] == 0x03            # NDEF Message TLV tag
    assert tlv[2] == 0xD1            # MB|ME|SR|TNF=well-known
    assert tlv[3] == 0x01            # type length
    assert tlv[5] == 0x55            # 'U' — URI record
    assert tlv[6] == 0x04            # abbreviation: "https://"
    assert 0xFE in tlv               # terminator


def test_http_uses_a_different_abbreviation_code():
    tlv = build_ndef_tlv("http://example.com/c?m=" + MIRROR_PLACEHOLDER)
    assert tlv[6] == 0x03


def test_non_http_scheme_is_refused():
    for bad in ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)",
                "example.com"]:
        with pytest.raises(TagLayoutError):
            build_ndef_tlv(bad)


def test_tlv_is_padded_to_whole_pages():
    """NTAG213 is written a 4-byte page at a time; a partial page would leave
    whatever was there before."""
    for host in ["a.dev", "abc.dev", "abcd.dev", "abcde.workers.dev"]:
        tlv = build_ndef_tlv(build_verify_url(host, TOKEN))
        assert len(tlv) % 4 == 0, host


def test_declared_lengths_match_the_actual_content():
    tlv = build_ndef_tlv(build_verify_url(HOST, TOKEN))
    message_len = tlv[1]
    payload_len = tlv[4]
    record = tlv[2:2 + message_len]
    assert len(record) == message_len
    assert len(record) == 4 + payload_len
    assert tlv[2 + message_len] == 0xFE  # terminator immediately after the record
