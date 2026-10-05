"""_disable_preexisting_mirror: the pre-enabled-mirror guard. §6.5.

Some stock NTAG216 arrives with the ASCII mirror already enabled (observed:
CFG0/E3h byte 0 = C4h, MIRROR_CONF = 11b, mirror at page 0Fh). While that is
live, a read of the mirrored pages returns the chip's substituted UID/counter
ASCII rather than the physical bytes underneath — so the mandatory NDEF
byte-compare reports a mismatch on a write that actually succeeded. It looks
exactly like a torn write and is not one.

The first version of this guard called `ntag.ntag2xx_write_block`, which does
not exist (that is a method on the PN532 object, and `ntag` deliberately does
not wrap it because the wrapper reports failure by returning False). The bug was
latent: the function returns early when no mirror is set, so it would only have
crashed on exactly the tags it was written to handle. Hence
test_the_config_write_goes_through_ntag_write_page.
"""
from __future__ import annotations

import enroller
import pytest

import ntag
import tag_config

CFG0 = tag_config.CFG0_PAGE          # 0xE3


class FakePN532:
    """Minimal PN532 holding one writable config page."""

    def __init__(self, cfg0: bytes | None, *, write_status=0x00, readback=None):
        self.page = cfg0
        self.write_status = write_status
        self.readback = readback          # override what the verify read returns
        self.writes: list[tuple[int, list[int]]] = []

    def ntag2xx_read_block(self, page):
        assert page == CFG0
        if self.readback is not None and self.writes:
            return self.readback
        return self.page

    def call_function(self, command, params=None, response_length=0):
        # ntag.write_page routes here: [0x01, 0xA2, page, d0..d3]
        params = list(params or [])
        assert command == ntag.CMD_IN_DATA_EXCHANGE
        assert params[1] == ntag.CMD_WRITE
        self.writes.append((params[2], params[3:]))
        if self.write_status == 0x00:
            self.page = bytes(params[3:])
        return [self.write_status]

    def firmware_version(self):
        return (0x32, 0x01, 0x06, 0x07)

    def read_passive_target(self, timeout=1):
        return b"\x04\xa1\xb2\xc3\xd4\xe5\xf6"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(ntag.time, "sleep", lambda _s: None)


def test_a_tag_with_no_mirror_is_left_untouched():
    pn = FakePN532(bytes([0x04, 0x00, 0x0F, 0xFF]))   # MIRROR_CONF = 00b
    assert enroller._disable_preexisting_mirror(pn) is False
    assert pn.writes == [], "a tag without a mirror must not be written to"


def test_a_pre_enabled_mirror_is_cleared():
    """C4h = 11000100b: MIRROR_CONF 11b, STRG_MOD_EN 1. Observed on real stock."""
    pn = FakePN532(bytes([0xC4, 0x00, 0x0F, 0xFF]))
    assert enroller._disable_preexisting_mirror(pn) is True
    assert pn.page == bytes([0x04, 0x00, 0x0F, 0xFF])


def test_only_the_mirror_mode_bits_are_touched():
    """MIRROR_PAGE, MIRROR_BYTE, STRG_MOD_EN and AUTH0 must survive verbatim. A
    careless whole-page write here loses the mirror position or the password
    protection, on a page that may already be locked."""
    pn = FakePN532(bytes([0xFF, 0x5A, 0x2B, 0xE3]))
    enroller._disable_preexisting_mirror(pn)
    written = pn.page
    assert written[0] & 0xC0 == 0, "mirror mode bits must be cleared"
    assert written[0] & 0x3F == 0x3F, "every other bit of byte 0 must survive"
    assert written[1:] == bytes([0x5A, 0x2B, 0xE3]), "bytes 1-3 must survive"


@pytest.mark.parametrize("mirror_byte", [0x40, 0x80, 0xC0])
def test_every_enabled_mirror_mode_is_detected(mirror_byte):
    pn = FakePN532(bytes([mirror_byte, 0x00, 0x0F, 0xFF]))
    assert enroller._disable_preexisting_mirror(pn) is True


def test_the_config_write_goes_through_ntag_write_page():
    """Regression: the first version called a function that does not exist, and
    did so only on tags that had a mirror set. Pin the call path."""
    pn = FakePN532(bytes([0xC4, 0x00, 0x0F, 0xFF]))
    enroller._disable_preexisting_mirror(pn)
    assert len(pn.writes) == 1
    page, data = pn.writes[0]
    assert page == CFG0
    assert data == [0x04, 0x00, 0x0F, 0xFF]


def test_a_rejected_config_write_raises():
    """write_page checks the PN532 status byte, so a refused config write cannot
    pass silently the way ntag2xx_write_block's False return did."""
    pn = FakePN532(bytes([0xC4, 0x00, 0x0F, 0xFF]), write_status=0x02)
    with pytest.raises(ntag.NtagError):
        enroller._disable_preexisting_mirror(pn)


def test_a_mirror_that_will_not_clear_stops_enrolment():
    """If the mirror is still live, the NDEF read-back cannot be trusted, so
    this must not be allowed to continue into the byte-compare."""
    pn = FakePN532(bytes([0xC4, 0x00, 0x0F, 0xFF]),
                   readback=bytes([0xC4, 0x00, 0x0F, 0xFF]))
    with pytest.raises(ntag.NtagError, match="failed to disable the mirror"):
        enroller._disable_preexisting_mirror(pn)


def test_a_silent_tag_is_an_error_not_a_no_mirror_result():
    """ntag2xx_read_block returns None on a failed read. Treating that as 'no
    mirror' would walk straight into the false mismatch this guard prevents."""
    pn = FakePN532(None)
    with pytest.raises(ntag.NtagError, match="did not answer"):
        enroller._disable_preexisting_mirror(pn)


def test_a_short_config_read_is_an_error():
    pn = FakePN532(bytes([0xC4, 0x00]))
    with pytest.raises(ntag.NtagError, match="expected 4"):
        enroller._disable_preexisting_mirror(pn)
