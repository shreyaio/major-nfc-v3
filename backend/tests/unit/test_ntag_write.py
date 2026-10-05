"""The PN532 write and read paths in pi/ntag.py. ARCHITECTURE.md §6.8.

These are the regression tests for the enrolment blocker: a multi-page NDEF
write that failed intermittently (CRC error 02h, timeout 01h, RF protocol error
0Bh, and twice a single-byte read-back mismatch) while every short command —
GET_VERSION, READ_SIG — succeeded every time.

The cause was not the RF link. It was two defects in how failures were handled:

  1. `adafruit_pn532.ntag2xx_write_block` reports a failed write by RETURNING
     False, and ntag.write_page discarded the return value. A write the PN532
     had explicitly rejected was recorded as a success and the retries never
     fired.

  2. `call_function` returns None when its `_wait_ready` expires, which made the
     library's wrapper raise TypeError on `response[0]`. write_page caught bare
     Exception and retried WITHOUT draining the response frame the PN532 posted
     a moment later, so the frame stream ran one frame behind. Because
     `process_response` only validates `response[1] == command + 1`, and every
     page write is the same command, a one-frame-behind stream passes that check
     silently for the rest of the burst.

A fake PN532 is enough to pin all of it: ntag.py imports nothing but os, time,
logging and tag_layout, so it loads on a laptop with no reader attached.
"""
from __future__ import annotations

import pytest

import ntag


class FakePN532:
    """Records every call_function invocation and replays scripted responses.

    `write_results` is consumed one entry per WRITE exchange. An entry is either
    a response list (what call_function would return), or an Exception to raise.
    """

    def __init__(self, *, write_results=None, read_payload=b"",
                 firmware_failures=0, reselect_uid=b"\x04\xa1\xb2\xc3\xd4\xe5\xf6"):
        self.write_results = list(write_results or [])
        self.read_payload = read_payload
        self.firmware_failures = firmware_failures
        self.reselect_uid = reselect_uid
        self.calls: list[tuple[int, list[int]]] = []
        self.fast_reads: list[tuple[int, int]] = []
        self.firmware_calls = 0
        self.reselects = 0

    def call_function(self, command, params=None, response_length=0):
        params = list(params or [])
        self.calls.append((command, params))

        if command == ntag.CMD_IN_DATA_EXCHANGE:
            result = self.write_results.pop(0) if self.write_results else [0x00]
            if isinstance(result, Exception):
                raise result
            return result

        if command == ntag.CMD_IN_COMMUNICATE_THRU and params[0] == ntag.CMD_FAST_READ:
            start, end = params[1], params[2]
            self.fast_reads.append((start, end))
            lo = (start - ntag.NDEF_START_PAGE) * 4
            nbytes = (end - start + 1) * 4
            return [0x00, *list(self.read_payload[lo:lo + nbytes])]

        raise AssertionError(f"unexpected command {command:#04x}")

    def firmware_version(self):
        self.firmware_calls += 1
        if self.firmware_calls <= self.firmware_failures:
            raise RuntimeError("Response frame preamble does not contain 0x00FF!")
        return (0x32, 0x01, 0x06, 0x07)

    def read_passive_target(self, timeout=1):
        self.reselects += 1
        return self.reselect_uid


@pytest.fixture(autouse=True)
def _no_settle_delay(monkeypatch):
    """The settle delay is load-bearing on hardware and pure latency in tests."""
    monkeypatch.setattr(ntag.time, "sleep", lambda _s: None)


# ------------------------------------------------- 1. rejected writes raise ---

@pytest.mark.parametrize("status,fragment", [
    (0x01, "timeout"),
    (0x02, "CRC error"),
    (0x0B, "RF protocol error"),
])
def test_a_rejected_write_raises_instead_of_being_accepted(status, fragment):
    """THE core regression. A non-zero status byte must not be silently accepted.

    ntag2xx_write_block returns False here rather than raising, and the old
    write_page ignored that, so the page stayed unwritten and only the read-back
    byte-compare two steps later noticed.
    """
    pn = FakePN532(write_results=[[status]] * ntag.NDEF_PAGE_WRITE_RETRIES)
    with pytest.raises(ntag.NtagError) as err:
        ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")
    assert fragment in str(err.value)
    assert f"{status:#04x}" in str(err.value)


def test_every_retry_is_actually_spent_on_a_rejected_write():
    pn = FakePN532(write_results=[[0x02]] * ntag.NDEF_PAGE_WRITE_RETRIES)
    with pytest.raises(ntag.NtagError):
        ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")
    writes = [c for c in pn.calls if c[0] == ntag.CMD_IN_DATA_EXCHANGE]
    assert len(writes) == ntag.NDEF_PAGE_WRITE_RETRIES


def test_a_transient_rejection_is_retried_and_succeeds():
    pn = FakePN532(write_results=[[0x02], [0x00]])
    ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")
    assert len([c for c in pn.calls if c[0] == ntag.CMD_IN_DATA_EXCHANGE]) == 2


def test_the_write_frame_is_byte_identical_to_the_library_wrapper():
    """InDataExchange, target 01h, A2h, page, four data bytes — the exact bytes
    adafruit_pn532.ntag2xx_write_block sends. Issuing it directly is only safe
    while that stays true."""
    pn = FakePN532(write_results=[[0x00]])
    ntag.write_page(pn, 0x07, b"\xde\xad\xbe\xef")
    assert pn.calls[0] == (0x40, [0x01, 0xA2, 0x07, 0xDE, 0xAD, 0xBE, 0xEF])


def test_a_short_page_is_refused_before_it_reaches_the_reader():
    pn = FakePN532()
    with pytest.raises(ntag.NtagError, match="exactly 4 bytes"):
        ntag.write_page(pn, 0x04, b"\x01\x02\x03")
    assert pn.calls == []


# ------------------------------------------------ 2. desync is not retried ----

def test_a_driver_timeout_is_reported_as_a_bus_desync():
    """call_function returning None means the response frame is still pending.
    That is a framing fault with a named recovery, not an RF fault."""
    pn = FakePN532(write_results=[None] * ntag.NDEF_PAGE_WRITE_RETRIES)
    with pytest.raises(ntag.NtagError) as err:
        ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")
    assert "pending on the bus" in str(err.value)


def test_the_bus_is_resynced_and_the_tag_reselected_between_retries():
    """Retrying without draining the orphaned frame is what turned one dropped
    frame into a whole corrupted burst."""
    pn = FakePN532(write_results=[None, [0x00]], firmware_failures=1)
    ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")
    assert pn.firmware_calls == 2, "the stale frame must be drained by a probe"
    assert pn.reselects == 1, "the tag must be re-selected after a failed exchange"


def test_resync_drains_a_stale_frame_then_reselects():
    pn = FakePN532(firmware_failures=1)
    assert ntag.resync(pn) is True
    assert pn.firmware_calls == 2
    assert pn.reselects == 1


def test_resync_gives_up_when_the_reader_never_answers():
    """Past this point it is no longer a framing problem, and the caller must not
    be told the bus is healthy."""
    pn = FakePN532(firmware_failures=ntag.BUS_RESYNC_PROBES + 1)
    assert ntag.resync(pn) is False
    assert pn.reselects == 0


def test_resync_reports_failure_when_the_tag_has_left_the_field():
    pn = FakePN532(reselect_uid=None)
    assert ntag.resync(pn) is False


def test_a_write_fails_fast_when_the_bus_cannot_be_resynced():
    pn = FakePN532(write_results=[[0x02], [0x00]],
                   firmware_failures=ntag.BUS_RESYNC_PROBES + 1)
    with pytest.raises(ntag.NtagError, match="could not be resynced"):
        ntag.write_page(pn, 0x04, b"\x01\x02\x03\x04")


# ----------------------------------------------------- 3. chunked FAST_READ ---

def test_fast_read_is_split_into_chunks_and_rejoined():
    """One big read left no slack in the driver's buffer: _read_frame asks
    _read_data for length + 7, which for a 96-byte record is exactly the 106
    bytes the frame occupies on the wire."""
    payload = bytes(range(96))
    pn = FakePN532(read_payload=payload)
    got = ntag.fast_read(pn, 0x04, 0x04 + 24 - 1)
    assert got == payload
    assert pn.fast_reads == [(0x04, 0x13), (0x14, 0x1B)]
    assert all((e - s + 1) <= ntag.FAST_READ_CHUNK_PAGES for s, e in pn.fast_reads)


def test_a_single_page_read_is_one_exchange():
    pn = FakePN532(read_payload=b"\xaa\xbb\xcc\xdd")
    assert ntag.fast_read(pn, 0x04, 0x04) == b"\xaa\xbb\xcc\xdd"
    assert pn.fast_reads == [(0x04, 0x04)]


def test_the_lock_sequence_can_read_the_static_lock_page():
    """apply_lock_sequence reads page 02h to preserve the two UID bytes that
    share it with the static lock bytes. The old guard started at 04h, so the
    one irreversible path in the build raised before it began."""
    pn = FakePN532(read_payload=b"")
    pn.read_payload = b"\x00" * 200  # offsets below NDEF_START_PAGE read as zero
    assert len(ntag.fast_read(pn, 0x02, 0x02)) == 4
    assert pn.fast_reads == [(0x02, 0x02)]


def test_a_read_past_the_end_of_user_memory_is_refused():
    pn = FakePN532()
    with pytest.raises(ntag.NtagError, match="outside readable memory"):
        ntag.fast_read(pn, 0xE0, 0xE2)


def test_an_inverted_range_is_refused():
    pn = FakePN532()
    with pytest.raises(ntag.NtagError, match="outside readable memory"):
        ntag.fast_read(pn, 0x10, 0x08)


# ------------------------------------------------- 4. read-back diagnostics ---

def test_verify_ndef_passes_on_an_exact_readback():
    tlv = bytes(range(32))
    ntag.verify_ndef(FakePN532(read_payload=tlv), tlv)


def test_verify_ndef_names_the_mismatching_byte_and_page():
    tlv = bytes(32)
    corrupt = bytearray(tlv)
    corrupt[9] = 0x7F
    with pytest.raises(ntag.NtagError) as err:
        ntag.verify_ndef(FakePN532(read_payload=bytes(corrupt)), tlv)
    assert "byte 9" in str(err.value)
    assert "0x06" in str(err.value)  # page 04h + 9 // 4


def test_an_opcode_in_the_readback_is_called_out_as_a_framing_fault():
    """A read-back whose first byte is 3Ah is the FAST_READ opcode itself. No RF
    fault can put a command opcode at data offset 0, and reading that symptom as
    a marginal link sent this debugging session down a dead end for a night."""
    tlv = bytes(32)
    corrupt = bytearray(tlv)
    corrupt[0] = ntag.CMD_FAST_READ
    with pytest.raises(ntag.NtagError) as err:
        ntag.verify_ndef(FakePN532(read_payload=bytes(corrupt)), tlv)
    assert "COMMAND OPCODE" in str(err.value)
    assert "misaligned" in str(err.value)


def test_a_truncated_readback_is_reported_as_a_framing_fault():
    """A FAST_READ is fixed-length, so a short answer is a misparsed frame
    rather than a tag that replied briefly.

    transceive catches this one frame earlier than verify_ndef's own length
    guard, which is the better layer for it: the caller is told the exchange was
    misparsed rather than that the tag's contents differ.
    """
    tlv = bytes(range(32))
    with pytest.raises(ntag.BusDesync, match="misparsed"):
        ntag.verify_ndef(FakePN532(read_payload=tlv[:28]), tlv)


# ------------------------------------------------------ transceive reporting --

def test_a_nonzero_status_names_the_command_and_decodes_the_code():
    class Rejecting(FakePN532):
        def call_function(self, command, params=None, response_length=0):
            return [0x0B]

    with pytest.raises(ntag.NtagError) as err:
        ntag.get_version(Rejecting())
    assert "GET_VERSION" in str(err.value)
    assert "RF protocol error" in str(err.value)


def test_a_missing_response_to_a_short_command_is_also_a_desync():
    class Silent(FakePN532):
        def call_function(self, command, params=None, response_length=0):
            return None

    with pytest.raises(ntag.BusDesync, match="READ_SIG"):
        ntag.read_sig(Silent())
