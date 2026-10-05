"""Raw NTAG216 commands over the PN532, plus the NDEF write.
ARCHITECTURE.md §6.8.

`adafruit_pn532` exposes ntag2xx_read_block / ntag2xx_write_block but not
GET_VERSION, READ_SIG, READ_CNT, FAST_READ or PWD_AUTH. Those go through
InCommunicateThru (0x42) — see transceive() for why 0x40 cannot be used.

THE WRITE IS ALSO ISSUED DIRECTLY and not via ntag2xx_write_block, because that
wrapper reports a failed write by RETURNING False and crashes outright when the
driver times out. Both failure modes were being swallowed, which is what made a
24-page NDEF write fail intermittently while every short command succeeded. See
_write_page_once for the full account, and resync() for the bus-state half of it.
"""
from __future__ import annotations

import logging
import os
import time

from tag_layout import NDEF_START_PAGE

log = logging.getLogger("ntag")

# InCommunicateThru, NOT InDataExchange (40h). See transceive() for why.
CMD_IN_COMMUNICATE_THRU = 0x42

# InDataExchange. Used ONLY for the page write (see _write_page_once), because
# WRITE (A2h) is a MIFARE command the PN532 firmware handles natively and the
# 40h path is the one the reader's anti-tearing timing is built around.
CMD_IN_DATA_EXCHANGE = 0x40

# MIFARE Ultralight / NTAG WRITE. The 4-byte page write, as opposed to
# COMPATIBILITY_WRITE (A0h), which writes 16 bytes and NTAG does not want.
CMD_WRITE = 0xA2

# PN532 error codes from the status byte of an InDataExchange /
# InCommunicateThru response (PN532 user manual §7.1, table 15). These are the
# three that a failing multi-page write actually produces, and before the fix in
# _write_page_once they were being DISCARDED rather than reported.
PN532_STATUS = {
    0x00: "ok",
    0x01: "timeout — the tag did not answer in time",
    0x02: "CRC error in the tag's response",
    0x03: "parity error",
    0x0B: "RF protocol error",
    0x13: "an error in the data format",
}

# NTAG21x command bytes (NXP datasheet rev 3.2) -- identical across the family
CMD_GET_VERSION = 0x60
CMD_READ_SIG = 0x3C
CMD_READ_CNT = 0x39
CMD_FAST_READ = 0x3A
CMD_PWD_AUTH = 0x1B

# A genuine NTAG216 returns vendor 04h (NXP) and storage size 13h. Anything else
# is not the silicon we think it is (attack A12, finding F9a).
#
# Storage-size byte, NXP datasheet: 0Fh NTAG213, 11h NTAG215, 13h NTAG216. This
# build targets NTAG216 ONLY. Do not relax this check to accept a sibling chip:
# the configuration pages sit at different addresses on each, so an NTAG213
# would take our config write into the middle of its user memory, corrupt the
# NDEF record and never enable the mirror -- with no error until the tag fails
# the live-mirror confirmation.
NXP_VENDOR_ID = 0x04
NTAG216_STORAGE_SIZE = 0x13

# NTAG216 user memory is 04h..E1h (888 bytes). On NTAG213 it was 04h..27h.
# Most bytes one FAST_READ can return in a single PN532 frame. Mirrors
# tag_layout.PN532_FRAME_BYTES; the two modules do not import each other.
PN532_FRAME_BYTES = 252

USER_PAGE_FIRST = 0x04
USER_PAGE_LAST = 0xE1

# Lowest page a READ/FAST_READ may target. 00h-01h are the UID, 02h holds the
# two remaining UID bytes plus the static lock bytes, 03h is the capability
# container. All four are readable and none are user memory, which is why the
# read guard and the write guard do not share a bound.
READ_PAGE_FIRST = 0x00

# Carried over VERBATIM from v1's pi_app.py. Writing ~24 pages back-to-back
# without pacing causes real "Response frame preamble does not contain 0x00FF!"
# I2C errors on this hardware, and the tag needs time to finish its internal
# EEPROM write cycle before the next command lands. This was found empirically.
# Do not "clean it up".
NDEF_PAGE_WRITE_DELAY = float(os.getenv("NDEF_PAGE_WRITE_DELAY", "0.05"))
NDEF_PAGE_WRITE_RETRIES = int(os.getenv("NDEF_PAGE_WRITE_RETRIES", "3"))

# Pages per FAST_READ. See fast_read() for why this is not one big read.
FAST_READ_CHUNK_PAGES = int(os.getenv("FAST_READ_CHUNK_PAGES", "16"))

# Probes used to re-align the I2C frame stream after a failed exchange. See
# resync(). Four is generous: one orphaned frame is the realistic case.
BUS_RESYNC_PROBES = 4


class NtagError(RuntimeError):
    """Any failure talking to the tag."""


class TagRejected(NtagError):
    """The tag is not acceptable for enrolment. Do not ship it."""


class BusDesync(NtagError):
    """The I2C frame stream is out of step with the driver: a command's response
    frame was left unread on the bus, so every later read is one frame behind.

    This is NOT an RF problem and no amount of slowing the bus down or improving
    the tag's placement fixes it. It happens whenever `call_function` returns
    None (its `_wait_ready` timed out) and the PN532 then posts the response
    anyway. The cure is resync(), which must run before the next command.
    """


# --------------------------------------------------------------- transport ---

def transceive(pn532, payload: list[int], response_length: int) -> bytes:
    """Send a raw ISO14443A-3 command to the selected tag. Returns the response
    minus the status byte.

    THIS MUST BE InCommunicateThru (42h), NOT InDataExchange (40h).

    InDataExchange makes the PN532 firmware interpret the payload's first byte
    as a MIFARE command. NTAG's GET_VERSION is 60h, which is also MIFARE
    Classic's AUTHENTICATE KEY A — so the reader tries to run an authentication
    handshake, answers with a frame the driver rejects outright ("Received
    unexpected command response!"), and the tag never sees the command at all.
    The failure looks like a broken tag or a wiring fault; it is neither.

    42h passes the bytes through untouched, which is what every command in this
    module needs. Note it takes NO target number — that byte belongs to 40h
    only, and sending it here would be transmitted to the tag as data.

    Hardware-confirmed on NTAG216: 40h fails, 42h returns 0004040201001303."""
    resp = pn532.call_function(CMD_IN_COMMUNICATE_THRU,
                               params=list(payload),
                               response_length=response_length + 1)
    if resp is None:
        # call_function's own _wait_ready timed out. The PN532 will very likely
        # post the response a moment later with nobody reading it, which leaves
        # the frame stream one frame behind. Say so, and say it is recoverable.
        raise BusDesync(
            f"no response to InCommunicateThru {_cmd_name(payload)} within the "
            f"driver timeout — the response frame is probably still pending on "
            f"the bus. resync() before the next command.")
    if len(resp) < 1:
        raise NtagError(f"empty response to InCommunicateThru {_cmd_name(payload)}")
    if resp[0] != 0x00:
        raise NtagError(
            f"InCommunicateThru {_cmd_name(payload)} status {resp[0]:#04x}: "
            f"{PN532_STATUS.get(resp[0], 'unknown PN532 error code')}")
    data = bytes(resp[1:])
    if len(data) < response_length:
        # A SHORT frame is the signature of a misparsed response, not of a tag
        # that answered briefly: FAST_READ and friends are fixed-length. Most
        # often _read_frame found its 0xFF in the wrong place and truncated.
        raise BusDesync(
            f"InCommunicateThru {_cmd_name(payload)} returned {len(data)}B, "
            f"expected {response_length}B — the response frame was misparsed. "
            f"resync() before the next command.")
    return data


def _cmd_name(payload: list[int]) -> str:
    """Human-readable command name for error messages, so a log line says which
    exchange failed instead of just a status code."""
    names = {CMD_GET_VERSION: "GET_VERSION", CMD_READ_SIG: "READ_SIG",
             CMD_READ_CNT: "READ_CNT", CMD_FAST_READ: "FAST_READ",
             CMD_PWD_AUTH: "PWD_AUTH"}
    if not payload:
        return "<empty>"
    return names.get(payload[0], f"{payload[0]:#04x}")


def resync(pn532, *, reselect: bool = True) -> bool:
    """Re-align the I2C frame stream, then re-select the tag. Returns success.

    WHY THIS EXISTS. `adafruit_pn532.call_function` returns None when its
    `_wait_ready` expires, and `process_response` is never reached — so the
    response frame the PN532 posts a moment later is never read off the bus.
    Every subsequent command then reads the PREVIOUS command's frame.

    In a 24-page NDEF write that is silent, because `process_response` validates
    a frame with `response[1] == command + 1` and every page write is the SAME
    command. A stream that is one frame behind passes that check, so the burst
    runs to completion consuming stale responses, and the FAST_READ that follows
    lands on a misaligned frame. That is where a read-back "mismatch" whose
    first byte is 3Ah — the FAST_READ opcode itself — comes from. No RF fault can
    put a command opcode at data offset 0.

    The drain works by probing GetFirmwareVersion: a desynced stream makes it
    raise while consuming one orphaned frame, so probing until it parses leaves
    the stream aligned. Then the tag is re-selected, because a failed exchange
    may have left it deselected and InCommunicateThru has no target byte to
    re-establish one.
    """
    aligned = False
    for probe in range(BUS_RESYNC_PROBES):
        try:
            pn532.firmware_version()
            aligned = True
            break
        except Exception as exc:  # every failure mode here is itself a drain
            log.debug("resync probe %d consumed a stale frame: %s", probe + 1, exc)
            time.sleep(0.02)
    if not aligned:
        log.error("bus resync FAILED after %d probes — the PN532 is not "
                  "responding to GetFirmwareVersion at all. This is no longer a "
                  "framing problem: check wiring and power.", BUS_RESYNC_PROBES)
        return False
    if not reselect:
        return True
    uid = pn532.read_passive_target(timeout=0.5)
    if uid is None:
        log.warning("bus resynced but the tag is no longer in the field")
        return False
    return True


# ---------------------------------------------------------------- commands ---

def get_version(pn532) -> bytes:
    return transceive(pn532, [CMD_GET_VERSION], 8)


def assert_ntag216(pn532) -> bytes:
    """GET_VERSION gate (A12, F9a). Returns the raw 8-byte version on success."""
    version = get_version(pn532)
    if len(version) < 8:
        raise TagRejected(f"GET_VERSION returned {len(version)} bytes, expected 8")
    vendor, storage = version[1], version[6]
    if vendor != NXP_VENDOR_ID:
        raise TagRejected(f"vendor byte {vendor:#04x}, expected {NXP_VENDOR_ID:#04x} (NXP)")
    if storage != NTAG216_STORAGE_SIZE:
        raise TagRejected(
            f"storage size {storage:#04x}, expected {NTAG216_STORAGE_SIZE:#04x} (NTAG216)")
    return version


def read_sig(pn532) -> bytes:
    """READ_SIG (3Ch 00h) — 32-byte ECDSA/secp128r1 signature over the UID,
    written by NXP at chip manufacture. Enrolment only: this command is
    unreachable from Web NFC and from iOS background reading (§6.6)."""
    return transceive(pn532, [CMD_READ_SIG, 0x00], 32)


def read_counter(pn532, byte_order: str) -> int:
    """READ_CNT (39h 02h) — the 24-bit one-way NFC counter.

    `byte_order` is NOT guessed. It comes from CNT_BYTE_ORDER, calibrated once on
    a scrap tag (§6.4, §20.7), because implementations differ on whether the
    mirrored ASCII rendering is MSB- or LSB-first relative to this response. Get
    it wrong and every enrol_counter is wrong and the velocity bound is nonsense
    — a silent, hard-to-debug failure.
    """
    if byte_order not in ("msb", "lsb"):
        raise NtagError(
            f"CNT_BYTE_ORDER must be 'msb' or 'lsb', got {byte_order!r}. "
            f"Run `python enroller.py --calibrate` on a scrap tag (§20.7).")
    raw = transceive(pn532, [CMD_READ_CNT, 0x02], 3)
    return int.from_bytes(raw, "big" if byte_order == "msb" else "little")


def fast_read(pn532, start: int, end: int) -> bytes:
    """FAST_READ (3Ah) — pages `start`..`end` inclusive, 4 bytes each.

    READ IN CHUNKS, deliberately. The PN532 can return up to PN532_FRAME_BYTES
    in one frame, so a whole NDEF record fits, and the previous version asked
    for it in one go. That left NO SLACK in the driver's read buffer:
    `_read_frame(length)` calls `_read_data(length + 7)`, which for a 96-byte
    record is exactly the 106 bytes the frame occupies on the wire. `_read_frame`
    then skips leading 00h bytes before it looks for FFh — and the PN532 over
    I2C does not emit a fixed number of them. One extra preamble byte still
    parses; two, and the frame checksum is computed over a slice Python has
    silently truncated, so the read fails or comes back a byte short.

    Chunking at FAST_READ_CHUNK_PAGES keeps every read far inside the buffer, so
    preamble jitter is absorbed instead of corrupting the parse. It also keeps
    each I2C transaction short, which matters on a Raspberry Pi whose hardware
    I2C handles the PN532's clock stretching poorly.

    Pages 00h-03h are readable (UID, internal, lock bytes, capability
    container) even though they are not writable user memory — the lock sequence
    reads page 02h to preserve the two UID bytes that share it. So the lower
    bound here is READ_PAGE_FIRST, not USER_PAGE_FIRST.
    """
    if not READ_PAGE_FIRST <= start <= end <= USER_PAGE_LAST:
        raise NtagError(
            f"FAST_READ range {start:#04x}-{end:#04x} outside readable memory "
            f"({READ_PAGE_FIRST:#04x}-{USER_PAGE_LAST:#04x})")
    if FAST_READ_CHUNK_PAGES < 1:
        raise NtagError("FAST_READ_CHUNK_PAGES must be at least 1")

    out = bytearray()
    page = start
    while page <= end:
        chunk_end = min(page + FAST_READ_CHUNK_PAGES - 1, end)
        nbytes = (chunk_end - page + 1) * 4
        out += transceive(pn532, [CMD_FAST_READ, page, chunk_end], nbytes)
        page = chunk_end + 1
    return bytes(out)


def pwd_auth(pn532, password: bytes) -> bytes:
    """PWD_AUTH (1Bh) — returns the 2-byte PACK. Only used once tag locking is
    enabled; AUTHLIM is deliberately 0 so a failed attempt cannot brick the tag."""
    if len(password) != 4:
        raise NtagError("PWD must be exactly 4 bytes")
    return transceive(pn532, [CMD_PWD_AUTH, *list(password)], 2)


# ------------------------------------------------------------------- write ---

def _write_page_once(pn532, page: int, data: bytes) -> None:
    """One WRITE (A2h) exchange. Raises on anything short of success.

    This sends the SAME BYTES as `pn532.ntag2xx_write_block(page, data)` —
    InDataExchange, target 01h, A2h, page, four data bytes — and is written out
    here rather than called because the library's wrapper ends with:

        response = self.call_function(_COMMAND_INDATAEXCHANGE, ...)
        return response[0] == 0x00

    Two defects follow from that, and together they are the reason a multi-page
    NDEF write failed intermittently while every short command succeeded:

    1. IT RETURNS False RATHER THAN RAISING when the PN532 reports a non-zero
       status — a timeout (01h), a CRC error (02h), an RF protocol error (0Bh).
       write_page used to ignore that return value, so a write the reader had
       EXPLICITLY REPORTED AS FAILED was recorded as a success, the retries
       never fired, and the page simply stayed unwritten. The read-back
       byte-compare two steps later was the only thing that noticed, which is
       where a one-byte "mismatch" with no preceding error comes from.

    2. IT CRASHES WITH TypeError when call_function returns None, because None
       is not subscriptable. write_page caught bare Exception, so that became an
       ordinary retry — but the response frame was still pending on the bus, and
       nothing re-aligned the stream. See BusDesync and resync().

    Issuing the command directly fixes both and, as a bonus, puts the PN532's
    real status byte in the error message instead of a bool.
    """
    resp = pn532.call_function(CMD_IN_DATA_EXCHANGE,
                               params=[0x01, CMD_WRITE, page & 0xFF, *list(data)],
                               response_length=1)
    if resp is None:
        raise BusDesync(
            f"no response to WRITE of page {page:#04x} within the driver "
            f"timeout — the response frame is probably still pending on the bus")
    if len(resp) < 1:
        raise NtagError(f"empty response to WRITE of page {page:#04x}")
    if resp[0] != 0x00:
        raise NtagError(
            f"WRITE of page {page:#04x} rejected, status {resp[0]:#04x}: "
            f"{PN532_STATUS.get(resp[0], 'unknown PN532 error code')}")


def write_page(pn532, page: int, data: bytes) -> None:
    """One 4-byte page, with retries and the settle delay. See the module note.

    Every failed attempt is logged WITH ITS TRACEBACK and the stream is resynced
    before the retry. Retrying without a resync is what turned a single dropped
    frame into a whole corrupted burst: the retry's own response then landed one
    frame behind, and so did every page after it.
    """
    if len(data) != 4:
        raise NtagError(f"page write must be exactly 4 bytes, got {len(data)}")
    last_err: Exception | None = None
    for attempt in range(1, NDEF_PAGE_WRITE_RETRIES + 1):
        try:
            _write_page_once(pn532, page, data)
            if attempt > 1:
                log.info("page %#04x written on attempt %d", page, attempt)
            time.sleep(NDEF_PAGE_WRITE_DELAY)
            return
        except Exception as exc:  # re-raised below as NtagError
            last_err = exc
            log.warning("page %#04x write attempt %d/%d failed: %s",
                        page, attempt, NDEF_PAGE_WRITE_RETRIES, exc,
                        exc_info=True)
            if attempt < NDEF_PAGE_WRITE_RETRIES:
                # Re-align the frame stream and re-select the tag BEFORE
                # retrying. Without this the retry inherits the desync.
                if not resync(pn532):
                    raise NtagError(
                        f"write failed at page {page:#04x} on attempt {attempt} "
                        f"and the bus could not be resynced: {exc}") from exc
                time.sleep(NDEF_PAGE_WRITE_DELAY * 2)  # extra settle before retry
    raise NtagError(
        f"write failed at page {page:#04x} after {NDEF_PAGE_WRITE_RETRIES} "
        f"attempts: {last_err}")


def write_ndef(pn532, tlv: bytes) -> int:
    """Write a padded NDEF TLV starting at page 04h. Returns the page count."""
    if len(tlv) % 4:
        raise NtagError("TLV must be padded to whole pages before writing")
    pages_needed = len(tlv) // 4
    available = USER_PAGE_LAST - NDEF_START_PAGE + 1
    if pages_needed > available:
        raise NtagError(
            f"NDEF needs {pages_needed} pages, only {available} available on NTAG216")
    for i in range(pages_needed):
        write_page(pn532, NDEF_START_PAGE + i, tlv[i * 4:(i + 1) * 4])
    return pages_needed


def read_ndef(pn532, page_count: int) -> bytes:
    """Read back `page_count` pages from 04h, for the mandatory byte-compare."""
    end = NDEF_START_PAGE + page_count - 1
    return fast_read(pn532, NDEF_START_PAGE, min(end, USER_PAGE_LAST))


def verify_ndef(pn532, tlv: bytes) -> None:
    """Read back and BYTE-COMPARE. Never skip this.

    NTAG21x protects lock bits and the counter against tearing in hardware, but
    the NDEF area is not protected (A13). This compare is what catches a torn
    write — and it is also what catches an offset miscalculation before the
    mirror config is written.
    """
    readback = read_ndef(pn532, len(tlv) // 4)
    if len(readback) < len(tlv):
        # Report this as a framing fault, not a tag fault. A FAST_READ is
        # fixed-length: a tag that answers at all answers in full, so a short
        # read-back means the response frame was misparsed.
        raise BusDesync(
            f"NDEF read-back is {len(readback)}B, wrote {len(tlv)}B — the "
            f"response frame was truncated, not the tag's contents")
    if readback[:len(tlv)] != tlv:
        for i, (want, got) in enumerate(zip(tlv, readback, strict=False)):
            if want != got:
                hint = ""
                if got in (CMD_FAST_READ, CMD_GET_VERSION, CMD_READ_SIG,
                           CMD_READ_CNT):
                    # An opcode in the data stream is not something RF noise can
                    # produce. Name it, so this is not mistaken for a bad link.
                    hint = (f" — {got:#04x} is a COMMAND OPCODE, which means the "
                            f"frame stream is misaligned rather than the tag "
                            f"misread; resync() and retry")
                raise NtagError(
                    f"NDEF read-back mismatch at byte {i} "
                    f"(page {NDEF_START_PAGE + i // 4:#04x}): "
                    f"wrote {want:#04x}, read {got:#04x}{hint}")
        raise NtagError("NDEF read-back differs beyond the compared prefix")
