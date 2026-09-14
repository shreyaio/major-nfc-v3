"""Raw NTAG213 commands over the PN532, plus the hardware-proven NDEF write.
ARCHITECTURE.md §6.8.

`adafruit_pn532` exposes ntag2xx_read_block / ntag2xx_write_block but not
GET_VERSION, READ_SIG, READ_CNT, FAST_READ or PWD_AUTH. Those go through
InDataExchange (0x40) with target 1.
"""
from __future__ import annotations

import os
import time

from tag_layout import NDEF_START_PAGE

CMD_IN_DATA_EXCHANGE = 0x40

# NTAG213 command bytes (NXP datasheet rev 3.2)
CMD_GET_VERSION = 0x60
CMD_READ_SIG = 0x3C
CMD_READ_CNT = 0x39
CMD_FAST_READ = 0x3A
CMD_PWD_AUTH = 0x1B

# A genuine NTAG213 returns vendor 04h (NXP) and storage size 0Fh. Anything else
# is not the silicon we think it is (attack A12, finding F9a).
NXP_VENDOR_ID = 0x04
NTAG213_STORAGE_SIZE = 0x0F

USER_PAGE_FIRST = 0x04
USER_PAGE_LAST = 0x27

# Carried over VERBATIM from v1's pi_app.py. Writing ~24 pages back-to-back
# without pacing causes real "Response frame preamble does not contain 0x00FF!"
# I2C errors on this hardware, and the tag needs time to finish its internal
# EEPROM write cycle before the next command lands. This was found empirically.
# Do not "clean it up".
NDEF_PAGE_WRITE_DELAY = float(os.getenv("NDEF_PAGE_WRITE_DELAY", "0.05"))
NDEF_PAGE_WRITE_RETRIES = int(os.getenv("NDEF_PAGE_WRITE_RETRIES", "3"))


class NtagError(RuntimeError):
    """Any failure talking to the tag."""


class TagRejected(NtagError):
    """The tag is not acceptable for enrolment. Do not ship it."""


# --------------------------------------------------------------- transport ---

def transceive(pn532, payload: list[int], response_length: int) -> bytes:
    """Send a raw ISO14443A-3 command to the selected tag. `payload` is the NTAG
    command bytes; target 1 is prepended. Returns the response minus the status
    byte."""
    resp = pn532.call_function(CMD_IN_DATA_EXCHANGE,
                               params=[0x01, *list(payload)],
                               response_length=response_length + 1)
    if resp is None or len(resp) < 1 or resp[0] != 0x00:
        raise NtagError(f"InDataExchange status {resp[0] if resp else 'none'}")
    return bytes(resp[1:])


# ---------------------------------------------------------------- commands ---

def get_version(pn532) -> bytes:
    return transceive(pn532, [CMD_GET_VERSION], 8)


def assert_ntag213(pn532) -> bytes:
    """GET_VERSION gate (A12, F9a). Returns the raw 8-byte version on success."""
    version = get_version(pn532)
    if len(version) < 8:
        raise TagRejected(f"GET_VERSION returned {len(version)} bytes, expected 8")
    vendor, storage = version[1], version[6]
    if vendor != NXP_VENDOR_ID:
        raise TagRejected(f"vendor byte {vendor:#04x}, expected {NXP_VENDOR_ID:#04x} (NXP)")
    if storage != NTAG213_STORAGE_SIZE:
        raise TagRejected(
            f"storage size {storage:#04x}, expected {NTAG213_STORAGE_SIZE:#04x} (NTAG213)")
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
    """FAST_READ (3Ah) — pages `start`..`end` inclusive, 4 bytes each."""
    if not USER_PAGE_FIRST <= start <= end <= USER_PAGE_LAST:
        raise NtagError(f"FAST_READ range {start:#04x}-{end:#04x} outside user memory")
    return transceive(pn532, [CMD_FAST_READ, start, end], (end - start + 1) * 4)


def pwd_auth(pn532, password: bytes) -> bytes:
    """PWD_AUTH (1Bh) — returns the 2-byte PACK. Only used once tag locking is
    enabled; AUTHLIM is deliberately 0 so a failed attempt cannot brick the tag."""
    if len(password) != 4:
        raise NtagError("PWD must be exactly 4 bytes")
    return transceive(pn532, [CMD_PWD_AUTH, *list(password)], 2)


# ------------------------------------------------------------------- write ---

def write_page(pn532, page: int, data: bytes) -> None:
    """One 4-byte page, with retries and the settle delay. See the module note."""
    if len(data) != 4:
        raise NtagError(f"page write must be exactly 4 bytes, got {len(data)}")
    last_err: Exception | None = None
    for attempt in range(1, NDEF_PAGE_WRITE_RETRIES + 1):
        try:
            pn532.ntag2xx_write_block(page, list(data))
            last_err = None
            break
        except Exception as exc:
            last_err = exc
            if attempt < NDEF_PAGE_WRITE_RETRIES:
                time.sleep(NDEF_PAGE_WRITE_DELAY * 2)  # extra settle before retry
    if last_err is not None:
        raise NtagError(
            f"write failed at page {page:#04x} after {NDEF_PAGE_WRITE_RETRIES} "
            f"attempts: {last_err}")
    time.sleep(NDEF_PAGE_WRITE_DELAY)


def write_ndef(pn532, tlv: bytes) -> int:
    """Write a padded NDEF TLV starting at page 04h. Returns the page count."""
    if len(tlv) % 4:
        raise NtagError("TLV must be padded to whole pages before writing")
    pages_needed = len(tlv) // 4
    available = USER_PAGE_LAST - NDEF_START_PAGE + 1
    if pages_needed > available:
        raise NtagError(
            f"NDEF needs {pages_needed} pages, only {available} available on NTAG213")
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
    if readback[:len(tlv)] != tlv:
        for i, (want, got) in enumerate(zip(tlv, readback, strict=False)):
            if want != got:
                raise NtagError(
                    f"NDEF read-back mismatch at byte {i} "
                    f"(page {NDEF_START_PAGE + i // 4:#04x}): "
                    f"wrote {want:#04x}, read {got:#04x}")
        raise NtagError("NDEF read-back is shorter than what was written")
