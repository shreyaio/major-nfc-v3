"""NTAG216 tag layout: verify URL, NDEF TLV, and the ASCII-mirror position.
ARCHITECTURE.md §6.1, §6.2.

Every byte offset here is load-bearing. The chip mirrors live UID + counter into
a fixed position in user memory; if the position we tell it (MIRROR_PAGE /
MIRROR_BYTE in CFG0) does not line up with where the `m=` placeholder actually
landed in the NDEF record, enabling the mirror corrupts the URL and every
consumer scan opens a broken link.

This module has no hardware dependency on purpose — it is pure arithmetic, unit
tested in backend/tests/unit/test_tag_layout.py.
"""
from __future__ import annotations

# NTAG216 user memory is pages 04h-E1h (4-225), 888 bytes, and the factory
# Capability Container declares an NDEF data area of 6Dh x 8 = 872 bytes.
#
# WE DELIBERATELY DO NOT USE THAT MUCH. This builder emits a SHORT record with a
# single-byte TLV length field, which caps the NDEF message at 254 bytes however
# much memory the chip has. So on NTAG216 the RECORD FORMAT is the binding
# constraint, not the silicon -- the reverse of NTAG213, where 144 bytes of user
# memory bound a 137-byte cap.
#
# Supporting the 3-byte long form to reach 872 bytes would be pure complexity:
# the verify URL is ~70 bytes and the host budget below is already far wider than
# DNS permits. The extra memory is headroom we have no use for.
NDEF_START_PAGE = 0x04
USER_MEM_BYTES = 888

# Two ceilings, and the TIGHTER one wins.
#
#   MAX_RECORD_BYTES  254  largest record a single-byte TLV length can describe
#   PN532_FRAME_BYTES 252  most one FAST_READ can return in a single PN532 frame
#
# The second is the one that binds. ntag.read_ndef() reads the whole record back
# in ONE FAST_READ for the mandatory byte-compare (A13), so a record that cannot
# be read back in one frame cannot be verified -- and an unverifiable write is
# exactly what that compare exists to prevent. NTAG213's 137-byte cap sat below
# both ceilings, so neither was ever reachable there.
MAX_RECORD_BYTES = 254
PN532_FRAME_BYTES = 252
MAX_NDEF_BYTES = PN532_FRAME_BYTES

# 21 chars exactly: 14 hex of UID + the chip's automatic 'x' separator (78h)
# + 6 hex of counter. MIRROR_CONF = 11b needs all 21 bytes contiguous and free.
MIRROR_PLACEHOLDER = "00000000000000x000000"
MIRROR_LEN = len(MIRROR_PLACEHOLDER)

# 128-bit per-tag binding token, hex-encoded.
BINDING_TOKEN_BYTES = 16
BINDING_TOKEN_HEX_LEN = BINDING_TOKEN_BYTES * 2

URI_ABBREV = {"https://": 0x04, "http://": 0x03}


class TagLayoutError(ValueError):
    """Raised when a layout would not fit, or would not line up."""


def build_verify_url(host: str, token_hex: str) -> str:
    """The URL written into the tag. `m` is all-zero placeholder text that the
    chip overwrites on every read; `t` is written normally and never mirrored."""
    if len(token_hex) != BINDING_TOKEN_HEX_LEN:
        raise TagLayoutError(
            f"binding token must be {BINDING_TOKEN_HEX_LEN} hex chars, got {len(token_hex)}")
    if not host or "/" in host or ":" in host:
        raise TagLayoutError(f"host must be a bare hostname, got {host!r}")
    return f"https://{host}/c?m={MIRROR_PLACEHOLDER}&t={token_hex}"


def build_ndef_tlv(url: str) -> bytes:
    """Type-2-Tag NDEF URI record, TLV-wrapped, padded to whole 4-byte pages.

    Refuses to build anything over MAX_NDEF_BYTES rather than silently
    truncating — a truncated NDEF is the F10 failure, a tag that opens a broken
    URL and can never be fixed once locked.
    """
    prefix = next((p for p in URI_ABBREV if url.startswith(p)), None)
    if prefix is None:
        raise TagLayoutError("verify URL must be http(s)")
    abbrev = URI_ABBREV[prefix]

    rest = url[len(prefix):].encode("ascii")
    payload = bytes([abbrev]) + rest
    # TWO length fields bind here, not one: the record's own payload-length byte
    # AND the TLV length byte, which covers the 4-byte record header as well.
    # The TLV field is the tighter of the two, so it is the one to check.
    # Checking only the payload against 0xFF let a 255-byte payload through and
    # then died inside bytes([259]) with a bare ValueError -- unreachable while
    # NTAG213's 137-byte cap caught everything first, reachable on NTAG216.
    if len(payload) > MAX_RECORD_BYTES - 4:
        raise TagLayoutError(
            f"payload {len(payload)}B too long for a short record "
            f"(max {MAX_RECORD_BYTES - 4}B) — use a shorter host")

    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    if len(tlv) > MAX_NDEF_BYTES:
        raise TagLayoutError(
            f"NDEF {len(tlv)}B exceeds NTAG216 limit {MAX_NDEF_BYTES}B — "
            f"use a shorter host")
    tlv += b"\x00" * ((4 - len(tlv) % 4) % 4)  # pad to whole pages
    return tlv


def placeholder_offset(host: str) -> int:
    """Byte offset of the `m=` placeholder within user memory (page 04h byte 0).

    TLV layout from user-memory offset 0:
      0 : 0x03        NDEF Message TLV tag
      1 : L           message length
      2 : 0xD1        record header (MB|ME|SR|TNF=well-known)
      3 : 0x01        type length
      4 : payload_len
      5 : 0x55 ('U')  type
      6 : 0x04        URI abbreviation "https://"
      7 : first char of "<HOST>/c?m=..."
    """
    return 7 + len(host) + len("/c?m=")


def mirror_position(host: str) -> tuple[int, int]:
    """Returns (MIRROR_PAGE, MIRROR_BYTE) for the m= placeholder."""
    offset = placeholder_offset(host)
    page, byte = NDEF_START_PAGE + offset // 4, offset % 4
    # Datasheet: the mirror needs 21 free bytes and must not run past user memory.
    if offset + MIRROR_LEN > USER_MEM_BYTES:
        raise TagLayoutError("mirror would overrun user memory")
    if page < NDEF_START_PAGE:
        raise TagLayoutError("MIRROR_PAGE must be >= 04h")
    if page > 0xE1:
        raise TagLayoutError("MIRROR_PAGE must be <= E1h (end of NTAG216 user memory)")
    return page, byte


def extract_placeholder(tlv: bytes, host: str) -> bytes:
    """The 21 bytes at the computed mirror position, read out of a TLV buffer.

    `enroller.py` calls this on the data it READ BACK from the tag and asserts it
    equals MIRROR_PLACEHOLDER before writing the config pages. If it does not,
    the offset arithmetic and the actual write have diverged and enabling the
    mirror would corrupt the URL (§6.2).
    """
    offset = placeholder_offset(host)
    return tlv[offset:offset + MIRROR_LEN]
