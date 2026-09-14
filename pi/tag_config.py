"""NTAG213 configuration pages and the irreversible lock sequence.
ARCHITECTURE.md §6.5, §6.7.

Pages 29h (CFG0) and 2Ah (CFG1). Each is 4 bytes and must be written whole.

CFG0 — page 29h: [MIRROR, RFUI, MIRROR_PAGE, AUTH0]
    MIRROR byte:  bit7..6  MIRROR_CONF   = 11b  (UID + counter)
                  bit5..4  MIRROR_BYTE   = computed, 0..3
                  bit3     RFUI          = 0
                  bit2     STRG_MOD_EN   = 1    (strong modulation, default on)
                  bit1..0  RFUI          = 0

CFG1 — page 2Ah: [ACCESS, RFUI, RFUI, RFUI]
    ACCESS byte:  bit7     PROT              0 = write protection only
                  bit6     CFGLCK            0 = config writable, 1 = PERMANENT
                  bit5     RFUI              0
                  bit4     NFC_CNT_EN        1 = counter ON   <- the whole point
                  bit3     NFC_CNT_PWD_PROT  0 = counter readable without auth
                  bit2..0  AUTHLIM           000b = no attempt limit

Four choices, each with a stated reason:

  NFC_CNT_PWD_PROT = 0 — must be off. With it on, the counter is only mirrored
      after a password authentication, which a consumer's browser cannot perform.
      This is also the honest reason the counter is not confidentiality-protected.

  PROT = 0 — write protection only. Reads must stay open or no phone works.

  AUTHLIM = 000b — a genuine trade-off. AUTHLIM = 7 would block password
      brute-forcing (A9), but it also lets anyone with physical access
      PERMANENTLY BRICK a genuine pack by deliberately failing eight
      authentications (A10) — turning a security control into a DoS weapon
      against your own product. The password only guards reconfiguration and
      lock bytes already make the data area read-only, so the brute-force risk
      is low and the bricking risk is real. Leave it at 0.

  AUTH0 = 29h, not 2Bh — the source design doc said 2Bh, which protects only
      PWD/PACK, and those are already unreadable by design. It protects nothing
      that matters. 29h is what actually stops an attacker writing
      NFC_CNT_EN = 0 to kill the counter (A8). See §1.2.
"""
from __future__ import annotations

import hashlib
import hmac

CFG0_PAGE = 0x29
CFG1_PAGE = 0x2A
PWD_PAGE = 0x2B
PACK_PAGE = 0x2C
STATIC_LOCK_PAGE = 0x02
DYNAMIC_LOCK_PAGE = 0x28

AUTH0_DISABLED = 0xFF   # password protection off — testing posture
AUTH0_PROTECT_CONFIG = 0x29  # protect page 29h onward — production posture


class LockRefused(RuntimeError):
    """apply_lock_sequence() refused to run. This is the safe outcome."""


def cfg0_bytes(mirror_byte: int, mirror_page: int, auth0: int) -> list[int]:
    """CFG0 with MIRROR_CONF = 11b (UID + counter mirror) and STRG_MOD_EN = 1."""
    if not 0 <= mirror_byte <= 3:
        raise ValueError(f"MIRROR_BYTE must be 0..3, got {mirror_byte}")
    if not 0x04 <= mirror_page <= 0x27:
        raise ValueError(f"MIRROR_PAGE must be 04h..27h, got {mirror_page:#04x}")
    mirror = (0b11 << 6) | ((mirror_byte & 0b11) << 4) | (1 << 2)
    return [mirror, 0x00, mirror_page, auth0 & 0xFF]


def cfg1_bytes(*, cfglck: bool, prot: bool = False,
               cnt_en: bool = True, cnt_pwd_prot: bool = False,
               authlim: int = 0) -> list[int]:
    """CFG1. Defaults are the correct ones; every non-default needs a reason."""
    if not 0 <= authlim <= 7:
        raise ValueError("AUTHLIM must be 0..7")
    access = ((int(prot) << 7) | (int(cfglck) << 6) | (int(cnt_en) << 4)
              | (int(cnt_pwd_prot) << 3) | (authlim & 0b111))
    return [access, 0x00, 0x00, 0x00]


def testing_config(mirror_byte: int, mirror_page: int) -> tuple[list[int], list[int]]:
    """TAG_LOCK_ENABLED=false posture: counter and mirror ON, nothing locked.

    Critical point that is easy to get wrong: the counter and mirror are
    INDEPENDENT of locking. Enabling NFC_CNT_EN and MIRROR_CONF is an ordinary
    write to 29h/2Ah and stays reversible while CFGLCK = 0. So MTA works fully
    during testing with tags that remain rewritable (§6.7).
    """
    return (cfg0_bytes(mirror_byte, mirror_page, AUTH0_DISABLED),
            cfg1_bytes(cfglck=False))          # ACCESS = 0x10


def production_config(mirror_byte: int, mirror_page: int) -> tuple[list[int], list[int]]:
    """TAG_LOCK_ENABLED=true posture. CFGLCK = 1 is PERMANENT."""
    return (cfg0_bytes(mirror_byte, mirror_page, AUTH0_PROTECT_CONFIG),
            cfg1_bytes(cfglck=True))           # ACCESS = 0x50


def diversified_pwd(uid: str, master_hex: str) -> tuple[bytes, bytes]:
    """(PWD, PACK) derived per tag from TAG_PWD_MASTER + UID. One tag's password
    is useless against another. Only used when locking is enabled."""
    mac = hmac.new(bytes.fromhex(master_hex), uid.encode("ascii"), hashlib.sha256).digest()
    return mac[:4], mac[4:6]


def write_config(pn532, cfg0: list[int], cfg1: list[int]) -> None:
    """Write CFG0 then CFG1. Order matters: the mirror position must be in place
    before the counter is switched on, so the first mirrored read is correct."""
    import ntag
    ntag.write_page(pn532, CFG0_PAGE, bytes(cfg0))
    ntag.write_page(pn532, CFG1_PAGE, bytes(cfg1))


def apply_lock_sequence(pn532, uid: str, *, tag_lock_enabled: bool,
                        acknowledged_permanent: bool, pwd_master_hex: str,
                        mirror_byte: int, mirror_page: int,
                        ndef_pages: int) -> None:
    """EVERY STEP HERE IS IRREVERSIBLE. §6.7.

    Refuses to run unless TAG_LOCK_ENABLED=true AND the operator passed
    --i-understand-this-is-permanent to enroller.py. Runs only after the NDEF
    read-back byte-compare has passed.

    Order:
      1. Static lock bytes (page 02h, bytes 2-3) -> lock pages 03h-0Fh
      2. Dynamic lock bytes (page 28h)           -> lock the remaining pages
      3. Diversified PWD/PACK (2Bh/2Ch)
      4. AUTH0 = 29h and CFGLCK = 1 in CFG0/CFG1
    Then the caller power-cycles and reads once as a phone would, to confirm the
    mirror is still live.
    """
    import ntag

    if not tag_lock_enabled:
        raise LockRefused(
            "TAG_LOCK_ENABLED is false. Locking is off for this build phase "
            "(decision D5) — tags stay rewritable, and MTA still works fully.")
    if not acknowledged_permanent:
        raise LockRefused(
            "Locking is permanent and unrecoverable. Re-run enroller.py with "
            "--i-understand-this-is-permanent if you really mean it.")
    if not pwd_master_hex:
        raise LockRefused("TAG_PWD_MASTER is required when locking is enabled")

    # 1. Static lock bytes: lock pages 03h-0Fh. Bytes 0-1 of page 02h are part of
    #    the UID/internal area and must be written back as read, not zeroed.
    page02 = ntag.fast_read(pn532, 0x02, 0x02)[:4]
    ntag.write_page(pn532, STATIC_LOCK_PAGE, bytes([page02[0], page02[1], 0xFF, 0xFF]))

    # 2. Dynamic lock bytes: lock 10h upward in 2-page granularity, covering the
    #    pages the NDEF actually occupies. The 4th byte is RFUI and must be BDh.
    last_written_page = 0x04 + ndef_pages - 1
    dyn = _dynamic_lock_bytes(last_written_page)
    ntag.write_page(pn532, DYNAMIC_LOCK_PAGE, bytes([*dyn, 0xBD]))

    # 3. Diversified password, then 4. AUTH0 + CFGLCK. PWD must be set before
    #    AUTH0 takes effect, or the tag is protected by an unknown password.
    pwd, pack = diversified_pwd(uid, pwd_master_hex)
    ntag.write_page(pn532, PWD_PAGE, pwd)
    ntag.write_page(pn532, PACK_PAGE, bytes(pack) + b"\x00\x00")

    cfg0, cfg1 = production_config(mirror_byte, mirror_page)
    write_config(pn532, cfg0, cfg1)


def _dynamic_lock_bytes(last_page: int) -> list[int]:
    """Three dynamic lock bytes covering pages 10h..27h in 2-page blocks.

    LOCK byte 0 bit i -> pages (10h + 2i, 10h + 2i + 1), and so on across the
    three bytes. Pages at or below 0Fh are already covered by the static locks.
    """
    bits = [0, 0, 0]
    for page in range(0x10, min(last_page, 0x27) + 1):
        block = (page - 0x10) // 2
        bits[block // 8] |= 1 << (block % 8)
    return bits
