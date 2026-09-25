"""The Raspberry Pi enroller. Replaces v1's pi_app.py.
ARCHITECTURE.md §12.1.

    python enroller.py --batch AMX-2026-09-001
    python enroller.py --calibrate            # counter byte order, §20.7
    python enroller.py --drain                # flush the outbox and exit

THE ENROLMENT SEQUENCE, and why each step is where it is:

  0. Clock check, KeyProvider load, OUTBOX DRAIN, batch session open.
  1. Operator confirms batch + product. mfg_date comes from the BATCH, not from
     typing it per pack (F8).
  2. Wait for a tag.
  3. GET_VERSION -> assert vendor 04h, storage 0Fh, else REJECT (A12).
  4. READ_SIG -> originality check.
       FAILED      -> REJECT, quarantine, audit, count the rejection (A2, F9a)
       UNAVAILABLE -> proceed, record originality_status='unverified'
  5. token = 16 random bytes -> 32 hex chars.
  6. Build the URL and the NDEF TLV (raises if > 137 bytes).
  7. Write the TLV from page 04h, one page at a time, 3 retries + ~50 ms settle.
  8. FAST_READ and BYTE-COMPARE. Mismatch: retry once, then DISCARD THE TAG.
  9. Assert the 21 bytes at mirror_position() are the all-zero placeholder.
 10. READ_CNT -> enrol_counter.
 11. Write CFG0 (mirror) then CFG1 (NFC_CNT_EN=1). MTA IS ENABLED HERE.
 12. If TAG_LOCK_ENABLED and --i-understand-this-is-permanent: lock.
 13. POWER-CYCLE THE FIELD. Read once as a phone would. Assert the URL now
     carries a real UID and a counter STRICTLY GREATER than step 10.
     If not, the mirror is not working. DISCARD THE TAG. Do not ship it.
 14. Seal the record to the backend's public key.
 15. outbox.enqueue(...)  <- DURABLE, BEFORE ANY NETWORK I/O.
 16. Print "OK — queued". The drainer handles the rest.

STEP 13 IS THE MOST IMPORTANT OPERATIONAL STEP IN THE WHOLE BUILD. It is the only
way to know the mirror is actually working BEFORE the pack ships. A tag that
enrols cleanly but whose mirror never turns on produces MIRROR_DISABLED on every
consumer scan — a genuine pack that verifies badly, forever.

STEP 15 BEFORE ANY NETWORK CALL is the F3 fix (§5.4). Nothing is reported as
successful to the operator until the record is durably on disk.

THE QR FALLBACK IS GONE (F4, §12.2). v1 printed a QR of the same URL when the
NDEF write failed. A QR is static copyable data — a pack shipped with a QR
fallback has NONE of the physical binding this system exists to provide, and it
is indistinguishable to the consumer. If the tag write fails, discard the tag and
use a new one.
"""
from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys
import time
import uuid

from dotenv import load_dotenv

import batch_session
import clockcheck
import crypto_envelope
import drainer as drainer_mod
import keyprovider
import ntag
import originality
import outbox as outbox_mod
import tag_config
import tag_layout

load_dotenv()

log = logging.getLogger("enroller")

POWER_CYCLE_SECONDS = 1.5
READBACK_RETRIES = 2


class TagDiscarded(RuntimeError):
    """This tag must not ship. Bin it and use a new one."""


# ----------------------------------------------------------------- hardware ---

def open_pn532():
    """Import the hardware libraries lazily so --calibrate, --drain and the unit
    tests all work on a laptop with no PN532 attached."""
    import board
    import busio
    from adafruit_pn532.i2c import PN532_I2C

    i2c = busio.I2C(board.SCL, board.SDA)
    pn532 = PN532_I2C(i2c, debug=False)
    pn532.SAM_configuration()
    return pn532


def wait_for_tag(pn532, timeout: float = 30.0) -> bytes:
    deadline = time.time() + timeout
    while time.time() < deadline:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid:
            return bytes(uid)
    raise TimeoutError("no tag presented")


def uid_clean(uid: bytes) -> str:
    """Canonical UID form: uppercase hex, no separators. MUST match
    backend/tag_index.normalise_uid. Pinned by tests/vectors/uid.json."""
    return "".join(f"{b:02X}" for b in uid)


# ------------------------------------------------------------------- enrol ----

def enrol_one(pn532, *, cfg: dict, session, box, product_id: str) -> dict:
    """One tag, start to finish. Returns the queued payload."""
    host = cfg["public_host"]

    # 2. Present a tag.
    print("  present a tag...")
    uid_bytes = wait_for_tag(pn532)
    uid = uid_clean(uid_bytes)
    print(f"  UID {uid}")

    # 3. GET_VERSION gate (A12).
    version = ntag.assert_ntag213(pn532)

    # 4. Originality signature (L1). Enrolment only — READ_SIG is unreachable
    #    from Web NFC and from iOS background reading, so this protects
    #    enrolment, not verification (§6.6).
    try:
        signature = ntag.read_sig(pn532)
        status = originality.verify_originality(uid_bytes, signature,
                                                cfg["nxp_pubkey"])
    except ntag.NtagError as exc:
        log.warning("READ_SIG failed: %s", exc)
        status = originality.OriginalityStatus.UNAVAILABLE

    accept, originality_status = originality.decide(status, cfg["originality_policy"])
    if not accept:
        raise TagDiscarded(
            f"originality check FAILED for {uid}. Quarantine this tag. A run of "
            f"these means your supplier shipped counterfeit silicon — that is a "
            f"procurement alert, and finding it here is the point.")
    if originality_status == "unverified":
        print("  originality: UNVERIFIED (no NXP public key configured)")
    else:
        print(f"  originality: {originality_status}")

    # 5-6. Binding token, URL, TLV.
    token_hex = secrets.token_bytes(tag_layout.BINDING_TOKEN_BYTES).hex().upper()
    url = tag_layout.build_verify_url(host, token_hex)
    tlv = tag_layout.build_ndef_tlv(url)
    mirror_page, mirror_byte = tag_layout.mirror_position(host)
    print(f"  NDEF {len(tlv)}B, mirror at page {mirror_page:#04x} byte {mirror_byte}")

    # 7-8. Write, then read back and BYTE-COMPARE. Never skip the compare: the
    #      NDEF area has no hardware anti-tearing protection (A13).
    pages = ntag.write_ndef(pn532, tlv)
    for attempt in range(READBACK_RETRIES):
        try:
            ntag.verify_ndef(pn532, tlv)
            break
        except ntag.NtagError as exc:
            if attempt + 1 >= READBACK_RETRIES:
                raise TagDiscarded(f"NDEF read-back mismatch: {exc}") from exc
            log.warning("read-back mismatch, rewriting: %s", exc)
            ntag.write_ndef(pn532, tlv)

    # 9. The placeholder must be exactly where the mirror config says it is. If
    #    it is not, enabling the mirror would corrupt the URL.
    readback = ntag.read_ndef(pn532, pages)
    found = tag_layout.extract_placeholder(readback, host)
    if found != tag_layout.MIRROR_PLACEHOLDER.encode("ascii"):
        raise TagDiscarded(
            f"placeholder is not at the computed mirror position: got {found!r}. "
            f"The offset arithmetic and the actual write have diverged.")

    # 10. Capture the counter as it stands after our own handful of reads.
    enrol_counter = ntag.read_counter(pn532, cfg["cnt_byte_order"])
    print(f"  counter at enrolment: {enrol_counter}")

    # 11. Enable the mirror and the counter. MTA is live from here.
    cfg0, cfg1 = tag_config.testing_config(mirror_byte, mirror_page)
    if cfg["tag_lock_enabled"]:
        cfg0, cfg1 = tag_config.production_config(mirror_byte, mirror_page)
    tag_config.write_config(pn532, cfg0, cfg1)

    # 12. Optional, irreversible.
    if cfg["tag_lock_enabled"]:
        tag_config.apply_lock_sequence(
            pn532, uid, tag_lock_enabled=True,
            acknowledged_permanent=cfg["lock_acknowledged"],
            pwd_master_hex=cfg["tag_pwd_master"],
            mirror_byte=mirror_byte, mirror_page=mirror_page, ndef_pages=pages)

    # 13. Power-cycle and confirm the mirror is LIVE. The single most important
    #     operational check in the build.
    _power_cycle(pn532)
    live_counter = _confirm_mirror_live(pn532, host, pages, enrol_counter)
    print(f"  mirror confirmed live, counter now {live_counter}")

    # 14. Seal to the backend's PUBLIC key. The Pi cannot read the register back.
    sealed = crypto_envelope.seal_record(
        {"product_id": product_id,
         "batch_id": session.batch_ref,
         "mfg_date": session.mfg_date,
         "tag_uid": uid},
        cfg["field_recipient_pub"])

    payload = {
        "schema": "nfcmed.enrol.v2",
        "crypto_version": "aes_gcm_v2",
        "batch_ref": session.batch_ref,
        "binding_token_hash": _sha256_hex(token_hex),
        "enrol_counter": enrol_counter,
        "originality_status": originality_status,
        "binding_class": "counter",
        "tag_version": version.hex().upper(),
        "sealed": sealed,
    }

    # 15. DURABLE, BEFORE ANY NETWORK I/O. This is the F3 fix.
    box.enqueue(payload, idempotency_key=str(uuid.uuid4()))
    return payload


def _sha256_hex(token_hex: str) -> str:
    import hashlib
    return hashlib.sha256(token_hex.upper().encode("ascii")).hexdigest()


def _power_cycle(pn532) -> None:
    """Drop and re-raise the RF field so the chip re-reads its config and starts
    mirroring. Without this the tag in hand still has the pre-config state."""
    try:
        pn532.power_down()
    except Exception:
        pass
    time.sleep(POWER_CYCLE_SECONDS)
    try:
        pn532.SAM_configuration()
    except Exception:
        pass
    wait_for_tag(pn532, timeout=10)


def _confirm_mirror_live(pn532, host: str, pages: int, enrol_counter: int) -> int:
    """Read the tag exactly as a phone would and assert the mirror really fired.

    Two things must now be true: the placeholder has been replaced by a real UID,
    and the counter is STRICTLY GREATER than what we recorded at step 10 (our own
    confirmation read advanced it).
    """
    data = ntag.read_ndef(pn532, pages)
    mirrored = tag_layout.extract_placeholder(data, host)
    try:
        text = mirrored.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TagDiscarded("mirrored bytes are not ASCII") from exc

    if text == tag_layout.MIRROR_PLACEHOLDER or text.startswith("00000000000000"):
        raise TagDiscarded(
            "the mirror did not fire — the URL still contains the placeholder. "
            "This tag would return MIRROR_DISABLED on every consumer scan. "
            "DISCARD IT. Do not ship it.")

    uid_part, _, counter_part = text.partition("x")
    if len(uid_part) != 14 or len(counter_part) != 6:
        raise TagDiscarded(f"mirrored value has the wrong shape: {text!r}")

    try:
        live_counter = int(counter_part, 16)
    except ValueError as exc:
        raise TagDiscarded(f"mirrored counter is not hex: {counter_part!r}") from exc

    if live_counter <= enrol_counter:
        raise TagDiscarded(
            f"counter did not advance ({live_counter} <= {enrol_counter}). Either "
            f"NFC_CNT_EN did not take, or CNT_BYTE_ORDER is wrong. DISCARD THIS "
            f"TAG and re-run --calibrate.")
    return live_counter


# --------------------------------------------------------------- calibration --

def calibrate(pn532, byte_order_guess: str = "msb") -> str:
    """§6.4 / §20.7. Determine CNT_BYTE_ORDER on a scrap tag. Never guess.

    Enable the counter and mirror on a scrap tag, READ_CNT for the raw 3 bytes,
    read the mirrored ASCII, and see which interpretation matches. If the Pi and
    the backend disagree on this, every enrol_counter is wrong and the velocity
    bound is nonsense — a silent, hard-to-debug failure.
    """
    uid_bytes = wait_for_tag(pn532)
    ntag.assert_ntag213(pn532)
    raw = ntag.transceive(pn532, [ntag.CMD_READ_CNT, 0x02], 3)
    msb = int.from_bytes(raw, "big")
    lsb = int.from_bytes(raw, "little")

    print(f"UID           {uid_clean(uid_bytes)}")
    print(f"READ_CNT raw  {raw.hex().upper()}")
    print(f"  as MSB-first: {msb}  ({msb:06X})")
    print(f"  as LSB-first: {lsb}  ({lsb:06X})")
    print()
    print("Now read the tag's NDEF URL with a phone and look at the 6 hex digits")
    print("after the 'x' in the m= parameter. Whichever line above matches is your")
    print("CNT_BYTE_ORDER. Record it in BOTH pi/.env and backend/.env, and write")
    print("it into backend/tests/vectors/counter.json.")
    print()
    print("Both the Pi and the backend refuse to start without it (§15.4) — that is")
    print("deliberate, because guessing corrupts data silently.")
    return byte_order_guess


# --------------------------------------------------------------------- main ---

def load_settings(args) -> dict:
    required = {
        "DEVICE_ID": os.getenv("DEVICE_ID", ""),
        "BACKEND_URL": os.getenv("BACKEND_URL", ""),
        "PUBLIC_HOST": os.getenv("PUBLIC_HOST", ""),
        "CNT_BYTE_ORDER": os.getenv("CNT_BYTE_ORDER", ""),
        "FIELD_RECIPIENT_PUB": os.getenv("FIELD_RECIPIENT_PUB", ""),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise SystemExit(f"pi/.env is missing: {', '.join(missing)}")
    if required["CNT_BYTE_ORDER"].lower() not in ("msb", "lsb"):
        raise SystemExit(
            "CNT_BYTE_ORDER must be 'msb' or 'lsb'. Run --calibrate on a scrap "
            "tag first (§20.7). There is no default on purpose.")

    return {
        "device_id": required["DEVICE_ID"],
        "backend_url": required["BACKEND_URL"],
        "public_host": required["PUBLIC_HOST"],
        "cnt_byte_order": required["CNT_BYTE_ORDER"].lower(),
        "field_recipient_pub": bytes.fromhex(required["FIELD_RECIPIENT_PUB"]),
        "nxp_pubkey": os.getenv("NXP_ORIGINALITY_PUBKEY", ""),
        "originality_policy": os.getenv("ORIGINALITY_POLICY", "reject").lower(),
        "tag_lock_enabled": os.getenv("TAG_LOCK_ENABLED", "false").lower()
        in ("1", "true", "yes", "on"),
        "tag_pwd_master": os.getenv("TAG_PWD_MASTER", ""),
        "lock_acknowledged": args.i_understand_this_is_permanent,
        "admin_token": os.getenv("ADMIN_TOKEN", ""),
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    ap = argparse.ArgumentParser(description="NFC medicine tag enroller (v2)")
    ap.add_argument("--batch", help="batch_ref of an OPEN batch")
    ap.add_argument("--calibrate", action="store_true",
                    help="determine CNT_BYTE_ORDER on a scrap tag, then exit")
    ap.add_argument("--drain", action="store_true",
                    help="flush the outbox and exit")
    ap.add_argument("--status", action="store_true",
                    help="print outbox depth and exit")
    ap.add_argument("--i-understand-this-is-permanent", action="store_true",
                    dest="i_understand_this_is_permanent",
                    help="required alongside TAG_LOCK_ENABLED=true; IRREVERSIBLE")
    args = ap.parse_args()

    box = outbox_mod.open_outbox()

    if args.status:
        print(f"outbox: {box.stats()}  depth={box.depth()}  failed={box.failed_count()}")
        for row in box.failed_rows():
            print(f"  FAILED id={row['id']} attempts={row['attempts']} "
                  f"error={row['last_error']}")
        return 0

    # --calibrate MUST come before load_settings. Its whole purpose is to
    # determine CNT_BYTE_ORDER, and load_settings refuses to start without that
    # value — so gating calibration on it made the one command that produces it
    # unreachable, with an error telling you to run the command you just ran.
    # calibrate() needs the reader and nothing else.
    if args.calibrate:
        calibrate(open_pn532())
        return 0

    settings = load_settings(args)
    provider = keyprovider.load_key_provider(
        os.getenv("KEY_PROVIDER", "file"),
        privkey_hex=os.getenv("DEVICE_PRIVATE_KEY", ""),
        device_id=settings["device_id"])
    drainer = drainer_mod.Drainer(box, provider, settings["backend_url"],
                                 admin_token=settings["admin_token"])

    if args.drain:
        sent = drainer.drain_now(max_seconds=300)
        print(f"drained {sent}; depth now {box.depth()}")
        return 0

    if not args.batch:
        ap.error("--batch is required (or use --calibrate / --drain / --status)")

    # 0. Clock, then DRAIN THE BACKLOG, then open the batch. A Pi rebooted
    #    mid-run must flush before it is allowed to create more work.
    clockcheck.assert_clock_sane(settings["backend_url"])
    pending = box.depth()
    if pending:
        print(f"outbox has {pending} unsent records — draining before we start...")
        drainer.drain_now(max_seconds=120)
        if box.depth():
            print(f"WARNING: {box.depth()} records still unsent. Genuine packs are "
                  f"shipping without records. Fix connectivity before enrolling more.")

    session = batch_session.load(settings["backend_url"], args.batch,
                                settings["admin_token"])
    batch_session.confirm_countersignature(session)

    if settings["tag_lock_enabled"]:
        print("\n*** TAG LOCKING IS ENABLED. Every tag written from here is "
              "PERMANENTLY locked. ***\n")
    else:
        print("\nTag locking: DISABLED (testing posture). Tags stay rewritable; "
              "the counter and mirror still work fully.\n")

    pn532 = open_pn532()
    drainer.start()
    last_clock_check = time.time()
    enrolled = 0

    try:
        while True:
            product_id = input("product_id (blank to finish): ").strip()
            if not product_id:
                break

            if time.time() - last_clock_check > clockcheck.RECHECK_INTERVAL_S:
                clockcheck.assert_clock_sane(settings["backend_url"])
                last_clock_check = time.time()

            try:
                enrol_one(pn532, cfg=settings, session=session, box=box,
                          product_id=product_id)
            except TagDiscarded as exc:
                print(f"  DISCARD THIS TAG: {exc}\n")
                continue
            except (ntag.TagRejected, ntag.NtagError) as exc:
                print(f"  TAG REJECTED: {exc}\n")
                continue
            except TimeoutError:
                print("  no tag presented; skipping\n")
                continue

            enrolled += 1
            print(f"  OK — queued. outbox depth {box.depth()}, "
                  f"enrolled this session {enrolled}\n")
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        print("flushing the outbox before exit...")
        drainer.drain_now(max_seconds=120)
        drainer.stop()
        depth = box.depth()
        if depth:
            print(f"WARNING: {depth} records still unsent. Run "
                  f"`python enroller.py --drain` once connectivity is back. "
                  f"Do not ship those packs until it reports depth 0.")
        else:
            print("outbox empty — every pack enrolled this session is recorded.")
        box.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
