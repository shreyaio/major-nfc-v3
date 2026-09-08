"""
Raspberry Pi + PN532 tag-writing app.

Writes two things to each NFC tag:
1. Pages 4-7 (paper cipher block, UNTOUCHED): a 16-byte ciphertext block using the
   custom bit-shift/inversion cipher described in the paper (Section III-B). This
   demonstrates the paper's algorithm and is kept byte-for-byte identical to the
   original implementation.
2. Pages 8+ (new): a standard NDEF URI record pointing at the consumer verify
   webpage (`https://<host>/verify.html?t=<tag_uid_hash>`), so tapping the tag with
   a phone opens the verification page natively.

Posts the full record to the backend over HTTPS/HTTP using AES-256-GCM
(crypto_version: "aes_gcm_v1") — the production crypto path. No key material
(key_chars/key_mac) is ever sent; the server derives the same per-tag key
independently from AES_MASTER_KEY + tag_uid_hash, exactly like this script does.
"""

import board
import busio
import time
import requests
import json
import os
import threading
import hmac as _hmac
import hashlib
import json as _json
import secrets
from adafruit_pn532.i2c import PN532_I2C
from dotenv import load_dotenv

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

load_dotenv()

SHARED_SECRET  = bytes.fromhex(os.getenv("SHARED_SECRET", ""))
AES_MASTER_KEY = bytes.fromhex(os.getenv("AES_MASTER_KEY", ""))

# This device's own Ed25519 identity. The private key never leaves this Pi --
# it's never sent in a request and never stored server-side. The backend only
# ever needs the matching public key (see backend/config.py PI_PUBLIC_KEYS) to
# verify signatures, so leaking the server's config can't be used to forge a
# write under this device's identity.
PI_PRIVATE_KEY = bytes.fromhex(os.getenv("PI_PRIVATE_KEY", ""))
_pi_signing_key = Ed25519PrivateKey.from_private_bytes(PI_PRIVATE_KEY)

# ================= CONFIG =================
BACKEND_URL             = os.getenv("BACKEND_URL", "http://localhost:5000")
FRONTEND_VERIFY_BASE_URL = os.getenv("FRONTEND_VERIFY_BASE_URL", "http://localhost:5000")
SHELF_LIFE_DAYS         = int(os.getenv("SHELF_LIFE_DAYS", "365"))

# ================= PAPER CRYPTO (UNTOUCHED — matches backend/crypto_paper.py) =================

def derive_key_chars(tag_uid: str, shared_secret: bytes):
    raw   = _hmac.new(shared_secret, tag_uid.encode(), hashlib.sha256).digest()
    chars = [chr(32 + (b % 95)) for b in raw[:4]]
    keys  = []
    for ch in chars:
        ascii_val = ord(ch)
        bits      = format(ascii_val, '08b')
        msb_val   = int(bits[0:4], 2) % 2
        lsb_val   = int(bits[4:8], 2)
        keys.append(msb_val * 10 + lsb_val)
    return keys, chars


def circular_left_shift_bits(byte_val, n):
    """Circular left shift of an 8-bit value by n positions."""
    n = n % 8
    return ((byte_val << n) | (byte_val >> (8 - n))) & 0xFF


def circular_right_shift_bits(byte_val, n):
    """Circular right shift of an 8-bit value by n positions."""
    n = n % 8
    return ((byte_val >> n) | (byte_val << (8 - n))) & 0xFF


def invert_bits(byte_val):
    """Invert all bits of a byte."""
    return (~byte_val) & 0xFF


def apply_key_to_block(block_bytes, key_pair, direction):
    """
    Apply one key pair to a block of bytes.

    key_pair : integer like 01, 04, 19, 18
      first_digit  = key_pair // 10  -> start byte position (0 or 1 after %2)
      last_digit   = key_pair  % 10  -> shift amount (>8 means invert)

    direction : 'left' or 'right'

    From Section III-B:
      - Operate from first_digit position to end of block
      - If last_digit == 0 or last_digit > 8 -> invert bits
      - Else -> circular shift in given direction by last_digit positions
    """
    first_digit = key_pair // 10    # byte position to start from
    last_digit  = key_pair  % 10    # number of bit shifts

    result = bytearray(block_bytes)
    for i in range(first_digit, len(result)):
        if last_digit == 0 or last_digit > 8:
            result[i] = invert_bits(result[i])
        elif direction == 'left':
            result[i] = circular_left_shift_bits(result[i], last_digit)
        else:
            result[i] = circular_right_shift_bits(result[i], last_digit)
    return bytes(result)


def encrypt_paper(plaintext_str, keys):
    """
    Data Encryption — Section III-B of the paper.
    1. Pad and divide plaintext into 10-byte blocks
    2. Split keys into K1 (first half) and K2 (second half)
    3. Apply K1 keys with circular LEFT shift
    4. Apply K2 keys with circular RIGHT shift
    Returns ciphertext as bytes.
    """
    raw = plaintext_str.encode('latin-1', errors='replace')
    pad_len = (10 - len(raw) % 10) % 10
    raw += b'_' * pad_len

    blocks = [bytearray(raw[i:i+10]) for i in range(0, len(raw), 10)]

    mid   = (len(keys) + 1) // 2
    k1    = keys[:mid]
    k2    = keys[mid:]

    encrypted_blocks = []
    for block in blocks:
        b = bytes(block)
        for kp in k1:
            b = apply_key_to_block(b, kp, 'left')
        for kp in k2:
            b = apply_key_to_block(b, kp, 'right')
        encrypted_blocks.append(b)

    return b''.join(encrypted_blocks)


def decrypt_paper(cipher_bytes, keys):
    """
    Data Decryption — Section III-C of the paper.
    Reverse of encryption:
    1. Divide ciphertext into 10-byte blocks
    2. Apply K2 keys in REVERSE order with circular LEFT shift
    3. Apply K1 keys in REVERSE order with circular RIGHT shift
    4. Concatenate blocks and strip padding
    """
    blocks = [cipher_bytes[i:i+10] for i in range(0, len(cipher_bytes), 10)]

    mid = (len(keys) + 1) // 2
    k1  = keys[:mid]
    k2  = keys[mid:]

    decrypted_blocks = []
    for block in blocks:
        b = bytes(block)
        for kp in reversed(k2):
            b = apply_key_to_block(b, kp, 'left')
        for kp in reversed(k1):
            b = apply_key_to_block(b, kp, 'right')
        decrypted_blocks.append(b)

    result = b''.join(decrypted_blocks)
    return result.rstrip(b'_').decode('latin-1', errors='replace')


def encrypt_for_nfc(plaintext_str, keys):
    """
    Encrypt and return exactly 16 bytes for NFC writing (4 pages x 4 bytes).
    Pads/truncates the encrypted output to fit NFC block size.
    """
    cipher = encrypt_paper(plaintext_str[:15], keys)  # keep it short
    if len(cipher) < 16:
        cipher = cipher + b'\x00' * (16 - len(cipher))
    return cipher[:16]


def decrypt_from_nfc(cipher_bytes, keys):
    """Decrypt 16 bytes read from NFC tag."""
    cipher_bytes = cipher_bytes.rstrip(b'\x00')
    pad_len = (10 - len(cipher_bytes) % 10) % 10
    cipher_bytes += b'_' * pad_len
    return decrypt_paper(cipher_bytes, keys)


# ================= MODERN CRYPTO (production path — matches backend/crypto_modern.py) =================

def derive_tag_key(tag_uid_hash_hex: str, master_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"nfc-tag-aes-key:" + tag_uid_hash_hex.encode(),
    )
    return hkdf.derive(master_secret)


def aes_gcm_encrypt(plaintext: str, key: bytes) -> tuple:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce.hex(), ct.hex()


# ================= NDEF (tap-to-verify link written to pages 8+) =================

def build_ndef_uri_message(url: str) -> bytes:
    """
    Wraps `url` in a Type-2-Tag NDEF URI record, TLV-wrapped and terminated,
    ready to be written starting at page 8. Uses the NFC Forum URI abbreviation
    code matching the URL's actual scheme so only the rest of the URL is stored.
    """
    # 0x03 = "http://" abbreviation, 0x04 = "https://" abbreviation (NFC Forum URI codes).
    # Must match whichever scheme FRONTEND_VERIFY_BASE_URL actually uses, or the tag will
    # decode to the wrong protocol when a phone taps it.
    if url.startswith("https://"):
        abbrev_code, prefix = 0x04, "https://"
    elif url.startswith("http://"):
        abbrev_code, prefix = 0x03, "http://"
    else:
        raise ValueError("FRONTEND_VERIFY_BASE_URL must start with http:// or https:// for NDEF writing")
    rest = url[len(prefix):].encode("ascii")

    payload = bytes([abbrev_code]) + rest
    record = bytes([0xD1, 0x01, len(payload), ord('U')]) + payload  # short record, TNF=well-known, type='U'

    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])  # NDEF Message TLV + Terminator TLV

    # Pad to a whole number of 4-byte pages
    pad_len = (4 - len(tlv) % 4) % 4
    tlv += b'\x00' * pad_len
    return tlv


NDEF_START_PAGE = 8
NDEF_AVAILABLE_PAGES = 32  # NTAG213 user memory pages 8-39 (128 bytes)

QR_FALLBACK_DIR = os.getenv("QR_FALLBACK_DIR", "qr_codes")


def save_qr_fallback(url: str, tag_uid: str) -> str:
    """Generates a printable QR code PNG for `url` when NDEF writing isn't possible
    (e.g. the URL is too long for NTAG213's remaining user memory, or the write
    itself fails). Returns the saved file path."""
    import qrcode
    os.makedirs(QR_FALLBACK_DIR, exist_ok=True)
    path = os.path.join(QR_FALLBACK_DIR, f"{tag_uid}.png")
    qrcode.make(url).save(path)
    return path


NDEF_PAGE_WRITE_DELAY = float(os.getenv("NDEF_PAGE_WRITE_DELAY", "0.05"))
NDEF_PAGE_WRITE_RETRIES = int(os.getenv("NDEF_PAGE_WRITE_RETRIES", "3"))


def write_ndef(pn532, url: str):
    """
    Writes the NDEF TLV one 4-byte page at a time. Unlike the 4-page paper-cipher
    block, this is ~29 pages for a typical URL -- long enough that a transient
    I2C/RF hiccup (e.g. "Response frame preamble does not contain 0x00FF!") or
    the tag not finishing its internal EEPROM write cycle before the next command
    becomes a real risk. Each page write gets a few retries, and a short pause
    after every successful write gives the tag's EEPROM cycle time to finish
    before the next command lands.
    """
    tlv = build_ndef_uri_message(url)
    pages_needed = len(tlv) // 4
    if pages_needed > NDEF_AVAILABLE_PAGES:
        raise ValueError(
            f"NDEF record needs {pages_needed} pages but only {NDEF_AVAILABLE_PAGES} are "
            f"available on NTAG213 (pages 8-39). Use a shorter FRONTEND_VERIFY_BASE_URL, or "
            f"switch to NTAG215/216 for more user memory."
        )
    for i in range(pages_needed):
        page_data = list(tlv[i*4:(i+1)*4])
        page_num = NDEF_START_PAGE + i
        last_err = None
        for attempt in range(1, NDEF_PAGE_WRITE_RETRIES + 1):
            try:
                pn532.ntag2xx_write_block(page_num, page_data)
                last_err = None
                break
            except Exception as e:
                last_err = e
                if attempt < NDEF_PAGE_WRITE_RETRIES:
                    time.sleep(NDEF_PAGE_WRITE_DELAY * 2)  # extra settle time before retrying
        if last_err is not None:
            raise RuntimeError(
                f"NDEF write failed at page {page_num} after {NDEF_PAGE_WRITE_RETRIES} attempts: {last_err}"
            )
        time.sleep(NDEF_PAGE_WRITE_DELAY)


# ================= HELPERS =================

def uid_clean(uid):
    return "".join("{:02X}".format(x) for x in uid)


def sign_body(body: dict) -> tuple:
    """Returns (timestamp_str, hex_signature). Signs with this device's Ed25519
    private key -- the backend verifies with the matching public key only."""
    ts      = str(int(time.time()))
    payload = ts + _json.dumps(body, sort_keys=True, separators=(',', ':'))
    sig     = _pi_signing_key.sign(payload.encode('utf-8')).hex()
    return ts, sig


# ================= BACKEND =================

def send_backend(product_id, batch_id, mfg, tag_uid, tag_uid_hash):
    """Encrypts every field with AES-256-GCM (crypto_version=aes_gcm_v1) and posts
    the signed record to the backend. No key material is ever transmitted."""
    key = derive_tag_key(tag_uid_hash, AES_MASTER_KEY)

    pid_iv, pid_ct = aes_gcm_encrypt(product_id, key)
    bid_iv, bid_ct = aes_gcm_encrypt(batch_id,   key)
    mfg_iv, mfg_ct = aes_gcm_encrypt(mfg,        key)
    uid_iv, uid_ct = aes_gcm_encrypt(tag_uid,    key)

    nonce = secrets.token_hex(8)

    body = {
        "crypto_version": "aes_gcm_v1",
        "nonce":          nonce,
        "tag_uid_hash":   tag_uid_hash,
        "product_id":     {"iv": pid_iv, "data": pid_ct},
        "batch_id":       {"iv": bid_iv, "data": bid_ct},
        "mfg_date":       {"iv": mfg_iv, "data": mfg_ct},
        "shelf_life":     SHELF_LIFE_DAYS,
        "tag_uid":        {"iv": uid_iv, "data": uid_ct},
    }
    ts, sig = sign_body(body)
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp":  ts,
        "X-Signature":  sig,
    }
    try:
        r = requests.post(BACKEND_URL + "/api/products", json=body, headers=headers, timeout=5)
        print("[Backend]", r.status_code, r.text)
    except Exception as e:
        print("[Backend] Request failed:", e)


# ================= MAIN =================

START_PAGE = 4  # safe user memory area for the paper-cipher block (pages 4-7)


def main():
    print("========== SYSTEM START ==========")

    try:
        i2c   = busio.I2C(board.SCL, board.SDA)
        pn532 = PN532_I2C(i2c, debug=False)
        pn532.SAM_configuration()
        print("PN532 Ready\n")
    except Exception as e:
        print("[ERROR] PN532 Init Failed:", e)
        return

    while True:
        try:
            # ================= USER INPUT =================
            print("\n--- Enter Product Details ---")
            product_id = input("Product ID: ")
            batch_id   = input("Batch ID: ")
            mfg        = input("Manufacturing Date (YYYY-MM-DD): ")

            print("\nTap NFC card now...")

            # ================= WAIT FOR CARD =================
            uid = None
            while uid is None:
                uid = pn532.read_passive_target(timeout=0.5)
                print(".", end="", flush=True)

            print("\nCard detected!")

            tag = uid_clean(uid)
            print("[Card] UID:", tag)
            tag_uid_hash = hashlib.sha256(tag.encode('latin-1')).hexdigest()

            # ================= PAPER CIPHER — WRITE (untouched, demonstrates the paper) =================
            paper_keys, key_chars = derive_key_chars(tag, SHARED_SECRET)
            print("[Paper cipher] Key chars:", key_chars)

            encrypted_block = encrypt_for_nfc(product_id, paper_keys)
            for i in range(4):
                page_data = encrypted_block[i*4:(i+1)*4]
                pn532.ntag2xx_write_block(START_PAGE + i, list(page_data))
            print("[NFC] Paper-cipher block write success")

            read_data = b''
            for i in range(4):
                page = pn532.ntag2xx_read_block(START_PAGE + i)
                read_data += bytes(page)
            decrypted = decrypt_from_nfc(read_data, paper_keys)
            print("[NFC] Paper-cipher read-back:", decrypted)

            # ================= NDEF — WRITE (tap-to-verify link) =================
            verify_url = f"{FRONTEND_VERIFY_BASE_URL}/verify.html?t={tag_uid_hash}"
            try:
                write_ndef(pn532, verify_url)
                print("[NFC] NDEF write success:", verify_url)
            except Exception as e:
                print("[WARN] NDEF write failed, falling back to a printable QR code:", e)
                print(f"       Verify URL: {verify_url}")
                try:
                    qr_path = save_qr_fallback(verify_url, tag)
                    print(f"       QR code saved: {qr_path} (print and attach to packaging)")
                except Exception as qr_err:
                    print(f"       QR fallback also failed: {qr_err}")
                    print(f"       Manually print a QR code for: {verify_url}")

            # ================= BACKEND (NON-BLOCKING, AES-256-GCM) =================
            threading.Thread(
                target=send_backend,
                args=(product_id, batch_id, mfg, tag, tag_uid_hash),
                daemon=True
            ).start()

            print("Done. Ready for next scan.\n")
            time.sleep(1)

        except Exception as e:
            print("[ERROR]", e)


if __name__ == "__main__":
    main()
