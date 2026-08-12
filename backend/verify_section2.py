import hmac
import hashlib
import json
import requests
import os
from dotenv import load_dotenv

load_dotenv()

SHARED_SECRET = bytes.fromhex(os.getenv("SHARED_SECRET", ""))
BACKEND_URL = "http://localhost:5000"

def derive_keys(key_chars, secret):
    raw = ''.join(key_chars).encode('ascii')
    mac = hmac.new(secret, raw, hashlib.sha256).hexdigest()
    keys = []
    for ch in key_chars:
        ascii_val = ord(ch)
        bits = format(ascii_val, '08b')
        msb_val = int(bits[0:4], 2) % 2
        lsb_val = int(bits[4:8], 2)
        keys.append(msb_val * 10 + lsb_val)
    return keys, mac

# Sample data
key_chars = ['A', 'D', 'Y', 'X']
keys, key_mac = derive_keys(key_chars, SHARED_SECRET)

# We need to encrypt something to send it as RPi would
def circular_left_shift_bits(byte_val, n):
    n = n % 8
    return ((byte_val << n) | (byte_val >> (8 - n))) & 0xFF

def apply_key_to_block(block_bytes, key_pair, direction):
    first_digit = key_pair // 10
    last_digit  = key_pair  % 10
    result = bytearray(block_bytes)
    for i in range(first_digit, len(result)):
        if last_digit == 0 or last_digit > 8:
            result[i] = (~result[i]) & 0xFF
        elif direction == 'left':
            result[i] = circular_left_shift_bits(result[i], last_digit)
    return bytes(result)

def encrypt_paper(plaintext_str, keys):
    raw = plaintext_str.encode('ascii', errors='replace')
    pad_len = (10 - len(raw) % 10) % 10
    raw += b'_' * pad_len
    blocks = [bytearray(raw[i:i+10]) for i in range(0, len(raw), 10)]
    mid = (len(keys) + 1) // 2
    k1, k2 = keys[:mid], keys[mid:]
    encrypted_blocks = []
    for block in blocks:
        b = bytes(block)
        for kp in k1: b = apply_key_to_block(b, kp, 'left')
        # Simplified for testing
        encrypted_blocks.append(b)
    return b''.join(encrypted_blocks)

def encrypt_cbc(plaintext, keys):
    iv = os.urandom(10)
    # Simple block encryption for test
    ct = encrypt_paper(plaintext, keys)
    return iv.hex(), ct.hex()

pid_iv, pid_ct = encrypt_cbc("PROD-001", keys)
bid_iv, bid_ct = encrypt_cbc("BATCH-001", keys)
mfg_iv, mfg_ct = encrypt_cbc("2026-04-12", keys)
uid_iv, uid_ct = encrypt_cbc("TAG-12345", keys)

payload = {
    "key_chars": key_chars,
    "key_mac": key_mac,
    "product_id": {"iv": pid_iv, "data": pid_ct},
    "batch_id": {"iv": bid_iv, "data": bid_ct},
    "mfg_date": {"iv": mfg_iv, "data": mfg_ct},
    "shelf_life": 365,
    "tag_uid": {"iv": uid_iv, "data": uid_ct}
}

print("Sending payload...")
try:
    r = requests.post(f"{BACKEND_URL}/api/products", json=payload)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
except Exception as e:
    print(f"Error: {e}")
