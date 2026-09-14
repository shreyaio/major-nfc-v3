"""
Paper cipher — the custom block cipher described in the accompanying research
paper (Section III-B/III-C). Untouched, byte-for-byte identical to the original
implementation. This is NOT the production crypto path (see crypto_modern.py for
that) — it's kept exactly as-is so the paper's results stay reproducible.
"""

from datetime import datetime, timedelta
import hmac as _hmac
import hashlib


def derive_session_keys(key_chars: list, shared_secret: bytes):
    """
    Re-derive key pairs from key_chars using the same logic as the RPi.
    Also returns the expected HMAC so the caller can verify the RPi owns
    the shared secret.
    """
    raw = ''.join(key_chars).encode('ascii')
    expected_mac = _hmac.new(shared_secret, raw, hashlib.sha256).hexdigest()
    keys = []
    for ch in key_chars:
        ascii_val = ord(ch)
        bits      = format(ascii_val, '08b')
        msb_val   = int(bits[0:4], 2) % 2
        lsb_val   = int(bits[4:8], 2)
        keys.append(msb_val * 10 + lsb_val)
    return keys, expected_mac


def circular_left_shift_bits(byte_val, n):
    n = n % 8
    return ((byte_val << n) | (byte_val >> (8 - n))) & 0xFF

def circular_right_shift_bits(byte_val, n):
    n = n % 8
    return ((byte_val >> n) | (byte_val << (8 - n))) & 0xFF

def invert_bits(byte_val):
    return (~byte_val) & 0xFF

def apply_key_to_block(block_bytes, key_pair, direction):
    first_digit = key_pair // 10
    last_digit  = key_pair  % 10
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
    raw = plaintext_str.encode('latin-1', errors='replace')
    pad_len = (10 - len(raw) % 10) % 10
    raw += b'_' * pad_len
    blocks = [raw[i:i+10] for i in range(0, len(raw), 10)]
    mid = (len(keys) + 1) // 2
    k1, k2 = keys[:mid], keys[mid:]
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
    Reverse of encrypt_paper:
    1. Apply K2 in reverse with LEFT shift  (undoes right shift)
    2. Apply K1 in reverse with RIGHT shift (undoes left shift)
    """
    blocks = [cipher_bytes[i:i+10] for i in range(0, len(cipher_bytes), 10)]
    mid = (len(keys) + 1) // 2
    k1, k2 = keys[:mid], keys[mid:]
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

def decrypt_cbc_paper(iv_hex, data_hex, keys):
    """
    CBC-mode decryption using the paper's block cipher.
    Matches encrypt_cbc_paper() from the RPi code.
    """
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(data_hex)

    blocks = [ciphertext[i:i+10] for i in range(0, len(ciphertext), 10)]
    prev = iv
    plaintext = b''

    for block in blocks:
        # Decrypt the block
        dec = decrypt_paper(block, keys).encode('latin-1', errors='replace')
        dec = dec[:10].ljust(10, b'_')          # normalise to 10 bytes
        # XOR with previous ciphertext block (or IV for first block)
        xored = bytes(x ^ y for x, y in zip(dec, prev))
        plaintext += xored
        prev = block                             # advance CBC chain

    return plaintext.rstrip(b'_').decode('latin-1', errors='replace')

def decrypt_field(iv_hex, data_hex, keys):
    """
    Drop-in replacement for the old AES decrypt_field.
    Called from app.py with the session keys.
    """
    return decrypt_cbc_paper(iv_hex, data_hex, keys)
