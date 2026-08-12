"""
Production crypto path — AES-256-GCM with per-tag keys derived via HKDF-SHA256.

Design point: no key material is ever transmitted in a request or stored in the
database. Both the Pi and the server independently derive the same per-tag key
from `tag_uid_hash` (public — it's just a lookup index, sent in cleartext anyway)
and AES_MASTER_KEY (a secret that never leaves either trusted endpoint, distinct
from SHARED_SECRET used for HMAC request signing).

This coexists with the untouched paper cipher in crypto_paper.py — rows are
tagged with a `crypto_version` column so the two schemes never mix.
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag  # re-exported for callers


def derive_tag_key(tag_uid_hash_hex: str, master_secret: bytes) -> bytes:
    """Derive a 32-byte AES-256 key unique to this tag from AES_MASTER_KEY."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"nfc-tag-aes-key:" + tag_uid_hash_hex.encode(),
    )
    return hkdf.derive(master_secret)


def aes_gcm_encrypt(plaintext: str, key: bytes) -> tuple:
    """Returns (nonce_hex, ciphertext_hex). Ciphertext includes the GCM auth tag."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce.hex(), ct.hex()


def aes_gcm_decrypt(nonce_hex: str, ciphertext_hex: str, key: bytes) -> str:
    """Raises cryptography.exceptions.InvalidTag if the key is wrong or data was tampered."""
    nonce = bytes.fromhex(nonce_hex)
    ct = bytes.fromhex(ciphertext_hex)
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")
