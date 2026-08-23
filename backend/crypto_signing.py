"""
Ed25519 device-signature verification -- replaces the old single-shared-HMAC-
secret scheme for authenticating that a POST /api/products write came from a
trusted device.

Asymmetric by design: each device (the Pi) holds a private key that never
leaves it. The backend only ever needs the corresponding PUBLIC key to verify
signatures, so leaking the backend's configuration (env vars, Render
dashboard, etc.) does not give an attacker the ability to forge a valid write
-- unlike HMAC, where the same secret both signs and verifies.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def verify_ed25519_signature(payload: bytes, signature_hex: str, public_keys: list) -> bool:
    """True if signature_hex is a valid Ed25519 signature over payload for ANY
    key in public_keys (each 32 raw bytes). Any parse failure (bad hex, wrong
    length key/signature) is treated as invalid -- never raised, so a
    misconfigured env var fails closed instead of 500ing the request."""
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False

    for raw_pubkey in public_keys:
        try:
            Ed25519PublicKey.from_public_bytes(raw_pubkey).verify(signature, payload)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False
