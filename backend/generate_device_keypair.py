"""
One-time helper: generates a fresh Ed25519 keypair for a device (the Pi) or
for the test suite's own fixture identity.

Run once per identity needed:
    python generate_device_keypair.py

The private key must go ONLY into that device's own .env (pi/.env for the
real Pi) -- never into backend/.env, never into Render, never committed.
The public key is safe to share: add it to backend/.env's PI_PUBLIC_KEYS
(comma-separated if there's more than one trusted device) and to Render's
environment variables.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


def main():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_hex = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    print(f"PI_PRIVATE_KEY={priv_hex}")
    print("  -> that device's own .env ONLY. Never commit, never put server-side.\n")
    print(f"PI_PUBLIC_KEY={pub_hex}")
    print("  -> backend/.env PI_PUBLIC_KEYS (comma-joined with any other trusted keys)")
    print("     + Render environment variables. Safe to share.")


if __name__ == "__main__":
    main()
