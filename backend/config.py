import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL  = os.getenv("DATABASE_URL")
SHARED_SECRET = bytes.fromhex(os.getenv("SHARED_SECRET", ""))

# Comma-separated trusted Ed25519 public keys (32-byte raw, hex), one per
# registered device. Replaces SHARED_SECRET for HTTP-request-level write auth
# on POST /api/products (see crypto_signing.py). SHARED_SECRET itself is
# untouched -- still used for the paper-cipher's key_mac check and
# derive_key_chars.
PI_PUBLIC_KEYS = [bytes.fromhex(k.strip()) for k in os.getenv("PI_PUBLIC_KEYS", "").split(",") if k.strip()]

# Distinct from SHARED_SECRET: used only to derive per-tag AES-256-GCM keys (crypto_modern.py),
# never for HMAC request signing.
AES_MASTER_KEY = bytes.fromhex(os.getenv("AES_MASTER_KEY", ""))

# Static key required in the X-Admin-Key header for /api/admin/* routes.
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# Base URL of the consumer verify frontend (used when building the NDEF/QR link written to tags).
FRONTEND_VERIFY_BASE_URL = os.getenv("FRONTEND_VERIFY_BASE_URL", "http://localhost:5000")