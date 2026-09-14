# ARCHITECTURE.md — NFC Medicine Authenticity System

This document is a build specification, not a narrative report. It's written so
that an AI coding agent (or a new developer) given **only this file** could
reproduce the system from scratch: exact tech stack, exact schema, exact
algorithms, exact API contracts, exact deployment steps. Where a design choice
has a reason, the reason is stated briefly — but the point of this file is
"what to build," not "why it's good."

---

## 1. What this system does

An anti-counterfeiting system for pharmaceutical packaging using NFC tags.

- A **Raspberry Pi 4 + PN532 NFC module** writes an authenticity record onto an
  **NTAG213** tag at packaging time, and registers that same record with a
  cloud backend over HTTPS.
- A **consumer** later taps the tag with a phone. The phone opens a webpage
  that asks the backend "is this genuine?" and the backend answers based on
  its own database record — never based on anything printed on the tag itself.
- Two independent encryption schemes are implemented side by side on every
  record: a custom lightweight cipher (kept for reproducing a specific
  research paper's results) and a production-grade path (AES-256-GCM +
  Ed25519) that is what actually secures the deployed system.

---

## 2. Tech stack

| Layer | Technology | Notes |
|---|---|---|
| Backend language/framework | Python 3.13, Flask 3.x | `backend/app.py` is the whole app, single file |
| WSGI server (production) | gunicorn | Flask dev server (`app.run()`) only used locally |
| Database | PostgreSQL, hosted on Supabase | Connected via **session pooler**, not direct connection (see §11) |
| DB driver | psycopg2 | All queries parameterized (`%s`), never string-built SQL |
| Crypto library | `cryptography` (pyca) | AES-GCM, HKDF, Ed25519 all from this one package |
| Rate limiting | flask-limiter | In-memory storage (single-instance deployment) |
| CORS | flask-cors | Scoped to `/api/verify/*` only |
| Env config | python-dotenv | `.env` files, never committed |
| Hosting (backend) | Render (PaaS) | Free web service tier; auto-deploys from `main` on GitHub |
| Hosting sits behind | Cloudflare (via Render) | Has its own WAF — see §12 |
| Database hosting | Supabase | Managed Postgres + Row Level Security |
| Frontend | Plain HTML/CSS/vanilla JS | No framework, no build step, no npm |
| Consumer NFC read | Web NFC API (`NDEFReader`) | Chrome for Android only, requires HTTPS |
| Device | Raspberry Pi 4 Model B | I²C-connected PN532 |
| Device NFC library | `adafruit-circuitpython-pn532`, `adafruit-blinka` | |
| NFC tag hardware | NXP NTAG213 | 144 bytes user memory, pages 4–39 |
| Version control | Git, GitHub | Feature branches + PRs for breaking changes |
| Testing | pytest + `requests` (live HTTP, not mocked) | `backend/tests/` |

No JavaScript framework, no ORM, no message queue, no container orchestration.
Deliberately minimal — this is a college-scale project, not enterprise infra.

---

## 3. Repository structure

```
├── backend/
│   ├── app.py                  # The entire Flask app — all routes
│   ├── config.py                # Loads all env vars
│   ├── db.py                    # psycopg2 connection helper (+ sslmode injection)
│   ├── admin_auth.py            # X-Admin-Key decorator
│   ├── audit.py                 # log_audit() → audit_log table
│   ├── crypto_paper.py          # Untouched custom cipher (research paper subject)
│   ├── crypto_modern.py         # AES-256-GCM + HKDF (production path)
│   ├── crypto_signing.py        # Ed25519 signature verification
│   ├── generate_device_keypair.py  # One-off: generates an Ed25519 keypair
│   ├── init_db.py               # Idempotent: CREATE TABLE IF NOT EXISTS
│   ├── migrate.py               # Idempotent: additive schema migration + RLS
│   ├── supabase_schema.sql      # Full schema as one paste-into-Supabase script
│   ├── requirements.txt
│   ├── .env                     # Not committed — see §5
│   └── tests/
│       ├── conftest.py          # Shared fixtures, test device Ed25519 keypair
│       ├── test_functional.py
│       ├── test_replay.py
│       ├── test_clone.py
│       ├── test_device_impersonation.py
│       ├── test_mitm.py
│       ├── test_birthday.py
│       ├── test_injection.py
│       ├── test_zz_bruteforce.py   # Named to sort/run last (see file docstring)
│       └── report.py            # Generates evidence/report.md from test runs
├── frontend/
│   ├── index.html               # Manual tag-ID entry (fallback/testing)
│   ├── verify.html              # The actual verification result page
│   ├── app.js                   # Live NFC scan logic + verify API call
│   ├── style.css
│   └── manifest.json
├── pi/
│   ├── pi_app.py                # Raspberry Pi tag-writing script
│   ├── requirements.txt         # Hardware-specific deps (separate from backend's)
│   └── .env                     # Not committed
├── render.yaml                  # Render Blueprint (service config)
└── .gitignore / .gitattributes
```

`backend/` and `pi/` have **separate** `requirements.txt` files — the Pi's
hardware libraries (`board`, `busio`, `adafruit-*`) have no reason to be
installed on the server, and vice versa.

---

## 4. Database schema

Postgres (Supabase). Run this once (idempotent, safe to re-run):

```sql
CREATE TABLE IF NOT EXISTS products (
    id             SERIAL PRIMARY KEY,
    product_id     TEXT NOT NULL,
    product_id_iv  TEXT NOT NULL,
    batch_id       TEXT NOT NULL,
    batch_id_iv    TEXT NOT NULL,
    mfg_date       TEXT NOT NULL,
    mfg_date_iv    TEXT NOT NULL,
    tag_uid        TEXT NOT NULL,
    tag_uid_iv     TEXT NOT NULL,
    shelf_life     INTEGER NOT NULL,
    expiry_date    DATE NOT NULL,
    payload_hash   TEXT NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    nonce          TEXT NOT NULL UNIQUE,   -- replay protection at the DB level
    key_chars      TEXT,                   -- only populated for crypto_version = 'paper_v1'
    tag_uid_hash   TEXT NOT NULL,
    crypto_version TEXT NOT NULL DEFAULT 'paper_v1'   -- 'paper_v1' | 'aes_gcm_v1'
);
CREATE INDEX IF NOT EXISTS idx_tag_uid_hash ON products(tag_uid_hash);
CREATE INDEX IF NOT EXISTS idx_tag_uid      ON products(tag_uid);

CREATE TABLE IF NOT EXISTS audit_log (
    id           SERIAL PRIMARY KEY,
    event_type   TEXT NOT NULL,   -- 'product_write' | 'verify_attempt' | 'admin_products_list' | 'admin_key_fetch' | 'auth_failure'
    tag_uid_hash TEXT,
    result       TEXT,            -- 'success' | 'authentic' | 'expired' | 'tampered' | 'unknown' | 'duplicate_nonce' | 'bad_signature' | ...
    source_ip    TEXT,
    user_agent   TEXT,
    detail       JSONB,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_tag_uid_hash ON audit_log(tag_uid_hash);
CREATE INDEX IF NOT EXISTS idx_audit_event_type    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at     ON audit_log(created_at);

-- Row Level Security: enabled with ZERO policies granted to anon/authenticated.
-- The backend connects as Supabase's "postgres" role, which has BYPASSRLS, so
-- this doesn't affect the app. What it does: Supabase auto-generates a public
-- REST API (PostgREST) for every project, reachable with the project's anon
-- key. With RLS on and no permissive policies, that API can neither read nor
-- write these tables — the Flask backend becomes the only path to this data.
ALTER TABLE products  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
```

Note: `product_id`, `batch_id`, `mfg_date`, `tag_uid` columns hold **ciphertext
hex**, never plaintext. Their `_iv` counterparts hold the IV (paper cipher, 10
bytes) or GCM nonce (modern path, 12 bytes), also hex.

---

## 5. Environment variables

### `backend/.env`

| Var | Purpose | Example shape |
|---|---|---|
| `DATABASE_URL` | Supabase Postgres connection string — **session pooler**, not direct | `postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres` |
| `SHARED_SECRET` | 32-byte hex. Used **only** by the paper-cipher's `key_mac` check and `derive_key_chars` — unrelated to HTTP write auth | `secrets.token_hex(32)` |
| `AES_MASTER_KEY` | 32-byte hex. Root secret for HKDF-deriving per-tag AES-256-GCM keys | `secrets.token_hex(32)` |
| `PI_PUBLIC_KEYS` | Comma-separated Ed25519 public keys (32-byte hex each), one per trusted device | `<hex1>,<hex2>` |
| `ADMIN_API_KEY` | Static key required in `X-Admin-Key` header for `/api/admin/*` | `secrets.token_hex(32)` |
| `FRONTEND_VERIFY_BASE_URL` | Not used by the backend itself — present for parity with the Pi's `.env`, safe to leave unset | |

### `pi/.env`

| Var | Purpose |
|---|---|
| `SHARED_SECRET` | Must match `backend/.env` exactly |
| `AES_MASTER_KEY` | Must match `backend/.env` exactly |
| `PI_PRIVATE_KEY` | This device's Ed25519 private key (32-byte hex). Generated once via `generate_device_keypair.py`, never leaves this file, never committed, never sent server-side |
| `BACKEND_URL` | e.g. `https://<app>.onrender.com` — full backend origin, no trailing slash |
| `FRONTEND_VERIFY_BASE_URL` | Same origin as `BACKEND_URL` in this deployment (backend serves the frontend) |
| `SHELF_LIFE_DAYS` | Default shelf life if not overridden per-product |

`SHARED_SECRET` and `AES_MASTER_KEY` are **shared** between Pi and backend
(symmetric). `PI_PRIVATE_KEY` / `PI_PUBLIC_KEYS` are an **asymmetric pair** —
the private half exists only on the Pi, the public half(s) only on the
backend. Never put a private key server-side.

---

## 6. Core cryptography — reimplementation-level detail

Two schemes coexist, selected per-row by `crypto_version`.

### 6.1 Paper cipher (`crypto_paper.py`) — untouched, do not modify

This is the subject of an accompanying research paper. Keep byte-for-byte
identical if reproducing.

**Key derivation** (`derive_session_keys` / matching Pi-side `derive_key_chars`):
1. `raw = HMAC-SHA256(SHARED_SECRET, tag_uid)` → take first 4 bytes `b0..b3`.
2. Map each byte to a printable ASCII char: `chr(32 + (b_i % 95))`.
3. For each char `c`: `bits = format(ord(c), '08b')`; `msb = int(bits[0:4], 2) % 2`; `lsb = int(bits[4:8], 2)`; `key_pair = msb*10 + lsb`.
4. Result: 4 integer `key_pair` values (each 0–19). Split in half: `K1 = keys[:mid]`, `K2 = keys[mid:]` where `mid = (len(keys)+1)//2`.

**Block cipher** (`encrypt_paper` / `decrypt_paper`):
1. Pad plaintext to a multiple of 10 bytes with `b'_'` (0x5F).
2. Split into 10-byte blocks.
3. For each block, apply every `K1` key with `direction='left'`, then every `K2` key with `direction='right'` (encrypt); reverse order + reverse directions to decrypt.
4. `apply_key_to_block(block, key_pair, direction)`: `first_digit = key_pair // 10` (start byte offset), `last_digit = key_pair % 10`. For bytes from `first_digit` to end of block: if `last_digit == 0 or last_digit > 8` → bitwise invert (`~byte & 0xFF`); else → circular bit-shift by `last_digit` positions (left or right per `direction`).

**CBC wrapper** (`decrypt_cbc_paper`, Pi-side `encrypt_cbc_paper`): standard CBC
chaining — XOR each 10-byte plaintext block against the previous ciphertext
block (or a random 10-byte IV for block 0) before running it through the block
cipher.

### 6.2 Production path — AES-256-GCM (`crypto_modern.py`)

```python
def derive_tag_key(tag_uid_hash_hex: str, master_secret: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"nfc-tag-aes-key:" + tag_uid_hash_hex.encode()).derive(master_secret)

def aes_gcm_encrypt(plaintext: str, key: bytes) -> tuple[str, str]:  # (nonce_hex, ciphertext_hex)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce.hex(), ct.hex()

def aes_gcm_decrypt(nonce_hex, ciphertext_hex, key) -> str:
    return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex), None).decode("utf-8")
    # raises cryptography.exceptions.InvalidTag on tamper/wrong key
```

Both Pi and backend call `derive_tag_key(tag_uid_hash, AES_MASTER_KEY)`
independently — the key is never transmitted or stored. Encrypt every field
(`product_id`, `batch_id`, `mfg_date`, `tag_uid`) separately, each with its own
fresh random nonce.

### 6.3 Write authentication — Ed25519 (`crypto_signing.py`)

```python
def verify_ed25519_signature(payload: bytes, signature_hex: str, public_keys: list[bytes]) -> bool:
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
    return False   # never raises — fails closed on any malformed input
```

**Signing payload**: `payload = timestamp_str + json.dumps(body, sort_keys=True, separators=(',', ':'))`,
signed as UTF-8 bytes. `timestamp_str` and `hex(signature)` go in request
headers `X-Timestamp` / `X-Signature`. Server independently rebuilds the same
canonical payload from the received body + `X-Timestamp` header before
verifying — this is what makes tampering with the body invalidate the
signature. Also reject if `abs(now - timestamp) > 30` seconds.

### 6.4 Tamper detection

`payload_hash = SHA256(json.dumps({product_id, batch_id, mfg_date, tag_uid: <all four ciphertext hex values>}, sort_keys=True, separators=(',',':')))`,
stored per-row at write time, recomputed at verify time. Mismatch (or an
`InvalidTag` from GCM decryption) ⇒ status `tampered`. This catches
cross-record ciphertext substitution that a per-field GCM tag alone would not.

---

## 7. Backend API

All routes in `backend/app.py`. `CORS` scoped to `/api/verify/*` only
(`origins: "*"`, safe — that response never contains secrets).

| Route | Method | Auth | Rate limit | Purpose |
|---|---|---|---|---|
| `/health` | GET | none | none | Liveness check |
| `/` | GET | none | none | Serves `frontend/index.html` |
| `/api/products` | POST | Ed25519 signature (`X-Timestamp`, `X-Signature` headers) | 30/min | Register a new tag record (called by the Pi) |
| `/api/verify/<tag_uid_hash>` | GET | none (public) | 20/min | Consumer verification — the core route |
| `/api/admin/products` | GET | `X-Admin-Key` header | 60/min | List all records (ciphertext, for debugging) |
| `/api/admin/keys/<tag_uid_hash>` | GET | `X-Admin-Key` header | 10/min | Legacy/debug: fetch `key_chars` for a paper_v1 row |

### `POST /api/products` — request body

```json
{
  "crypto_version": "aes_gcm_v1",
  "nonce": "<16 hex chars, unique per write>",
  "tag_uid_hash": "<sha256(tag_uid) hex>",
  "product_id": {"iv": "<hex>", "data": "<hex>"},
  "batch_id":   {"iv": "<hex>", "data": "<hex>"},
  "mfg_date":   {"iv": "<hex>", "data": "<hex>"},
  "shelf_life": 365,
  "tag_uid":    {"iv": "<hex>", "data": "<hex>"}
}
```
For `crypto_version: "paper_v1"`, additionally include `"key_chars": [...]` and
`"key_mac": "<hex>"`; omit for `"aes_gcm_v1"`.

**Server-side logic, in order:**
1. Verify Ed25519 signature (§6.3) → 403 if invalid.
2. Validate required fields present → 400 if missing.
3. If `paper_v1`: re-derive session keys from `key_chars`, verify `key_mac` via `hmac.compare_digest` → 403 if mismatch.
4. Decrypt **only** `mfg_date` (per `crypto_version`) → compute `expiry_date = mfg_date + shelf_life days`.
5. Compute `payload_hash` over the four ciphertext blobs.
6. `INSERT` — nonce column is `UNIQUE`; catch `psycopg2.errors.UniqueViolation` → 409 (this is the actual replay defense, not just the timestamp check).
7. Audit-log the outcome regardless of branch taken.
8. Response: `{"status": "success", "message": "Product stored", "expiry_date": "YYYY-MM-DD"}`.

### `GET /api/verify/<tag_uid_hash>` — response shapes

```json
// unknown tag
{"status": "unknown"}

// authentic or expired
{
  "status": "authentic",       // or "expired"
  "product_id": "...", "batch_id": "...", "mfg_date": "...", "expiry_date": "...",
  "verified_at": "2026-01-01T00:00:00+00:00"
}

// tampered
{"status": "tampered", "verified_at": "..."}
```

**Logic**: look up latest row by `tag_uid_hash` (`ORDER BY id DESC LIMIT 1`) →
if none, `unknown`. Else recompute `payload_hash`; if mismatched or decryption
raises `InvalidTag`, → `tampered`. Else if `today > expiry_date` → `expired`.
Else → `authentic`. **Never** return ciphertext, IV/nonce, `key_chars`, or any
secret in this response — this route is public. Audit-log every call.

### Connection handling pattern (all DB-touching routes)

```python
conn = get_connection()
if not conn:
    return jsonify({"error": "Database connection failed"}), 500
try:
    ...
    conn.commit()   # if writing
except SomeError:
    conn.rollback()
    return ...
finally:
    conn.close()
```
Always guard `conn is None`, always `rollback()` on write error, always
`close()` in `finally` — a psycopg2 connection left open on every error path is
a real leak under load (discovered via the brute-force test suite).

---

## 8. Security middleware

- **Rate limiting**: `flask_limiter.Limiter(get_remote_address, app=app, storage_uri="memory://", default_limits=["200 per hour"])`, then `@limiter.limit("N/minute")` per route (see table above). In-memory storage — fine for one instance, needs Redis if ever scaled to multiple workers.
- **Admin auth** (`admin_auth.py`): decorator checking `hmac.compare_digest(request.headers.get("X-Admin-Key",""), ADMIN_API_KEY)` → 401 + audit-log `auth_failure` on mismatch.
- **Audit logging** (`audit.py`): `log_audit(event_type, tag_uid_hash=None, result=None, source_ip=None, user_agent=None, detail=None)` — best-effort, must never raise (wrap DB write in try/except, print on failure, don't break the caller's request).
- **`db.py` SSL handling**: Supabase requires TLS. Auto-inject `sslmode=require` into `DATABASE_URL` if not already present (via `urllib.parse`), so it works regardless of whether the pasted connection string already has it.

---

## 9. Frontend

Static files, served same-origin by Flask (`Flask(__name__, static_folder="../frontend", static_url_path="")`).

- **`index.html`**: manual tag-ID entry field (testing/fallback), links to `verify.html?t=<hash>`.
- **`verify.html`** + **`app.js`**: the actual verification UX. Logic:
  1. If `'NDEFReader' in window` (Web NFC support): show a **"Tap to Scan"** button. On click, `new NDEFReader().scan()`, listen for `onreading`, extract `event.serialNumber` (colon-separated hex, e.g. `"04:35:1a:9d:c9:2a:81"`), strip colons + uppercase, compute `SHA-256` via `crypto.subtle.digest` (matches backend's `hashlib.sha256(uid).hexdigest()` byte-for-byte since the UID string is pure ASCII hex), call `GET /api/verify/<that hash>`. **This ignores the `t=` URL parameter entirely when Web NFC is available** — that's the point, a URL parameter is copyable, a live physical read is not.
  2. Else (no Web NFC — iOS, desktop): fall back to trusting `t=` from the URL, with an explicit on-page note that live verification wasn't available.
  3. Render one of 4 states: green **AUTHENTIC** (+ product details), amber **EXPIRED**, red **TAMPERED — DO NOT USE**, gray **UNKNOWN TAG**.

---

## 10. Raspberry Pi script (`pi/pi_app.py`)

Loop, per product:
1. Prompt operator for `product_id`, `batch_id`, `mfg_date` (stdin).
2. `pn532.read_passive_target()` → wait for tag tap → get raw UID bytes → `uid_clean()` → uppercase hex string, no separators (e.g. `"04351A9DC92A81"`).
3. `tag_uid_hash = sha256(uid).hexdigest()`.
4. **Paper cipher write** (untouched): derive `key_chars`/session keys from UID + `SHARED_SECRET`, `encrypt_for_nfc(product_id, keys)` → exactly 16 bytes → write to NTAG213 pages 4–7 (4 pages × 4 bytes) via `ntag2xx_write_block`. Read back and decrypt to confirm.
5. **NDEF write**: build a Type-2-Tag NDEF URI record for `{FRONTEND_VERIFY_BASE_URL}/verify.html?t={tag_uid_hash}`, TLV-wrapped (`0x03` NDEF Message TLV + `0xFE` Terminator TLV), using abbreviation code `0x03` for `http://` or `0x04` for `https://` per the URL's actual scheme. Write starting at page 8, one page at a time, **with retry (3 attempts) and a ~50ms settle delay after each successful page write** — writing ~29 pages back-to-back without pacing causes real `"Response frame preamble does not contain 0x00FF!"` I2C errors on actual hardware (confirmed). On persistent failure, fall back to generating a QR code PNG of the same URL (`qrcode` library) and print the URL to the console either way.
6. **Backend write** (background thread, non-blocking): AES-256-GCM-encrypt all 4 fields with the independently-derived `crypto_modern`-equivalent key, sign with the Pi's Ed25519 private key, `POST /api/products` with `crypto_version: "aes_gcm_v1"`.

`SHARED_SECRET` (paper cipher) and `PI_PRIVATE_KEY` (Ed25519 signing) are used
for **completely different, unrelated purposes** — don't conflate them.

---

## 11. Deployment

**Backend → Render:**
- `render.yaml` Blueprint: `rootDir: backend`, `buildCommand: pip install -r requirements.txt`, `startCommand: gunicorn app:app --bind 0.0.0.0:$PORT`.
- Set `DATABASE_URL`, `SHARED_SECRET`, `AES_MASTER_KEY`, `PI_PUBLIC_KEYS`, `ADMIN_API_KEY` as Render environment variables (never in `render.yaml` itself — mark `sync: false`).
- Render's free tier sleeps after ~15 min idle; first request after that has a ~30–50s cold-start delay. Not a bug, just something to warm up before a live demo.
- Render's edge sits behind **Cloudflare**, which runs its own WAF — expect it to independently block obvious SQLi/attack-looking payloads before they even reach the Flask app. This is a real, separate defense layer, not something this codebase controls.

**Database → Supabase:**
- Use the **Session pooler** connection string, not "Direct connection." The direct-connection hostname (`db.<ref>.supabase.co`) resolves **IPv6-only**, which fails to connect from hosts without IPv6 egress (Render included, in practice) — symptom is `{"error": "Database connection failed"}` in production while the same code works fine locally. The pooler hostname (`aws-0-<region>.pooler.supabase.com`) supports IPv4.
- Run `backend/supabase_schema.sql` once via the Supabase SQL Editor (or `init_db.py` + `migrate.py` via Python) against a fresh project.

**Local dev:**
```bash
cd backend
python -m venv venv          # or use a repo-root venv, either works
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe init_db.py
venv\Scripts\python.exe migrate.py
venv\Scripts\python.exe app.py
```

---

## 12. Known limitations (do not silently "fix" these without discussing scope — they're deliberate trade-offs)

1. **Physical tag cloning**: live NFC verification (§9.1) defeats copying a genuine tag's link onto an arbitrary blank NTAG213. It does **not** defeat a specifically-sourced UID-rewritable ("magic") clone tag with copied content — standard NTAG213 has no way to prove UID authenticity beyond the UID value itself. Full fix requires SUN/SDM-capable hardware (NXP NTAG 424 DNA), not implemented.
2. **Web NFC platform coverage**: live verification only works on Chrome for Android. iOS and desktop fall back to trusting the static URL parameter (disclosed on-page, not hidden).
3. **Novel cipher (§6.1)**: intentionally weak by modern standards (small keyspace, limited non-linearity) — kept as-is because it's the subject of a research paper, not because it's believed secure. Never "harden" it; that would invalidate the paper's reproducibility.
4. **Rate limiter storage**: in-process memory. Fine for one Render instance; would silently stop working correctly (each worker gets its own counter) if ever scaled to multiple gunicorn workers/instances without adding a shared store.
5. **Nonce randomness**: not yet validated against NIST SP 800-22. `secrets.token_hex(8)` (64 bits) is used; a birthday-bound collision needs ~5.4×10⁹ requests, considered infeasible against the deployed rate limits, but this hasn't been formally tested.

---

*This file describes the system as actually built and deployed (Supabase + Render + Ed25519 + live Web NFC verification), not an earlier or aspirational version. If reproducing: build in the order — schema → backend crypto modules → API routes → middleware → frontend → Pi script → deploy — testing with `backend/tests/` after each stage rather than only at the end.*
