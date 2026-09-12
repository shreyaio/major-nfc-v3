# NFC Medicine Authenticity System — v2

An anti-counterfeiting system for pharmaceutical packaging, built on commodity
NTAG213 tags with no secure element and no per-tag cost increase.

A Raspberry Pi enrols each pack's tag at packaging time. A consumer later taps it with
any phone — **no app, Android or iPhone** — and the chip writes its own UID and a
hardware read counter into the URL the phone opens. The server keeps the highest
counter it has seen for that tag. A genuine tag's counter only ever moves forward. A
clone has its own counter, so the moment both are in circulation the two streams
interleave and the server sees a value that does not advance.

That mechanism is **Monotonic Tap Attestation (MTA)**; the detection layer is
**Counter Divergence Detection (CDD)**.

## What this system does and does not claim

**It does not prevent cloning.** NTAG213 holds no secret key and can prove nothing
cryptographically. Anyone who can read a genuine tag can write the same data to
another tag.

**It detects a clone that is actually in circulation**, with a small and computable
expected number of consumer taps, at zero additional per-tag cost. Detection gets
*faster* the more copies a counterfeiter makes — with *k* copies of one identifier,
the probability of detection within two taps is `1 − 1/k`.

The strongest negative verdict the system will ever emit is `SUSPECT_DUPLICATE`. It
never says "counterfeit", because when a genuine tag and a clone both report counters,
attribution is genuinely ambiguous — the velocity bound narrows it, a human resolves it.

## Architecture

```
Raspberry Pi 4 + PN532  ──signed──►  Cloudflare Worker  ──►  Flask on Render  ──►  Supabase
      │                              (rate limit, cache)                            Postgres
      └─► durable SQLite outbox                                                        │
          (retries until the server acknowledges)              daily signed Merkle root ┘
                                                                        │
Any phone, no app ──tap──► chip fills UID+counter into URL ──────────────┘
```

Full build specification: [`ARCHITECTURE.md`](./ARCHITECTURE.md). Read that before
changing anything — the failure modes in this system are mostly silent.

## Repository

| Directory | Ships to | Contents |
|---|---|---|
| `backend/` | Render | Flask API, crypto, services, schema, tests |
| `pi/` | Raspberry Pi | Enroller, NTAG commands, outbox, key provider |
| `edge/` | Cloudflare | Worker: rate limiting, caching, canonicalisation |
| `frontend/` | Served by Render | Consumer verification page, report form, admin console |
| `legacy/paper_cipher/` | **Nowhere** | Offline reproducibility for the earlier paper. Not deployed, not imported. |
| `docs/` | — | Threat model, attack matrix, operator runbook |

`backend/` and `pi/` have separate `requirements.txt` files and never import from each
other. Shared logic is duplicated deliberately and pinned by test vectors in
`backend/tests/vectors/`.

---

## Setup

There are six manual steps. Everything else is automated.

### 1. Install

```bash
git clone https://github.com/<owner>/major-project-nfc.git
cd major-project-nfc

python -m venv venv
source venv/bin/activate                # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

On the Raspberry Pi only:

```bash
pip install -r pi/requirements.txt
sudo raspi-config        # Interface Options → I2C → Enable
i2cdetect -y 1           # PN532 should appear at 0x24
```

### 2. Generate keys

```bash
echo "keys.local.json" >> .gitignore     # do this FIRST
python backend/scripts/gen_keys.py --out keys.local.json

python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <FIELD_PRIV_HEX>
python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <ROW_PRIV_HEX>
```

**Store `KEK` somewhere with different access control from the Render dashboard** — a
password manager, not a second environment variable sitting next to the wrapped blobs.
If `KEK` lives beside what it wraps, the envelope encryption has bought you nothing.

`ADMIN_TOKEN_KEY` and `TRANSPARENCY_KEY` never go on any server. They live offline and
in GitHub Actions secrets respectively.

### 3. Supabase

1. Create a project. Copy the **Session pooler** connection string.
   Not "Direct connection" — that hostname resolves IPv6-only and will not connect
   from Render. The symptom is a database error in production while everything works
   locally.
2. SQL Editor → run `backend/schema/001_core.sql`, then `backend/schema/002_rls.sql`.
3. Register the Pi:
   ```sql
   INSERT INTO device_registry (device_id, label, public_key)
   VALUES ('<uuid>', 'pi-line-1', '<ed25519 pubkey hex>');
   ```
4. Verify RLS is working: with the project's **anon** key, a PostgREST call to
   `/rest/v1/products` must return nothing. If it returns rows, stop and fix it — that
   endpoint is public.

### 4. Fill in `.env`

Copy `backend/.env.example` → `backend/.env` and `pi/.env.example` → `pi/.env`.
Every variable is documented in `ARCHITECTURE.md` §21.

Two that are easy to miss:

- **`CNT_BYTE_ORDER`** — must be calibrated (step 6) and identical on both sides. Both
  the Pi and the backend refuse to start without it.
- **`PUBLIC_HOST`** — the host written into every tag URL. Fix it before enrolling any
  tag you intend to keep; changing it later invalidates every tag already in the field.

### 5. Deploy

**Backend → Render.** Create from `render.yaml`, set every variable from §21 in the
dashboard, set the health check path to `/health`, and confirm the start command shows
`--workers 2`. The worker count is pinned deliberately — an unpinned count makes the
origin rate limiter's configured thresholds meaningless.

**Edge → Cloudflare.**

```bash
cd edge
npx wrangler kv namespace create RL
npx wrangler kv namespace create NEG      # paste both ids into wrangler.toml
npx wrangler secret put ORIGIN_URL
npx wrangler deploy
```

Put the resulting `*.workers.dev` hostname into `PUBLIC_HOST` on the Pi.

**Repository settings** (do these by hand — they close real attacks):
branch protection on `main` with required review and signed commits; disable secret
access for `pull_request` workflows; turn **off** Render auto-deploy-on-push; 2FA on
GitHub, Render, Supabase and Cloudflare with separate passwords.

### 6. Calibrate the counter byte order

```bash
python pi/enroller.py --calibrate
```

Hold a **scrap** tag to the reader. The script enables the counter and mirror, reads
the counter both ways, and tells you whether the mirrored ASCII is MSB- or LSB-first.
Put the answer in both `.env` files.

This is not optional. If the two sides disagree, every enrolment records a wrong
`enrol_counter`, every velocity bound is nonsense, and the failure is silent.

---

## Running

**Enrol a batch:**

```bash
# Open the batch (admin console or API) — needs two named people and a quota.
python pi/enroller.py --batch AMX-2026-09-001
```

Tap a tag. The script runs the full sequence — originality check, NDEF write,
read-back byte-compare, counter capture, mirror config, power-cycle confirmation —
then queues the record in the local outbox. The drainer sends it and retries until the
server acknowledges.

**Watch the outbox.** It is displayed continuously. Depth above zero for more than a
few minutes means genuine packs are shipping without records — that is the failure
mode with the worst consumer outcome, and it is the one to watch for.

**Verify:** tap the tag with any phone. No app.

**Local development:**

```bash
python -m flask --app "backend.app:create_app()" run --port 5000
pytest backend/tests/unit backend/tests/integration -v
```

Some tests run against a live server rather than mocks — start the server first.
`mkcert` is a local prerequisite if you need HTTPS locally (Web NFC requires it).

---

## Before your first real batch

- [ ] A scrap tag survives the full flow and its URL shows an incrementing counter
- [ ] A magic tag is rejected by the originality gate
- [ ] 20 enrolments with the network unplugged all arrive exactly once on reconnect
- [ ] An iPhone with no app produces a correct verdict from a tap
- [ ] `/health` posture reads the way you expect
- [ ] A backup has been restored into a scratch project at least once
- [ ] `NXP_ORIGINALITY_PUBKEY` is populated, or `unverified` is a knowingly accepted state

---

## Current posture and known gaps

Be direct about these. They belong in the paper's limitations section too.

| Gap | Status |
|---|---|
| **Tag transplant / refill** — peeling a tag from a genuine empty pack onto a fake one | Not closed, and not closeable in software. Requires tamper-evident packaging. |
| **Tag locking disabled** (`TAG_LOCK_ENABLED=false`) | Deliberate for this phase — tags stay rewritable for testing. Attacks A7 (field NDEF rewrite) and A8 (disabling the counter) are open until the flag flips. The counter and mirror work regardless. |
| **The counter is plaintext** | Anyone who sees one tap's URL knows that tag's counter at that instant. This is the irreducible gap versus NTAG 424 DNA's CMAC. |
| **Look-alike domains** | No custom domain under the free-only constraint, so this stays weak. |
| **Full host compromise of the backend** | Still yields the field-decryption key in memory. Envelope encryption raises the bar; only an HSM removes this. |
| **Pi signing key in plaintext on the SD card** | Accepted for this phase. Mitigated by per-batch enrolment quotas enforced as a database constraint — a stolen key buys a bounded number of enrolments, not unlimited ones. The `KeyProvider` interface lets an ATECC608A drop in with no call-site changes. |
| **Post-quantum signatures** | Out of scope. Version fields are reserved (`X-Sig-Alg`, `device_registry.sig_alg`) so ML-DSA can be added without a schema migration. |
| **Originality signature strength** | secp128r1 gives roughly 64-bit security. Treat it as a filter against casual clone silicon, not as cryptographic proof. |

## Cost

| Component | Tier | Cost |
|---|---|---|
| Cloudflare Workers + KV | Free — 100k requests/day | ₹0 |
| Render web service | Free — 1 instance | ₹0 |
| Supabase Postgres | Free — 500 MB | ₹0 |
| GitHub Actions | Free — 2,000 min/month | ₹0 |
| NTAG213 tags | Unchanged from v1 | — |

**Total additional recurring cost: zero.**

## License and attribution

The `legacy/paper_cipher/` directory contains the custom cipher from the earlier
research paper, kept verbatim for reproducibility. It is **not deployed, not imported
by any running code, and must not be**. Its test vectors are there so the earlier
paper's results remain reproducible offline.