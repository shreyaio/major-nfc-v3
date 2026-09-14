# NFC Medicine Authenticity System — v2

An anti-counterfeiting system for pharmaceutical packaging, built on **NTAG213**
tags that cost a few rupees each and work on **any phone, with no app, on Android
and iOS alike**.

- **Design specification:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — the build spec
- **Threat model:** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **Attack traceability:** [`docs/ATTACK_MATRIX.md`](docs/ATTACK_MATRIX.md)
- **Day-to-day procedures:** [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md)

---

## What it claims, and what it does not

> **It does not prevent cloning.** NTAG213 holds no secret and can prove nothing
> cryptographically. Anyone who reads a genuine tag can write the same data to
> another tag.

What it does is **detect an in-circulation clone with bounded expected latency**,
using three chip features that v1 left switched off:

| Feature | What it gives us |
|---|---|
| **NFC counter** (24-bit, one-way) | A value that changes on every tap and cannot be written, reset or decreased |
| **UID + counter ASCII mirror** | The chip injects that value into the URL itself — so it reaches the server **with no app and no Web NFC, on iOS too** |
| **ECC originality signature** | The Pi can refuse to enrol counterfeit silicon at packaging time |

The mechanism is **Monotonic Tap Attestation (MTA)**: the server keeps the highest
counter it has seen per tag, and a value that is not strictly greater is evidence
of a duplicate.

Moving the claim from *prevention* to *bounded-latency detection* is not a
weakening. It is the only version of the claim the hardware supports — and the
latency is quantifiable, which is what makes it a result rather than a hope.

**The system never says "counterfeit" or "fake".** Attribution is genuinely
ambiguous: an attacker who pre-advances a clone's counter makes the *genuine* pack
trip the alarm. The strongest negative verdict is `SUSPECT_DUPLICATE`, and it
routes to a human.

---

## How it works, in two flows

**Enrol.** Operator opens a batch (two people, quota enforced by a database
CHECK) → Pi detects a tag → `GET_VERSION` and `READ_SIG` gate the silicon → NDEF
written with an all-zero mirror placeholder → **read back and byte-compared** →
counter captured → mirror and counter config written → **power-cycled and
confirmed live** → record sealed to the backend's public key → **written to a
durable local SQLite outbox before any network call** → a background drainer
retries until the server returns 2xx.

**Verify.** Consumer taps → the chip substitutes its live UID and counter into
the URL → the phone opens `https://<host>/c?m=<uid>x<counter>&t=<token>` → the
Cloudflare Worker canonicalises, rate-limits and serves a page shell instantly →
the page calls `/api/v2/verify` → the origin runs the counter state machine,
checks the row signature, recall status and expiry → returns a verdict, a
per-check breakdown, and **the binding level actually achieved**.

---

## Repository layout

```
backend/      Flask API on Render — app factory, routes/, services/, schema/
pi/           Raspberry Pi enroller — NTAG213 driver, durable outbox, drainer
edge/         Cloudflare Worker — rate limiting, negative caching, instant shell
frontend/     Plain HTML/CSS/vanilla JS — no framework, no build step, no npm
legacy/       The research-paper cipher, offline only. NOT DEPLOYED, NOT IMPORTED.
docs/         Threat model, attack matrix, operator runbook
```

**Nothing in `backend/` imports from `pi/`, and nothing in `pi/` imports from
`backend/`.** They ship to different machines. The three pieces of logic they
share — UID normalisation, envelope sealing, request signing — are duplicated
deliberately and pinned by shared test vectors in `backend/tests/vectors/`, with
a CI check that runs both implementations against the same file.

---

## Quick start

```bash
python -m venv venv
source venv/bin/activate                 # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt

# Unit tests need no database, no server and no hardware.
cd backend && python -m pytest tests/unit -q
```

Full setup — keys, Supabase, Render, Cloudflare, and the counter calibration —
is in **ARCHITECTURE.md §20** and summarised in the runbook.

---

## The security posture, stated rather than implied

`/health` reports the operating posture, and the admin console shows it as a
banner, because **the configuration you are running should never be something you
have to remember**:

```json
{"posture": {"tag_locking": "disabled",
             "originality_policy": "reject",
             "crypto_versions": ["aes_gcm_v2"],
             "edge_expected": true}}
```

### Residual risks this build does not close

Stated here rather than quietly designed around:

1. **Tag transplant / refill (A11).** Peeling a genuine tag off an empty pack onto
   a counterfeit one defeats every mechanism here. It requires tamper-evident
   packaging, and it is not a software problem.
2. **The counter is plaintext.** Anyone who observes one tap's URL knows that
   tag's counter at that instant. This is the irreducible gap versus NTAG 424
   DNA's CMAC, and it is the price of working with no app.
3. **Tag locking is off (`TAG_LOCK_ENABLED=false`).** Deliberate for this phase.
   Attacks A7 and A8 — field NDEF rewrite, and disabling the counter — stay open
   until the flag is turned on. `/health` says so.
4. **A full host compromise of the running backend** still yields the
   field-decryption key in memory. Envelope encryption raises the bar; it does not
   eliminate this. There is no free HSM.
5. **No custom domain.** The look-alike-domain defence (B1) is weak: an attacker
   can register a plausible `*.workers.dev` name as easily as we did.

### One operational caveat that no test can enforce

The backend's two private keys are stored **wrapped under a `KEK`**, so reading
the environment variables is not enough to decrypt the register or forge a row
signature. **That only holds if `KEK` lives somewhere with genuinely different
access control from the Render dashboard** — a password manager, not a second
environment variable next to the blobs it unwraps.

If you put `KEK` beside what it wraps, the envelope has bought you nothing, and
the threat model's capability (v) is not actually answered.

---

## What changed from v1, in one paragraph

v1's structure, in one sentence: *everything protected the database record,
nothing protected the physical tag.* Ed25519 protected the write request, AES-GCM
protected the stored fields, a `UNIQUE` nonce protected against replay — and none
of them answered the consumer's actual question, *is this object the one the
record describes?* v1's only answer was a Web NFC live read, which works on one
browser on one OS and is defeated by a UID-rewritable tag. v2 answers it with the
chip's own one-way counter, on every phone. Along the way: the paper cipher left
the deployed path entirely (one crypto version, hard reject for anything else),
`payload_hash` became a real Ed25519 row signature, the unsalted `SHA-256(UID)`
lookup key became a keyed HMAC index, the fire-and-forget enrolment thread became
a durable outbox, and the audit log became a hash chain whose head is published
daily.

The full file-by-file change ledger is **ARCHITECTURE.md §5**.

---

## Testing

```bash
cd backend
python -m pytest tests/unit -q          # no DB, no server, no hardware
TEST_BASE_URL=https://... python -m pytest tests/integration -q
```

The test worth looking at first is
[`tests/unit/test_verdict_machine.py`](backend/tests/unit/test_verdict_machine.py).
The verdict state machine is a pure function, so the test enumerates **all 2,304
combinations** of its inputs and asserts a single property:

> No combination yields `authentic` unless every check passed.

That is the strongest guarantee in the codebase, and it is cheap precisely because
the decision logic has no database and no Flask inside it.

The 86-attack suite is Phase 8 and is **not written yet** — deliberately.
`docs/ATTACK_MATRIX.md` maps every attack to the mechanism that already defends
against it; `backend/tests/attacks/README.md` records which are already covered by
existing tests, and which are **known-open**. Do not present a v2 column as
measured results until the tests have actually run: an unexpected failure you
found and reported is worth more to a reviewer than a clean sweep they suspect was
curated.

---

## Cost

Zero recurring. Cloudflare Workers + KV, Render web service, Supabase Postgres
and GitHub Actions, all on free tiers. No paid KMS, no Redis, no message queue,
no blockchain — the transparency log (§14.3) is the answer to that last one, and
it is far cheaper.
