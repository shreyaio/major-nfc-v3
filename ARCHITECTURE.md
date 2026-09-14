# ARCHITECTURE.md — NFC Medicine Authenticity System **v2**

**Status:** build specification, **implemented**. Supersedes v1, which is archived at
`docs/archive/ARCHITECTURE_v1.md`.
**Audience:** an AI coding agent (Claude Code) with repo write access, plus one human
operator who performs the manual steps listed in §20.

---

## Implementation status

Phases 0–7 of §18 are built. What that means concretely:

| Phase | State | Evidence |
|---|---|---|
| 0 — Ground truth | Done, **except the counter calibration** | §5 deletions applied; paper cipher moved to `legacy/`; `schema/001`+`002` written; `tests/vectors/counter.json` is still a **placeholder** |
| 1 — Tag pipeline | Code complete, **not hardware-tested** | `tests/unit/test_tag_layout.py` covers the arithmetic exhaustively; no tag has actually been written yet |
| 2 — Backend core | Done | `tests/unit/test_verdict_machine.py` enumerates all 2,304 combinations |
| 3 — Backend routes | Done | `tests/integration/*` — they skip until `TEST_BASE_URL` is set |
| 4 — Durability | Done | `pi/outbox.py`, `pi/drainer.py`; the 20-tags-offline check is an operator step |
| 5 — Edge | Code complete, **not deployed** | `edge/` — needs KV namespaces and `wrangler deploy` |
| 6 — Consumer | Done | Needs a real Android phone and a real iPhone to sign off |
| 7 — Ops | Workflows written, **secrets not set** | `.github/workflows/*` |
| 8 — Evaluation | **Not started, deliberately** | §16 is a traceability matrix, not a work list; `backend/tests/attacks/` is scaffold only |

**Three things are genuinely unfinished and are the operator's to do**, because each
needs hardware or credentials this repository must not contain:

1. **`CNT_BYTE_ORDER` is uncalibrated** (§6.4, §20.7). Both the Pi and the backend
   refuse to start without it. It is not guessed anywhere.
2. **`NXP_ORIGINALITY_PUBKEY` is empty** (§6.6). Absent, `originality.py` returns
   `UNAVAILABLE` and records `originality_status='unverified'`. It never reports
   `verified`.
3. **Every secret in §21 is unset.** `scripts/gen_keys.py` generates them; nothing is
   committed.

The §16.9 scoreboard must **not** be presented as measured results until Phase 8 has
actually run.

This file is written so that an agent given **only this file plus the existing repo**
can build the whole system. Where a design choice has a reason, the reason is one or
two lines. Where a value is load-bearing (a config byte, a canonicalisation rule, a
byte offset), it is stated exactly.

---

## 0. How to use this document

**Read §1–§5 before writing any code.** §5 is the change ledger: it says, file by
file, what is deleted, kept, rewritten or created. Do not start editing files in the
order you encounter them; follow the build order in §18.

**Rules for the agent:**

1. **Do not invent cryptographic constants.** Two values in this system must come
   from outside: NXP's originality-signature public key (§6.6) and every secret in
   `.env` (§21). If either is missing at runtime, the affected check must degrade to
   an explicit, logged, *visible* "unverified" state — never to a silent pass.
2. **Do not write per-attack patches.** §16 lists 86 attacks. Each maps to a
   *mechanism* that already exists in the design. If an attack in §16 has no
   mechanism next to it, that is a bug in this document — flag it, do not invent a
   one-off fix in a route handler.
3. **Every route returns the error envelope in §15.2.** No bare `jsonify({"error": str(e)})`.
4. **Nothing in `backend/` may import from `pi/`, and nothing in `pi/` may import
   from `backend/`.** Shared logic is duplicated deliberately (they ship to different
   machines) and pinned by shared test vectors in `tests/vectors/`.
5. **Irreversible tag operations are config-gated and default to off.** See §6.7.
6. When you finish a phase in §18, run that phase's checks before starting the next.

---

## 1. What changes from v1, and why

v1's structure, in one sentence: **everything protects the database record, nothing
protects the physical tag.** Ed25519 protects the write request, AES-GCM protects the
stored fields, the nonce `UNIQUE` constraint protects against replay. None of them
answer the consumer's actual question — *is this object the one the record describes?*
v1's only answer was a Web NFC live read, which works on one browser on one OS and is
defeated by a UID-rewritable tag.

v2 changes that by using three NTAG213 hardware features that v1 left switched off:

| Feature | What it gives us | Where used |
|---|---|---|
| **NFC counter** (24-bit, one-way, `NFC_CNT_EN`) | A value that changes on every tap and cannot be written, reset or decreased | §6, §9.7 |
| **UID + counter ASCII mirror** (`MIRROR_CONF = 11b`) | The chip injects that value into the URL itself — so it reaches the server **with no app and no Web NFC, on iOS too** | §6.2 |
| **ECC originality signature** (`READ_SIG`, secp128r1) | The Pi can refuse to enrol counterfeit/"magic" silicon at packaging time | §6.6 |

The mechanism built on this is **Monotonic Tap Attestation (MTA)** — the server keeps
the highest counter it has seen per tag; a value that is not strictly greater is
evidence of a duplicate. The detection layer is **Counter Divergence Detection (CDD)**.

**The security claim changes shape.** v2 does **not** prevent cloning. NTAG213 holds
no secret and can prove nothing cryptographically. v2 *detects an in-circulation clone
with bounded expected latency*. Every verdict string, log line and doc comment in this
codebase must respect that distinction. Specifically: **the system never emits the
word "counterfeit" or "fake" as a verdict.** The strongest negative verdict is
`SUSPECT_DUPLICATE`.

### 1.1 Decisions taken (and confirmed) for this build

| # | Decision | Consequence for the build |
|---|---|---|
| D1 | **Edge layer: Cloudflare Worker, free tier** | New deploy target `edge/`. Distributed rate limiting in KV, negative-lookup caching, request canonicalisation, instant page shell. §11 |
| D2 | **Pi signing key: file-based, behind a `KeyProvider` interface** | `FileKeyProvider` ships now; `Atecc608aKeyProvider` is a stub with the same interface. No call site ever touches raw key bytes. §7.5 |
| D3 | **Paper cipher removed entirely** | `crypto_paper.py` deleted from the deployed backend and from `pi_app.py`. Single crypto version `aes_gcm_v2`. Anything else is a hard reject, not a fallback. §5, §7.2 |
| D4 | **Quantum / ML-DSA: out of scope for now** | Ed25519 only — but every signature and every ciphertext carries an explicit `alg` version field so ML-DSA can be added later without a schema migration. §7.7 |
| D5 | **Tag locking OFF by default (`TAG_LOCK_ENABLED=false`)** | Tags stay rewritable for testing. The counter and mirror still work — see §6.7 for why these are independent. Attacks A7 and A8 remain open until the flag is turned on; the system reports this honestly in `/health`. |
| D6 | **No custom domain** — Worker on `*.workers.dev`, origin on `*.onrender.com` | URL fits NTAG213 comfortably (§6.1), but the B1 homograph defence stays weak. Stated, not hidden. |
| D7 | **Free tiers only** | Cloudflare Workers + KV, Render web service, Supabase Postgres, GitHub Actions. No paid KMS, no Redis, no queue. §14 |

### 1.2 Two v1 claims that were wrong, corrected here

**The `AUTH0` value in the source design doc is wrong.** It specified `AUTH0 = 2Bh`
and described it as protecting the configuration pages. On NTAG213, page `29h` is
CFG0, `2Ah` is CFG1 (which holds `NFC_CNT_EN`), `2Bh` is PWD and `2Ch` is PACK.
`AUTH0 = 2Bh` therefore protects only PWD/PACK, which are already unreadable by
design — it protects nothing that matters. To stop attack A8 (an attacker writing
`NFC_CNT_EN = 0` to kill the counter) you need **`AUTH0 = 29h`**. This build uses
`29h`. See §6.5.

**The identifier space is 2^48, not 2^56.** SN0 is fixed at `04h` on all NXP chips,
and UIDs within a reel are contiguous. An unsalted `SHA-256(UID)` lookup key is
therefore precomputable. v2 replaces it with a **keyed index**,
`tag_index = HMAC-SHA256(TAG_INDEX_KEY, uid)`, and makes the 128-bit binding token
mandatory. See §7.4.

---

## 2. Scope, constraints, non-goals

**In scope:** the three deployables — Raspberry Pi enroller, backend API + edge
worker, consumer and admin frontend — plus ops automation and a test scaffold.

**Hard constraints:**

- Zero recurring infrastructure cost. Free tiers only.
- Keep NTAG213. No NTAG 424 DNA, no secure-element tags.
- Must work on an unmodified consumer phone with no app, on Android **and iOS**.
- Tags must stay rewritable during this build phase (`TAG_LOCK_ENABLED=false`).

**Explicit non-goals (do not build these):**

- Post-quantum signatures (ML-DSA/SLH-DSA). Version fields are reserved; no code.
- Per-attack test files for the 86 attacks. §16 is a traceability matrix, not a work
  list. The test *scaffold* in §17 is in scope; the individual attack tests come later.
- Blockchain / distributed ledger. The transparency log (§14.3) is the answer to that
  question and is far cheaper.
- Any cipher other than AES-256-GCM.
- A mobile app. The whole point is that none is needed.

**Known residual risks that this build does not close** — state these in the README,
do not quietly design around them:

1. **A11, tag transplant / refill.** Peeling a genuine tag off an empty pack onto a
   counterfeit one defeats every mechanism here. Requires tamper-evident packaging.
2. **The counter is plaintext.** Anyone who observes one tap's URL knows that tag's
   counter at that instant. This is the irreducible gap versus NTAG 424 DNA's CMAC.
3. **A7/A8 while `TAG_LOCK_ENABLED=false`.** Deliberate, for this phase.
4. **Full host compromise of the backend** still yields the field-decryption key.
   Envelope encryption raises the bar; it does not eliminate this.

---

## 3. System overview

```
 MANUFACTURER SITE            EDGE                ORIGIN              DATA
 ─────────────────            ────                ──────              ────

 Raspberry Pi 4          Cloudflare Worker     Flask + gunicorn     Supabase
 + PN532 (I²C)           (free tier)           on Render            Postgres
 + KeyProvider                │                 (free tier)            │
   (file → ATECC608A)         │                      │                 │
        │                     │                      │                 │
        │  ① enrol   ┌────────┴────────┐   ┌─────────┴────────┐  ┌─────┴──────┐
        ├───────────►│ canonicalise    │──►│ /api/v2/enrol    │─►│ batches    │
        │   signed   │ rate limit (KV) │   │ /api/v2/verify   │  │ products   │
        │   Ed25519  │ neg-cache       │   │ /api/v2/report   │  │ counter_   │
        │            │ size/method gate│   │ /api/v2/admin/*  │  │  state     │
        ▼            │ page shell      │   └─────────┬────────┘  │ incidents  │
  ┌───────────┐      └────────┬────────┘             │           │ audit_log  │
  │  OUTBOX   │               ▲                      │           │ reports    │
  │ (SQLite,  │               │                      ▼           │ transp_root│
  │  durable) │──── retry ────┘              nightly GH Action   └─────┬──────┘
  └───────────┘     til 2xx                  ├─ signed Merkle root     │
                                             ├─ pg_dump backup ────────┘
 CONSUMER                                    └─ keep-warm ping
 ────────
 Any phone, no app                                   │
 ② tap → chip fills UID+counter into URL             ▼
   iOS:     background NDEF read → browser    Public transparency log
   Android: background read (+ optional       (GitHub repo, signed commits)
            Web NFC live read as a bonus)
```

**The two flows, in one line each.**

**Enrol (①):** operator authorises a batch → Pi detects tag → `GET_VERSION` →
`READ_SIG` (L1) → write NDEF with an all-zero mirror placeholder → read back and
byte-compare → `READ_CNT` to capture `enrol_counter` → write mirror/counter config →
(optionally lock) → power-cycle and confirm the mirror is live → **write to the local
SQLite outbox** → background drainer POSTs to `/api/v2/enrol` with an idempotency key
and retries until 2xx.

**Verify (②):** consumer taps → the chip substitutes live UID + counter into the URL →
phone opens `https://<host>/c?m=<uid>x<counter>&t=<token>` → Worker canonicalises,
rate-limits and serves the page shell instantly → page calls `/api/v2/verify` →
origin parses `m`, computes `tag_index`, checks binding token, runs the counter state
machine (§9.7), checks row signature, recall status and expiry → returns a verdict
plus a per-check breakdown plus the binding level actually achieved.

---

## 4. Final repository structure

`[KEEP]` exists and is unchanged · `[MOD]` exists and is rewritten · `[NEW]` ·
`[DEL]` is deleted.

```
major-project-nfc/
├── ARCHITECTURE.md                      [MOD] this file
├── README.md                            [NEW] setup + operator runbook (§20)
├── render.yaml                          [MOD] pinned workers, new env vars
├── .gitignore                           [KEEP]
├── .github/
│   └── workflows/
│       ├── keepwarm.yml                 [NEW] 10-min ping, origin + DB (§14.1)
│       ├── backup.yml                   [NEW] nightly pg_dump, encrypted (§14.2)
│       ├── transparency.yml             [NEW] daily signed Merkle root (§14.3)
│       └── ci.yml                       [NEW] pytest + pip-audit + ruff (§14.4)
│
├── backend/
│   ├── app.py                           [MOD] app factory only — no route logic
│   ├── config.py                        [MOD] typed, validated, fail-fast
│   ├── errors.py                        [NEW] exception hierarchy + envelope (§15)
│   ├── db.py                            [MOD] ThreadedConnectionPool + ctx manager
│   ├── logging_setup.py                 [NEW] structured JSON logs + redaction
│   ├── metrics.py                       [NEW] in-process counters → /metrics
│   ├── ratelimit.py                     [NEW] Postgres-backed second-layer limiter
│   ├── keys.py                          [NEW] envelope unwrap + key registry (§7.6)
│   ├── crypto_envelope.py               [NEW] X25519 + HKDF + AES-256-GCM (§7.3)
│   ├── crypto_rowsig.py                 [NEW] Ed25519 row signatures (§7.4)
│   ├── crypto_signing.py                [MOD] request sig verify, alg-versioned
│   ├── tag_index.py                     [NEW] keyed tag index + UID normalisation
│   ├── mirror.py                        [NEW] strict `m` parameter parser (§9.6)
│   ├── audit.py                         [MOD] hash-chained, best-effort (§9.9)
│   ├── auth_admin.py                    [NEW] scoped short-lived tokens (§9.10)
│   ├── routes/
│   │   ├── __init__.py                  [NEW] blueprint registration
│   │   ├── health.py                    [NEW] /health, /metrics
│   │   ├── enrol.py                     [NEW] /api/v2/enrol, /api/v2/reenrol
│   │   ├── verify.py                    [NEW] /api/v2/verify  ← core route
│   │   ├── report.py                    [NEW] /api/v2/report
│   │   ├── admin.py                     [NEW] /api/v2/admin/*
│   │   └── transparency.py              [NEW] /.well-known/transparency/latest
│   ├── services/
│   │   ├── __init__.py                  [NEW]
│   │   ├── enrolment.py                 [NEW] enrol/reenrol business logic
│   │   ├── verification.py              [NEW] verdict state machine (§9.7)
│   │   ├── counter.py                   [NEW] MTA/CDD logic + velocity bound
│   │   ├── batches.py                   [NEW] quota + two-person authorisation
│   │   └── transparency.py              [NEW] Merkle tree construction
│   ├── schema/
│   │   ├── 001_core.sql                 [NEW] full v2 schema (§8)
│   │   ├── 002_rls.sql                  [NEW] RLS + grants
│   │   └── 003_seed_dev.sql             [NEW] dev-only seed data
│   ├── scripts/
│   │   ├── gen_keys.py                  [NEW] generates every keypair + KEK
│   │   ├── wrap_secret.py               [NEW] envelope-wrap a secret for .env
│   │   ├── mint_admin_token.py          [NEW] issues a scoped admin token
│   │   └── verify_transparency.py       [NEW] third-party root verifier
│   ├── requirements.txt                 [MOD] pinned + hashed
│   ├── requirements-dev.txt             [NEW]
│   └── tests/                           [MOD] see §17
│       ├── conftest.py                  [MOD]
│       ├── vectors/                     [NEW] cross-device test vectors
│       ├── unit/                        [NEW]
│       ├── integration/                 [NEW]
│       └── attacks/                     [NEW] scaffold only — see §17.3
│
├── pi/
│   ├── enroller.py                      [NEW] main loop (replaces pi_app.py)
│   ├── ntag.py                          [NEW] raw NTAG213 commands via PN532 (§6.8)
│   ├── tag_layout.py                    [NEW] URL, NDEF TLV, mirror offset (§6.2)
│   ├── tag_config.py                    [NEW] CFG0/CFG1 bytes, lock sequence (§6.5)
│   ├── originality.py                   [NEW] secp128r1 READ_SIG verify (§6.6)
│   ├── keyprovider.py                   [NEW] File / ATECC608A interface (§7.5)
│   ├── crypto_envelope.py               [NEW] mirror of backend's (§7.3)
│   ├── outbox.py                        [NEW] durable SQLite queue (§12.3)
│   ├── drainer.py                       [NEW] background sender with backoff
│   ├── clockcheck.py                    [NEW] NTP drift gate (§12.5)
│   ├── batch_session.py                 [NEW] two-person batch open/close
│   ├── requirements.txt                 [MOD]
│   └── pi_app.py                        [DEL] replaced by enroller.py
│
├── edge/                                [NEW] Cloudflare Worker (§11)
│   ├── src/index.js
│   ├── src/ratelimit.js
│   ├── src/canonicalise.js
│   ├── src/shell.html
│   ├── wrangler.toml
│   └── package.json
│
├── frontend/
│   ├── index.html                       [MOD] landing / manual entry
│   ├── verify.html                      [MOD] the /c landing page (§13.2)
│   ├── report.html                      [NEW] consumer report form
│   ├── admin.html                       [NEW] admin console (§13.4)
│   ├── app.js                           [MOD] verdict rendering + binding levels
│   ├── admin.js                         [NEW]
│   ├── sw.js                            [NEW] offline state only (§13.5)
│   ├── style.css                        [MOD]
│   └── manifest.json                    [KEEP]
│
├── legacy/
│   └── paper_cipher/                    [NEW] offline reproducibility only
│       ├── README.md                    ← "NOT DEPLOYED. NOT IMPORTED."
│       ├── crypto_paper.py              ← moved verbatim from backend/
│       └── test_vectors.json
│
└── docs/
    ├── ATTACK_MATRIX.md                 [NEW] §16, extracted for the paper
    ├── THREAT_MODEL.md                  [NEW] revised, resolves Contradiction 1
    ├── OPERATOR_RUNBOOK.md              [NEW] batch open/close, incident triage
    └── archive/ARCHITECTURE_v1.md       [NEW] the superseded v1 spec
```

**Deviations from the plan above, as built.** Small additions, each with a reason:

| Path | Why it exists |
|---|---|
| `backend/routes/enrol.py` | Holds `/enrol` **and** `/reenrol`. They share the entire authentication preamble, and splitting them would duplicate the part that must never drift. |
| `backend/scripts/gen_vectors.py` | Regenerates `tests/vectors/*` from the real implementations, so the cross-device pins cannot be hand-edited into agreement. |
| `backend/scripts/publish_transparency.py` | The job `transparency.yml` runs. §14.3 described the steps but named no file. |
| `backend/tests/unit/test_cross_device.py` | The build-time failure for §15.3 rule 7. |
| `backend/tests/integration/test_concurrency.py` | §17.2 item 5 — the counter-advance race. |
| `frontend/strings.js`, `report.js`, `index.js` | §13.3 asks for verdict strings keyed by language, and the CSP allows no inline script, so each page needs its own module. |
| `backend/.env.example`, `pi/.env.example` | §21 as a file you can copy, rather than a table you retype. |

`backend/schema/003_seed_dev.sql` exists as planned but is dev-only and carries
placeholder key material rather than anything usable.

---

## 5. Change ledger — file by file

This section is the authoritative "what happens to the existing repo". Work through
it during Phase 0 of §18.

### 5.1 Delete

| Path | Why |
|---|---|
| `backend/crypto_paper.py` | **Move** to `legacy/paper_cipher/`, then delete from `backend/`. Closes Contradiction 2 and attack E8. Nothing in `backend/` may import it. |
| `backend/utils.py` | Re-exports the paper cipher and computes the unkeyed `payload_hash` (F15). Both are gone. Its one surviving function, `calculate_expiry`, moves into `services/enrolment.py`. |
| `backend/final_checklist.py`, `verify_hardening.py`, `verify_section2.py`, `schema_check.py`, `schema_recreate.py`, `schema_update.py`, `scratch/check_schema.py` | Ad-hoc one-off scripts superseded by `schema/*.sql` and the test suite. Dead weight an agent will otherwise try to keep consistent. |
| `backend/init_db.py`, `backend/migrate.py` | Replaced by numbered SQL files in `schema/`, applied by the operator (§20). |
| `backend/mkcert.exe` | A 24 MB Windows binary in version control. Remove; document `mkcert` as a local dev prerequisite instead. |
| `backend/supabase_schema.sql` | Replaced by `schema/001_core.sql` + `002_rls.sql`. |
| `pi/pi_app.py` | Replaced by the `pi/` modules. Its NDEF write-with-retry-and-settle-delay logic is **hardware-proven and must be carried over verbatim** into `pi/ntag.py` (see §6.8). |
| `NFC_Project_Architecture_and_Security.pdf`, `NFC_Project_Changes_Report.pdf`, `NFC_System_Architecture_Report.{md,pdf}` | Stale generated reports. Move to `docs/archive/` or delete. |
| `/api/admin/keys/<tag_uid_hash>` route | Serves key material over HTTP (F19, D16). Deleted, not disabled. A test asserts it returns 404. |
| `/test-db` route | Unauthenticated DB reachability oracle. Folded into `/health` with no detail leak. |

### 5.2 Keep, unchanged in spirit

- The **decision to make every verdict server-side**. The tag influences data, never
  the verdict logic. Preserve this absolutely.
- **Ed25519 for write authentication.** Correct reasoning in v1; kept and extended.
- **Parameterised SQL everywhere.** No string-built SQL, ever.
- **Audit logging that never raises.** A logging failure must not break its caller.
- **RLS enabled with zero policies for `anon`/`authenticated`.** This closes the
  auto-generated PostgREST API (F7a). Extend to all new tables.
- **Session-pooler connection string, not direct.** The direct Supabase hostname is
  IPv6-only and fails from Render. Keep the `sslmode=require` injection in `db.py`.
- **Testing against a live server rather than mocks.** Keep.
- **The NDEF page-write retry + ~50 ms settle delay.** Real hardware I²C behaviour,
  empirically derived. Carry it over verbatim.

### 5.3 Rewrite

| Path | Nature of the rewrite |
|---|---|
| `backend/app.py` | 418 lines with all route logic inline becomes an app factory: config validation, logging, pool init, blueprint registration, error handlers. **No business logic.** |
| `backend/db.py` | Add `ThreadedConnectionPool` + a `@contextmanager` that always returns the connection. Closes D24 (connection-pool exhaustion on error paths). |
| `backend/config.py` | Fail fast at import: if a required secret is missing or malformed, raise with the variable name. Never default a secret to `""`. |
| `backend/audit.py` | Add hash chaining (§9.9) and IP hashing (§9.11). Keep the never-raises contract. |
| `backend/crypto_signing.py` | Add an `alg` parameter and a per-device key lookup instead of a flat `PI_PUBLIC_KEYS` list. |
| `frontend/app.js` | New verdict set, binding levels, report link, offline state. Web NFC becomes a *bonus* confirmation, not the primary path. |
| `render.yaml` | Pin `--workers 2 --threads 4`, add new env vars, add a health check path. |

### 5.4 The single most important change

**F3 — the fire-and-forget background thread on the Pi.** Today, `pi_app.py` writes
the tag, then spawns a daemon thread that POSTs to the backend and prints the result.
If that POST fails — cold start, Wi-Fi drop, DNS, rate limit — the tag is already on a
pack and no record exists. That pack verifies as `unknown` forever, and a consumer
holding genuine medicine is told it is not in the register.

This is the most likely real-world failure of the entire system and it has the worst
possible user-facing outcome. The fix (§12.3) is a durable local SQLite outbox written
**before** any network call, drained by a worker that retries until the server returns
2xx with a matching idempotency key. Nothing is deleted from the outbox until then.
Build this early — it is Phase 1, not Phase 3.

---

## 6. Tag layer — NTAG213 specification

Everything in this section comes from the NXP NTAG213/215/216 datasheet (Rev 3.2).
Values are exact. Get them wrong and you either brick tags or silently lose MTA.

### 6.1 Memory map and URL budget

NTAG213 user memory: **pages 04h–27h (4–39), 144 bytes**. Maximum NDEF message with
the standard Capability Container: **137 bytes**.

v1 used pages 4–7 for the paper-cipher block. That is gone (§5.1), so **the NDEF TLV
starts at page 04h, byte 0**. This matters: every mirror offset in §6.2 is computed
from that assumption.

The tag URL is:

```
https://<HOST>/c?m=00000000000000x000000&t=<32 hex chars>
```

- `m` — 21 characters, written as all zeros. **The chip overwrites this on every read**
  with 14 hex chars of UID + the automatic separator `x` (78h) + 6 hex chars of counter.
- `t` — the per-tag 128-bit random binding token (32 hex chars). Written normally, not
  mirrored.

Budget check with the Worker host (`<worker>.<subdomain>.workers.dev`, ~24 chars):

| Component | Bytes |
|---|---|
| NDEF Message TLV tag + length | 2 |
| Record header (`D1 01 <len> 55`) | 4 |
| URI abbreviation code (`04` = `https://`) | 1 |
| `<HOST>` | ~24 |
| `/c?m=` | 5 |
| `m` value | 21 |
| `&t=` | 3 |
| `t` value | 32 |
| Terminator TLV (`FE`) | 1 |
| **Total** | **~93 of 137** |

Comfortable. **Hard rule: `tag_layout.py` must compute this at enrolment time and
refuse to write if the TLV exceeds 137 bytes, rather than silently truncating.** A
truncated NDEF is the F10 failure — a tag that opens a broken URL.

### 6.2 Mirror placement — the exact computation

The chip mirrors into a position given by `MIRROR_PAGE` (a page number) and
`MIRROR_BYTE` (0–3 within that page). It needs **21 contiguous bytes** free for
`MIRROR_CONF = 11b`.

Given the TLV starts at page 4 byte 0, the byte offset of the `m` placeholder *within
user memory* is deterministic:

```
TLV layout from user-memory offset 0:
  offset 0 : 0x03            NDEF Message TLV tag
  offset 1 : L               message length
  offset 2 : 0xD1            record header (MB|ME|SR|TNF=well-known)
  offset 3 : 0x01            type length
  offset 4 : payload_len
  offset 5 : 0x55 ('U')      type
  offset 6 : 0x04            URI abbreviation: "https://"
  offset 7 : first char of "<HOST>/c?m=..."

placeholder_offset = 7 + len(HOST) + len("/c?m=")
                   = 7 + len(HOST) + 5
MIRROR_PAGE = 4 + (placeholder_offset // 4)
MIRROR_BYTE =      placeholder_offset %  4
```

```python
# pi/tag_layout.py
NDEF_START_PAGE   = 0x04
USER_MEM_BYTES    = 144
MAX_NDEF_BYTES    = 137
MIRROR_PLACEHOLDER = "00000000000000x000000"   # 21 chars, exactly
BINDING_TOKEN_HEX_LEN = 32

def build_verify_url(host: str, token_hex: str) -> str:
    assert len(token_hex) == BINDING_TOKEN_HEX_LEN
    return f"https://{host}/c?m={MIRROR_PLACEHOLDER}&t={token_hex}"

def build_ndef_tlv(url: str) -> bytes:
    """Type-2-Tag NDEF URI record, TLV-wrapped, padded to whole 4-byte pages."""
    if url.startswith("https://"):
        abbrev, prefix = 0x04, "https://"
    elif url.startswith("http://"):
        abbrev, prefix = 0x03, "http://"
    else:
        raise ValueError("verify URL must be http(s)")
    rest = url[len(prefix):].encode("ascii")
    payload = bytes([abbrev]) + rest
    if len(payload) > 0xFF:
        raise ValueError("payload too long for a short record")
    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    if len(tlv) > MAX_NDEF_BYTES:
        raise ValueError(f"NDEF {len(tlv)}B exceeds NTAG213 limit {MAX_NDEF_BYTES}B")
    tlv += b"\x00" * ((4 - len(tlv) % 4) % 4)          # pad to whole pages
    return tlv

def mirror_position(host: str) -> tuple[int, int]:
    """Returns (MIRROR_PAGE, MIRROR_BYTE) for the m= placeholder."""
    offset = 7 + len(host) + len("/c?m=")
    page, byte = NDEF_START_PAGE + offset // 4, offset % 4
    # Datasheet: the mirror needs 21 free bytes and must not run past user memory.
    if offset + 21 > USER_MEM_BYTES:
        raise ValueError("mirror would overrun user memory")
    if page < 0x04:
        raise ValueError("MIRROR_PAGE must be >= 04h")
    return page, byte
```

**Verification requirement:** after writing, `enroller.py` must read the tag back and
assert that the 21 bytes at the computed position are exactly `MIRROR_PLACEHOLDER`
before writing the config pages. If they are not, the offset calculation and the
actual write have diverged, and enabling the mirror would corrupt the URL.

### 6.3 What the server receives

On a consumer tap the chip substitutes live values, so the phone opens:

```
https://<HOST>/c?m=04A1B2C3D4E5F6x0001A7&t=9f3c...
                  └───────┬──────┘ └──┬─┘
                      UID (14 hex)  counter (6 hex)
```

**Normalisation rules — apply these identically on the Pi and the backend, and pin
them with a shared test vector in `tests/vectors/mirror.json`:**

1. `m` must match `^[0-9A-Fa-f]{14}x[0-9A-Fa-f]{6}$` exactly. Uppercase it. Any other
   shape is a `400`, not a verdict. (Closes B3, B5.)
2. UID is the 14 hex chars, uppercase, no separators — the same string form the Pi
   hashes. `04A1B2C3D4E5F6`, never `04:a1:b2:...`.
3. Counter is `int(m[15:21], 16)`.
4. If `uid == "00000000000000" and counter == 0`, the mirror is not enabled on this
   tag → verdict `MIRROR_DISABLED`, never `UNKNOWN` and never `AUTHENTIC`. (Closes B7.)

### 6.4 Counter byte order — calibrate, do not guess

`READ_CNT` (39h 02h) returns 3 bytes. The datasheet documents the counter as 24-bit
but implementations differ on whether the mirrored ASCII rendering is MSB-first or
LSB-first relative to the `READ_CNT` response.

**Do not guess.** Phase 0 (§18) includes a one-time calibration:

1. Enable the counter and mirror on a scrap tag.
2. `READ_CNT` → record the 3 raw bytes.
3. Read the NDEF and extract the 6 mirrored hex chars.
4. Compare. Store the answer as `CNT_BYTE_ORDER = "msb" | "lsb"` in `pi/.env` and
   `backend/.env`, and write a test vector into `tests/vectors/counter.json`.

Both `pi/ntag.py::read_counter()` and `backend/mirror.py::parse_counter()` read that
setting. If the two disagree, every enrolment records a wrong `enrol_counter` and the
velocity bound (§9.7) is nonsense — a silent, hard-to-debug failure. Fail loudly at
startup if the setting is unset.

### 6.5 Configuration bytes

Pages `29h` (CFG0) and `2Ah` (CFG1). Each is 4 bytes; you must write the whole page.

**CFG0 — page 29h:** `[MIRROR, RFUI, MIRROR_PAGE, AUTH0]`

```
MIRROR byte:  bit7..6  MIRROR_CONF   = 11b  (UID + counter)
              bit5..4  MIRROR_BYTE   = computed, 0..3
              bit3     RFUI          = 0
              bit2     STRG_MOD_EN   = 1    (strong modulation, default on)
              bit1..0  RFUI          = 0

MIRROR = (0b11 << 6) | (mirror_byte << 4) | (1 << 2)
```

**CFG1 — page 2Ah:** `[ACCESS, RFUI, RFUI, RFUI]`

```
ACCESS byte:  bit7     PROT              0 = write protection only (reads stay open)
              bit6     CFGLCK            0 = config still writable, 1 = PERMANENT lock
              bit5     RFUI              0
              bit4     NFC_CNT_EN        1 = counter ON          ← the whole point
              bit3     NFC_CNT_PWD_PROT  0 = counter readable without auth ← must be 0
              bit2..0  AUTHLIM           000b = no attempt limit
```

```python
# pi/tag_config.py
def cfg0_bytes(mirror_byte: int, auth0: int) -> list[int]:
    mirror = (0b11 << 6) | ((mirror_byte & 0b11) << 4) | (1 << 2)
    return [mirror, 0x00, MIRROR_PAGE, auth0]

def cfg1_bytes(*, cfglck: bool, prot: bool = False,
               cnt_en: bool = True, cnt_pwd_prot: bool = False,
               authlim: int = 0) -> list[int]:
    access = ((prot << 7) | (cfglck << 6) | (cnt_en << 4)
              | (cnt_pwd_prot << 3) | (authlim & 0b111))
    return [access, 0x00, 0x00, 0x00]

# Testing phase (TAG_LOCK_ENABLED=false):
#   cfg0_bytes(mirror_byte, auth0=0xFF)   -> AUTH0=FFh: password protection disabled
#   cfg1_bytes(cfglck=False)              -> ACCESS = 0x10
# Production (TAG_LOCK_ENABLED=true):
#   cfg0_bytes(mirror_byte, auth0=0x29)   -> protect config pages onward
#   cfg1_bytes(cfglck=True)               -> ACCESS = 0x50
```

Three choices, each with a stated reason — put these in the paper, they are exactly
the kind of considered trade-off reviewers reward:

- **`NFC_CNT_PWD_PROT = 0`.** Must be off. With it on, the counter is only mirrored
  after a password authentication, which a consumer's browser cannot perform. This is
  also the honest reason the counter is not confidentiality-protected.
- **`PROT = 0`.** Write-protection only. Reads must stay open or no phone works.
- **`AUTHLIM = 000b`.** A genuine trade-off. `AUTHLIM = 7` would block password
  brute-forcing (A9) — but it also lets anyone with physical access **permanently
  brick a genuine pack** by deliberately failing eight authentications (A10), turning
  a security control into a DoS weapon against your own product. Since the password
  only guards reconfiguration, and lock bytes already make the data area read-only,
  the brute-force risk is low and the bricking risk is real. Leave `AUTHLIM = 0`.
- **`AUTH0 = 29h`, not `2Bh`.** See §1.2. `2Bh` protects only PWD/PACK, which are
  already unreadable. `29h` is what actually stops an attacker writing
  `NFC_CNT_EN = 0` to kill the counter (A8).

### 6.6 Originality signature (L1) — enrolment only

`READ_SIG` (3Ch 00h) returns a 32-byte ECDSA signature over the UID, produced with
NXP's private key at chip manufacture. Curve: **secp128r1**.

Three things the agent must handle honestly:

1. **`cryptography` does not support secp128r1.** Use the pure-Python `ecdsa`
   package with a hand-defined curve. Add `ecdsa>=0.19` to `pi/requirements.txt`.
2. **Do not invent NXP's public key.** It comes from NXP application note AN11350.
   The operator pastes it into `pi/.env` as `NXP_ORIGINALITY_PUBKEY` (§21). If it is
   absent, `originality.py` returns `UNAVAILABLE`, the enrolment proceeds, and the
   record is stored with `originality_status = 'unverified'` — visible in the admin
   console and in `/health`. **It must never silently report `verified`.**
3. **`READ_SIG` is unreachable from Web NFC and from iOS background reading.** Both
   expose only NDEF content and the serial number. So L1 protects *enrolment*, not
   *verification*. Overstating this is the fastest way to lose a reviewer.

```python
# pi/originality.py  — shape, not a drop-in
from enum import Enum
class OriginalityStatus(str, Enum):
    VERIFIED    = "verified"
    FAILED      = "failed"       # genuine check, genuine failure → reject the tag
    UNAVAILABLE = "unavailable"  # no pubkey / no ecdsa lib → record, do not reject

def verify_originality(uid_bytes: bytes, sig_32: bytes) -> OriginalityStatus:
    """ECDSA/secp128r1 over the raw 7-byte UID, verified against NXP's public key.
    Signature is r||s, 16 bytes each. Never raises."""
    ...
```

**Policy on `FAILED`:** reject the tag, do not enrol, write an audit row, increment
the `originality_rejections` metric. A *run* of failures means your supplier shipped
counterfeit silicon — that is a procurement alert (§14.5), and discovering it at
packaging time is exactly the point. Configurable via `ORIGINALITY_POLICY =
reject | warn`; default `reject`, `warn` only for bring-up on known-good stock.

Honest framing for the paper: secp128r1 gives roughly 64-bit security. The originality
signature is a **filter against casual clone silicon, not a cryptographic proof of
authenticity**. The evidence that it works today — publicly sold "magic" NTAG213 tags
fail it and report counter `000000` — is empirical, not cryptographic.

### 6.7 Locking — config-gated, irreversible, off for now

`TAG_LOCK_ENABLED=false` for this build phase. **Critical point that is easy to get
wrong: the counter and mirror are independent of locking.** Enabling `NFC_CNT_EN` and
`MIRROR_CONF` is an ordinary write to pages 29h/2Ah, and stays reversible as long as
`CFGLCK = 0`. So **MTA works fully during testing with tags that remain rewritable.**

What `TAG_LOCK_ENABLED=true` adds later, in this order:

1. Static lock bytes (page 02h, bytes 2–3) → lock pages 03h–0Fh.
2. Dynamic lock bytes (page 28h) → lock the remaining written pages, 2-page granularity.
3. Diversified PWD/PACK (pages 2Bh/2Ch), derived from `TAG_PWD_MASTER` + UID.
4. `AUTH0 = 29h` and `CFGLCK = 1` in CFG0/CFG1.
5. Power-cycle, then read once as a phone would, to confirm the mirror is still live.

**Every one of those is irreversible.** Implementation requirements:

- `tag_config.py::apply_lock_sequence()` must refuse to run unless
  `TAG_LOCK_ENABLED=true` **and** a `--i-understand-this-is-permanent` flag was passed
  to `enroller.py`.
- It runs only after the NDEF read-back byte-compare has passed.
- Test the sequence on scrap tags until it is right. A mistake here destroys the tag.
- `/health` must report `{"tag_locking": "disabled"}` so the operating posture is
  never ambiguous, and the admin console must show it as a banner.

### 6.8 Raw NTAG commands over the PN532

`adafruit_pn532` exposes `ntag2xx_read_block` / `ntag2xx_write_block` but not
`GET_VERSION`, `READ_SIG`, `READ_CNT` or `PWD_AUTH`. Those go through
`InDataExchange` (0x40) with target 1:

```python
# pi/ntag.py
CMD_IN_DATA_EXCHANGE = 0x40

def transceive(pn532, payload: list[int], response_length: int) -> bytes:
    """Send a raw ISO14443A-3 command to the selected tag. `payload` is the NTAG
    command bytes; target 1 is prepended. Returns the response minus the status byte."""
    resp = pn532.call_function(CMD_IN_DATA_EXCHANGE,
                               params=[0x01] + payload,
                               response_length=response_length + 1)
    if resp is None or len(resp) < 1 or resp[0] != 0x00:
        raise NtagError(f"InDataExchange status {resp[0] if resp else 'none'}")
    return bytes(resp[1:])

def get_version(pn532) -> bytes:
    return transceive(pn532, [0x60], 8)

def read_sig(pn532) -> bytes:
    return transceive(pn532, [0x3C, 0x00], 32)

def read_counter(pn532, byte_order: str) -> int:
    raw = transceive(pn532, [0x39, 0x02], 3)
    return int.from_bytes(raw, "big" if byte_order == "msb" else "little")

def fast_read(pn532, start: int, end: int) -> bytes:
    return transceive(pn532, [0x3A, start, end], (end - start + 1) * 4)
```

**`GET_VERSION` assertion** (attack A12, F9a): a genuine NTAG213 returns vendor `04h`
and storage size `0Fh`. Assert both before proceeding. Anything else → reject.

**Carry over from `pi_app.py` verbatim:** the page-by-page NDEF write with 3 retries
per page and a ~50 ms settle delay after each successful write. Writing ~24 pages
back-to-back without pacing causes real `"Response frame preamble does not contain
0x00FF!"` I²C errors on this hardware. This was found empirically; do not "clean it up".

**Anti-tearing (A13):** NTAG21x protects lock bits and the counter against tearing in
hardware, but the NDEF area is not protected. The mandatory read-back byte-compare
after writing is what catches a torn write. Never skip it.

---

## 7. Cryptographic design

### 7.1 The key separation table

This table is the answer to Contradiction 1 in the threat model (the adversary who
reads the backend's entire configuration). **No single compromise breaks more than one
property.**

| Key | Algorithm | Held by | Never held by | Protects |
|---|---|---|---|---|
| `DEVICE_SIGNING_KEY` | Ed25519 private | Pi, via `KeyProvider` | Backend, DB | Enrolment write authenticity |
| `DEVICE_PUBLIC_KEY` | Ed25519 public | Backend (`device_registry` table) | — | (verification only) |
| `FIELD_RECIPIENT_KEY` | X25519 private | Backend, **envelope-wrapped** | Pi, DB | Confidentiality of product fields |
| `FIELD_RECIPIENT_PUB` | X25519 public | Pi, backend | — | (encryption only) |
| `ROW_SIGNING_KEY` | Ed25519 private | Backend, **envelope-wrapped**, separate from above | Pi, DB | Row integrity (expiry, status, crypto_version) |
| `TAG_INDEX_KEY` | 32-byte HMAC secret | Backend only | Pi, DB | Enumeration resistance of the lookup index |
| `TAG_PWD_MASTER` | 32-byte secret | Pi only | Backend | Diversified tag PWD/PACK (only when locking) |
| `ADMIN_TOKEN_KEY` | Ed25519 private | Offline / CI | Runtime backend | Minting scoped admin tokens |
| `TRANSPARENCY_KEY` | Ed25519 private | GitHub Actions secret | Runtime backend | Signing Merkle roots |
| `KEK` (key-encryption key) | 32-byte AES key | Supplied at deploy, held in a system with **different access control** than the code repo and the hosting dashboard | Git, DB | Unwrapping the two wrapped keys above |
| `IP_HASH_KEY` | 32-byte, rotates daily | Backend | — | Pseudonymising source IPs (DPDP Act) |

The critical change from v1: **the Pi no longer holds `AES_MASTER_KEY`.** In v1, one
cheap Linux box held both the signing key and the key that decrypts every record in
the database — compromising it broke confidentiality *and* integrity of the whole
system (F1 + F2). In v2 the Pi holds only a *public* encryption key. It can write
records; it cannot read the register.

### 7.2 One crypto version

`crypto_version = "aes_gcm_v2"`. Anything else is a **hard reject**, never a fallback:

```python
ALLOWED_CRYPTO_VERSIONS = frozenset({"aes_gcm_v2"})
if row["crypto_version"] not in ALLOWED_CRYPTO_VERSIONS:
    raise RecordInvalid("unsupported crypto_version")     # → verdict RECORD_INVALID
```

`crypto_version` is also inside the row signature (§7.4), so it cannot be flipped in
the database at all. This closes F14, D13 and E8 — three findings, one line of policy.

### 7.3 Field encryption — envelope to the backend's public key

Per-record scheme, implemented identically in `backend/crypto_envelope.py` and
`pi/crypto_envelope.py`, pinned by `tests/vectors/envelope.json`:

1. The Pi generates a random 32-byte **DEK** (data encryption key).
2. Each field is encrypted separately: `AES-256-GCM(DEK, fresh 12-byte nonce, field)`.
   Fields: `product_id`, `batch_id`, `mfg_date`, `tag_uid`.
   **AAD is mandatory** and binds the ciphertext to its slot:
   `aad = b"nfcmed/v2/field/" + field_name.encode()`. This is what stops D11
   (cross-field or cross-record ciphertext substitution) at the primitive level.
3. The DEK is wrapped to the backend's X25519 public key:
   - ephemeral X25519 keypair `(esk, epk)`
   - `shared = X25519(esk, FIELD_RECIPIENT_PUB)`
   - `wrap_key = HKDF-SHA256(ikm=shared, salt=None, info=b"nfcmed/v2/dek-wrap", len=32)`
   - `enc_dek = epk(32) || nonce(12) || AESGCM(wrap_key).encrypt(nonce, DEK, aad=b"nfcmed/v2/dek")`
4. The Pi sends the four ciphertexts + `enc_dek`. **It keeps no copy of the DEK.**

```python
# shared shape — both copies must produce identical output for the test vector
def seal_record(fields: dict[str, str], recipient_pub: bytes) -> dict:
    dek = os.urandom(32)
    out = {}
    for name, value in fields.items():
        nonce = os.urandom(12)
        aad = b"nfcmed/v2/field/" + name.encode()
        ct = AESGCM(dek).encrypt(nonce, value.encode("utf-8"), aad)
        out[name] = {"n": nonce.hex(), "c": ct.hex()}
    esk = X25519PrivateKey.generate()
    shared = esk.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    wrap_key = HKDF(algorithm=SHA256(), length=32, salt=None,
                    info=b"nfcmed/v2/dek-wrap").derive(shared)
    wn = os.urandom(12)
    wrapped = AESGCM(wrap_key).encrypt(wn, dek, b"nfcmed/v2/dek")
    epk = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    out["enc_dek"] = (epk + wn + wrapped).hex()
    return out
```

**Why this rather than v1's HKDF-from-a-shared-master:** v1's design required the same
symmetric `AES_MASTER_KEY` on both ends. Under the project's own threat model — an
adversary who obtains the backend's entire configuration — that voids the
confidentiality claim outright. Envelope-to-public-key means the Pi cannot decrypt,
and reading the backend's *environment variables* is not sufficient either, because
`FIELD_RECIPIENT_KEY` is stored wrapped (§7.6).

**Residual risk, stated plainly:** a full host compromise of the running backend still
yields the unwrapped key in memory. Only an HSM removes that, and there is no free
HSM. Document it; do not pretend otherwise. (E10.)

### 7.4 Row integrity — Ed25519, not a hash

v1's `payload_hash` was an unkeyed SHA-256 over four public ciphertext values. An
attacker with database write access could change the expiry date and simply recompute
it (F13, F15, D12). It was a checksum, not an integrity control.

v2 signs every security-relevant field with `ROW_SIGNING_KEY`:

```python
ROW_SIG_FIELDS = [
    "tag_index", "binding_token_hash",
    "product_id_ct", "batch_id_ct", "mfg_date_ct", "tag_uid_ct",
    "enc_dek", "shelf_life", "expiry_date", "crypto_version",
    "enrol_counter", "batch_ref", "status", "device_id",
    "originality_status", "enrolled_at", "row_sig_alg", "row_key_version",
]

def canonical(row: dict) -> bytes:
    return json.dumps({k: row[k] for k in ROW_SIG_FIELDS},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")

row_sig = ed25519_sign(ROW_SIGNING_KEY, b"nfcmed/v2/row:" + canonical(row))
```

**Verified on every single verify.** Signature mismatch → verdict `RECORD_INVALID`,
never `AUTHENTIC`, and an audit row with `result="row_sig_invalid"`.

Note what is inside the signature: `expiry_date`, `status`, `crypto_version` and
`enrol_counter`. An attacker with full DB read/write can now change nothing without
detection. That directly closes D12 and D13, and it is the single highest-leverage
change in the backend.

`row_key_version` is stored per row so rotation is: add the new version → dual-accept
both → lazily re-sign old rows → retire the old version. Build the version column now;
retrofitting it after a million rows is painful.

### 7.5 `KeyProvider` — the Pi's signing interface

Decision D2: file-based now, ATECC608A later, **no call site ever touches raw key bytes.**

```python
# pi/keyprovider.py
class KeyProvider(Protocol):
    def device_id(self) -> str: ...
    def public_key(self) -> bytes: ...            # 32 raw bytes, Ed25519
    def sign(self, message: bytes) -> bytes: ...  # 64 raw bytes

class FileKeyProvider:
    """Reads a hex Ed25519 private key from pi/.env. The key is in plaintext on an
    SD card — this is a KNOWN, ACCEPTED weakness for this phase (finding F1). The
    per-batch enrolment quota (§12.6) is what bounds the damage if it is stolen."""
    def __init__(self, privkey_hex: str, device_id: str): ...

class Atecc608aKeyProvider:
    """STUB. Same interface. The private key is generated inside the chip over I²C
    (address 0x60, same bus as the PN532) and never leaves it. Implementing this
    later requires zero changes to enroller.py or drainer.py."""
    def __init__(self, i2c, slot: int = 0):
        raise NotImplementedError("ATECC608A support not built — use FileKeyProvider")
```

`enroller.py` and `drainer.py` accept a `KeyProvider` and nothing else. Selection is
via `KEY_PROVIDER=file|atecc608a` in `pi/.env`.

**Per-batch quotas are the real mitigation for F1**, not the key store. Even with a
stolen signing key, an attacker can only enrol inside an open, quota-limited batch
(§12.6). That converts an unlimited compromise into a bounded one, for free.

### 7.6 Envelope-wrapped secrets at the backend

`FIELD_RECIPIENT_KEY` and `ROW_SIGNING_KEY` are **never** stored raw in Render's
environment. They are stored wrapped:

```
FIELD_RECIPIENT_KEY_WRAPPED = <hex: nonce(12) || AESGCM(KEK).encrypt(...)>
ROW_SIGNING_KEY_WRAPPED     = <hex: nonce(12) || AESGCM(KEK).encrypt(...)>
KEK                         = <hex 32 bytes>   ← supplied at deploy time
```

`backend/keys.py` unwraps both at boot and holds them in memory only. `scripts/gen_keys.py`
generates everything; `scripts/wrap_secret.py` produces the wrapped blobs to paste.

This does not make key theft impossible. It means **reading the environment variables
is no longer sufficient**, which is precisely what the threat model's capability (v)
requires. The point is only defensible if `KEK` lives somewhere with genuinely
different access control from the Render dashboard — a password manager, a sealed
envelope, anything that is not the same login. If you put `KEK` next to the wrapped
blobs, you have gained nothing; say so in the README.

### 7.7 Request signing, with algorithm agility

```
X-Device-Id:      <uuid>              which device_registry row
X-Timestamp:      <unix seconds>
X-Sig-Alg:        ed25519             reserved: ed25519+mldsa65
X-Signature:      <hex>
X-Idempotency-Key:<uuid4>

signed_payload = b"nfcmed/v2/req:" + alg + "\n" + timestamp + "\n"
               + idempotency_key + "\n"
               + sha256(raw_request_body_bytes).hexdigest()
```

Three deliberate differences from v1:

1. **Hash the raw body bytes** rather than re-serialising the parsed JSON. v1 rebuilt
   `json.dumps(body, sort_keys=True)` server-side, which makes the signature depend on
   Python's JSON serialiser agreeing with the client's. Hashing the received bytes
   removes an entire class of canonicalisation mismatch.
2. **The idempotency key is inside the signature**, so it cannot be swapped (D9).
3. **The timestamp window is two-sided**: reject if `now - ts > 30` *or* `ts - now > 30`.
   v1 used `abs()` which is already two-sided — keep that, and add an explicit test,
   because D8 (future-dated timestamp) is currently untested.

`X-Sig-Alg` is validated against an allow-list of one. It exists so ML-DSA can be added
later by extending the allow-list and the `device_registry.sig_alg` column — no schema
migration, no route changes. That is the whole of the crypto-agility requirement for
this build.

### 7.8 The keyed tag index

```python
# backend/tag_index.py
def normalise_uid(uid: str) -> str:
    """Canonical UID form: uppercase hex, no separators. MUST be identical on the Pi
    and the backend. Pinned by tests/vectors/uid.json."""
    u = uid.replace(":", "").replace("-", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{14}", u):
        raise ValueError("uid must be 14 hex chars")
    return u

def tag_index(uid: str, key: bytes) -> str:
    return hmac.new(key, normalise_uid(uid).encode("ascii"), hashlib.sha256).hexdigest()
```

`TAG_INDEX_KEY` lives **only** on the backend. The Pi never computes an index — it
sends the UID inside the sealed envelope, and the backend derives the index after
decrypting at enrol time. At verify time the backend gets the UID directly from the
mirror and computes the index itself.

This closes E5 (precomputation over the ~2^48 UID space) and D9. It also means the
`products` table contains no value from which a UID can be recovered without both the
`TAG_INDEX_KEY` and the field-decryption key.

---

## 8. Database schema

Postgres on Supabase. Two files, run once by the operator in the SQL Editor (§20).
This is a **fresh register** — v2 is not migration-compatible with v1 rows (the
lookup index is keyed, the paper cipher is gone, `payload_hash` is replaced). If you
have v1 data you care about, export it first; otherwise start clean.

### 8.1 `schema/001_core.sql`

```sql
-- ============================================================================
-- NFC Medicine Authenticity System v2 — core schema
-- Idempotent. Safe to re-run.
-- ============================================================================

-- ---------------------------------------------------------------- devices ---
CREATE TABLE IF NOT EXISTS device_registry (
    device_id       UUID PRIMARY KEY,
    label           TEXT        NOT NULL,
    public_key      TEXT        NOT NULL,              -- Ed25519, 64 hex chars
    sig_alg         TEXT        NOT NULL DEFAULT 'ed25519',
    status          TEXT        NOT NULL DEFAULT 'active',   -- active | revoked
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT device_status_valid CHECK (status IN ('active','revoked')),
    CONSTRAINT device_sig_alg_valid CHECK (sig_alg IN ('ed25519'))
);

-- ---------------------------------------------------------------- batches ---
-- Two-person authorisation + enrolment quota. This is the cheapest mitigation
-- for a stolen Pi signing key (F1): a compromise is bounded by the open quota.
CREATE TABLE IF NOT EXISTS batches (
    batch_ref        TEXT        PRIMARY KEY,           -- operator-visible, e.g. 'AMX-2026-09-001'
    product_name     TEXT        NOT NULL,
    mfg_date         DATE        NOT NULL,
    shelf_life_days  INTEGER     NOT NULL,
    quota            INTEGER     NOT NULL,
    enrolled_count   INTEGER     NOT NULL DEFAULT 0,
    status           TEXT        NOT NULL DEFAULT 'open',  -- open|closed|recalled|withdrawn
    opened_by        TEXT        NOT NULL,
    countersigned_by TEXT        NOT NULL,               -- the second person (F12, G5)
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at        TIMESTAMPTZ,
    recall_notice    TEXT,
    recalled_at      TIMESTAMPTZ,
    CONSTRAINT batch_status_valid CHECK (status IN ('open','closed','recalled','withdrawn')),
    CONSTRAINT batch_quota_positive CHECK (quota > 0),
    CONSTRAINT batch_quota_not_exceeded CHECK (enrolled_count <= quota),
    CONSTRAINT batch_two_person CHECK (countersigned_by <> opened_by),
    CONSTRAINT batch_shelf_life_sane CHECK (shelf_life_days BETWEEN 1 AND 3650)
);

-- `batch_quota_not_exceeded` is a DB-level invariant on purpose. Enforce invariants
-- where they cannot be bypassed — an application-level count is a race, a CHECK is not.

-- --------------------------------------------------------------- products ---
CREATE TABLE IF NOT EXISTS products (
    id                 BIGSERIAL   PRIMARY KEY,
    tag_index          TEXT        NOT NULL UNIQUE,     -- HMAC(TAG_INDEX_KEY, uid). UNIQUE closes D10/F7.
    binding_token_hash TEXT        NOT NULL,            -- SHA-256 of the 128-bit token on the tag

    product_id_ct      TEXT        NOT NULL,            -- {"n":...,"c":...} JSON text, AES-256-GCM
    batch_id_ct        TEXT        NOT NULL,
    mfg_date_ct        TEXT        NOT NULL,
    tag_uid_ct         TEXT        NOT NULL,
    enc_dek            TEXT        NOT NULL,            -- epk||nonce||wrapped DEK, hex

    shelf_life         INTEGER     NOT NULL,
    expiry_date        DATE        NOT NULL,
    crypto_version     TEXT        NOT NULL DEFAULT 'aes_gcm_v2',
    enrol_counter      INTEGER     NOT NULL,            -- counter value captured at enrolment
    batch_ref          TEXT        NOT NULL REFERENCES batches(batch_ref),
    device_id          UUID        NOT NULL REFERENCES device_registry(device_id),
    originality_status TEXT        NOT NULL DEFAULT 'unverified',
    status             TEXT        NOT NULL DEFAULT 'active',
    binding_class      TEXT        NOT NULL DEFAULT 'counter',  -- counter | none (QR fallback, F4)
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_by      BIGINT      REFERENCES products(id),

    row_sig            TEXT        NOT NULL,
    row_sig_alg        TEXT        NOT NULL DEFAULT 'ed25519',
    row_key_version    INTEGER     NOT NULL DEFAULT 1,

    CONSTRAINT products_crypto_version_valid CHECK (crypto_version = 'aes_gcm_v2'),
    CONSTRAINT products_status_valid
        CHECK (status IN ('active','recalled','withdrawn','destroyed','superseded')),
    CONSTRAINT products_originality_valid
        CHECK (originality_status IN ('verified','unverified','failed')),
    CONSTRAINT products_binding_class_valid CHECK (binding_class IN ('counter','none')),
    CONSTRAINT products_enrol_counter_sane CHECK (enrol_counter BETWEEN 0 AND 16777215)
);
CREATE INDEX IF NOT EXISTS idx_products_tag_index ON products(tag_index);
CREATE INDEX IF NOT EXISTS idx_products_batch_ref ON products(batch_ref);

-- ----------------------------------------------------- MTA counter state ---
CREATE TABLE IF NOT EXISTS tag_counter_state (
    tag_index         TEXT        PRIMARY KEY REFERENCES products(tag_index) ON DELETE CASCADE,
    max_counter       INTEGER     NOT NULL,
    observation_count INTEGER     NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_region       TEXT,                             -- coarse geo, for impossible-travel
    status            TEXT        NOT NULL DEFAULT 'ok', -- ok | suspect_duplicate | frozen
    CONSTRAINT counter_state_status_valid CHECK (status IN ('ok','suspect_duplicate','frozen')),
    CONSTRAINT counter_state_max_sane CHECK (max_counter BETWEEN 0 AND 16777215)
);

-- G1: SUSPECT_DUPLICATE is STICKY. There is deliberately no path from
-- 'suspect_duplicate' back to 'ok' except an explicit, audited admin action.
-- A counterfeiter must not be able to probe which stolen identifiers are still good.

CREATE TABLE IF NOT EXISTS divergence_incident (
    id               BIGSERIAL   PRIMARY KEY,
    tag_index        TEXT        NOT NULL,
    observed_counter INTEGER     NOT NULL,
    expected_min     INTEGER     NOT NULL,
    velocity_bound   INTEGER,
    kind             TEXT        NOT NULL,   -- rollback | repeat | velocity | geo | mirror_disabled
    source_ip_hash   TEXT,
    user_agent_class TEXT,
    resolution       TEXT        NOT NULL DEFAULT 'open', -- open|confirmed|false_positive|closed
    resolved_by      TEXT,
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT incident_kind_valid
        CHECK (kind IN ('rollback','repeat','velocity','geo','mirror_disabled')),
    CONSTRAINT incident_resolution_valid
        CHECK (resolution IN ('open','confirmed','false_positive','closed'))
);
CREATE INDEX IF NOT EXISTS idx_incident_tag_index  ON divergence_incident(tag_index);
CREATE INDEX IF NOT EXISTS idx_incident_created_at ON divergence_incident(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_open       ON divergence_incident(resolution)
    WHERE resolution = 'open';

-- --------------------------------------------------------- idempotency ----
CREATE TABLE IF NOT EXISTS idempotency_key (
    key             UUID        PRIMARY KEY,
    device_id       UUID        NOT NULL,
    request_hash    TEXT        NOT NULL,      -- sha256 of the raw body
    response_status INTEGER     NOT NULL,
    response_body   JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_idem_created_at ON idempotency_key(created_at);

-- --------------------------------------------------------- audit (chained) -
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGSERIAL   PRIMARY KEY,
    event_type   TEXT        NOT NULL,
    tag_index    TEXT,
    actor        TEXT,                          -- device_id, admin subject, or 'public'
    result       TEXT,
    source_ip_hash TEXT,                        -- HMAC(IP_HASH_KEY_today, ip). Never a raw IP.
    user_agent_class TEXT,                      -- 'android-chrome' etc. Never the raw UA string.
    detail       JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hash    TEXT        NOT NULL,
    entry_hash   TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tag_index  ON audit_log(tag_index);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC);

-- -------------------------------------------------------- consumer reports -
CREATE TABLE IF NOT EXISTS consumer_report (
    id            BIGSERIAL   PRIMARY KEY,
    tag_index     TEXT,
    verdict_shown TEXT,
    pharmacy_name TEXT,
    city          TEXT,
    note          TEXT,
    contact       TEXT,                          -- optional, consumer-supplied
    triage        TEXT        NOT NULL DEFAULT 'new',  -- new|reviewing|actioned|spam
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT report_triage_valid CHECK (triage IN ('new','reviewing','actioned','spam'))
);
CREATE INDEX IF NOT EXISTS idx_report_triage ON consumer_report(triage) WHERE triage = 'new';

-- ---------------------------------------------------------- transparency ---
CREATE TABLE IF NOT EXISTS transparency_root (
    id            BIGSERIAL   PRIMARY KEY,
    as_of_date    DATE        NOT NULL UNIQUE,
    merkle_root   TEXT        NOT NULL,
    record_count  INTEGER     NOT NULL,
    audit_head    TEXT        NOT NULL,          -- latest audit_log.entry_hash
    signature     TEXT        NOT NULL,
    published_url TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------- rate limiting ----
-- Second layer behind the Cloudflare Worker, for the case where the edge is
-- bypassed (someone hits the Render origin directly). Fixed-window counters.
CREATE TABLE IF NOT EXISTS rate_limit_bucket (
    bucket_key   TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    hits         INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (bucket_key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rl_window ON rate_limit_bucket(window_start);
```

### 8.2 `schema/002_rls.sql`

```sql
-- Every table gets RLS with ZERO policies for anon/authenticated. The backend
-- connects as Supabase's `postgres` role (BYPASSRLS) and is unaffected. What this
-- closes is the auto-generated PostgREST API, which every Supabase project exposes
-- and which is reachable with the project's anon key. Missing this leaks the whole
-- database (F7a). v1 got this right for two tables — extend it to all of them.
ALTER TABLE device_registry    ENABLE ROW LEVEL SECURITY;
ALTER TABLE batches            ENABLE ROW LEVEL SECURITY;
ALTER TABLE products           ENABLE ROW LEVEL SECURITY;
ALTER TABLE tag_counter_state  ENABLE ROW LEVEL SECURITY;
ALTER TABLE divergence_incident ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_key    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log          ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer_report    ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_root  ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_bucket  ENABLE ROW LEVEL SECURITY;

ALTER TABLE device_registry    FORCE ROW LEVEL SECURITY;
ALTER TABLE products           FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log          FORCE ROW LEVEL SECURITY;

-- Retention (F30, DPDP Act 2023): audit rows older than 90 days are deleted.
-- Run from the nightly GitHub Action, not a Postgres extension (pg_cron is not
-- available on the free tier).
```

### 8.3 Schema invariants the application must not duplicate in Python

These are enforced in the database on purpose. Do not add a redundant Python check
that can drift from them — read the constraint error and map it to an API error:

| Constraint | Attack closed | Maps to |
|---|---|---|
| `products.tag_index UNIQUE` | D10, F7 — re-enrolment shadowing | `409 tag_already_enrolled` |
| `batches.batch_quota_not_exceeded` | F10a, G5 — unlimited enrolment with a stolen key | `409 batch_quota_exhausted` |
| `batches.batch_two_person` | F12 — single-operator enrolment | `400 countersignature_required` |
| `products.crypto_version = 'aes_gcm_v2'` | E8, D13 — downgrade | `500` + `RECORD_INVALID` |
| `idempotency_key PRIMARY KEY` | D9, F11 — double insert on retry | replay of the stored response |

---

## 9. Backend

Flask + gunicorn on Render free tier. Start command is pinned:

```
gunicorn "app:create_app()" --bind 0.0.0.0:$PORT --workers 2 --threads 4 \
         --timeout 30 --graceful-timeout 10 --access-logfile - --error-logfile -
```

**Workers are pinned at 2 deliberately.** v1 left this to Render's default, which
means the in-process rate limiter kept a separate counter per worker — its configured
limits were silently N times looser than reported (F16). Any evaluation that reports
rate-limiter behaviour must state the worker count, or the number means nothing.

### 9.1 `app.py` — factory only

```python
def create_app() -> Flask:
    cfg = load_config()            # raises on any missing/malformed secret
    setup_logging(cfg)             # JSON to stdout, with secret redaction
    keys.load(cfg)                 # unwrap FIELD_RECIPIENT_KEY + ROW_SIGNING_KEY
    db.init_pool(cfg)              # ThreadedConnectionPool
    app = Flask(__name__, static_folder="../frontend", static_url_path="")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024        # D19: body size cap
    register_blueprints(app)
    register_error_handlers(app)                        # §15
    register_security_headers(app)                      # §9.12
    return app
```

**No route logic in this file.** Every handler lives in `routes/`, every decision in
`services/`. Route modules validate and serialise; service modules decide. The verdict
state machine must be unit-testable without Flask.

### 9.2 `config.py` — fail fast

```python
REQUIRED = ["DATABASE_URL", "KEK", "FIELD_RECIPIENT_KEY_WRAPPED",
            "ROW_SIGNING_KEY_WRAPPED", "TAG_INDEX_KEY", "ADMIN_TOKEN_PUBKEY",
            "IP_HASH_SEED", "CNT_BYTE_ORDER", "PUBLIC_HOST"]

def load_config() -> Config:
    missing = [k for k in REQUIRED if not os.getenv(k)]
    if missing:
        raise ConfigError(f"missing required env vars: {', '.join(missing)}")
    # Validate shapes, not just presence: hex length, URL scheme, enum membership.
    ...
```

Never `os.getenv("SECRET", "")`. A secret that defaults to empty string turns a
misconfiguration into a silent security hole — v1 did this for `SHARED_SECRET`,
`AES_MASTER_KEY` and `ADMIN_API_KEY`.

### 9.3 `db.py` — pooled, always returned

```python
_pool: ThreadedConnectionPool | None = None

def init_pool(cfg):
    global _pool
    _pool = ThreadedConnectionPool(minconn=1, maxconn=cfg.db_pool_max,  # default 6
                                   dsn=_with_sslmode(cfg.database_url))

@contextmanager
def connection(*, write: bool = False):
    """Always returns the connection to the pool. Rolls back on any exception.
    Closes D24 — v1 leaked a connection on every error path that returned early."""
    if _pool is None:
        raise ServiceUnavailable("database pool not initialised")
    conn = _pool.getconn()
    try:
        yield conn
        if write:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)
```

Keep the `sslmode=require` injection from v1's `db.py` verbatim, and keep the
**session pooler** connection string. The direct Supabase hostname resolves IPv6-only
and fails from Render; the symptom is a database error in production while the same
code works locally.

`maxconn` must be ≤ Supabase's free-tier pooler limit. With `--workers 2`, total
connections are `2 × db_pool_max`. Keep `db_pool_max = 6`.

### 9.4 Route inventory

| Route | Method | Auth | Edge limit | Origin limit | Purpose |
|---|---|---|---|---|---|
| `/health` | GET | none | — | — | Liveness + server time + posture flags |
| `/metrics` | GET | scoped token | — | 60/min | Counters (§14.5) |
| `/c` | GET | none | 60/min per IP-prefix | — | Tag landing page (served by the edge) |
| `/api/v2/enrol` | POST | device Ed25519 + idempotency key | 120/min per device | 60/min | Register a tag |
| `/api/v2/reenrol` | POST | device sig + batch authorisation token | 10/min | 5/min | Explicit supersede, audited |
| `/api/v2/verify` | GET | none | per-tag + per-IP-prefix | 120/min | **Consumer verification** |
| `/api/v2/report` | POST | proof-of-work | 5/min | 5/min | Consumer report |
| `/api/v2/admin/batches` | GET/POST | scoped token `batch:write` | — | 60/min | Open/close/list batches |
| `/api/v2/admin/recall` | POST | scoped token `recall` | — | 10/min | Batch recall |
| `/api/v2/admin/incidents` | GET/PATCH | scoped token `incident:read/write` | — | 60/min | Divergence triage |
| `/api/v2/admin/reports` | GET/PATCH | scoped token `report:read` | — | 60/min | Consumer report triage |
| `/.well-known/transparency/latest` | GET | none | — | — | Signed Merkle root |

`/api/v1/*`, `/api/products`, `/api/verify/<hash>`, `/api/admin/keys/<hash>` and
`/test-db` all return **404** (D15, D16). Add an explicit test asserting this.

### 9.5 `POST /api/v2/enrol`

**Request body** (JSON, ≤ 64 KB):

```json
{
  "schema": "nfcmed.enrol.v2",
  "crypto_version": "aes_gcm_v2",
  "batch_ref": "AMX-2026-09-001",
  "binding_token_hash": "<sha256 hex of the 128-bit token written to the tag>",
  "enrol_counter": 3,
  "originality_status": "verified",
  "binding_class": "counter",
  "tag_version": "0004040201000F03",
  "sealed": {
    "product_id": {"n": "<hex>", "c": "<hex>"},
    "batch_id":   {"n": "<hex>", "c": "<hex>"},
    "mfg_date":   {"n": "<hex>", "c": "<hex>"},
    "tag_uid":    {"n": "<hex>", "c": "<hex>"},
    "enc_dek":    "<hex>"
  }
}
```

Note what is **not** sent: no `tag_index`, no `shelf_life`, no `expiry_date`, no
plaintext anything. The backend derives all three — `shelf_life` from the batch,
`expiry_date` from the decrypted `mfg_date`, `tag_index` from the decrypted UID. A
client that cannot state the expiry date cannot get the expiry date wrong (F8).

**Server-side order of operations. Do not reorder — each step assumes the previous
one passed:**

```
 1. Enforce method + Content-Type: application/json.                  → 415
 2. Enforce body size and JSON depth limits.                          → 413 / 400
 3. Look up X-Device-Id in device_registry; must exist and be active. → 403
 4. Verify X-Signature over the RAW body bytes per §7.7.              → 403
      Signature verification happens BEFORE any field parsing.
      Unparsed attacker data must never reach a parser. (v1 got this right.)
 5. Two-sided timestamp window check, ±30 s.                          → 403
 6. Idempotency: SELECT on X-Idempotency-Key.
      - found, request_hash matches  → replay the stored response verbatim, stop.
      - found, request_hash differs  → 409 idempotency_conflict.      (D9)
      - not found                    → continue.
 7. Validate the schema field and crypto_version against the allow-list. → 400
 8. Load the batch. Must exist, status='open', enrolled_count < quota. → 409
 9. Unseal the DEK, decrypt tag_uid and mfg_date ONLY.                → 400 on InvalidTag
      Do not decrypt product_id/batch_id here — nothing needs them yet.
10. mfg_date sanity: parseable, not in the future, not older than 10 years,
      and equal to the batch's mfg_date (± a configured tolerance).   → 400  (F8)
11. tag_index = HMAC(TAG_INDEX_KEY, normalise_uid(uid)).
12. expiry_date = mfg_date + batch.shelf_life_days.
13. Build the row, compute row_sig (§7.4).
14. Single transaction:
      INSERT INTO products ...
      UPDATE batches SET enrolled_count = enrolled_count + 1 WHERE batch_ref = %s
      INSERT INTO tag_counter_state (tag_index, max_counter) VALUES (%s, enrol_counter)
      INSERT INTO idempotency_key ...
    Catch UniqueViolation on products.tag_index  → 409 tag_already_enrolled  (D10)
    Catch CheckViolation on batch_quota          → 409 batch_quota_exhausted (F10a)
15. Audit-log the outcome on every branch, including the failures.
16. 201 {"status":"enrolled","tag_index":"<hex>","expiry_date":"YYYY-MM-DD"}
```

Step 14 being **one transaction** matters: an insert that succeeds while the quota
increment fails would let the quota drift, and the quota is the mitigation for a
stolen signing key.

`POST /api/v2/reenrol` is identical except it requires a separate
`X-Batch-Authorisation` token, sets `superseded_by` on the old row, sets its status to
`superseded`, resets `tag_counter_state`, and writes an audit entry with a mandatory
free-text `reason`. There is no implicit supersede path anywhere in the codebase.

### 9.6 `GET /api/v2/verify` — input handling

```
GET /api/v2/verify?m=04A1B2C3D4E5F6x0001A7&t=<32 hex>
```

```python
# backend/mirror.py
M_PATTERN = re.compile(r"^[0-9A-F]{14}x[0-9A-F]{6}$")
T_PATTERN = re.compile(r"^[0-9A-F]{32}$")
PLACEHOLDER_UID = "00000000000000"

def parse_mirror(raw_m: str, raw_t: str) -> Mirror:
    # NFKC-normalise then uppercase BEFORE matching, so full-width and mixed-case
    # inputs are rejected by the pattern rather than sneaking past it. (B5)
    m = unicodedata.normalize("NFKC", raw_m).strip().upper()
    t = unicodedata.normalize("NFKC", raw_t).strip().upper()
    if not M_PATTERN.fullmatch(m) or not T_PATTERN.fullmatch(t):
        raise BadRequest("malformed_parameters")
    uid, counter = m[:14], int(m[15:21], 16)
    if uid == PLACEHOLDER_UID and counter == 0:
        return Mirror(uid=uid, counter=counter, placeholder=True)   # → MIRROR_DISABLED
    return Mirror(uid=uid, counter=counter, placeholder=False)
```

Additional input rules, all enforced before any database work:

- **Duplicate parameters are rejected outright** (B8). Flask's `request.args.get`
  silently takes the first; use `request.args.getlist` and reject `len != 1`.
- **`t` is mandatory.** There is no UID-only fallback path anywhere (B6). Fail closed.
- **Length caps before regex** — reject any parameter over 64 chars without running a
  regex over it (B4, and it keeps the regex from becoming a DoS surface).
- **The edge canonicalises first** (§11.3), and the origin re-validates. Differential
  parsing between edge and origin is B9; the fix is that both use the same rules and
  the origin never trusts the edge's parse.

### 9.7 The verdict state machine — `services/verification.py`

This is the core of the system. Implement it as a pure function over
`(mirror, product_row, counter_state, batch, now)` returning a `Verdict`, with no
Flask and no database access inside it, so it is exhaustively unit-testable.

```
INPUT: mirror (uid, counter, placeholder), t (binding token), request metadata

 0. If mirror.placeholder                    → MIRROR_DISABLED, binding="none"
                                                (the tag's mirror was never enabled)
 1. tag_index = HMAC(TAG_INDEX_KEY, uid)
 2. row = SELECT ... FROM products WHERE tag_index = %s
    If none                                  → UNKNOWN
 3. constant_time_compare(sha256(t), row.binding_token_hash)
    If mismatch                              → UNKNOWN   (never "wrong token" — an
                                                attacker learns nothing from UNKNOWN)
 4. verify_row_sig(row)
    If invalid                               → RECORD_INVALID   (D12, D13, F13, F15)
 5. state = SELECT ... FROM tag_counter_state WHERE tag_index = %s
    If state.status in ('suspect_duplicate','frozen')
                                             → SUSPECT_DUPLICATE   (sticky, G1)
 6. COUNTER CHECK — the MTA core:
      if mirror.counter <= state.max_counter:
          kind = 'repeat' if mirror.counter == state.max_counter else 'rollback'
          → divergence(kind)                 → SUSPECT_DUPLICATE
 7. VELOCITY BOUND — the attribution fix:
      days = max((now - row.enrolled_at).days, 1)
      bound = row.enrol_counter + MAX_TAPS_PER_DAY * days + VELOCITY_GRACE
      if mirror.counter > bound:
          → divergence('velocity')           → SUSPECT_DUPLICATE
 8. Advance state (single UPDATE, see below).
 9. if row.status == 'recalled' or batch.status == 'recalled'
                                             → RECALLED + recall notice   (F20, G2)
    if row.status in ('withdrawn','destroyed')→ WITHDRAWN
10. if today > row.expiry_date               → EXPIRED
11.                                          → AUTHENTIC
```

**Step 8 must be atomic and must not lose a concurrent update.** Two taps arriving
together must not both read the same `max_counter` and both pass:

```sql
UPDATE tag_counter_state
   SET max_counter       = %(counter)s,
       observation_count = observation_count + 1,
       last_seen_at      = NOW()
 WHERE tag_index = %(tag_index)s
   AND max_counter < %(counter)s
   AND status = 'ok'
RETURNING max_counter;
```

If this returns no row, another request already advanced past this counter — which is
itself a divergence. Re-read the state and route to step 6. Doing the comparison in
the `WHERE` clause is what makes MTA correct under concurrency; a read-then-write in
Python is a race that a mass-produced clone will find.

**On divergence, in one transaction:**

1. `INSERT INTO divergence_incident (...)`
2. `UPDATE tag_counter_state SET status='suspect_duplicate'`
3. Audit-log with `result='divergence'` and the kind
4. Increment the `divergence_incidents_total` metric (this is an alerting signal)
5. Return `SUSPECT_DUPLICATE`

**Never return "counterfeit" or "fake".** Attribution is genuinely ambiguous: an
attacker who pre-advances a clone's counter causes the *genuine* pack to trip the
alarm. The velocity bound (step 7) handles the realistic version of that — a pack
manufactured eleven days ago cannot plausibly have been tapped 900,000 times, and the
counter cannot be written, only advanced by real reads at ~10 ms each. But the honest
response to divergence is to flag both readings, open an incident and hand the
decision to a human. Declaring the wrong pack counterfeit is a worse failure than
declaring an ambiguity.

**Tuning:** `MAX_TAPS_PER_DAY = 50` (generous for a medicine pack, still catches an
attacker by ~1000×), `VELOCITY_GRACE = 20` (absorbs enrolment-time reads and honest
repeat scans in the first days). Both configurable. Also alert if any counter exceeds
100,000 — that is an anomaly in its own right regardless of the bound.

### 9.8 Verify response — uniform shape, uniform time

```json
{
  "verdict": "authentic",
  "binding": "counter",
  "product": {"name": "...", "batch": "...", "mfg_date": "...", "expiry": "..."},
  "checks": {"record": "pass", "counter": "pass", "recall": "pass", "expiry": "pass"},
  "incident": null,
  "verified_at": "2026-09-12T10:04:00+05:30"
}
```

Verdicts: `authentic` · `expired` · `recalled` · `withdrawn` · `suspect_duplicate` ·
`mirror_disabled` · `record_invalid` · `unknown`.

Binding levels (F33 — v1 could not distinguish these at all):

| Level | Meaning |
|---|---|
| `counter+liveread` | Mirrored counter **and** a Web NFC live read on this device |
| `counter` | Mirrored counter from the tag's own URL — the normal, strong case |
| `none` | No counter present (placeholder, or a `binding_class='none'` record) |

Returning the per-check breakdown is deliberate: it makes the system auditable from
outside, it is honest about what was actually verified, and it costs nothing. It is
also the deployment metric for the paper — *what fraction of real verifications
received the strong guarantee?*

**Two anti-oracle requirements (F23, F24, D22):**

1. **Same shape and similar size for every verdict.** `product` is always present as a
   key; it is `null` for negative verdicts. `unknown` must not be a visibly shorter
   response than `authentic`.
2. **Response-time floor.** Measure elapsed time in the handler; if under
   `VERIFY_TIME_FLOOR_MS` (default 120), sleep the remainder before responding. An
   `unknown` returns after one indexed lookup while an `authentic` does a lookup plus
   an X25519 unwrap plus four GCM decryptions — the difference is measurable and leaks
   registration status even with identical bodies.

```python
start = time.perf_counter()
verdict = verification.decide(...)
elapsed_ms = (time.perf_counter() - start) * 1000
if elapsed_ms < cfg.verify_time_floor_ms:
    time.sleep((cfg.verify_time_floor_ms - elapsed_ms) / 1000)
return jsonify(verdict.to_dict())
```

### 9.9 Hash-chained audit log

```python
def log_audit(**fields) -> None:
    """Best-effort. MUST NOT raise — a logging failure must never break its caller.
    v1 got this contract right; keep it exactly."""
    try:
        with db.connection(write=True) as conn, conn.cursor() as cur:
            cur.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE")
            row = cur.fetchone()
            prev = row[0] if row else "0" * 64
            entry = canonical_json(fields)
            entry_hash = sha256((prev + entry).encode()).hexdigest()
            cur.execute("INSERT INTO audit_log (..., prev_hash, entry_hash) VALUES (...)",
                        (..., prev, entry_hash))
    except Exception as exc:
        logger.warning("audit_write_failed", extra={"error": str(exc)})
```

The daily transparency job publishes the head `entry_hash`. An attacker with database
access who deletes their own trace breaks the chain, and the break becomes **publicly
provable** (F25). Without this, the audit log is not independent evidence for the
paper — it can be edited by exactly the adversary it is meant to catch.

`scripts/verify_transparency.py` walks the chain and reports the first break. Run it
in CI nightly.

**The `FOR UPDATE` matters.** Two concurrent audit writes without it produce two
entries claiming the same `prev_hash`, which is indistinguishable from tampering. If
lock contention becomes a problem, batch audit writes — do not drop the lock.

### 9.10 Admin authentication

v1 used one static string in `X-Admin-Key` with no scoping, expiry or rotation path
(F18). v2 uses short-lived signed tokens:

```
token = base64url(payload) + "." + base64url(ed25519_sign(ADMIN_TOKEN_KEY, payload))
payload = {"sub": "shreya", "scopes": ["recall","incident:write"],
           "iat": ..., "exp": ..., "jti": "<uuid>"}
```

- Minted offline by `scripts/mint_admin_token.py`. **`ADMIN_TOKEN_KEY` never reaches
  the runtime backend** — the backend holds only `ADMIN_TOKEN_PUBKEY`.
- Max lifetime 12 hours, enforced at verification.
- Scopes are checked per route: `@require_scope("recall")`.
- Every admin action writes an audit row including `sub` and `jti` (who did it), and
  that row is inside the audit chain.
- Constant-time comparison everywhere; the token is verified by signature, so there is
  no secret to brute-force (D14).

### 9.11 Privacy — no raw IPs, no raw user agents

F30 and India's DPDP Act 2023. Consumer scan records tied to IP and time are personal
data, and the roadmap explicitly wants to use them for geographic analysis.

```python
def hash_ip(ip: str) -> str:
    """Daily-rotating HMAC. Enough for rate limiting and same-source correlation
    within a day; useless afterwards. The raw IP is never written anywhere."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = hmac.new(cfg.ip_hash_seed, day.encode(), hashlib.sha256).digest()
    return hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:32]

def classify_ua(ua: str) -> str:
    """Coarse bucket only: 'android-chrome' | 'ios-safari' | 'desktop' | 'bot' | 'other'.
    Never store the raw User-Agent string."""
```

Plus: 90-day retention on `audit_log`, enforced by the nightly Action; a short privacy
notice on the verification page; and a `region` field on counter state that is coarse
(state/city level) rather than a precise location. The impossible-travel signal (§9.7
note) needs coarse geography, not tracking.

### 9.12 Security headers and CORS

Applied via `@app.after_request` on every response:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
                         connect-src 'self'; img-src 'self' data:;
                         base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=()
Cache-Control: no-store        ← on every /api/v2/verify response (C9)
```

`frame-ancestors 'none'` closes C3 (clickjacking the verification page under a fake
"authentic" overlay). `Cache-Control: no-store` on verdicts closes C9 (back-button
replay of an old verdict).

**CORS:** scope to your own origins only. v1 used `origins: "*"` on the verify route.
That was defensible — no secrets are returned — but it also means anyone can build a
convincing verification page against your API, including a counterfeiter running a
look-alike site that always says "authentic" (F28). Set
`CORS(app, resources={r"/api/v2/*": {"origins": cfg.allowed_origins}})` with the Worker
origin and the Render origin listed explicitly.

No inline scripts anywhere in the frontend — the CSP above forbids them, and that is
what makes C4 (XSS via a hostile product name) unexploitable even if output encoding
were missed.

---

## 10. API contracts — full reference

Every response, success or failure, is JSON. Every error uses the envelope in §15.2.

### 10.1 `GET /health`

```json
{
  "status": "ok",
  "version": "2.0.0",
  "server_time": "2026-09-12T10:04:00+00:00",
  "posture": {
    "tag_locking": "disabled",
    "originality_policy": "reject",
    "crypto_versions": ["aes_gcm_v2"],
    "edge_expected": true
  }
}
```

`server_time` exists so the Pi can measure clock drift before it starts a run (§12.5).
`posture` exists so the operating configuration is never ambiguous — if locking is off
or originality checks are unavailable, that is visible without reading the code. No
database detail, no version strings of dependencies, no connection status beyond ok/degraded.

### 10.2 `POST /api/v2/enrol`

Headers: `Content-Type`, `X-Device-Id`, `X-Timestamp`, `X-Sig-Alg`, `X-Signature`,
`X-Idempotency-Key`. Body: §9.5.

| Status | `code` | Meaning |
|---|---|---|
| 201 | — | Enrolled |
| 200 | — | Idempotent replay of a previous success |
| 400 | `malformed_request` | Schema, field shape, or JSON depth |
| 400 | `mfg_date_invalid` | Unparseable, future-dated, too old, or batch mismatch |
| 400 | `decrypt_failed` | `enc_dek` or a field failed GCM authentication |
| 403 | `bad_signature` | Signature, timestamp window, or unknown/revoked device |
| 409 | `tag_already_enrolled` | `products.tag_index` UNIQUE violation |
| 409 | `batch_quota_exhausted` | Batch CHECK violation |
| 409 | `batch_not_open` | Batch closed, recalled or withdrawn |
| 409 | `idempotency_conflict` | Same key, different body hash |
| 413 | `payload_too_large` | Over 64 KB |
| 415 | `unsupported_media_type` | Not `application/json` |
| 429 | `rate_limited` | Includes `Retry-After` |
| 503 | `service_unavailable` | Database pool unavailable |

**The Pi treats 400/403/409 as terminal** (move the outbox row to `failed`, alert the
operator) and 429/5xx/network errors as **retryable**. Getting this split wrong is how
an outbox either spins forever on a permanently bad record or silently drops a good one.

### 10.3 `GET /api/v2/verify`

Query: `m` (required), `t` (required), `live` (optional, `1` when the page performed a
Web NFC read). Response: §9.8. Errors: `400 malformed_parameters`,
`429 rate_limited`, `503 service_unavailable`.

Note there is **no 404**. An unregistered tag returns `200` with
`{"verdict": "unknown"}`. Status codes must not become a second, unnormalised oracle
alongside the response body (F23).

### 10.4 `POST /api/v2/report`

```json
{"tag_index": "...", "verdict_shown": "suspect_duplicate",
 "pharmacy_name": "...", "city": "...", "note": "...", "contact": "...",
 "pow": {"challenge": "...", "nonce": 812344}}
```

Proof-of-work instead of a CAPTCHA (G8): the page fetches a challenge, finds a nonce
where `sha256(challenge || nonce)` has `POW_DIFFICULTY_BITS` (default 18) leading zero
bits, and submits it. Costs a phone about a second and a flooder a great deal more. No
third-party CAPTCHA service, no tracking, no cost.

A consumer holding a real suspicious pack is the single most valuable signal in the
system, and v1 discarded it entirely (F35). Rate limit, triage, but never drop.

### 10.5 Admin routes

```
GET   /api/v2/admin/batches                 scope batch:read
POST  /api/v2/admin/batches                 scope batch:write
      {"batch_ref","product_name","mfg_date","shelf_life_days","quota",
       "opened_by","countersigned_by"}
POST  /api/v2/admin/batches/<ref>/close     scope batch:write
POST  /api/v2/admin/recall                  scope recall
      {"batch_ref","notice"}                → sets batches.status='recalled',
                                              cascades products.status, re-signs rows
GET   /api/v2/admin/incidents?status=open   scope incident:read
PATCH /api/v2/admin/incidents/<id>          scope incident:write
      {"resolution":"confirmed|false_positive|closed","note":"..."}
GET   /api/v2/admin/reports?triage=new      scope report:read
PATCH /api/v2/admin/reports/<id>            scope report:write
```

**Recall re-signs every affected row.** `status` is inside the row signature, so
changing it without re-signing would make every recalled pack return `RECORD_INVALID`
instead of `RECALLED` — technically safe, but it would mask a real regulatory event
behind a scary generic error. Do the re-sign inside the same transaction.

Clearing a `suspect_duplicate` state is **only** reachable through
`PATCH /api/v2/admin/incidents/<id>` with `resolution: "false_positive"`, by a human,
with a note, audited. There is no automatic recovery path. That stickiness is what
closes G1 — a counterfeiter must not be able to discover which stolen identifiers are
still good by probing the public API.

### 10.6 `GET /.well-known/transparency/latest`

```json
{"as_of_date":"2026-09-11","merkle_root":"<hex>","record_count":18422,
 "audit_head":"<hex>","signature":"<hex>","pubkey":"<hex>",
 "log_url":"https://github.com/<owner>/<repo>/blob/main/log/2026-09-11.json"}
```

---

## 11. Edge — Cloudflare Worker

Free tier: 100,000 requests/day, Workers KV for state. This is decision D1. It is a
second deploy target in JavaScript; keep it small and keep all business logic on the
origin.

### 11.1 What the Worker is for

| Responsibility | Closes |
|---|---|
| Distributed rate limiting in KV — global, not per-process | F16, F21, D21 |
| **Per-tag** rate limiting, not just per-IP | G1, D21 |
| Negative-lookup caching, so enumeration never reaches the origin | F23, D21 |
| Instant page shell while the origin cold-starts | F22 |
| Method / Content-Type / size / depth gates before the origin | D17, D18, D19, D20, B4 |
| Parameter canonicalisation and duplicate rejection | B5, B8, B9 |
| Security headers on the shell | C3, F29 |

### 11.2 Routing

```
<worker>.<subdomain>.workers.dev/c              → serve shell.html immediately
<worker>.<subdomain>.workers.dev/api/v2/verify  → gate, cache, proxy to origin
<worker>.<subdomain>.workers.dev/api/v2/report  → gate, proxy
<worker>.<subdomain>.workers.dev/*              → proxy to origin (enrol, admin)
```

The tag URL host is the **Worker** host. That makes the Worker load-bearing: if it is
removed, tags in the field stop resolving. Mitigations, both required:

1. The origin serves the identical routes, so a DNS/host change is a config edit and
   not a redeployment of tags.
2. `edge/README.md` states the dependency explicitly, and the runbook includes "how to
   fail over to the origin host".

### 11.3 Canonicalisation and rate limiting

```js
// edge/src/canonicalise.js
export function canonicaliseVerify(url) {
  const p = url.searchParams;
  for (const k of ["m", "t"]) {
    if (p.getAll(k).length !== 1) throw new BadRequest("duplicate_parameter"); // B8
  }
  const m = p.get("m").normalize("NFKC").trim().toUpperCase();
  const t = p.get("t").normalize("NFKC").trim().toUpperCase();
  if (m.length > 64 || t.length > 64) throw new BadRequest("parameter_too_long"); // B4
  if (!/^[0-9A-F]{14}X[0-9A-F]{6}$/.test(m.replace("x", "X")))
    throw new BadRequest("malformed_parameters");                                // B3, B5
  if (!/^[0-9A-F]{32}$/.test(t)) throw new BadRequest("malformed_parameters");
  return { m, t };
}
```

The origin re-runs equivalent validation and **never trusts the edge's parse**. Two
independent parsers that must agree is the defence against B9 (edge/origin
differential smuggling); trusting one of them would defeat the purpose.

```js
// edge/src/ratelimit.js — fixed window in KV
// Three composite buckets, all checked:
//   ip:<prefix>      /24 for IPv4, /48 for IPv6  — NOT a single address.
//                    Carrier-grade NAT in India means an entire operator region can
//                    share addresses and a busy pharmacy's Wi-Fi is one IP. Keying on
//                    a single address throttles real consumers before attackers (F21).
//   tag:<index-ish>  hash of the m parameter's UID portion.
//                    A single pack verified 500 times in an hour from 500 addresses is
//                    the signal you actually want, and a per-IP limiter cannot see it.
//   sess:<cookie>    soft throttle for real users — slow down, don't block.
const LIMITS = {
  "ip":   { window: 60, max: 60  },
  "tag":  { window: 3600, max: 30 },
  "sess": { window: 60, max: 30  },
};
```

KV is eventually consistent, so these limits are approximate. That is fine — it is
still far stronger than v1's per-process in-memory counters, which were silently N
times looser than configured. The Postgres limiter in `backend/ratelimit.py` is the
second layer for direct-to-origin traffic.

### 11.4 Cold start and caching

Render free tier sleeps after ~15 minutes idle; the first request then takes 30–50
seconds. A consumer standing at a pharmacy counter will not wait 30 seconds, and
abandonment means the system provides no protection at all. This is a security
property, not a convenience one (F22). Three mitigations together:

1. **The shell renders instantly** from the Worker with a "Checking…" state, so the
   consumer sees something in under 100 ms regardless of origin state.
2. **Negative verdicts are cached at the edge** for `NEG_CACHE_TTL` (default 300 s),
   keyed by `sha256(m||t)`. **Positive verdicts are never cached** — a cached
   `authentic` would defeat the counter check entirely, which is the whole mechanism.
3. **A GitHub Action pings the origin every 10 minutes** (§14.1), which also keeps the
   Supabase project from pausing on idle (F26).

`edge/src/shell.html` is a self-contained document with inlined critical CSS and no
external requests. It fetches the verdict and hands off to the same rendering code as
`frontend/app.js`.

---

## 12. Raspberry Pi enroller

Three deployables, one repo. `pi/` ships to the Pi; nothing in it imports from
`backend/`.

### 12.1 Enrolment sequence

```
 0. Startup: clock check (§12.5), KeyProvider load, outbox drain, batch session open.
 1. Operator confirms batch + product. mfg_date comes from the BATCH, not from typing.
 2. Wait for tag: pn532.read_passive_target()
 3. GET_VERSION → assert vendor 04h, storage 0Fh                    → else REJECT (A12)
 4. READ_SIG → verify_originality(uid, sig)
       FAILED      → REJECT, quarantine, audit, increment rejection metric  (A2, F9a)
       UNAVAILABLE → proceed, record originality_status='unverified'
 5. token = secrets.token_bytes(16)                                  → 32 hex chars
 6. url = build_verify_url(PUBLIC_HOST, token.hex())
    tlv = build_ndef_tlv(url)        ← raises if > 137 bytes
 7. Write TLV from page 04h, one page at a time,
    3 retries per page + ~50 ms settle delay after each success      ← carried from v1
 8. FAST_READ the whole NDEF area and BYTE-COMPARE against tlv       → mismatch: retry
    once, then DISCARD THE TAG. (F10, A13)
 9. Assert the 21 bytes at mirror_position() are the all-zero placeholder.
10. READ_CNT → enrol_counter (a handful of reads from steps 3, 4, 8)
11. Write CFG0 (mirror config) then CFG1 (NFC_CNT_EN=1).             ← MTA enabled here
12. If TAG_LOCK_ENABLED and --i-understand-this-is-permanent:
        apply_lock_sequence()                                         (§6.7)
13. Power-cycle the field. Read the tag once as a phone would.
    Assert the URL now carries a real UID and a counter STRICTLY GREATER than step 10.
    → If not, the mirror is not working. DISCARD THE TAG. Do not ship it.
14. sealed = seal_record({product_id, batch_id, mfg_date, tag_uid}, FIELD_RECIPIENT_PUB)
15. outbox.enqueue(payload, idempotency_key=uuid4())   ← DURABLE, BEFORE any network I/O
16. Print "OK — queued". The drainer handles the rest.
```

**Step 13 is the most important operational step in the whole build.** It is the only
way to know the mirror is actually working *before* the pack ships. A tag that enrols
cleanly but whose mirror never turns on produces `MIRROR_DISABLED` on every consumer
scan — a genuine pack that verifies badly, forever.

**Step 15 before any network call** is the F3 fix. See §12.3.

### 12.2 The QR fallback is removed (F4)

v1 fell back to printing a QR of the same URL when the NDEF write failed. A QR is
static copyable data — a pack shipped with a QR fallback has **none** of the physical
binding the system exists to provide, and it is indistinguishable to the consumer.

v2: **if the tag write fails, discard the tag and use a new one.** If line continuity
genuinely requires a fallback, that pack's record is enrolled with
`binding_class = 'none'`, and verification returns `binding: "none"` with reduced-guarantee
copy on the page. The consumer is told the truth rather than shown a false green.

### 12.3 The durable outbox

```python
# pi/outbox.py
SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT    NOT NULL UNIQUE,
    payload         TEXT    NOT NULL,      -- the exact JSON body to POST
    state           TEXT    NOT NULL DEFAULT 'pending',  -- pending|inflight|acked|failed
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at REAL    NOT NULL DEFAULT 0,
    created_at      REAL    NOT NULL,
    acked_at        REAL
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(state, next_attempt_at);
"""
```

Rules, all of them load-bearing:

- `enqueue()` runs `INSERT` + `COMMIT` **before** `enroller.py` reports success to the
  operator. Use SQLite WAL mode and `PRAGMA synchronous=FULL` — a pack that ships
  while its record is lost to an unflushed page cache is the exact failure being fixed.
- The drainer is a separate thread (or process) that polls `state='pending' AND
  next_attempt_at <= now`, marks `inflight`, POSTs, and on 2xx marks `acked`.
- **Backoff:** 2, 4, 8, 16, 32, 60, 120, 300 s, then every 300 s indefinitely, with
  ±20% jitter. Never give up on a retryable error.
- **Terminal errors** (400/403/409 per §10.2) mark `failed` and raise an operator
  alert. `409 tag_already_enrolled` from a *replayed* idempotency key is a success,
  not a failure — check the idempotency key first.
- **Drain on startup, before accepting new enrolments.** A Pi rebooted mid-run must
  flush its backlog first.
- `enroller.py` displays the outbox depth continuously. Depth above zero for more than
  15 minutes is an alerting signal (§14.5) — it means genuine packs are shipping
  without records.
- Nothing is ever deleted from the outbox. `acked` rows are archived, not dropped —
  they are the reconciliation record.

### 12.4 Reconciliation

`pi/drainer.py --reconcile` walks `acked` rows and confirms each `tag_index` verifies
against the backend. Run it at the end of every batch. This catches the case where a
2xx was received but the row was later lost — rare, but the cost of missing it is
unverifiable packs in circulation.

### 12.5 Clock discipline (F9)

The signature window is ±30 s. Packaging lines are often on isolated networks with no
NTP, and when the clock drifts every write is rejected with 403 — an error that looks
like an authentication failure and will send you debugging the wrong thing.

```python
# pi/clockcheck.py
def assert_clock_sane(backend_url: str, max_drift_s: int = 10) -> None:
    r = requests.get(f"{backend_url}/health", timeout=10)
    server = datetime.fromisoformat(r.json()["server_time"])
    drift = abs((datetime.now(timezone.utc) - server).total_seconds())
    if drift > max_drift_s:
        raise ClockDriftError(
            f"Local clock is {drift:.0f}s from the server. Enrolment is disabled.\n"
            f"Fix: sudo timedatectl set-ntp true && sudo systemctl restart systemd-timesyncd\n"
            f"Then re-run. Do NOT proceed — every write will be rejected."
        )
```

Called at startup and again every 10 minutes during a run. Refuse to enrol on drift,
with that message. A clear "set the clock" instruction now saves an afternoon later.

### 12.6 Batch session — two-person authorisation and quotas

```
$ python enroller.py --batch AMX-2026-09-001
Batch AMX-2026-09-001 — Amoxicillin 500mg
  mfg_date 2026-09-10   shelf_life 730 days   quota 5000   enrolled 0
Opened by: shreya
Countersigned by: ________     ← must differ from opened_by (DB CHECK)
```

The quota is a **database CHECK constraint**, not a Python counter. The 5,001st
enrolment fails at the database, whatever the client believes. This is the cheapest
mitigation for F1 (a stolen Pi signing key): it converts an unlimited compromise into
a bounded one for free. It also closes G5 (an insider pre-enrolling blank tags against
real batch numbers), because enrolments outside an open batch have nowhere to land.

`mfg_date` comes from the batch record, not from an operator typing it per pack (F8).
One typo would otherwise produce a wrong expiry date on a medicine pack, signed and
permanently recorded.

---

## 13. Frontend

Plain HTML/CSS/vanilla JS. No framework, no build step, no npm. The design goal is
**enough transparency to be auditable, not a dashboard**. Every element on the consumer
page must either change what the consumer does or explain what was actually checked.

### 13.1 Pages

| File | Purpose |
|---|---|
| `verify.html` + `app.js` | The `/c` landing page. The only page a consumer ever sees. |
| `report.html` | Consumer report form, reached from any negative verdict. |
| `index.html` | Manual tag-ID entry, for testing without hardware. Clearly labelled as such. |
| `admin.html` + `admin.js` | Operator console: batches, incidents, reports, posture. |
| `sw.js` | Service worker — offline state only. |

### 13.2 The consumer page

Render in three bands, top to bottom:

1. **The verdict**, large, colour-coded, with one concrete action.
2. **The product details**, when there are any.
3. **What was checked** — the `checks` object from the response, as four labelled
   pass/fail rows, plus the binding level in plain words.

Band 3 is the transparency requirement. It is four lines, not a dashboard:

```
Record signature      ✓ checked
Tap counter           ✓ checked  (live value read from the chip)
Recall status         ✓ not recalled
Expiry                ✓ in date
```

When binding is `none`, band 3 says so explicitly: *"This check could not read a live
value from the chip — the result is based on the link only, which is weaker."*

### 13.3 Verdict copy

In a health context, verdict wording is a safety control, not UX polish. v1's
"UNKNOWN TAG" tells a worried patient nothing about what to do (F36). **Every negative
verdict carries a concrete next action.**

| Verdict | Heading | Body | Action |
|---|---|---|---|
| `authentic` | Checks passed | This pack matches the manufacturer's record. | — |
| `expired` | Past its expiry date | Genuine, but expired on {date}. Do not use. | Return to pharmacist |
| `recalled` | Recalled — do not use | {recall notice} | Return to pharmacist · Report |
| `suspect_duplicate` | Do not use | This pack's code has been seen on more than one item. | Report this pack |
| `mirror_disabled` | Cannot fully check | This tag did not return a live value from its chip. | Report · ask pharmacist |
| `record_invalid` | Cannot confirm | We could not confirm this pack's record. Do not use until checked. | Report |
| `unknown` | Not found | Not in our register. It may be fake, or the pack may predate this system. | Do not use without checking with your pharmacist |
| offline | Cannot verify — no connection | We could not reach the verification service. | Try again with a connection |

Three rules for this table:

- **Never the word "counterfeit" or "fake" as a verdict.** Attribution is ambiguous
  (§9.7). "Fake" is a claim the system cannot support and a defamation risk.
- **Never a bare failure.** Every negative state routes to `report.html` or to a human.
- **Localisation and accessibility are in scope:** verdict strings in a `strings.js`
  keyed by language, high contrast, minimum 18px body text. A patient who cannot read
  the verdict is not protected by it.

### 13.4 Admin console

Vanilla JS against the scoped-token admin API. Token pasted into a session-only field —
never stored in `localStorage` (an XSS then yields an admin token).

Four panes:

- **Posture** — the `/health` posture block as a banner. If `tag_locking: disabled`,
  show an amber bar: *"Tags are rewritable — testing configuration."* The operating
  posture must never be something you have to remember.
- **Batches** — open/close, quota used vs. remaining, two-person fields.
- **Incidents** — open divergences, newest first, with kind, observed vs. expected
  counter, and the resolve action. This is the triage queue that makes
  `SUSPECT_DUPLICATE` recoverable by a human and only by a human.
- **Reports** — consumer submissions, triage states.

### 13.5 Web NFC and the service worker

**Web NFC is now a bonus, not the primary path.** The counter arrives in the URL on
iOS and Android alike, which is what closes F31 and F32 — v1's strongest security
property was unavailable to roughly half the market and to every iPhone.

If `NDEFReader` exists, offer an optional "Read the chip directly" button. On success,
re-call verify with `live=1` and the binding becomes `counter+liveread`. On failure or
permission denial, **do not degrade the verdict** — the counter path already ran
(C7). Never block the result behind a permission prompt.

```js
// sw.js — offline state ONLY. Never cache a verdict.
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/")) {
    e.respondWith(fetch(e.request).catch(() =>
      new Response(JSON.stringify({verdict: "offline"}),
                   {status: 503, headers: {"Content-Type": "application/json"}})));
  }
});
```

The service worker caches the shell and static assets only. **It must never cache an
API response.** A cached positive verdict would defeat the counter check permanently
and is exactly attack C5. Scope it narrowly and assert this in a test.

---

## 14. Operations

All free tier. Four GitHub Actions workflows.

### 14.1 `keepwarm.yml` — every 10 minutes

```yaml
on:
  schedule: [{cron: "*/10 * * * *"}]
jobs:
  ping:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsS --max-time 60 "${{ secrets.ORIGIN_URL }}/health" > /dev/null
      - run: curl -fsS --max-time 60 "${{ secrets.WORKER_URL }}/health" > /dev/null
```

Keeps Render's instance warm (F22) and touches Supabase so a free project does not
pause on idle (F26). GitHub's scheduled runners are best-effort and can be late under
load — that is acceptable here; the edge shell covers the gap.

### 14.2 `backup.yml` — nightly

`pg_dump` → encrypt with `age` or `gpg` to an **offline** public key → commit to a
private repo or upload as an artifact. The encryption key is not on any server (F8a).

**Test the restore quarterly.** An untested backup is not a backup. Put it in the
runbook with a date.

Same workflow enforces retention: `DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '90 days'`
and `DELETE FROM idempotency_key WHERE created_at < NOW() - INTERVAL '30 days'` (F30).

### 14.3 `transparency.yml` — daily

This is the answer to "shouldn't this be on a blockchain?", and it is a paper
contribution in its own right.

1. `SELECT id, row_sig FROM products ORDER BY id` → build a Merkle tree over `row_sig`.
2. Read the latest `audit_log.entry_hash` (the chain head).
3. Sign `{as_of_date, merkle_root, record_count, audit_head}` with `TRANSPARENCY_KEY`
   (a GitHub Actions secret — **never** on the runtime backend).
4. Commit `log/<date>.json` to a public repository with a signed commit.
5. `POST` the same object into `transparency_root` so `/.well-known/transparency/latest`
   can serve it.

What this buys, at zero cost: anyone can prove a record existed on a given date via a
Merkle inclusion proof, and you cannot silently rewrite history. No consortium, no
tokens, no per-transaction fee. A ledger is usually proposed to remove the need to
trust a single custodian of the database — this delivers that property directly.

`scripts/verify_transparency.py` is the third-party verifier: given a `tag_index` and
an inclusion proof, it confirms membership under a published root. Ship it, document
it, and reference it in the paper.

### 14.4 `ci.yml` — on push and PR

```
ruff check .
pytest backend/tests/unit backend/tests/integration
pip-audit --strict                  # F2a
pip install --require-hashes -r backend/requirements.txt   # F1a
```

Plus repository settings the operator must apply by hand (§20.4): branch protection on
`main`, required review, **secrets not exposed to pull-request workflows** (F3a),
signed commits, and no auto-deploy from an unreviewed push (F4a). v1 auto-deployed
from `main` on every push, which makes a single bad push a production compromise.

### 14.5 Observability

Structured JSON logs to stdout (Render captures them) with a **secret redaction
filter** in the log formatter — any value matching a known secret, or a key named
`*_KEY`/`*_SECRET`/`DATABASE_URL`, is replaced with `***` before emission (F6a). Add
one test that forces an exception containing `DATABASE_URL` and asserts it is redacted.

`/metrics` exposes counters. Four alert signals, and only four:

| Signal | Why |
|---|---|
| Any `divergence_incident` row inserted | A possible clone is in circulation. **Security alert.** |
| `originality_rejections > 0` on a production batch | Your supplier may have shipped counterfeit silicon. **Security alert.** |
| Outbox depth > 0 for more than 15 minutes | Genuine packs are shipping without records. **This is the 3 a.m. one.** |
| Verify error rate > 1% over 5 minutes | The consumer path is broken. |

Everything else is a dashboard number, not an alert. Four signals that always mean
something beat twenty that mostly do not.

---

## 15. Error handling and internal consistency

The brief asked that the system not be internally broken — properly wired, with real
error management and consistency. This section is the contract that delivers that.
Treat it as binding on every module.

### 15.1 Exception hierarchy

```python
# backend/errors.py
class AppError(Exception):
    status = 500
    code = "internal_error"
    public_message = "Something went wrong. Please try again."
    def __init__(self, detail: str | None = None, **context): ...

class BadRequest(AppError):        status, code = 400, "malformed_request"
class Unauthorized(AppError):      status, code = 401, "unauthorized"
class Forbidden(AppError):         status, code = 403, "forbidden"
class NotFound(AppError):          status, code = 404, "not_found"
class Conflict(AppError):          status, code = 409, "conflict"
class PayloadTooLarge(AppError):   status, code = 413, "payload_too_large"
class UnsupportedMedia(AppError):  status, code = 415, "unsupported_media_type"
class RateLimited(AppError):       status, code = 429, "rate_limited"
class ServiceUnavailable(AppError):status, code = 503, "service_unavailable"

class RecordInvalid(AppError):     ...   # row signature failed — NOT an HTTP error;
                                         # caught by the verify service and turned
                                         # into a verdict, never a 500.
```

### 15.2 The error envelope

```json
{"error": {"code": "malformed_parameters",
           "message": "The verification link is not valid.",
           "request_id": "01J8...",
           "retry_after": null}}
```

Rules, enforced by the global error handler:

- **`message` is consumer-safe and never contains internals.** No stack traces, no SQL,
  no exception `repr`, no file paths (D23). v1 returned `jsonify({"error": str(e)})`
  in a dozen places — that leaks whatever psycopg2 felt like saying.
- **`detail` and full context go to the structured log**, keyed by `request_id`, never
  to the client. The `request_id` is how you correlate a user report to a log line.
- **Any unhandled exception is a 500 with `code: "internal_error"`** and a logged
  traceback. No route may return an ad-hoc error dict.
- **`retry_after` is set on 429 and 503** and mirrored in the `Retry-After` header, so
  the Pi's drainer backs off correctly instead of guessing.

### 15.3 Consistency rules — the invariants an agent must not break

1. **Fail to a safe state.** When uncertain, the verdict is "cannot confirm", never
   `authentic`. Every `except` branch in the verification path must select a negative
   or indeterminate verdict. There must be no code path where an exception results in
   a positive verdict.
2. **Never let an audit failure break a request**, and never let a request failure skip
   an audit write. Audit on every branch, including the early returns.
3. **Every write that touches more than one table is one transaction.** Enrolment
   (product + batch counter + counter state + idempotency) and divergence (incident +
   state + audit) are the two that matter.
4. **One source of truth per fact.** `expiry_date` is derived from `mfg_date` +
   `batch.shelf_life_days` at enrolment and never recomputed at verify. `shelf_life`
   comes from the batch, never from the request. Duplicated derivations drift.
5. **Every comparison of a secret or a token uses `hmac.compare_digest`** (E7).
   Audit every comparison in the codebase once, at the end of Phase 2.
6. **No route constructs SQL by string concatenation.** Parameterised, always.
7. **The Pi and the backend share three canonicalisation rules** — UID normalisation,
   envelope sealing, and the request-signing payload. All three are pinned by vectors
   in `tests/vectors/`, and both implementations are tested against the same file. A
   drift here is invisible until production, so make it a build-time failure.
8. **`RecordInvalid` is a verdict, not a 500.** A tampered row must produce a calm
   negative answer to the consumer, not a server error.
9. **Nothing returns a raw database identifier to a public caller.** `products.id`,
   `nonce`, ciphertext and `enc_dek` never appear in a public response.
10. **The three deployables never import each other.** Duplication between
    `pi/crypto_envelope.py` and `backend/crypto_envelope.py` is intentional; the test
    vectors are what keep them honest.

### 15.4 Degradation matrix

| Failure | Behaviour | Never |
|---|---|---|
| Database unreachable | `503` + `retry_after`; page shows "cannot verify right now" | A verdict |
| `KEK` missing or unwrap fails | Refuse to start, log the variable name | Start with a nil key |
| `TAG_INDEX_KEY` missing | Refuse to start | Fall back to plain SHA-256 |
| Row signature key unavailable at verify | `record_invalid` for every row, `/health` degraded | `authentic` |
| Edge Worker down | Origin serves the same routes directly | Tags stop working |
| KV unavailable | Origin's Postgres limiter takes over | Unlimited requests |
| Originality pubkey absent on the Pi | `originality_status='unverified'`, visible | `'verified'` |
| Outbox disk full | Refuse to enrol, alert the operator loudly | Write a tag with no queued record |
| Counter byte order unset | Refuse to start (both Pi and backend) | Guess |

The last two are the ones that silently destroy data integrity, which is why both are
startup failures rather than runtime warnings.

---

## 16. Attack traceability matrix

The brief was explicit: **do not add code addressing each attack one by one.** The
security must already be in the system. This section exists so that when the attack
suite is written later, every entry can be traced to a mechanism that is already
built — and so that a gap is visible as a gap rather than as a missing test.

**How to read it:** "Mechanism" is *where the defence lives*. If you are about to add
a special case in a route handler for one of these IDs, stop — either the mechanism is
missing from the design (flag it) or you are patching a symptom.

Counts follow the source design document: 86 attacks across classes A–H, where class D
is D1–D16; D17–D24 are listed as additions and are included here.

### 16.1 Class A — Tag and physical layer

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| A1 | Blank-tag link copy | Copied URL carries a frozen counter → not strictly greater | §9.7 step 6 |
| A2 | UID-rewritable magic tag | Magic tags report counter `000000` and fail originality | §6.6, §9.7 |
| A3 | Counter freeze replay | `counter <= max_counter` → `repeat` divergence | §9.7 step 6 |
| A4 | Counter rollback | Same check, `rollback` kind | §9.7 step 6 |
| A5 | Counter fast-forward | Velocity bound from `enrol_counter` + pack age | §9.7 step 7 |
| A6 | Genuine-tag counter exhaustion (DoS) | Detected, flagged, incident raised for human triage | §9.7, §10.5 |
| A7 | Field NDEF rewrite | Static + dynamic lock bytes — **open while `TAG_LOCK_ENABLED=false`** | §6.7 |
| A8 | Config rewrite to disable the counter | `AUTH0=29h` + `CFGLCK` — **open while locking is off** | §6.5, §6.7 |
| A9 | Tag password brute force | 2^32 at ~200/s ≈ 250 days of continuous physical access | §6.5 |
| A10 | Deliberate `AUTHLIM` bricking | `AUTHLIM=0` chosen precisely to prevent this | §6.5 |
| A11 | Tag transplant / refill | **Not closed.** Requires tamper-evident packaging | §2 residual risk 1 |
| A12 | Counterfeit NXP silicon at enrolment | `GET_VERSION` + `READ_SIG` gate | §6.6, §6.8, §12.1 |
| A13 | Tearing during enrolment | Hardware anti-tearing + mandatory read-back byte-compare | §6.8, §12.1 step 8 |
| A14 | Relay (NFCGate-style) | Relay must use a real tag, which advances that tag's real counter → the genuine holder's next scan diverges. Self-limiting and self-reporting | §9.7 |

### 16.2 Class B — NDEF and URL layer

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| B1 | Homograph / look-alike domain | **Weak** — no custom domain (D6). Printed host on pack is the only mitigation | §1.1 D6 |
| B2 | Open redirect abuse | No redirect endpoints exist; assert in tests | §9.4 |
| B3 | URL parameter injection | Strict charset/length parse before any use | §9.6, §11.3 |
| B4 | Oversized parameter | Length cap before regex, at edge and origin | §9.6, §11.3 |
| B5 | Unicode / mixed-case bypass | NFKC-normalise, uppercase, then strict pattern | §9.6, §11.3 |
| B6 | Missing-parameter fallback | `t` mandatory, no UID-only path, fail closed | §9.6 |
| B7 | Placeholder passthrough | Explicit `MIRROR_DISABLED` verdict | §6.3 rule 4, §9.7 step 0 |
| B8 | Parameter pollution | `getlist` + reject duplicates, both layers | §9.6, §11.3 |
| B9 | Fragment / query smuggling | Two independent parsers that must agree; origin never trusts the edge | §11.3 |
| B10 | NDEF record-type confusion | Single URI record, byte-compared at enrolment | §12.1 step 8 |

### 16.3 Class C — Client and browser layer

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| C1 | URL-trust downgrade on iOS | Counter is in the URL itself — works on iOS | §6.2, §13.5 |
| C2 | Screenshot / link sharing | A shared URL's counter is stale → divergence | §9.7 |
| C3 | Clickjacking | `frame-ancestors 'none'` | §9.12 |
| C4 | XSS via product fields | Output encoding + strict CSP, no inline scripts | §9.12, §13 |
| C5 | Service-worker verdict poisoning | SW never caches API responses; narrow scope | §13.5 |
| C6 | Fake verification app | No app exists to impersonate; publish the canonical host | §13.3 |
| C7 | Web NFC permission denial | Verdict never blocked on the permission; binding reports the truth | §13.5 |
| C8 | Browser-extension response tampering | Client is untrusted by definition; server-side incident record is authoritative | §9.7 |
| C9 | Cached-verdict replay | `Cache-Control: no-store` on verdicts | §9.12 |
| C10 | Offline blank-state confusion | Explicit "cannot verify" state | §13.5, §15.4 |

### 16.4 Class D — API and protocol layer

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| D1 | Unsigned enrolment | Signature required before parsing | §9.5 step 4 |
| D2 | Forged signature | Ed25519 verify, fails closed on malformed input | §7.7 |
| D3 | Valid but untrusted key | `device_registry` lookup, status must be `active` | §9.5 step 3 |
| D4 | Signature splicing | Signature covers `sha256(raw body)` + ts + idempotency key | §7.7 |
| D5 | Verbatim replay | Idempotency key replay returns the stored response | §9.5 step 6 |
| D6 | Fresh signature over a used key | Same; `request_hash` must match | §9.5 step 6 |
| D7 | Stale timestamp | Two-sided ±30 s window | §7.7 |
| D8 | Future timestamp | Same check — explicitly tested this time | §7.7 |
| D9 | Idempotency reuse, different body | `409 idempotency_conflict` | §9.5 step 6 |
| D10 | Re-enrolment shadowing | `products.tag_index UNIQUE` | §8.3 |
| D11 | Cross-tag ciphertext substitution | Per-record DEK + per-field AAD | §7.3 |
| D12 | Expiry extension via the database | `expiry_date` inside the row signature | §7.4 |
| D13 | Crypto downgrade via the database | Allow-list + `crypto_version` inside the row signature + DB CHECK | §7.2, §8.1 |
| D14 | Admin key brute force | Signature-verified scoped tokens — no secret to guess | §9.10 |
| D15 | Admin route enumeration | v1 routes return 404; admin paths under one prefix | §9.4 |
| D16 | Legacy key endpoint | `/api/admin/keys/*` **deleted** | §5.1 |
| D17 | HTTP method confusion | Explicit method allow-list, edge + origin | §11.1 |
| D18 | Content-type confusion | Strict `application/json` check → 415 | §9.5 step 1 |
| D19 | JSON depth / billion-laughs | Depth + size limits before parse | §9.1, §11.1 |
| D20 | Slowloris / slow POST | Edge timeouts + gunicorn `--timeout 30` | §9, §11.1 |
| D21 | Verify enumeration | Per-tag edge limits + negative-lookup caching | §11.3 |
| D22 | Timing oracle on registration | Response-time floor | §9.8 |
| D23 | Error-message information leak | Error envelope; details only to logs | §15.2 |
| D24 | Connection-pool exhaustion | Pooled context manager that always returns the connection | §9.3 |

### 16.5 Class E — Cryptographic layer

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| E1 | GCM nonce reuse | Fresh `os.urandom(12)` per encryption, fresh DEK per record | §7.3 |
| E2 | GCM tag truncation | `cryptography` rejects; surfaces as `decrypt_failed` | §7.3 |
| E3 | Bit-flip on stored ciphertext | GCM `InvalidTag` → `RECORD_INVALID` | §9.7 step 4 |
| E4 | Nonce birthday collision | No write-nonce scheme remains; idempotency keys are 128-bit UUIDs | §7.7 |
| E5 | Unsalted hash precomputation | Keyed `tag_index` = HMAC, key backend-only | §7.8 |
| E6 | Length extension on `payload_hash` | `payload_hash` removed; Ed25519 row signature instead | §7.4 |
| E7 | Non-constant-time comparison | `hmac.compare_digest` everywhere; audited once per phase | §15.3 rule 5 |
| E8 | Weak-cipher downgrade | `crypto_paper.py` deleted; allow-list of one | §5.1, §7.2 |
| E9 | HKDF info collision | Fixed domain-separated `info` strings, length-prefixed | §7.3 |
| E10 | Master-secret compromise | **Partial.** Envelope wrapping + key separation. Full host compromise still yields it | §7.6, §2 residual risk 4 |
| E11 | Signature malleability | Ed25519 is not malleable | §7.7 |

### 16.6 Class F — Infrastructure and supply chain

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| F1a | Dependency confusion / typosquat | `pip install --require-hashes`, pinned | §14.4 |
| F2a | Compromised transitive dependency | `pip-audit --strict` in CI, build fails | §14.4 |
| F3a | CI/CD secret exfiltration | Secrets not exposed to PR workflows | §14.4, §20.4 |
| F4a | Auto-deploy from `main` abuse | Branch protection + required review + signed commits | §14.4, §20.4 |
| F5a | Hosting dashboard takeover | **Partial.** Mandatory 2FA, separate accounts per service | §20.4 |
| F6a | Database credential leak in logs | Secret redaction filter in the log formatter + a test | §14.5 |
| F7a | Supabase PostgREST exposure | RLS on **every** table, zero anon policies | §8.2 |
| F8a | Backup exfiltration | Backups encrypted to an offline key | §14.2 |
| F9a | Counterfeit tag supply | Originality gate + rejection-rate alert to procurement | §6.6, §14.5 |
| F10a | Rogue packaging device | **Partial.** Per-batch DB quota bounds the damage; device attestation would close it | §12.6 |

### 16.7 Class G — Business logic and abuse

This is the class v1's suite omitted entirely, and it is where the most damaging
real-world attacks live.

| ID | Attack | Mechanism | Where |
|---|---|---|---|
| G1 | Verification-as-a-service abuse | Per-tag limits **and** sticky `SUSPECT_DUPLICATE` with no automatic recovery | §8.1, §10.5 |
| G2 | Recall evasion | `RECALLED` verdict, status inside the row signature | §10.5, §9.7 step 9 |
| G3 | Expired-stock relabelling | `expiry_date` inside the row signature | §7.4 |
| G4 | Grey-market / parallel import | **Partial.** Coarse-region analytics on counter state | §9.11 |
| G5 | Pre-enrolment harvesting | Batch quotas + two-person authorisation + open-batch requirement | §12.6 |
| G6 | Verdict laundering | **Partial.** Counter divergence still catches the reused identifier | §9.7 |
| G7 | Competitor denial-of-reputation | **Partial.** Human incident review before any public flag | §10.5 |
| G8 | Report-channel abuse | Proof-of-work + rate limits + triage states | §10.4 |
| G9 | Enumeration for market intelligence | **Partial.** Only a verdict is returned; counters are inherently informative | §9.8 |

**G1 is the one to emphasise.** A free, public, unauthenticated verification API is a
gift to a counterfeiter: it lets them test which stolen identifiers are still good
before committing them to production. Making `SUSPECT_DUPLICATE` sticky — once
flagged, always flagged, pending human review — is what removes this. It costs nothing
and it is the single most valuable business-logic control in the redesign.

### 16.8 Class H — Forward-looking and quantum

Out of scope for this build (D4). Recorded so the version fields are not removed as
dead code.

| ID | Attack | Position |
|---|---|---|
| H1 | Shor against Ed25519 | Open. `X-Sig-Alg` and `device_registry.sig_alg` reserved for `ed25519+mldsa65` |
| H2 | Grover against AES-256-GCM | Closed already — 2^128 effective. No change needed |
| H3 | Grover against the tag-hash space | Closed by the 128-bit binding token + keyed index (§7.8) |
| H4 | Harvest-now-decrypt-later on TLS | Partial. Fields are AES-256-GCM ciphertext *inside* TLS, so payloads survive |
| H5 | Quantum attack on the NXP originality signature | Open and unfixable — NXP's key, NXP's curve. Treat L1 as a weak-but-useful filter |
| H6 | Store-and-forge on the transparency log | Open. SLH-DSA would close it; the log is low-volume so this is cheap to add later |

### 16.9 The honest scoreboard

Do not present a v2 column as measured results until the tests have actually run.
Present it as the designed target, then measure, then report what you actually got —
including anything that fails unexpectedly. An unexpected failure you found and
reported is worth more to a reviewer than a clean sweep they suspect was curated.

Known-open in this build, by design or by constraint:

| ID | Why open |
|---|---|
| A11 | Irreducible without tamper-evident packaging |
| A7, A8 | `TAG_LOCK_ENABLED=false` for this phase — closes when the flag flips |
| B1 | No custom domain under the free-only constraint |
| E10, F5a, F10a | Partial — no HSM, no device attestation |
| H1, H5, H6 | Quantum explicitly out of scope |

---

## 17. Test scaffold

Per the brief, the 86 attack tests come later. What is in scope now is the scaffold
they will slot into, plus the tests that prove the system is internally consistent.

### 17.1 Layout

```
backend/tests/
├── conftest.py            live-server fixtures, test device identity, DB helpers
├── vectors/
│   ├── uid.json           UID normalisation cases (Pi ↔ backend)
│   ├── envelope.json      seal/unseal fixed-input vectors
│   ├── mirror.json        m-parameter parse cases, valid and hostile
│   ├── counter.json       byte-order calibration result (§6.4)
│   └── rowsig.json        canonical JSON + signature vector
├── unit/
│   ├── test_verdict_machine.py    ← exhaustive, no DB, no Flask
│   ├── test_mirror_parse.py
│   ├── test_envelope.py
│   ├── test_rowsig.py
│   ├── test_tag_layout.py         ← NDEF TLV + mirror offset arithmetic
│   └── test_errors.py             ← envelope shape, redaction
├── integration/
│   ├── test_enrol_flow.py
│   ├── test_verify_flow.py
│   ├── test_idempotency.py
│   ├── test_batch_quota.py
│   ├── test_recall.py
│   ├── test_audit_chain.py
│   └── test_dead_routes.py        ← asserts v1 routes are 404
└── attacks/
    ├── README.md          ← maps §16 IDs to files; most are stubs for now
    └── conftest.py
```

### 17.2 The tests that must exist before Phase 5

1. **`test_verdict_machine.py`** — the verdict function is pure, so enumerate the state
   space: every combination of placeholder/real mirror × known/unknown tag × token
   match/mismatch × row sig valid/invalid × counter state ok/suspect × counter
   below/equal/above max × within/over velocity bound × status active/recalled ×
   in-date/expired. Assert that **no combination yields `authentic` unless every check
   passed.** This single test is the strongest guarantee in the codebase.
2. **Cross-device vector tests** — `pi/crypto_envelope.py` and
   `backend/crypto_envelope.py` must both satisfy `vectors/envelope.json`; both UID
   normalisers must satisfy `vectors/uid.json`. Run in CI.
3. **`test_audit_chain.py`** — write N entries, delete one directly via SQL, assert the
   verifier reports the break at the right index.
4. **`test_dead_routes.py`** — `/api/products`, `/api/verify/<hash>`,
   `/api/admin/keys/<hash>`, `/test-db`, `/.env` all return 404.
5. **Concurrency test on counter advance** — fire N simultaneous verifies with the same
   counter value; assert exactly one succeeds and the rest produce a divergence.
6. **Redaction test** — force an error containing `DATABASE_URL`; assert `***` in the
   emitted log line.

### 17.3 Rules for the attack tests when they are written

- Each test file is named for its class (`test_class_a_tag.py`) and each test function
  for its ID (`def test_a3_counter_freeze_replay():`).
- Each writes a structured JSONL evidence record — carry over v1's
  `tests/evidence/*.jsonl` + `report.py` approach, it is a genuinely good idea.
- Tests run against a **live server with a known, pinned worker count**. v1's
  rate-limit evaluation is not defensible without this, because per-worker counters
  made the observed limit N times looser than the configured one.
- Attack tests never mutate production data. They run against a separate Supabase
  project, or against a batch reserved for testing.

---

## 18. Build order

Do not build in file order. Each phase ends with a check; do not start the next until
it passes.

| Phase | Work | Done when |
|---|---|---|
| **0 — Ground truth** | Apply §5 deletions. Move the paper cipher to `legacy/`. Generate keys (`scripts/gen_keys.py`). Run `schema/001` + `002`. Calibrate `CNT_BYTE_ORDER` on a scrap tag (§6.4). | A scrap tag has the counter enabled, the mirror live, and the byte order recorded in both `.env` files and `vectors/counter.json` |
| **1 — Tag pipeline** | `pi/tag_layout.py`, `ntag.py`, `tag_config.py`, `originality.py`. | A tag is enrolled, read back byte-identical, power-cycled, and its URL now carries a real UID and an incremented counter. Attempt it with a magic tag and confirm the originality gate rejects it. |
| **2 — Backend core** | `errors.py`, `config.py`, `db.py`, `keys.py`, `crypto_envelope.py`, `crypto_rowsig.py`, `tag_index.py`, `mirror.py`, `services/verification.py`, `services/counter.py`. | `test_verdict_machine.py` passes exhaustively, with no Flask and no DB |
| **3 — Backend routes** | `routes/*`, `services/enrolment.py`, `services/batches.py`, `auth_admin.py`, `audit.py`, `ratelimit.py`. | Enrol → verify → divergence works end to end against a live server |
| **4 — Durability** | `pi/outbox.py`, `drainer.py`, `clockcheck.py`, `batch_session.py`, idempotency. | Enrol 20 tags with the network unplugged; reconnect; all 20 appear exactly once |
| **5 — Edge** | `edge/*`, Worker deploy, KV namespaces, host switch in `PUBLIC_HOST`. | A tag written with the Worker host verifies; rate limits engage globally across two browsers |
| **6 — Consumer** | `frontend/*`, verdict copy, report flow, service worker, offline state. | All eight verdicts render correctly on a real Android phone **and a real iPhone with no app** |
| **7 — Ops** | Four GitHub Actions, transparency log, backup + a tested restore, `/metrics`. | A signed Merkle root is published and `verify_transparency.py` validates it from a clean checkout |
| **8 — Evaluation** | Attack tests per §17.3, with a pinned worker count. | §16.9 scoreboard filled with **measured** results |

**Phase 4 is not optional and is not late.** F3 is the most likely real-world failure
of the system. If you are short of time, ship phases 0–4 and defer 5.

---

## 19. Threat model — the resolved version

v1's threat model granted the adversary the ability to obtain the backend's entire
configuration, including every trusted public key. But that configuration also
contained `AES_MASTER_KEY` and `SHARED_SECRET` — so under its own stated threat model,
the adversary decrypted every record in the database and the confidentiality claim was
void. That is Contradiction 1, and it had to be resolved one way or the other.

**v2 takes the stronger option: keep the broad capability and change the design so the
claim holds.**

**Adversary capabilities assumed:**

| # | Capability | v2 response |
|---|---|---|
| i | Read any tag, unlimited times | MTA — reading advances the real counter |
| ii | Write arbitrary blank or magic tags | Counter freeze / `000000` → divergence |
| iii | Intercept and modify any network traffic | TLS + Ed25519 request signatures |
| iv | Craft arbitrary requests to any endpoint | Signature-before-parse, strict input contracts |
| v | **Read the backend's entire environment** | Operational keys are envelope-wrapped; `KEK` lives elsewhere (§7.6) |
| vi | **Full read/write access to the database** | Row signatures over every security-relevant field; chained audit log; keys not in the DB |
| vii | Physical access to a pack on a shelf | Lock bytes (when enabled); velocity bound; no verdict change from reads alone |
| viii | Steal the Pi and its SD card | Per-batch quota bounds the damage; the Pi cannot decrypt the register |

**Explicitly out of scope:** a full host compromise of the running backend process
(yields the unwrapped keys in memory — no free HSM exists); physical-layer RF
fingerprinting attacks; and a compromised NXP signing key.

**The two claims v2 makes, stated precisely:**

> On commodity non-secure-element NFC hardware, a cloned tag that is actually used in
> circulation will be detected, with a computable and small expected number of consumer
> taps, without any app, on both Android and iOS, at zero additional per-tag cost.

> An adversary with full read/write access to the product register cannot alter any
> security-relevant field — expiry date, recall status, crypto version, binding token —
> without the alteration being detected on the next verification.

**What v2 does not claim:** that cloning is prevented. The chip has no secret key and
can prove nothing cryptographically. Anyone who reads a genuine tag can write the same
data to another tag. What is gained is **detection**, not **prevention** — and the
detection latency is quantifiable, which is what makes it a result rather than a hope.
Moving the claim from "prevention" to "bounded-latency detection" is not a weakening;
it is the only version of the claim the hardware supports.

---

## 20. Manual steps — what the operator does

Everything in this section is done by hand. The agent must not attempt any of it, and
must not commit any resulting secret.

### 20.1 Local environment

```bash
python -m venv venv
source venv/bin/activate                 # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
# On the Pi only:
pip install -r pi/requirements.txt
```

### 20.2 Generate keys

```bash
python backend/scripts/gen_keys.py --out keys.local.json
```

Produces: the device Ed25519 keypair, the X25519 field-recipient pair, the row-signing
pair, the admin-token pair, the transparency pair, plus `TAG_INDEX_KEY`, `IP_HASH_SEED`
and `KEK`.

```bash
python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <FIELD_PRIV_HEX>
python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <ROW_PRIV_HEX>
```

**`keys.local.json` is never committed.** Add it to `.gitignore` before generating it.
Store `KEK`, `ADMIN_TOKEN_KEY` and `TRANSPARENCY_KEY` somewhere with genuinely
different access control from the Render dashboard — a password manager, not a second
environment variable next to the wrapped blobs. If `KEK` sits beside what it wraps,
the envelope has bought nothing, and §19 capability (v) is not actually answered.

### 20.3 Supabase

1. New project → **Session pooler** connection string (not Direct connection — that
   hostname is IPv6-only and will not connect from Render).
2. SQL Editor → paste and run `backend/schema/001_core.sql`, then `002_rls.sql`.
3. Insert the Pi's device row:
   ```sql
   INSERT INTO device_registry (device_id, label, public_key)
   VALUES ('<uuid>', 'pi-line-1', '<ed25519 pubkey hex>');
   ```
4. Confirm RLS: with the project's anon key, a PostgREST call to `/rest/v1/products`
   must return no rows and no error detail.

### 20.4 GitHub repository settings

- Branch protection on `main`: required review, no force-push, signed commits (F4a).
- Actions → disable secret access for `pull_request` workflows (F3a).
- Secrets: `ORIGIN_URL`, `WORKER_URL`, `DATABASE_URL`, `TRANSPARENCY_KEY`,
  `BACKUP_ENCRYPTION_PUBKEY`.
- Turn **off** Render's auto-deploy-on-push; deploy from a tag or a manual trigger.
- 2FA on GitHub, Render, Supabase and Cloudflare, with separate passwords (F5a).

### 20.5 Render

Create from `render.yaml`, then set every variable in §21 in the dashboard. Confirm the
start command shows `--workers 2`. Set the health check path to `/health`.

### 20.6 Cloudflare

```bash
cd edge
npx wrangler kv namespace create RL
npx wrangler kv namespace create NEG
# paste both ids into wrangler.toml
npx wrangler secret put ORIGIN_URL
npx wrangler deploy
```

Note the deployed `*.workers.dev` hostname and put it in `PUBLIC_HOST` on the Pi — this
is the host that gets written into every tag URL, so **fix it before enrolling any tag
you intend to keep**.

### 20.7 Counter byte-order calibration

Run `python pi/enroller.py --calibrate` on a scrap tag and record the result in both
`.env` files as `CNT_BYTE_ORDER`. Both the Pi and the backend refuse to start without
it. See §6.4 for why guessing this silently corrupts every velocity bound.

### 20.8 Before the first real batch

- [ ] A scrap tag survives the full flow and shows an incrementing counter in its URL
- [ ] A magic tag is rejected by the originality gate (or `ORIGINALITY_POLICY` is
      knowingly set to `warn`)
- [ ] 20 enrolments with the network unplugged all arrive exactly once on reconnect
- [ ] An iPhone with no app produces a correct verdict from a tap
- [ ] `/health` posture reads the way you expect it to
- [ ] A backup has been restored into a scratch project at least once
- [ ] `NXP_ORIGINALITY_PUBKEY` is populated, or `originality_status: unverified` is a
      knowingly accepted state

---

## 21. Configuration reference

### 21.1 `backend/.env`

| Variable | Shape | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres` | **Session pooler.** IPv4. |
| `KEK` | 64 hex chars | Supplied at deploy. Not stored beside the wrapped blobs. |
| `FIELD_RECIPIENT_KEY_WRAPPED` | hex | X25519 private, wrapped under `KEK` |
| `FIELD_RECIPIENT_PUB` | 64 hex chars | Also goes in `pi/.env` |
| `ROW_SIGNING_KEY_WRAPPED` | hex | Ed25519 private, wrapped under `KEK` |
| `ROW_SIGNING_PUBKEY` | 64 hex chars | For external row verification |
| `ROW_KEY_VERSION` | integer | Default `1` |
| `TAG_INDEX_KEY` | 64 hex chars | **Backend only.** Never on the Pi. |
| `ADMIN_TOKEN_PUBKEY` | 64 hex chars | Public half only — the private key never reaches runtime |
| `IP_HASH_SEED` | 64 hex chars | Daily-rotating IP pseudonymisation |
| `CNT_BYTE_ORDER` | `msb` \| `lsb` | From §20.7. No default. |
| `PUBLIC_HOST` | hostname | Must equal the host written into tags |
| `ALLOWED_ORIGINS` | comma-separated | Worker origin + Render origin |
| `MAX_TAPS_PER_DAY` | integer | Default `50` |
| `VELOCITY_GRACE` | integer | Default `20` |
| `VERIFY_TIME_FLOOR_MS` | integer | Default `120` |
| `NEG_CACHE_TTL` | seconds | Default `300` |
| `POW_DIFFICULTY_BITS` | integer | Default `18` |
| `DB_POOL_MAX` | integer | Default `6`. With `--workers 2`, total = 12. |
| `AUDIT_RETENTION_DAYS` | integer | Default `90` |

### 21.2 `pi/.env`

| Variable | Shape | Notes |
|---|---|---|
| `KEY_PROVIDER` | `file` \| `atecc608a` | `atecc608a` raises `NotImplementedError` |
| `DEVICE_ID` | uuid | Must match a `device_registry` row |
| `DEVICE_PRIVATE_KEY` | 64 hex chars | `FileKeyProvider` only. Plaintext on the SD card — accepted weakness (F1), bounded by batch quotas. |
| `FIELD_RECIPIENT_PUB` | 64 hex chars | **Public key only.** The Pi cannot decrypt the register. |
| `BACKEND_URL` | origin, no trailing slash | For enrolment POSTs and the clock check |
| `PUBLIC_HOST` | hostname | Written into the tag URL. Usually the Worker host. |
| `CNT_BYTE_ORDER` | `msb` \| `lsb` | Must match the backend |
| `NXP_ORIGINALITY_PUBKEY` | hex | **From NXP AN11350.** Absent → `unverified`, never `verified`. |
| `ORIGINALITY_POLICY` | `reject` \| `warn` | Default `reject` |
| `TAG_LOCK_ENABLED` | `false` | **`false` for this build.** Irreversible when true. |
| `TAG_PWD_MASTER` | 64 hex chars | Only used when locking is enabled |
| `OUTBOX_PATH` | path | Default `./outbox.db`. WAL mode, `synchronous=FULL`. |
| `NDEF_PAGE_WRITE_DELAY` | seconds | Default `0.05` — carried from v1, hardware-derived |
| `NDEF_PAGE_WRITE_RETRIES` | integer | Default `3` — carried from v1 |

### 21.3 `edge/wrangler.toml`

`ORIGIN_URL` (secret), KV bindings `RL` and `NEG`, and the rate-limit constants
from §11.3.

### 21.4 Variables removed from v1

`SHARED_SECRET`, `AES_MASTER_KEY`, `PI_PUBLIC_KEYS`, `ADMIN_API_KEY`,
`FRONTEND_VERIFY_BASE_URL`, `QR_FALLBACK_DIR`. If any of these still appears anywhere
in the codebase after Phase 3, something was missed — grep for them as a check.

---

## 22. Open questions for the operator

Not blockers for the build, but they change the answer to something:

1. **A short custom domain.** The only real mitigation for B1. Under the free-only
   constraint the answer is no, and B1 stays weak — but a `.in` domain costs a few
   hundred rupees a year and would also shorten every tag URL. Worth a decision rather
   than a default.
2. **Test hardware.** Reproducing the magic-tag result needs one genuine NTAG213 and
   one UID-rewritable "magic" NTAG213. That comparison is a directly citable
   experimental result for the paper, not just a test.
3. **Whether the Worker host is permanent.** It is baked into every tag written. A
   later change invalidates every tag already in the field.
4. **Who countersigns batches.** The two-person control is a database constraint; it
   needs a second real person to be meaningful rather than one operator typing two names.

---

*This file describes the system to be built (MTA + CDD on NTAG213, envelope-encrypted
records, signed rows, durable enrolment, edge-mediated verification), not the system as
currently deployed. Build in the order in §18 and run each phase's check before moving
on — the failure modes here are mostly silent, and silent failures found at Phase 8
cost far more than the check that would have caught them at Phase 1.*