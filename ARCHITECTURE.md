# ARCHITECTURE.md — College Asset Register **v3**

**Status:** build specification. **NOT YET IMPLEMENTED.** The repository currently
contains the **v2 medicine build**, which is complete and is what the paper describes.
v2's specification is archived at `docs/archive/ARCHITECTURE_v2_medicine.md` and v1's at
`docs/archive/ARCHITECTURE_v1.md`.

**Audience:** an AI coding agent with repo write access, plus the operators who perform
the manual steps in §20.

**Companion:** `docs/ASSET_MIGRATION_PLAN.md` is the plain-language version of this
document — read it first if you want the *why* without the byte offsets.

---

## Implementation status

Nothing in this document is built. What exists is the v2 medicine system, and the
honest summary of how much of it survives is:

| Layer | v2 state | v3 disposition |
|---|---|---|
| Tag pipeline (`pi/ntag.py`, `tag_layout.py`, `tag_config.py`, `originality.py`) | Code complete, not hardware-tested | **Unchanged.** Not one byte offset moves. |
| MTA / CDD (`services/counter.py`, the counter half of the state machine) | Done | **Unchanged logic**, renamed table, per-category tap rate |
| Request signing, idempotency, device registry | Done | **Unchanged** |
| Field encryption, row signatures, KEK/envelope | Done | **Unchanged mechanism**, different field list, plus row versioning (§7.4) |
| Audit chain + Merkle transparency | Done | **Unchanged** |
| Verdict state machine | Done, 2,304 combinations enumerated | **Same shape and discipline**, new terminal states (§9.4) |
| Database schema | Done | **Replaced** (§8) |
| Backend routes/services | Done | Enrol and verify re-aimed; large new admin surface (§9) |
| Frontend | Done, 4 static panes | **Replaced** by a public scan page + a console (§13) |
| Edge (Cloudflare Worker) | Code complete, not deployed | **Retired** in favour of nginx on the college server (§11) |
| Ops (GitHub Actions) | Written, secrets unset | **Ported** to systemd timers (§14) |

**Three things carried over from v2 are still genuinely unfinished and are still the
operator's to do**, because each needs hardware or credentials this repository must not
contain:

1. **`CNT_BYTE_ORDER` is uncalibrated** (§6.4 of the v2 spec, §20.7 here). Both the Pi
   and the backend refuse to start without it. It is not guessed anywhere.
2. **`NXP_ORIGINALITY_PUBKEY` is empty.** Absent, `originality.py` returns `UNAVAILABLE`
   and records `originality_status='unverified'`. It never reports `verified`.
3. **Every secret in §21 is unset.** `scripts/gen_keys.py` generates them; nothing is
   committed.

---

## 0. How to use this document

**Read §1–§5 before writing any code.** §5 is the change ledger: it says, file by file,
what is deleted, kept, rewritten or created. Do not edit files in the order you
encounter them; follow the build order in §18.

**Rules for the agent, carried over from v2 and still binding:**

1. **Do not invent cryptographic constants.** Two values must come from outside: NXP's
   originality-signature public key and every secret in `.env` (§21). If either is
   missing at runtime, the affected check degrades to an explicit, logged, *visible*
   "unverified" state — never to a silent pass.
2. **Do not write per-attack patches.** Every attack maps to a *mechanism* that already
   exists in the design. If an attack has no mechanism next to it, that is a bug in this
   document — flag it, do not invent a one-off fix in a route handler.
3. **Every route returns the error envelope in §15.2.** No bare `jsonify({"error": str(e)})`.
4. **Nothing in `backend/` may import from `pi/`, and nothing in `pi/` may import from
   `backend/`.** Shared logic is duplicated deliberately (they ship to different
   machines) and pinned by shared test vectors in `tests/vectors/`.
5. **Irreversible tag operations are config-gated and default to off.**
6. **No business logic in route modules.** Routes validate and serialise; services
   decide. The verdict machine stays unit-testable without Flask.

**Two rules that are new in v3:**

7. **The signed row is immutable. Mutable state lives in its own tables.** If you find
   yourself wanting to `UPDATE assets SET condition = …`, you are in the wrong table —
   see §8.3. The only writes to `assets` are an insert, a supersede, and a correction
   that writes a *new signed version* (§9.6).
8. **Every mutation made from the console writes an audit row before the transaction
   commits.** There is no "quick edit" path that skips the chain. A register that cannot
   say who changed a condition from `faulty` to `healthy` is not an audit record, it is
   a spreadsheet.

---

## 1. What changes from v2, and why

v2's structure, in one sentence: **a write-once register of consumable objects, read by
anonymous strangers who ask one question.**

v3's structure, in one sentence: **a long-lived register of durable objects, continuously
maintained by a known staff, read both by anonymous passers-by and by the staff
themselves.**

Four consequences follow, and they are the whole of this document:

| v2 assumption | v3 reality | Where it lands |
|---|---|---|
| A record is written once and never changes | Condition, location and custodian change weekly for ten years | §8.3 — mutable state leaves the signed row |
| A scan asks a question | A scan is *also* an observation: this thing was here, at this time | §8.4 — `asset_sighting`, and stocktake falls out for free |
| The reader is an anonymous member of the public | Most readers are staff who need to *act* on what they see | §9.7, §13 — one login, two surfaces |
| Every object is the same kind of object | A DSO, a laptop and an almirah need different fields | §8.2 — `asset_category.field_spec` |

### 1.1 Decisions taken for this build

| # | Decision | Consequence |
|---|---|---|
| **D1** | **One login, not two.** Anonymous tap for everyone; a single staff login for the console. | A login the public must pass is a login nobody uses, and it would make the NFC tap pointless. There is no "user account" — the public is genuinely anonymous. §9.7 |
| **D2** | **The public tap view is a reduced field set, not the full record.** | Make, model, asset code, department, home location, condition and calibration state are public. Cost, vendor, PO, custodian contact and history are not. §9.3 |
| **D3** | **The signed row is immutable; `asset_profile` and `asset_state` are mutable and audited.** | Preserves row signatures as a real integrity control instead of a decoration. Correcting a signed field is a *supersede*, not an update. §7.4, §8.3, §9.6 |
| **D4** | **Categories are data, not code.** `asset_category.field_spec` drives the Pi's prompts, the console's forms, the table's columns and the API's validation. | A new kind of item needs no migration and no redeploy. §8.2 |
| **D5** | **Two orthogonal state axes: `lifecycle` and `condition`, both separate from `mta_status`.** | One `status` column always ends up meaning five things. And "this tag may be cloned" must never be collapsed with "this instrument is broken". §8.3 |
| **D6** | **Tag locking ON in production (`TAG_LOCK_ENABLED=true`), unlike v2.** | An asset code never changes over the object's life, so there is nothing to rewrite — and a tag that stays rewritable for ten years in a public lab is a standing invitation to attacks A7/A8. Re-tagging uses a **new tag** plus a supersede. §6.3 |
| **D7** | **No edge worker. nginx on the college server.** | One box the college owns. The `rate_limit_bucket` table was already built for the case where the edge is bypassed; it becomes the only layer. `EDGE_EXPECTED=false`. §11 |
| **D8** | **Positive verdicts are never cached, anywhere.** | This is what makes "edit in the console, visible on the next tap" true by construction rather than by a cache-invalidation scheme we would get wrong. §9.9 |
| **D9** | **Optimistic concurrency on every mutable write.** `If-Match` on a version counter; a mismatch is a 409, never a silent last-write-wins. | Two lab staff editing the same asset from two phones is the normal case, not the edge case. §9.5 |
| **D10** | **Saved views are first-class, stored server-side.** | "Very customisable" has to survive the user closing the tab, and a view a HOD builds should be shareable with their department. §13.4 |
| **D11** | **Ed25519 only, with explicit `alg` version fields everywhere.** Carried over from v2 (D4). | ML-DSA can be added later without a schema migration. |
| **D12** | **No build step, no framework, no npm in the frontend.** Carried over. | Strict CSP with no inline scripts is a security control, and it is much easier to keep when there is no bundler inserting things. §13 |

### 1.2 Re-writing a tag: what it does and does not do to MTA

This question comes up immediately, so it gets its own section rather than a footnote.

**The short answer: re-writing the NDEF record does not touch the counter, and does not
affect MTA.** The 24-bit NFC counter lives in its own one-way register in the chip's
configuration area, not in user memory. `WRITE` to pages 04h and upward rewrites the URL
and nothing else. The counter cannot be written, cannot be reset, and cannot be
decreased, by us or by anybody else. Power-cycling does not reset it. Erasing the whole
NDEF area does not reset it. It only ever goes up, once per qualifying read.

**But four things around it do break if you rewrite carelessly, and three of them are
silent.** These are the rules.

**Rule 1 — the mirror position must be re-derived, or the URL is corrupted.**
`CFG0` (page E3h) holds `MIRROR_PAGE` and `MIRROR_BYTE`, which point at the exact byte
where the 21-character placeholder `00000000000000x000000` sits inside the NDEF record.
The chip overwrites those 21 bytes at read time. If the new URL has a *different byte
length* — a different host, a longer path, a different URI-prefix abbreviation — the
placeholder lands somewhere else and the chip then injects the UID and counter into the
middle of the URL. Every subsequent tap opens a broken link. So a rewrite is a rewrite
of **the NDEF record and CFG0 together**, in that order, using
`tag_layout.mirror_position()` recomputed for the new URL. Never one without the other.

**Rule 2 — the binding token must be preserved, or re-enrolled.**
The `t=` parameter is 128 bits of randomness written into the NDEF as ordinary data; the
register stores only its SHA-256. If a rewrite mints a fresh token, the stored hash no
longer matches and **every scan returns `UNREGISTERED`** — not an error, not a warning,
just a silently dead asset. Either write back the identical token, or go through
`POST /api/v3/reenrol`, which supersedes the old row and registers the new token
properly.

**Rule 3 — on re-enrolment, `enrol_counter` must be the chip's *actual current* counter.**
This is the subtle one and it will bite somebody. `/reenrol` resets the high-water mark
and seeds a fresh `asset_state` from the submitted `enrol_counter`. But the physical
counter never reset — it is still at, say, 4,122. If a fresh state is seeded at `0`, then
the velocity bound on the very next tap is

```
B = c₀ + r·d + γ = 0 + 50·1 + 20 = 70
```

and the observed counter is 4,123, which is greater than B. The genuine asset
immediately trips `SUSPECT_DUPLICATE` with a `velocity` divergence, for no reason other
than bad bookkeeping. The enroller already does the right thing — step 12 reads
`READ_CNT` from the chip *after* enabling the counter — and that ordering must survive
into v3 unchanged. **Never seed a counter state from a constant.**

**Rule 4 — if the tag was locked, you cannot rewrite it at all.**
With `CFGLCK = 1` the static and dynamic lock bytes have made the data area permanently
read-only. There is no recovery; the lock bits are one-way. Under D6 this is the
production posture, and it is the reason re-tagging means *a new tag and a supersede*,
not a rewrite. Decide the hostname before locking anything (§20.8).

**And the "or anything else?" list — the other ways MTA can be weakened, each with its
mechanism:**

| Risk | Effect | Mechanism that handles it |
|---|---|---|
| Somebody writes `NFC_CNT_EN = 0` to CFG1 (attack A8) | Counter stops; the mirror emits the all-zero placeholder; every scan returns `MIRROR_DISABLED` | `AUTH0 = E3h` + `CFGLCK = 1` under D6. This is the main argument for locking in a college. |
| Somebody writes `NFC_CNT_PWD_PROT = 1` | Counter mirrors only after a password auth, which a phone browser cannot do | Same. Also explicitly set to 0 in `tag_config.cfg1_bytes()`. |
| A "magic" / UID-rewritable tag whose counter *can* be reset | The whole MTA argument collapses for that tag | The ECC originality gate at enrolment (`originality.py`) refuses non-genuine silicon. This is why `NXP_ORIGINALITY_PUBKEY` being unset is listed as a real gap and not a nicety. |
| The hostname changes | Old tags point at a dead host; new tags have a different URL length (Rule 1) | §20.8 — decide the hostname once, before the first tag. |
| Counter saturation at 2²⁴ = 16,777,215 taps | Counter stops advancing; every subsequent tap looks like a `repeat` | Not reachable. At 60 taps per day that is 766 years. Stated for completeness. |
| The velocity bound loosens as an asset ages | `B = c₀ + r·d + γ` grows without limit, so MTA is weakest on a ten-year-old asset | Accepted and documented as a limitation (§19). Mitigated in practice because a long-lived asset has a long, dense sighting history to compare against. |
| Honest repeat taps — a phone reloading the page, a double-tap at the cold-start timeout | A repeated `(m, t)` pair looks like a `repeat` divergence | The Ephemeral Verification Receipt (§9.4.1), carried over from the paper's design. Same client, same counter, within 5 minutes, is absorbed. |

**So: yes — you can leave tags writable and MTA still works perfectly.** v2 ran that way
on purpose (its D5). The reason v3 flips to locked is not MTA; it is A7/A8 and the fact
that a college asset is in a semi-public room for a decade.

### 1.3 One correction to carry forward

`pi/tag_config.py`'s module docstring says *"AUTH0 = 29h, not 2Bh"* in its prose while
the code correctly uses `AUTH0_PROTECT_CONFIG = 0xE3`. 29h/2Bh are **NTAG213** addresses
left over from the v1 source design doc; on NTAG216 the configuration pages are E3h/E4h,
which is what the constant and the v2 spec's §1.2 both say. The code is right and the
docstring is stale. Fix the docstring as part of Phase A — a wrong address in a comment
next to a correct constant is exactly how the mistake gets re-introduced later.

---

## 2. Scope, constraints, non-goals

**In scope:** three deployables — the Raspberry Pi enroller, the backend API, and the
two frontend surfaces — plus ops automation for a self-hosted college server and a test
scaffold.

**Hard constraints:**

- **NTAG216 only.** NTAG213's configuration pages, lock granularity and memory map are
  all different, and the two are not interchangeable. Stated again because it is the
  single most expensive thing to get wrong.
- **No app.** The public path is the phone's native NFC → browser → URL flow. Web NFC is
  a bonus on Android, never a requirement.
- **One college server.** No managed KMS, no Redis, no queue, no CDN. Postgres,
  gunicorn, nginx, systemd.
- **No frontend build step.** ES modules served as-is, strict CSP, no inline scripts.
- **The Pi may be offline.** Everything it does is durable on disk before any network
  call.

**Non-goals, stated so nobody builds them by accident:**

- **This is not a cryptographic tag-authentication system.** NTAG216 holds no secret and
  can prove nothing. v3 *detects an inconsistency with bounded latency*. Every verdict
  string must respect that.
- **This is not an accounting system.** It records purchase cost and funding source
  because an asset register must, but it is not the college's books, it does not
  reconcile with Tally, and depreciation (if built at all) is a report, not a ledger.
- **This is not an inventory/consumables system.** One row is one durable physical
  object with one tag. Resistors and printer paper do not belong here.
- **No biometrics, no student personal data.** The only people in the database are staff,
  and the only fields are name, employee code, department, email, role.

**Explicit non-goal carried from v2:** the system **never emits the word "counterfeit",
"fake", "stolen" or "theft" as a verdict.** The strongest negative verdict is
`SUSPECT_DUPLICATE`, and it means *"this identity has been seen on more than one object;
a human must look."* Attribution is genuinely ambiguous — an attacker who pre-advances a
clone's counter causes the *genuine* asset to trip the alarm. Accusing a lab assistant
of theft on the strength of a counter is the mistake this design exists to refuse.

---

## 3. System overview

Three lanes. Each is a separate trust domain and they meet only at the database.

### Lane 1 — the tap (public, anonymous, read-only)

```
  NTAG216            phone (no app)         nginx            backend
  ────────           ──────────────         ─────            ───────
  chip rewrites  →   native NFC opens   →   TLS, rate    →   5 evidence checks
  m = UID+counter    https://host/c?        limit,           atomic compare-and-advance
  into the URL       m=…&t=…                static           one uniform verdict
                                                             sighting recorded
                         ↑                                        │
                         └──────── asset passport page ───────────┘
                                   (reduced public field set)
```

### Lane 2 — the console (authenticated staff)

```
  staff phone/laptop     nginx        backend                    Postgres
  ──────────────────     ─────        ───────                    ────────
  login → scoped     →   TLS      →   @require_scope         →   assets        (immutable, signed)
  Ed25519 token                       services decide            asset_profile (mutable, audited)
  held in memory                      every mutation audited     asset_state   (operational + MTA)
  only                                optimistic concurrency     asset_sighting(append-only)
                                                                 audit_log     (hash-chained)
```

### Lane 3 — enrolment (the Pi, once per asset)

```
  chip gate      write NDEF     seal        SQLite      signed POST    backend
  ─────────      ──────────     ────        ──────      ───────────    ───────
  GET_VERSION →  read back   →  AES-GCM  →  outbox   →  Ed25519,    →  one transaction:
  READ_SIG       byte-compare   X25519      (durable    idempotent     signed row + initial
  (ECC)          mirror live    wrap        first)                     counter state + quota
```

And underneath all three, unchanged from v2: a **hash-chained audit log**, a **daily
Merkle root** signed by a CI-only key, and **published roots** that let an auditor verify
the register was not quietly edited — without being given access to the register.

**Where trust sits.** The tag and the phone are untrusted. nginx canonicalises and
rate-limits but decides nothing. The backend is the sole verdict authority. Postgres
holds the register and the mutable state. The transparency pipeline observes and
republishes but never participates in a verdict.

---

## 4. Repository structure

```
major-nfc-v3/
├── ARCHITECTURE.md                this file
├── README.md
├── docs/
│   ├── ASSET_MIGRATION_PLAN.md    the plain-language companion
│   ├── OPERATOR_RUNBOOK.md        rewritten for the college server
│   ├── THREAT_MODEL.md            rewritten for §19
│   ├── ATTACK_MATRIX.md
│   ├── PN532_WRITE_FIX.md         unchanged, hardware note
│   └── archive/
│       ├── ARCHITECTURE_v1.md
│       └── ARCHITECTURE_v2_medicine.md
├── backend/
│   ├── app.py                     factory only, no route logic
│   ├── config.py                  fail-fast config
│   ├── db.py  keys.py  audit.py  metrics.py  ratelimit.py  errors.py
│   ├── logging_setup.py  auth_admin.py
│   ├── crypto_envelope.py  crypto_rowsig.py  crypto_signing.py
│   ├── tag_index.py  mirror.py
│   ├── schema/
│   │   ├── 001_core.sql           assets, categories, lots, locations, people
│   │   ├── 002_rls.sql
│   │   ├── 003_state.sql          profile, state, sightings, saved views
│   │   ├── 004_workflow.sql       tickets, transfers, issues, stocktake
│   │   ├── 005_views.sql          read-only SQL views the console reads
│   │   ├── 006_seed_dev.sql
│   │   └── legacy-medicine/       v2 schema, kept verbatim
│   ├── routes/
│   │   ├── __init__.py  health.py  enrol.py  verify.py  report.py
│   │   ├── auth.py                NEW — login, refresh, whoami
│   │   ├── transparency.py
│   │   └── admin/
│   │       ├── __init__.py  assets.py  categories.py  lots.py
│   │       ├── state.py           the mutation surface
│   │       ├── incidents.py  reports.py  people.py  locations.py
│   │       ├── views.py           saved views
│   │       ├── stocktake.py  tickets.py  transfers.py   (phase F)
│   │       └── exports.py
│   ├── services/
│   │   ├── verification.py        the verdict machine — pure
│   │   ├── counter.py             MTA — unchanged logic
│   │   ├── enrolment.py  lots.py  categories.py
│   │   ├── assets.py              NEW — query, filter, aggregate
│   │   ├── state.py               NEW — the only writer of mutable state
│   │   ├── fieldspec.py           NEW — shared validator (also used by enrol)
│   │   ├── sightings.py  transparency.py
│   │   └── stocktake.py  tickets.py                      (phase F)
│   ├── scripts/                   gen_keys, mint_admin_token, wrap_secret,
│   │                              publish_transparency, verify_transparency,
│   │                              import_register.py  (NEW, CSV onboarding)
│   └── tests/                     unit, integration, attacks, vectors
├── pi/
│   ├── enroller.py                sequence unchanged; prompts are category-driven
│   ├── lot_session.py             was batch_session.py
│   ├── ntag.py  tag_layout.py  tag_config.py  originality.py   UNCHANGED
│   ├── crypto_envelope.py  keyprovider.py  outbox.py  drainer.py  clockcheck.py
│   └── requirements.txt
├── frontend/
│   ├── index.html                 landing: tap instructions, manual lookup, sign in
│   ├── scan.html                  the /c tap landing page — the asset passport
│   ├── report.html                report a fault
│   ├── style.css  manifest.json  sw.js
│   ├── scan.js  index.js  report.js  strings.js
│   └── app/                       the console
│       ├── index.html             shell, hash-routed
│       ├── router.js  api.js  session.js  state.js
│       ├── ui/ table.js  form.js  filter.js  chart.js  toast.js  modal.js
│       └── views/ overview.js  assets.js  asset-detail.js  categories.js
│                  lots.js  incidents.js  people.js  locations.js
│                  stocktake.js  tickets.js  reports.js  posture.js
├── deploy/                        NEW — replaces render.yaml + edge/
│   ├── nginx.conf  gunicorn.service  gunicorn.socket
│   ├── timers/ backup.timer  transparency.timer  retention.timer  alerts.timer
│   └── INSTALL.md
└── legacy/paper_cipher/           untouched
```

**Deleted outright:** `edge/` (D7), `render.yaml` (D7), `.github/workflows/keepwarm.yml`
(a free-tier Render concern that does not exist on a server the college owns).
`.github/workflows/ci.yml` stays — CI still runs the test suite on push.

---

## 5. Change ledger — file by file

### 5.1 Delete

| Path | Why |
|---|---|
| `edge/` | D7. Its three jobs — canonicalisation, rate limiting, negative caching — move to nginx and the existing `rate_limit_bucket` table. |
| `render.yaml` | D7. |
| `.github/workflows/keepwarm.yml` | Keeping a free Render dyno warm is meaningless on a self-hosted box. |
| `backend/schema/00{1,2,3}_*.sql` | Moved to `schema/legacy-medicine/`, not deleted — the paper's claims must stay reproducible. |

### 5.2 Keep, unchanged

`pi/ntag.py`, `pi/tag_layout.py`, `pi/tag_config.py` (bar the docstring fix in §1.3),
`pi/originality.py`, `pi/outbox.py`, `pi/drainer.py`, `pi/clockcheck.py`,
`pi/keyprovider.py`, `backend/crypto_signing.py`, `backend/crypto_rowsig.py`,
`backend/tag_index.py`, `backend/mirror.py`, `backend/audit.py`, `backend/db.py`,
`backend/keys.py`, `backend/errors.py`, `backend/logging_setup.py`,
`backend/metrics.py`, `backend/ratelimit.py`, `backend/services/transparency.py`,
`backend/scripts/*`.

That list is most of the hard parts of the system, and it is the point: **the physical
and cryptographic layers do not know what the object is.**

### 5.3 Rewrite

| Path | Change |
|---|---|
| `backend/schema/*` | §8, entirely new. |
| `backend/services/verification.py` | Same purity, same ordering discipline, new terminal states. §9.4 |
| `backend/services/enrolment.py` | Validates against `field_spec`; derives `warranty_until`, `calibration_due`, `asset_code`; writes `assets` + `asset_profile` + `asset_state` + lot counter in one transaction. |
| `backend/services/counter.py` | Logic identical. Table renamed `tag_counter_state` → `asset_state`; `max_taps_per_day` read per category. |
| `backend/services/batches.py` → `lots.py` | Same functions, procurement fields. |
| `backend/routes/verify.py` | Asset fields; optional location claim; writes a sighting. Response-time floor and uniform shape **retained**. |
| `backend/routes/admin.py` → `routes/admin/` | Split per §4. Same `@require_scope` guard, same audit-on-every-action rule. |
| `backend/auth_admin.py` | Gains a role→scope map and department scoping. Token format and verification untouched. |
| `backend/crypto_envelope.py` (both copies) | `SEALED_FIELDS` becomes `("asset_code","serial_no","commissioned_on","tag_uid")`. Vectors regenerated. |
| `pi/batch_session.py` → `pi/lot_session.py` | Lot metadata, category fetch. |
| `pi/enroller.py` | Steps 0–17 unchanged. Prompt loop generated from `field_spec`. New schema string. |
| `frontend/*` | §13, entirely new. |
| `docs/OPERATOR_RUNBOOK.md`, `docs/THREAT_MODEL.md` | Rewritten for the college deployment. |

### 5.4 The single most important change

**Mutable state leaves the signed row (D3).**

In v2, `products` was written once and the Ed25519 row signature covered the whole
record, so "the row signature verifies" and "nobody has edited this record" were the
same statement. If v3 simply added a `condition` column to that table, every legitimate
condition change would either break the signature or force a re-sign — and a signature
that is routinely re-issued by the application is not an integrity control, it is
ceremony.

So the register splits in three:

- **`assets`** — identity and provenance. Immutable. Signed. Changed only by an insert, a
  supersede, or a **correction that writes a new signed version** (§9.6).
- **`asset_profile`** — descriptive facts a human may legitimately correct later
  (make, model, the `spec` blob, cost, warranty dates). Mutable, versioned, every change
  in the audit chain.
- **`asset_state`** — operational truth (lifecycle, condition, location, custodian) plus
  the MTA high-water mark. Mutable, versioned, audited, and the thing the console edits
  all day.

The row signature now means exactly one thing, cleanly: *this asset's identity and
provenance are as they were at registration.* Everything else is protected by the audit
chain and the transparency log, which is the right tool for a fact that is supposed to
change.

---

## 6. Tag layer

### 6.1 Unchanged from v2

Everything in `docs/archive/ARCHITECTURE_v2_medicine.md` §6.1–§6.8 applies verbatim:
the NTAG216 memory map, the 254/252-byte NDEF ceilings and why the PN532 frame limit is
the binding one, the exact mirror-position computation, the counter byte-order
calibration requirement, the CFG0/CFG1 bit layout, the ECC originality gate, and the raw
command set. **Do not re-derive any of it. Do not "simplify" it.**

The verify URL keeps its shape:

```
https://<host>/c?m=00000000000000x000000&t=<32 hex>
```

`m` is the 21-character placeholder the chip overwrites on every qualifying read
(14 hex of UID, the chip's automatic `x` separator, 6 hex of counter); `t` is the
per-tag 128-bit binding token, written as ordinary data.

### 6.2 Re-writing an enrolled tag

The four rules are in §1.2 and are normative. Operationally there are exactly three
sanctioned procedures, and anything else is a bug:

**(a) Same asset, same tag, cosmetic NDEF change** — only possible while `CFGLCK = 0`.
Rewrite the NDEF *and* CFG0 together with a recomputed mirror position, preserve the
token byte-for-byte, read back and byte-compare, power-cycle, confirm the mirror is
live. The register is not touched; the counter keeps its history. Use
`enroller.py --rewrite --tag-index <…>`, which refuses unless the token read back
matches the stored hash.

**(b) Same asset, new tag** (the old tag was damaged, or tags are locked) — write a new
tag with a fresh token, then `POST /api/v3/reenrol` with a mandatory reason. The old
`assets` row is superseded and kept as evidence; its `asset_state` is deleted and a new
one seeded **from the chip's actual counter** (§1.2 Rule 3). The `asset_code` stays the
same — it belongs to the object, not to the tag.

**(c) New asset** — ordinary enrolment.

There is deliberately **no** implicit supersede. A tag that is already enrolled and
shows up at `/enrol` again is a `409`, never a quiet overwrite. Carried from v2's D10
and non-negotiable.

### 6.3 Locking posture (D6)

v2 shipped with `TAG_LOCK_ENABLED=false` because tags had to stay rewritable through
testing. v3 flips the default for production, and the reasoning is worth writing down
because it is the opposite conclusion from the same mechanism:

| | v2 (medicine) | v3 (college) |
|---|---|---|
| How long the tag is in the field | Weeks to months | Ten-plus years |
| Who can physically reach it | A patient, briefly | Anyone who walks into the lab, repeatedly, for years |
| Does the identifier ever need to change? | No | No — `asset_code` belongs to the object |
| Cost of a bricked tag | A discarded pack | Re-tag one asset and supersede |
| Attacks A7 (rewrite URL) / A8 (kill counter) | Accepted, documented as open | **Closed** |

So: `TAG_LOCK_ENABLED=true`, `AUTH0 = E3h`, `CFGLCK = 1`, diversified PWD/PACK per tag
from `TAG_PWD_MASTER`. `AUTHLIM` stays at `000b` — the v2 reasoning is unchanged and
still right: `AUTHLIM = 7` would stop password brute-forcing but would let anyone with
physical access permanently brick a genuine asset by deliberately failing eight
authentications, turning a security control into a denial-of-service weapon against the
college's own equipment.

`apply_lock_sequence()` still refuses to run without **both** `TAG_LOCK_ENABLED=true`
and the operator passing `--i-understand-this-is-permanent`, and still runs only after
the NDEF read-back byte-compare has passed. Keep both gates.

**Pilot exception:** run the first lab with locking **off** so mistakes are recoverable,
then switch on for the rollout. `/health` reports the posture in amber when locking is
off, exactly as it does today, so nobody can forget which mode a tag was written in.

---

## 7. Cryptographic design

### 7.1 Key separation

Unchanged from v2 except for the two new rows at the bottom.

| Key | Alg | Held by | Protects |
|---|---|---|---|
| Device signing | Ed25519 | Pi only | Enrolment authenticity |
| Field recipient | X25519 | Backend, wrapped | Field secrecy |
| Row signing | Ed25519 | Backend, wrapped | Row integrity |
| Tag index | HMAC-SHA256 | Backend only | Enumeration resistance |
| Admin token | Ed25519 | Offline / CI | Admin tokens |
| Transparency | Ed25519 | CI secret only | Signed Merkle roots |
| KEK | AES-256 | Separate access control | Unwraps the wrapped keys |
| **Session signing** | **Ed25519** | **Backend, wrapped** | **Login-minted tokens (§9.7) — the same format the offline script mints, so there is one verifier, not two** |
| **Password hashing** | **Argon2id** | **n/a (per-row salt)** | **Staff passwords, when LDAP is not available** |

On a single college server the KEK no longer sits with a different provider than the
keys it unwraps. That is a genuine weakening and §19 says so. Mitigate with: KEK in a
root-only file loaded via systemd `LoadCredential`, the wrapped keys in the application
`.env`, different file ownership, and the KEK **not** included in the nightly backup.

### 7.2 One crypto version

`aes_gcm_v2` remains the single accepted value. Anything else is a hard reject, never a
fallback — enforced in three independent places (a DB `CHECK`, the enrolment validator,
and the verdict machine). Carried from v2 and unchanged.

### 7.3 Field encryption — what is sealed and what is not

The envelope mechanism is identical: a random DEK per record, AES-256-GCM per field with
the field name as AAD, the DEK wrapped to the backend's X25519 public key, `epk||nonce||
wrapped` hex in `enc_dek`. What changes is the field list and, more importantly, the
**policy** about what deserves sealing.

```python
SEALED_FIELDS = ("asset_code", "serial_no", "commissioned_on", "tag_uid")
```

**Why only these four.** In v2 everything interesting was sealed because the register
was write-once and nothing queried it. In v3 the console must filter by department, group
by condition, sort by cost and count by category — and you cannot do
`WHERE location = 'EXTC-LAB-3'` against AES-GCM ciphertext. Sealing the operational
columns would mean decrypting the entire table on every page of every list. That is not
a security control, it is an outage.

So the rule is stated explicitly, and it is a *design decision with a cost*:

> **Seal the identity. Leave the operations in clear. Sign both.**
>
> The sealed four are the facts that bind this record to this physical object and this
> serial number. The unsealed rest is operational metadata whose confidentiality the
> college does not actually require — it is printed on a sticker on the side of the
> instrument — but whose **integrity** it very much does. Integrity comes from the row
> signature and the audit chain, not from encryption.

`tag_uid` in particular stays sealed, because the `tag_index = HMAC(TAG_INDEX_KEY, uid)`
construction only resists enumeration if the raw UID is not sitting in a column next to
it.

### 7.4 Row integrity — Ed25519, now versioned

v2 signed a canonical view of the immutable fields. v3 does the same, with one addition:
the signable view includes a `row_version` integer, and a correction to a signed field
writes a **new row at `row_version + 1`** rather than updating in place.

```python
SIGNABLE_FIELDS = (
    "tag_index", "binding_token_hash", "asset_code", "category_code",
    "asset_code_ct", "serial_no_ct", "commissioned_on_ct", "tag_uid_ct", "enc_dek",
    "commissioned_on", "lot_ref", "enrol_counter", "device_id",
    "originality_status", "binding_class", "crypto_version",
    "enrolled_at", "row_version", "row_key_version",
)
```

Canonicalisation is unchanged: sorted keys, no whitespace, UTF-8, dates as ISO strings.
Verification happens on every scan of a registered asset, and a failure is
`RECORD_INVALID` — never a downgrade to a weaker positive verdict.

The uniqueness constraint changes shape to support versioning. v2 freed a `tag_index` by
rewriting it to the string `superseded:{id}:{tag_index}`, which worked but made the
column mean two different things. v3 uses a partial unique index instead:

```sql
CREATE UNIQUE INDEX assets_tag_index_live
    ON assets(tag_index) WHERE superseded_at IS NULL;
```

Cleaner, and it keeps the historical rows queryable by their real `tag_index`.

### 7.5 `KeyProvider`, request signing, the keyed tag index

Unchanged from v2 §7.5, §7.7, §7.8. `FileKeyProvider` ships; `Atecc608aKeyProvider` is a
stub behind the same interface; no call site touches raw key bytes. Request signatures
are Ed25519 over
`alg || "\n" || timestamp || "\n" || idempotency_key || "\n" || sha256(raw_body)`,
verified **before the body is parsed**. `tag_index = HMAC-SHA256(TAG_INDEX_KEY, uid)`,
with the 128-bit binding token mandatory.

---

## 8. Database schema

Five files, idempotent, safe to re-run. The medicine schema moves to
`schema/legacy-medicine/` untouched.

### 8.1 `001_core.sql` — identity, categories, procurement, places, people

```sql
-- ------------------------------------------------------------- devices ---
-- Unchanged from v2.
CREATE TABLE IF NOT EXISTS device_registry (
    device_id   UUID PRIMARY KEY,
    label       TEXT NOT NULL,
    public_key  TEXT NOT NULL,                       -- Ed25519, 64 hex
    sig_alg     TEXT NOT NULL DEFAULT 'ed25519',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ,
    CONSTRAINT device_status_valid CHECK (status IN ('active','revoked')),
    CONSTRAINT device_sig_alg_valid CHECK (sig_alg IN ('ed25519'))
);

-- ---------------------------------------------------------- categories ---
-- D4: categories are DATA. Adding a kind of item is a form, not a migration.
CREATE TABLE IF NOT EXISTS asset_category (
    code                  TEXT PRIMARY KEY,          -- 'DSO', 'LAPTOP'
    name                  TEXT NOT NULL,
    parent_code           TEXT REFERENCES asset_category(code),
    id_prefix             TEXT NOT NULL,             -- mints asset_code
    field_spec            JSONB NOT NULL DEFAULT '[]'::jsonb,
    calibration_required  BOOLEAN NOT NULL DEFAULT FALSE,
    calibration_months    INTEGER,
    default_taps_per_day  INTEGER,                   -- overrides MAX_TAPS_PER_DAY
    depreciation_pct_year NUMERIC(5,2),
    icon                  TEXT,
    status                TEXT NOT NULL DEFAULT 'active',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            TEXT,
    CONSTRAINT category_status_valid CHECK (status IN ('active','archived')),
    CONSTRAINT category_field_spec_is_array CHECK (jsonb_typeof(field_spec) = 'array'),
    CONSTRAINT category_calibration_coherent
        CHECK (NOT calibration_required OR calibration_months IS NOT NULL),
    CONSTRAINT category_taps_sane
        CHECK (default_taps_per_day IS NULL OR default_taps_per_day BETWEEN 1 AND 5000),
    CONSTRAINT category_not_own_parent CHECK (parent_code IS DISTINCT FROM code)
);

-- --------------------------------------------------------- procurement ---
CREATE TABLE IF NOT EXISTS procurement_lot (
    lot_ref          TEXT PRIMARY KEY,               -- 'EXTC/PO/2026-27/014'
    description      TEXT NOT NULL,
    vendor           TEXT NOT NULL,
    po_number        TEXT,
    invoice_number   TEXT,
    invoice_date     DATE,
    received_on      DATE NOT NULL,
    warranty_months  INTEGER NOT NULL,
    quota            INTEGER NOT NULL,
    enrolled_count   INTEGER NOT NULL DEFAULT 0,
    total_value      NUMERIC(14,2),
    funding_source   TEXT,
    dept             TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open',
    opened_by        TEXT NOT NULL,
    countersigned_by TEXT NOT NULL,
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at        TIMESTAMPTZ,
    recall_notice    TEXT,
    recalled_at      TIMESTAMPTZ,
    CONSTRAINT lot_status_valid CHECK (status IN ('open','closed','recalled','withdrawn')),
    CONSTRAINT lot_quota_positive CHECK (quota > 0),
    CONSTRAINT lot_quota_not_exceeded CHECK (enrolled_count <= quota),
    CONSTRAINT lot_two_person CHECK (countersigned_by <> opened_by),
    CONSTRAINT lot_warranty_sane CHECK (warranty_months BETWEEN 0 AND 240)
);
```

`lot_quota_not_exceeded` and `lot_two_person` are DB-level invariants **on purpose**,
carried straight from v2. In medicine they bounded the damage from a stolen Pi key; here
they stop somebody tagging twelve oscilloscopes against a purchase order for ten. The
quota *is* the reconciliation between the invoice and the shelf, and an application-level
count is a race while a `CHECK` is not.

```sql
-- ------------------------------------------------------------- places ---
CREATE TABLE IF NOT EXISTS location (
    id        BIGSERIAL PRIMARY KEY,
    parent_id BIGINT REFERENCES location(id),
    kind      TEXT NOT NULL,                 -- campus|building|floor|room|bench|store
    code      TEXT NOT NULL UNIQUE,          -- 'EXTC-LAB-3'
    name      TEXT NOT NULL,
    dept      TEXT,
    lat       NUMERIC(9,6),
    lon       NUMERIC(9,6),
    status    TEXT NOT NULL DEFAULT 'active',
    CONSTRAINT location_kind_valid
        CHECK (kind IN ('campus','building','floor','room','bench','store')),
    CONSTRAINT location_status_valid CHECK (status IN ('active','archived')),
    CONSTRAINT location_not_own_parent CHECK (parent_id IS DISTINCT FROM id)
);

-- ------------------------------------------------------------ people ----
CREATE TABLE IF NOT EXISTS person (
    id            BIGSERIAL PRIMARY KEY,
    emp_code      TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    email         TEXT,
    dept          TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer',
    password_hash TEXT,                      -- Argon2id; NULL when LDAP-backed
    auth_source   TEXT NOT NULL DEFAULT 'local',  -- local | ldap
    status        TEXT NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT person_role_valid CHECK (role IN
        ('viewer','lab_staff','custodian','dept_admin','admin','auditor')),
    CONSTRAINT person_status_valid CHECK (status IN ('active','suspended')),
    CONSTRAINT person_auth_source_valid CHECK (auth_source IN ('local','ldap')),
    CONSTRAINT person_local_has_hash
        CHECK (auth_source <> 'local' OR password_hash IS NOT NULL)
);

-- ------------------------------------------------------------ assets ----
-- IMMUTABLE AND SIGNED. The only writes are an insert, a supersede, and a
-- correction that inserts row_version + 1. There is no UPDATE path that
-- changes a signed field. See §5.4 and §9.6.
CREATE TABLE IF NOT EXISTS assets (
    id                 BIGSERIAL PRIMARY KEY,
    tag_index          TEXT NOT NULL,                  -- HMAC(TAG_INDEX_KEY, uid)
    binding_token_hash TEXT NOT NULL,
    asset_code         TEXT NOT NULL,                  -- 'EXTC/DSO/2026/0042'
    category_code      TEXT NOT NULL REFERENCES asset_category(code),

    asset_code_ct      TEXT NOT NULL,
    serial_no_ct       TEXT NOT NULL,
    commissioned_on_ct TEXT NOT NULL,
    tag_uid_ct         TEXT NOT NULL,
    enc_dek            TEXT NOT NULL,

    commissioned_on    DATE NOT NULL,                  -- the "start date"
    lot_ref            TEXT NOT NULL REFERENCES procurement_lot(lot_ref),
    dept               TEXT NOT NULL,

    enrol_counter      INTEGER NOT NULL,
    device_id          UUID NOT NULL REFERENCES device_registry(device_id),
    originality_status TEXT NOT NULL DEFAULT 'unverified',
    binding_class      TEXT NOT NULL DEFAULT 'counter',
    crypto_version     TEXT NOT NULL DEFAULT 'aes_gcm_v2',
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    row_version        INTEGER NOT NULL DEFAULT 1,
    supersedes         BIGINT REFERENCES assets(id),
    superseded_at      TIMESTAMPTZ,
    supersede_reason   TEXT,

    row_sig            TEXT NOT NULL,
    row_sig_alg        TEXT NOT NULL DEFAULT 'ed25519',
    row_key_version    INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT assets_crypto_version_valid CHECK (crypto_version = 'aes_gcm_v2'),
    CONSTRAINT assets_originality_valid
        CHECK (originality_status IN ('verified','unverified','failed')),
    CONSTRAINT assets_binding_class_valid CHECK (binding_class IN ('counter','none')),
    CONSTRAINT assets_enrol_counter_sane CHECK (enrol_counter BETWEEN 0 AND 16777215),
    CONSTRAINT assets_supersede_has_reason
        CHECK (superseded_at IS NULL OR supersede_reason IS NOT NULL)
);

-- §7.4: exactly one live row per tag, history kept queryable by its real index.
CREATE UNIQUE INDEX IF NOT EXISTS assets_tag_index_live
    ON assets(tag_index) WHERE superseded_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS assets_asset_code_live
    ON assets(asset_code) WHERE superseded_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_lot      ON assets(lot_ref);
CREATE INDEX IF NOT EXISTS idx_assets_category ON assets(category_code);
CREATE INDEX IF NOT EXISTS idx_assets_dept     ON assets(dept);
```

### 8.2 `field_spec` — the flexibility contract

`asset_category.field_spec` is a JSON array of field descriptors. It is validated by
`services/fieldspec.py`, which is used in **three** places — category save, enrolment,
and profile edit — so the rules cannot drift between them.

```json
[
  {"key":"make",         "label":"Make",             "type":"text",   "required":true,  "max":80},
  {"key":"model",        "label":"Model",            "type":"text",   "required":true,  "max":80},
  {"key":"bandwidth_mhz","label":"Bandwidth (MHz)",  "type":"number", "min":1, "max":100000},
  {"key":"channels",     "label":"Channels",         "type":"select", "options":["2","4"]},
  {"key":"has_probe",    "label":"Probes supplied",  "type":"bool"},
  {"key":"purchased_on", "label":"Purchased on",     "type":"date"},
  {"key":"remarks",      "label":"Remarks",          "type":"longtext","max":2000}
]
```

**The rules, enforced by the validator:**

- `type` is one of `text | longtext | number | bool | date | select | multiselect`. No
  other type exists, ever. In particular there is no `html`, no `url` that renders, and
  no `json`.
- `key` matches `^[a-z][a-z0-9_]{0,39}$` and must be unique within the category.
- `select`/`multiselect` require a non-empty `options` array of ≤ 50 plain strings.
- Every value is bounded: `text` ≤ 200 chars (or `max`, whichever is smaller),
  `longtext` ≤ 4000, `number` is a finite JSON number within `min`/`max`,
  `date` is a valid ISO date.
- A category may define at most **40** fields; the whole `spec` object stored on an asset
  may not exceed **8 KB** serialised.
- **No field in `field_spec` may be security-relevant.** It is descriptive metadata. The
  validator rejects the reserved keys `tag_index`, `asset_code`, `serial_no`,
  `row_sig`, `status`, `lifecycle`, `condition`, `role`, `scopes`, `dept`.
- Removing a field from a category does **not** delete data already stored under that
  key. It is hidden from forms and tables and remains in the audit history. Deleting
  recorded facts because a form changed is data loss dressed up as a schema change.

### 8.3 `003_state.sql` — the mutable halves

```sql
-- Descriptive facts a human may legitimately correct. Mutable, versioned, audited.
CREATE TABLE IF NOT EXISTS asset_profile (
    asset_id        BIGINT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    make            TEXT,
    model           TEXT,
    spec            JSONB NOT NULL DEFAULT '{}'::jsonb,   -- validated vs field_spec
    purchase_cost   NUMERIC(12,2),
    funding_source  TEXT,
    warranty_until  DATE,
    amc_vendor      TEXT,
    amc_until       DATE,
    calibration_due DATE,
    calibration_cert TEXT,
    home_location_id BIGINT REFERENCES location(id),
    parent_asset_id BIGINT REFERENCES assets(id),         -- a PC's monitor, etc.
    version         INTEGER NOT NULL DEFAULT 1,           -- D9 optimistic concurrency
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT,
    CONSTRAINT profile_spec_is_object CHECK (jsonb_typeof(spec) = 'object'),
    CONSTRAINT profile_cost_sane CHECK (purchase_cost IS NULL OR purchase_cost >= 0),
    CONSTRAINT profile_not_own_parent CHECK (parent_asset_id IS DISTINCT FROM asset_id)
);
CREATE INDEX IF NOT EXISTS idx_profile_spec ON asset_profile USING GIN (spec);

-- Operational truth + the MTA high-water mark. The table the console edits all day.
CREATE TABLE IF NOT EXISTS asset_state (
    tag_index           TEXT PRIMARY KEY,
    asset_id            BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- MTA. Logic identical to v2's tag_counter_state.
    max_counter         INTEGER NOT NULL,
    observation_count   INTEGER NOT NULL DEFAULT 0,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mta_status          TEXT NOT NULL DEFAULT 'ok',

    -- the asset's own, human-managed state (D5: two orthogonal axes)
    lifecycle           TEXT NOT NULL DEFAULT 'in_store',
    condition           TEXT NOT NULL DEFAULT 'healthy',
    current_location_id BIGINT REFERENCES location(id),
    custodian_id        BIGINT REFERENCES person(id),
    issued_to_id        BIGINT REFERENCES person(id),
    issued_until        DATE,
    last_verified_at    TIMESTAMPTZ,
    last_lat            NUMERIC(9,6),
    last_lon            NUMERIC(9,6),
    geo_accuracy_m      INTEGER,
    notes               TEXT,

    version             INTEGER NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by          TEXT,

    CONSTRAINT state_mta_valid
        CHECK (mta_status IN ('ok','suspect_duplicate','frozen')),
    CONSTRAINT state_lifecycle_valid CHECK (lifecycle IN
        ('in_store','in_service','under_repair','issued_out','retired','lost','disposed')),
    CONSTRAINT state_condition_valid CHECK (condition IN
        ('healthy','minor_issue','faulty','unserviceable')),
    CONSTRAINT state_max_counter_sane CHECK (max_counter BETWEEN 0 AND 16777215),
    CONSTRAINT state_issued_coherent
        CHECK (lifecycle <> 'issued_out' OR issued_to_id IS NOT NULL),
    CONSTRAINT state_notes_bounded CHECK (notes IS NULL OR length(notes) <= 4000)
);
CREATE INDEX IF NOT EXISTS idx_state_lifecycle ON asset_state(lifecycle);
CREATE INDEX IF NOT EXISTS idx_state_condition ON asset_state(condition);
CREATE INDEX IF NOT EXISTS idx_state_location  ON asset_state(current_location_id);
CREATE INDEX IF NOT EXISTS idx_state_custodian ON asset_state(custodian_id);
CREATE INDEX IF NOT EXISTS idx_state_mta       ON asset_state(mta_status)
    WHERE mta_status <> 'ok';
CREATE INDEX IF NOT EXISTS idx_state_last_seen ON asset_state(last_seen_at);
```

**`mta_status` keeps its own name and its own column deliberately.** "This tag may be
cloned" and "this instrument is broken" are unrelated facts about different things — one
is about the label, one is about the object. Collapsing them into a single `status` is
the single most tempting and most damaging simplification available in this schema, and
it is forbidden.

**`suspect_duplicate` is still STICKY.** There is no path from `suspect_duplicate` back
to `ok` except an explicit, audited admin action through the incident queue (§9.8). A
counterfeiter — or a staff member covering a swap — must not be able to probe which
identifiers are still good by waiting for a flag to clear.

```sql
-- Every scan is an observation. Append-only. This is what makes stocktake free.
CREATE TABLE IF NOT EXISTS asset_sighting (
    id           BIGSERIAL PRIMARY KEY,
    tag_index    TEXT NOT NULL,
    asset_id     BIGINT REFERENCES assets(id),
    counter      INTEGER NOT NULL,
    verdict      TEXT NOT NULL,
    binding      TEXT NOT NULL,
    location_id  BIGINT REFERENCES location(id),   -- CLAIMED by the scanner
    lat          NUMERIC(9,6),
    lon          NUMERIC(9,6),
    accuracy_m   INTEGER,
    scanned_by   TEXT NOT NULL DEFAULT 'public',
    session_ref  TEXT,                              -- a stocktake run
    source_ip_hash TEXT,
    user_agent_class TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sighting_tag  ON asset_sighting(tag_index, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sighting_when ON asset_sighting(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sighting_run  ON asset_sighting(session_ref)
    WHERE session_ref IS NOT NULL;

-- D10: "very customisable" has to survive closing the tab.
CREATE TABLE IF NOT EXISTS saved_view (
    id          BIGSERIAL PRIMARY KEY,
    owner_id    BIGINT NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT 'private',   -- private | dept | global
    definition  JSONB NOT NULL,                    -- {filters, columns, sort, group}
    pinned      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT view_scope_valid CHECK (scope IN ('private','dept','global')),
    CONSTRAINT view_name_bounded CHECK (length(name) BETWEEN 1 AND 60),
    UNIQUE (owner_id, name)
);
```

Unchanged from v2 and carried over verbatim into `001`/`003`: `divergence_incident`,
`idempotency_key`, `audit_log`, `transparency_root`, `rate_limit_bucket`, and
`consumer_report` (renamed `fault_report`, same shape plus an `asset_id`).

### 8.4 `005_views.sql` — what the console actually reads

The console never joins six tables in JavaScript. One SQL view does it once:

```sql
CREATE OR REPLACE VIEW asset_overview AS
SELECT a.id, a.asset_code, a.category_code, c.name AS category_name,
       a.dept, a.commissioned_on, a.lot_ref, a.enrolled_at,
       a.originality_status, a.row_version,
       p.make, p.model, p.spec, p.purchase_cost, p.funding_source,
       p.warranty_until, p.amc_until, p.calibration_due,
       s.lifecycle, s.condition, s.mta_status,
       s.last_seen_at, s.last_verified_at, s.observation_count,
       s.version AS state_version, p.version AS profile_version,
       l.code AS location_code, l.name AS location_name,
       cu.name AS custodian_name, cu.emp_code AS custodian_code,
       (p.warranty_until IS NOT NULL AND p.warranty_until < CURRENT_DATE)
           AS warranty_expired,
       (p.calibration_due IS NOT NULL AND p.calibration_due < CURRENT_DATE)
           AS calibration_overdue,
       (s.last_seen_at < NOW() - INTERVAL '365 days') AS stale
  FROM assets a
  JOIN asset_category c  ON c.code = a.category_code
  LEFT JOIN asset_profile p ON p.asset_id = a.id
  LEFT JOIN asset_state   s ON s.asset_id = a.id
  LEFT JOIN location      l ON l.id = s.current_location_id
  LEFT JOIN person       cu ON cu.id = s.custodian_id
 WHERE a.superseded_at IS NULL;
```

`warranty_expired`, `calibration_overdue` and `stale` are **computed in the view, never
stored**. A stored "is expired" boolean is a fact with a clock in it, and it goes stale
the moment nobody runs the job that updates it. Carried from v2's §15.3 rule 4: one
source of truth per fact.

### 8.5 `002_rls.sql`

Same policy as v2 — RLS enabled with **zero policies** on every table, plus explicit
revokes for `anon` and `authenticated` if those roles exist. On a self-hosted Postgres
there is no PostgREST to leak through, so this is now belt-and-braces rather than
load-bearing. **Keep it anyway.** It costs nothing, and the deployment may move.

### 8.6 Invariants the application must not duplicate in Python

| Invariant | Enforced by |
|---|---|
| One live row per tag | `assets_tag_index_live` partial unique index |
| One live row per asset code | `assets_asset_code_live` |
| Lot quota never exceeded | `lot_quota_not_exceeded` CHECK |
| Two different people open a lot | `lot_two_person` CHECK |
| Only known lifecycle / condition / role values | CHECK constraints |
| An issued asset has somebody to chase | `state_issued_coherent` CHECK |
| A superseded row says why | `assets_supersede_has_reason` CHECK |
| Counter within 24 bits | `state_max_counter_sane`, `assets_enrol_counter_sane` |

Python may produce a *better error message* for any of these. Python may not be the
thing that enforces them.

---

## 9. Backend

### 9.1 Route inventory

API version moves to `/api/v3`. Every v2 route stays dead and returns the error
envelope, as `tests/integration/test_dead_routes.py` asserts.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness + posture |
| GET | `/metrics` | token | Counters |
| GET | `/c` | none | The tap landing page (static) |
| **GET** | **`/api/v3/verify`** | **none** | **The public verdict. Lane 1.** |
| POST | `/api/v3/report` | none or token | Report a fault |
| POST | `/api/v3/enrol` | device sig | Register an asset. Lane 3. |
| POST | `/api/v3/reenrol` | device sig + `asset:write` | Supersede onto a new tag |
| **POST** | **`/api/v3/auth/login`** | **none** | **Mint a scoped token. §9.7** |
| POST | `/api/v3/auth/logout` | token | Revoke the presented `jti` |
| GET | `/api/v3/auth/whoami` | token | Subject, role, scopes, dept |
| GET | `/api/v3/assets` | `asset:read` | Search, filter, sort, paginate |
| GET | `/api/v3/assets/<id>` | `asset:read` | Full record + profile + state |
| GET | `/api/v3/assets/<id>/history` | `asset:read` | Sightings + audit timeline |
| POST | `/api/v3/assets/<id>/correct` | `admin` | New signed row version. §9.6 |
| **PATCH** | **`/api/v3/assets/<id>/state`** | **`state:write`** | **Lifecycle, condition, location, custodian. §9.5** |
| **PATCH** | **`/api/v3/assets/<id>/profile`** | **`asset:write`** | **Make, model, spec, costs, dates** |
| POST | `/api/v3/assets/bulk/state` | `state:write` | Same change across ≤ 200 assets |
| GET/POST/PATCH | `/api/v3/categories[/<code>]` | `category:*` | D4 |
| GET/POST/PATCH | `/api/v3/lots[/<ref>]` | `lot:*` | Procurement |
| GET/POST/PATCH | `/api/v3/locations[/<id>]` | `location:*` | Place tree |
| GET/POST/PATCH | `/api/v3/people[/<id>]` | `people:*` | Staff and roles |
| GET/POST/DELETE | `/api/v3/views[/<id>]` | `asset:read` | Saved views. D10 |
| GET/PATCH | `/api/v3/incidents[/<id>]` | `incident:*` | MTA triage |
| GET/PATCH | `/api/v3/reports[/<id>]` | `report:*` | Fault triage |
| GET | `/api/v3/stats/<name>` | `asset:read` | Overview tiles and charts |
| GET | `/api/v3/export/assets.csv` | `asset:read` | Current view as CSV |
| GET | `/api/v3/reconcile` | `lot:read` | Drainer end-of-run check |
| GET | `/.well-known/transparency/latest` | none | Signed Merkle root |

Phase F adds `/api/v3/tickets`, `/transfers`, `/issues`, `/stocktake`.

### 9.2 `POST /api/v3/enrol`

Steps 1–6 (transport gates, device lookup, signature over the **raw body before any
parsing**, timestamp window, idempotency) are unchanged from v2 and stay in
`routes/enrol.py`. Steps 7–16 are in `services/enrolment.py`. Three things change.

**The request body:**

```json
{
  "schema": "colasset.enrol.v1",
  "crypto_version": "aes_gcm_v2",
  "lot_ref": "EXTC/PO/2026-27/014",
  "category_code": "DSO",
  "binding_token_hash": "<sha256 hex of the 32-hex token>",
  "enrol_counter": 4,
  "originality_status": "verified",
  "binding_class": "counter",
  "tag_version": "0004040201001303",
  "spec": {"make": "Tektronix", "model": "TBS1052C", "bandwidth_mhz": 50, "channels": "2"},
  "sealed": {
    "enc_dek": "<hex>",
    "asset_code":      {"n": "...", "c": "..."},
    "serial_no":       {"n": "...", "c": "..."},
    "commissioned_on": {"n": "...", "c": "..."},
    "tag_uid":         {"n": "...", "c": "..."}
  }
}
```

**What the client still does not send, and therefore cannot get wrong** — carried
straight from v2's F8 reasoning, which was about a wrong expiry date on a medicine pack
and is about a wrong warranty date here:

- `tag_index` — derived from the decrypted UID.
- `warranty_until` — derived as `lot.received_on + lot.warranty_months`.
- `calibration_due` — derived as `commissioned_on + category.calibration_months`, or
  `NULL` if the category does not require calibration.
- `dept` — taken from the lot.
- The initial `lifecycle` (`in_store`) and `condition` (`healthy`).

**`spec` is validated against `category.field_spec`** by `services/fieldspec.py` — the
same validator the console uses — and rejected with `invalid_spec` naming the offending
key. The Pi fetches `field_spec` when the lot session opens, so it can validate locally
too and fail at the bench instead of at the drainer.

**One transaction, as before:** insert `assets`, insert `asset_profile`, insert
`asset_state` with `max_counter = enrol_counter`, increment `lot.enrolled_count`, write
the idempotency record. An insert that succeeded while the quota increment failed would
let the quota drift, and the quota is a real control.

### 9.3 `GET /api/v3/verify` — the public lane

Query: `m` (the mirror value), `t` (the binding token), optional `live=1`, optional
`loc=<location code>`, optional `lat`/`lon`/`acc`.

**What is kept from v2, and must not be "cleaned up":**

- **Duplicate parameters are rejected outright.** `mirror.single_param()` exists because
  Flask's `args.get` silently takes the first value while a front layer may take the
  last, and that difference is exactly what parameter pollution relies on.
- **There is no 404 on this route.** An unregistered tag is `200` with
  `{"verdict":"unregistered"}`. Status codes must not become a second, unnormalised
  oracle alongside the body.
- **Uniform response shape and size class** for every verdict. `asset` is always present
  as a key and is `null` for negative verdicts.
- **The response-time floor** (`VERIFY_TIME_FLOOR_MS`, default 120 ms, measured across
  the whole handler). An `unregistered` returns after one indexed lookup; a `verified`
  does a lookup plus an X25519 unwrap plus four GCM decryptions. The difference is
  measurable and leaks registration status even with identical bodies.
- **`Cache-Control: no-store`** on every response. See §9.9 — this is what makes D8 true.
- **`live=1` is a claim**, never a verdict change. It can only upgrade the reported
  *binding label* to `counter+liveread`. A lying client gains nothing.

**What is new:**

- **The location claim is recorded, never trusted.** `loc`, `lat`, `lon` go into
  `asset_sighting` and, for an authenticated scanner, into `asset_state.last_lat/lon`.
  They do not enter the verdict machine. The same rule as `live=1`, for the same reason:
  it is a claim by an untrusted client. The trustworthy location signal is a
  *logged-in* scanner's selected `location_id`, and even that is a human assertion — the
  system's job is to flag the mismatch between claimed and expected, not to resolve it.
- **Every scan writes a sighting**, including anonymous ones and including negative
  verdicts. That is the stocktake dataset and the "last seen" column.
- **Two response tiers (D2).** Anonymous callers get the reduced field set; a caller
  presenting a valid token with `asset:read` gets the full one. **Both tiers return the
  same JSON keys**, with the restricted fields as `null` for anonymous callers, so the
  anti-oracle property survives the addition.

**Public tier:** verdict, binding, checks, asset code, category, make, model,
department, home location name, condition, lifecycle, calibration state, warranty state
(boolean only), incident reference if any, and the report link.

**Authenticated tier adds:** purchase cost, funding source, vendor, lot, PO, invoice,
custodian name and contact, current location, full `spec`, sighting history, open
tickets, and the action affordances.

### 9.4 The verdict state machine

`services/verification.py` keeps every property that made it testable: a **pure
function** over `(mirror, token, row, profile, state, lot, now, flags)` returning a
`Decision`. No Flask, no database, no clock of its own. The caller does the two
cryptographic comparisons (`token_matches`, `row_sig_valid`) and passes them in, so the
module stays free of key material.

The order is not arbitrary — each step assumes the previous one passed.

```
 0. placeholder mirror                      -> MIRROR_DISABLED      binding none
 1. tag_index = HMAC(TAG_INDEX_KEY, uid)    (caller)
 2. no live row                             -> UNREGISTERED
 3. binding token mismatch                  -> UNREGISTERED   (same answer as 2,
                                                deliberately — an attacker who guessed
                                                a UID but not the 128-bit token must
                                                learn nothing from the difference)
 4. crypto_version wrong OR row sig invalid -> RECORD_INVALID
 5. mta_status sticky-flagged               -> SUSPECT_DUPLICATE
 6. counter <= max_counter                  -> SUSPECT_DUPLICATE  (repeat | rollback)
 7. counter > velocity bound B              -> SUSPECT_DUPLICATE  (velocity)
 8. advance state (atomic, caller does it)
 9. lifecycle disposed / retired            -> DISPOSED
 9a. lot recalled, or lifecycle condemned    -> CONDEMNED
 9b. lifecycle lost                          -> REPORTED_LOST
10. condition faulty/unserviceable,
    or lifecycle under_repair                -> NEEDS_ATTENTION
10a. calibration_due < today                 -> CALIBRATION_OVERDUE
11.                                          -> VERIFIED
```

```
B = c₀ + r·d + γ        c₀ = enrol_counter
                        r  = category.default_taps_per_day  ?? MAX_TAPS_PER_DAY (50)
                        d  = max(age in days, 1)
                        γ  = VELOCITY_GRACE (20)
```

**The ten terminal states.** `VERIFIED`, `CALIBRATION_OVERDUE`, `NEEDS_ATTENTION`,
`CONDEMNED`, `DISPOSED`, `REPORTED_LOST`, `SUSPECT_DUPLICATE`, `MIRROR_DISABLED`,
`RECORD_INVALID`, `UNREGISTERED`.

**Why `EXPIRED` splits.** A medicine pack past its expiry is unusable; that is one fact
with one clock. An asset has three independent clocks and none of them makes it
unusable:

- **Calibration overdue** is a real amber verdict. The instrument works; its readings
  are not trustworthy for accredited work. This matters for lab accreditation and is the
  one clock a scanning student should see.
- **Warranty expired** is **not a verdict at all** — it is a boolean on the response,
  rendered as an informational line. Out-of-warranty equipment is the normal state of
  most of a college's inventory, and an amber screen on every tap would train everybody
  to ignore amber.
- **Condition** becomes `NEEDS_ATTENTION`, which is about the object rather than a date.

**The property the exhaustive test asserts is unchanged**, and it is the only one that
matters:

> **No combination of inputs yields `VERIFIED` unless every check passed.**

`tests/unit/test_verdict_machine.py` is **regenerated, not hand-edited**: it enumerates
the cross-product of mirror states × token match × row-sig validity × mta_status ×
counter relations × lifecycle × condition × calibration × lot status. With the v3 state
space that is roughly 11,000 combinations rather than v2's 2,304. It still runs in
seconds because the function is pure.

#### 9.4.1 Ephemeral Verification Receipt

Carried over from the paper's design and now more necessary, because an asset is
deliberately re-tapped. On a successful scan the server issues a short-lived HTTP-only
receipt

```
R = HMAC-SHA256(K_rcpt, tag_index || counter || client_nonce || τ)      τ ≤ 300 s
```

A valid receipt lets the **same client** reload the **same counter** without raising a
`repeat` divergence. A different device, or a request without the receipt, is subject to
duplicate detection as normal. **The receipt is continuity support, not an
authentication factor**, and it can never upgrade a verdict — it can only suppress a
false `repeat` from the same client inside five minutes.

### 9.5 `services/state.py` — the only writer of mutable state

This is the module behind "edit it from the dashboard", and it is deliberately narrow.

**There is no generic update endpoint.** `PATCH /assets/<id>/state` accepts a fixed set
of named transitions, each with its own validation, its own required scope, and its own
audit event type:

| Transition | Scope | Required with it |
|---|---|---|
| `set_condition` | `state:write` | `condition`, and a `note` when moving to `faulty`/`unserviceable` |
| `set_lifecycle` | `state:write` | `lifecycle`; `in_service` requires a location; `disposed` requires `admin` and a disposal reference |
| `set_location` | `state:write` | `location_id` |
| `assign_custodian` | `custodian:write` | `custodian_id` |
| `issue` / `return` | `custodian:write` | `issued_to_id`, `issued_until` |
| `record_calibration` | `state:write` | `calibrated_on`, certificate reference; recomputes `calibration_due` |
| `set_notes` | `state:write` | `notes` |

A generic "set any column" endpoint would make the audit log useless (`UPDATE asset_state
SET …` tells you nothing about intent) and would make authorisation impossible to reason
about. Named transitions are more code and they are worth it.

**Every call, without exception:**

1. Loads the row `FOR UPDATE`.
2. **Checks optimistic concurrency (D9).** The client sends `If-Match: <version>`; a
   mismatch is `409 version_conflict` carrying the current state so the UI can show
   "somebody else changed this — here is what it says now". Never last-write-wins. Two
   lab staff editing from two phones is the normal case.
3. Validates the transition (`disposed` → `in_service` is rejected; a disposal is
   reversed by an admin correction with a reason, not by a dropdown).
4. Applies it, bumps `version`, sets `updated_by` from the token subject.
5. **Writes an audit row inside the same transaction**, with `before` and `after`, the
   subject, and the token's `jti`.

**`mta_status` is not in that table of transitions and never will be.** The only way out
of `suspect_duplicate` is resolving the incident as `false_positive` through
`PATCH /api/v3/incidents/<id>`, by an admin, with a note of at least four characters,
audited. That is `G1` and it is the same rule v2 had.

**Bulk edits** (`POST /assets/bulk/state`) take at most 200 ids, apply the identical
named transition to each, and write **one audit row per asset** — not one for the batch.
An audit entry that says "200 assets changed" is not an audit entry.

### 9.6 Corrections to signed fields

Somebody will eventually type a serial number wrong. The signed row cannot be updated,
so:

`POST /api/v3/assets/<id>/correct` — `admin` scope, mandatory reason of ≥ 8 characters —
inserts a **new** `assets` row with `row_version + 1`, `supersedes = <old id>`, a freshly
sealed envelope and a fresh signature; stamps `superseded_at` and `supersede_reason` on
the old row; re-points `asset_profile` and `asset_state` at the new row id **without
touching the counter state**; and writes an audit entry carrying both ids and the reason.

The old row is archived, never deleted. **It is evidence, and a register that forgets is
not a register.** The transparency log already published its hash; making it vanish
would be exactly the thing the log exists to detect.

### 9.7 Authentication — one login (D1)

**There is no public user account.** The public taps a tag and reads a page. The only
login is for college staff.

The token format is **unchanged** from v2 — a compact Ed25519-signed envelope with
`sub`, `scopes`, `dept`, `iat`, `exp`, `jti`, max lifetime 12 hours. What is new is a
second way to *obtain* one, so that twenty lab staff are not pasting offline-minted
tokens:

```
POST /api/v3/auth/login     { emp_code, password }       -> { token, expires_at, profile }
```

- Authenticates against `person.password_hash` (**Argon2id**, per-row salt), or binds to
  the college LDAP/AD when `AUTH_SOURCE=ldap`. **LDAP is the better answer** — no
  password store of our own, no reset flow to build, accounts die when staff leave — and
  it should be asked for early (§22).
- On success the server mints **the identical token the offline script mints**, signed
  with the session key, with scopes derived from `person.role`. One format, one verifier,
  one code path.
- Rate limited at 5 attempts per minute per IP **and** per `emp_code`; ten consecutive
  failures set `locked_until = NOW() + 15 minutes`. The response is identical for
  "unknown user" and "wrong password" — a login form must not be a staff directory.
- `scripts/mint_admin_token.py` **stays**, as the break-glass path for when the database
  or LDAP is down. It is how the first admin account is created.
- **The token is held in a JS variable for the life of the tab and is never written to
  `localStorage`.** Unchanged from v2 and non-negotiable: an XSS anywhere on this origin
  would otherwise yield a token that can dispose of assets. 12 hours is short enough
  that re-entering it costs nothing. A `logout` revokes the `jti` server-side.

**Roles → scopes:**

| Role | Scopes | In words |
|---|---|---|
| `viewer` | `asset:read` (own dept) | Look at their department's register |
| `lab_staff` | `+ state:write` (own dept), `report:write` | Record condition, location and faults while standing in the lab |
| `custodian` | `+ custodian:write`, `report:read`, `asset:write` (own dept) | Everything for the assets they answer for |
| `dept_admin` | `+ lot:*`, `category:*`, `location:*`, `asset:write`, `stocktake:*` (own dept) | Register assets, define categories, run stocktakes |
| `admin` | all scopes, all departments, `incident:write`, `asset:correct` | Including the only path out of `suspect_duplicate` |
| `auditor` | `asset:read`, `report:read`, `incident:read`, `stocktake:read` — **all departments, no writes** | Read everything, change nothing |

**Department scoping is enforced in the service layer, not the UI.** Every query in
`services/assets.py` takes the caller's `dept` and `scopes`; a `viewer` from EXTC
requesting an asset from Mechanical gets `404 not_found`, not `403` — a `403` would
confirm the asset exists.

### 9.8 Incidents, reports, audit

**Incidents** are unchanged in mechanism and in tone. The MTA triage queue, resolutions
`confirmed | false_positive | closed`, a mandatory note of ≥ 4 characters, and
`false_positive` as the only path that clears a sticky flag. The console copy must keep
saying what v2's said: *a divergence means a tag's counter did not increase the way it
should have; that is evidence of a duplicate, it is not proof of which object is the
copy, and it is not an accusation against whoever last handled it.*

**Fault reports** replace consumer reports. The proof-of-work gate stays for anonymous
submissions (it is what stops a bored student filing four hundred of them) and is
skipped for authenticated ones.

**The audit log** is unchanged: hash-chained, `prev_hash`/`entry_hash`, one row per
event, no raw IPs (`HMAC(IP_HASH_KEY_today, ip)`), no raw user agents (a class string
like `android-chrome`). New event types: `state_change`, `profile_change`,
`asset_correct`, `category_change`, `login`, `login_failed`, `bulk_state_change`,
`stocktake_open`, `stocktake_close`.

Retention changes. v2 deleted audit rows after 90 days under DPDP. **An asset register
must keep its history for the life of the asset**, so: sighting and audit rows that
carry personal data (`source_ip_hash`, `user_agent_class`, anonymous scanner fields) are
scrubbed after 90 days; the *event* rows themselves are kept indefinitely with those
columns nulled. The hash chain is computed over the immutable fields, so scrubbing does
not break verification — **this must be true by construction, and
`tests/integration/test_audit_chain.py` must assert it after a simulated scrub.**

### 9.9 Liveness — why an edit shows up on the next tap (D8)

This is the "it should update globally" requirement, and the design answer is that there
is nothing to invalidate.

1. `GET /api/v3/verify` reads `asset_state` and `asset_profile` **on every request**.
   There is no application-level cache of asset data. Postgres is on the same box; the
   query is two indexed joins.
2. Every verify response carries `Cache-Control: no-store`, and nginx is configured to
   **never** cache `/api/v3/verify` regardless of what the response says.
3. The negative-lookup cache that the Cloudflare Worker provided is gone with the Worker
   (D7). If it is ever reintroduced it may cache **only** `UNREGISTERED`, never a
   positive verdict, and must be purged on enrolment — a cached positive verdict outlives
   the counter check and is attack C5.
4. The service worker provides an **offline state only**. It must never cache an API
   response. This is already asserted in `sw.js` and must stay.

So: a custodian marks a DSO `faulty` on their phone at 11:04; a student taps that DSO at
11:04:30 and the page says *Needs attention*. No cache invalidation, no pub/sub, no
websocket — just the absence of a cache.

**Inside the console**, where the user expects to see their own change immediately:
a successful mutation returns the **full updated record**, and the view re-renders from
the response rather than from local optimistic state. The assets table re-fetches on
focus and every 60 seconds while visible. Newly enrolled assets appear within one
drainer cycle, and the posture bar shows the Pi's queue depth so an operator can tell
"still draining" from "failed" (§12.3).

Server-Sent Events are the nicer version of the console refresh and are a Phase H item.
Polling is honest, trivial, and enough for a few dozen concurrent staff.

### 9.10 Privacy

Unchanged from v2 and extended to the new tables: no raw IP addresses anywhere, no raw
user-agent strings, `source_ip_hash` never returned by any API (it exists for same-day
correlation inside the database, not for a human to look at). New in v3: the only
personal data is staff contact details, there is no student data, and
`asset_sighting.scanned_by` is `'public'` unless the scanner was logged in and acting in
that capacity.

### 9.11 Security headers and CORS

Unchanged, with **one deliberate relaxation**:

```
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self';
frame-ancestors 'none'
```

`frame-ancestors 'none'` closes clickjacking. No inline scripts anywhere — that is what
makes XSS via a hostile make/model/notes string unexploitable even if output encoding
were missed, and with user-editable `spec` and `notes` fields v3 has **more** hostile-
string surface than v2 did, not less.

**The relaxation:** v2 sent `Permissions-Policy: geolocation=(), camera=(), microphone=()`,
which blocks geolocation outright. For geotagging to work at all this must become
`geolocation=(self)` — **on the scan page and the console only**, not on the API
responses, and camera/microphone stay denied. If geotagging is dropped from scope, revert
it; do not leave a permission enabled that nothing uses.

---

## 10. API contracts

### 10.1 `GET /api/v3/verify`

```
GET /api/v3/verify?m=04A1B2C3D4E5F6x0010A7&t=<32 hex>&live=1&loc=EXTC-LAB-3
```

```json
{
  "verdict": "verified",
  "binding": "counter",
  "checks": {"record":"pass","counter":"pass","lifecycle":"pass","calibration":"pass"},
  "asset": {
    "asset_code": "EXTC/DSO/2026/0042",
    "category": "DSO",
    "category_name": "Digital Storage Oscilloscope",
    "make": "Tektronix",
    "model": "TBS1052C",
    "dept": "EXTC",
    "home_location": "EXTC Lab 3",
    "lifecycle": "in_service",
    "condition": "healthy",
    "commissioned_on": "2026-08-12",
    "calibration_due": "2027-08-12",
    "warranty_expired": false,
    "custodian_name": null,
    "purchase_cost": null,
    "spec": null
  },
  "incident": null,
  "notice": null,
  "verified_at": "2026-10-25T11:04:31.882Z"
}
```

`custodian_name`, `purchase_cost` and `spec` are `null` here because the caller is
anonymous (D2). With a token carrying `asset:read` they are populated. **The key set is
identical either way** — that is the anti-oracle property, and it is also what lets the
scan page be one file instead of two.

`checks` always has exactly four keys with values `pass | fail | not_checked`. The
fourth key changes name from v2's `expiry` to `calibration`, and `recall` becomes
`lifecycle`.

### 10.2 `PATCH /api/v3/assets/<id>/state`

```http
PATCH /api/v3/assets/42/state
Authorization: Bearer <token>
If-Match: 7
Content-Type: application/json

{"transition": "set_condition", "condition": "faulty",
 "note": "Channel 2 dead, confirmed with a known-good probe"}
```

`200` returns the full updated record (§9.9) with `version: 8`.
`409 version_conflict` returns the current record so the UI can show the conflict.
`422 invalid_transition` when the move is not allowed from the current state.

### 10.3 `GET /api/v3/assets`

```
?q=tektronix              full-text over asset_code, make, model, serial-hash match
&category=DSO&dept=EXTC
&condition=faulty,minor_issue             comma = OR within a field
&lifecycle=in_service
&location=EXTC-LAB-3                      includes descendants of the location
&calibration=overdue                      overdue | due_60 | ok
&warranty=expired
&seen_before=2026-01-01                   "not seen since"
&spec.channels=4                          any field_spec key, exact match
&sort=-last_seen_at&page=1&per_page=50
&columns=asset_code,make,model,condition,location_code
```

Filters across different fields are ANDed; values within one field are ORed. Every
filter maps to an indexed column or a GIN-indexed `spec` key. `per_page` is capped at
200. The response carries `{items, total, page, per_page, facets}`, where `facets` are
the counts per value for the filterable fields — that is what lets the console show
"Faulty (12)" next to each filter without a second round trip.

### 10.4 Error envelope

Unchanged from v2. One shape on the wire, always:

```json
{"error": {"code": "version_conflict",
           "message": "Somebody else changed this record.",
           "request_id": "01JB7…"}}
```

`detail` and context go to the **log**, never to the client. No route may return an
ad-hoc error dict; every error leaves through the registered handlers in `app.py`.

---

## 11. Edge → nginx

The Cloudflare Worker is retired (D7). Its three jobs move:

| Worker job | Replacement |
|---|---|
| TLS, instant page shell | nginx serves `frontend/` directly; the origin already served `/c` itself so that removing the edge is a config change, not a redeployment of every tag |
| Request canonicalisation | `backend/mirror.py` already canonicalises and rejects duplicate parameters. The Worker was a second line, not the only one. |
| Distributed rate limiting | The `rate_limit_bucket` table, which v2 built **precisely for the case where the edge is bypassed**, plus nginx `limit_req` as a cheap first filter |
| Negative-lookup caching | Dropped. On one box with a local Postgres, an indexed miss is not worth a cache — and a cache here is how a positive verdict would eventually get cached by accident (D8). |

`EDGE_EXPECTED=false`, and `/health` reports it so the posture is never ambiguous.

nginx responsibilities, and nothing more: terminate TLS, serve static files with
long cache lifetimes for hashed assets and `no-store` for HTML, `limit_req` on
`/api/v3/verify` and `/api/v3/auth/login`, proxy everything else to the gunicorn socket,
set `X-Forwarded-For` so `audit.hash_ip` sees the real client, and **never cache
`/api/v3/*`**. It decides nothing.

---

## 12. Raspberry Pi enroller

### 12.1 The sequence

**Steps 0–17 are unchanged from v2 §12.1 and must be copied across verbatim**, including
every ordering constraint and the reason for it. The ones that get broken by people who
think they are redundant:

- **Step 11 before step 12.** Write CFG0 (mirror) then CFG1 (`NFC_CNT_EN=1`), *then*
  `READ_CNT`. A virgin tag has the counter off and NAKs `READ_CNT`, which the PN532
  reports as a bare `InCommunicateThru` status error. This pair has been inverted before.
- **Step 14, the power-cycle and mirror-live confirmation**, is the most important
  operational step in the build. It is the only way to know the mirror actually works
  *before* the asset goes into service. A tag that enrols cleanly but whose mirror never
  turns on produces `MIRROR_DISABLED` on every scan — a genuine asset that verifies badly,
  forever. Over a ten-year life that is far worse than it was for a medicine pack.
- **Step 16 before any network I/O.** `outbox.enqueue()` is durable on disk before
  anything is reported to the operator as successful.
- **No QR fallback.** If the tag write fails, discard the tag and use a new one. A QR is
  static copyable data and has none of the physical binding this system exists to
  provide.

### 12.2 What changes

```
python enroller.py --lot EXTC/PO/2026-27/014 --category DSO --location EXTC-LAB-3
```

1. `batch_session.py` → `lot_session.py`. Fetches the lot the same way, shows a banner
   with vendor / PO / quota / remaining, and still demands the countersignature from a
   second person at the console. The DB `CHECK` guarantees the two names differ on the
   record; the prompt is the operational half.
2. The session also fetches `asset_category.field_spec` once, and the per-item prompt
   loop is **generated from it**. Adding a category needs no change on the Pi.
3. `asset_code` is auto-minted as `{dept}/{id_prefix}/{year}/{seq}` with the operator
   pressing Enter, or typed if the college already has a numbering scheme (§22).
4. Sealed fields become `asset_code`, `serial_no`, `commissioned_on`, `tag_uid` in both
   copies of `crypto_envelope.py`; `tests/vectors/envelope.json` is regenerated. The rule
   that neither tree imports from the other still holds — the vectors are the contract.
5. Payload `schema` is `colasset.enrol.v1`.
6. `--rewrite` implements §6.2(a), and refuses unless the token read back from the tag
   hashes to the stored `binding_token_hash`.
7. `--print-label` (Phase H) for a label printer, so the sticker carries the human-
   readable asset code beside the inlay. People need to read an asset code without a
   phone.

### 12.3 Outbox, drainer, reconciliation

Unchanged. SQLite outbox, exponential backoff, idempotency key per item, "409 from a
replayed key is a success", and `--reconcile` at the end of every run to confirm every
queued item landed.

New: the drainer reports its queue depth to `/health`, and the console's posture bar
shows it. That is what turns "I tagged twelve things and see nine" from a mystery into
*"3 queued on pi-line-1"*.

### 12.4 Clock discipline

Unchanged. The Pi refuses to enrol if its clock is outside the signed timestamp window,
because a bad clock on the enroller produces records that cannot be verified and
timestamps that cannot be trusted.

---

## 13. Frontend

### 13.1 Two surfaces, one login (D1)

| Surface | Who | Auth | Built for |
|---|---|---|---|
| **Scan** — `/c` | Anyone who taps an asset | None | One screen, one phone, five seconds |
| **Console** — `/app` | College staff | One login | Finding things, slicing the register, changing state |

The public never signs in. Staff sign in once per tab and get the console *and* an
upgraded scan page — the same `/c` URL, same code, extra data and extra buttons, because
the token is in memory and `api.js` attaches it when present.

**Constraints that do not relax because the UI got bigger** — all of them are security
controls, not preferences: no build step, no framework, no npm, ES modules served as-is,
strict CSP with no inline scripts, **everything user-visible rendered through
`textContent` and never `innerHTML`**, and the token in a module variable, never in
`localStorage`. With user-editable `notes`, `spec` and category labels, v3 has more
attacker-controlled string surface than v2 did; these rules matter more, not less.

### 13.2 The scan page — the asset passport

```
┌────────────────────────────────────────┐
│  ✅  Verified                          │  verdict band, colour-coded
│      Tektronix TBS1052C                │
│      EXTC/DSO/2026/0042                │
├────────────────────────────────────────┤
│  Where it lives    EXTC Lab 3          │
│  Department        Electronics & Telecom│
│  Condition         Healthy             │
│  In service since  12 Aug 2026         │
│  Calibration       due 12 Aug 2027     │
│  Warranty          expired             │   ← info line, not a verdict
├────────────────────────────────────────┤
│  What was checked                      │
│    Record signature          pass      │
│    Tap counter               pass      │
│    Lifecycle                 pass      │
│    Calibration               pass      │
│    Physical binding: counter           │
├────────────────────────────────────────┤
│  [ Report a problem ]                  │
│  [ Sign in to update this asset ]      │
└────────────────────────────────────────┘
```

**Band 3 stays.** It is four lines, not a dashboard, and it is the honesty requirement:
the page states what was actually verified rather than implying everything was. It is
also the deployment metric for the paper — *what fraction of real scans received the
strong guarantee?*

**Signed in, the same page grows four buttons**, and this is what makes the system
pleasant to use rather than a chore:

```
│  [ Healthy ]  [ Faulty ]  [ Raise fault ]  [ ✓ Stocktake ]  │
│  [ Move… ]    [ Reassign custodian… ]       [ Full record ] │
```

Tap the thing, press one button, done. **No hunting for the asset in a table** — the tap
already identified it, which is the entire advantage NFC has over a spreadsheet. Each
button is one `PATCH /state` call with an `If-Match`, and the page re-renders from the
response.

**Web NFC stays a bonus, never a requirement.** If `NDEFReader` exists, offer a live-read
button that upgrades the binding label to `counter+liveread`. If the user declines the
permission or it fails, **the verdict is not degraded** — the counter path already ran.
Never block a result behind a permission prompt.

### 13.3 Console shell

A single hash-routed page. `router.js` maps `#/assets?...` to a view module; `api.js`
wraps `fetch`, attaches the token, turns the error envelope into a message, and raises a
toast on `409`; `session.js` holds the token and the profile for the tab's lifetime.

```
┌──────────────────────────────────────────────────────────────────┐
│ Asset Register          [ ⌕ search anything ]      EXTC ▾  ⏻     │
├──────────┬───────────────────────────────────────────────────────┤
│ Overview │                                                       │
│ Assets   │                   view renders here                   │
│ Categories                                                       │
│ Lots     │                                                       │
│ Locations│                                                       │
│ People   │                                                       │
│ Stocktake│                                                       │
│ Incidents│                                                       │
│ Faults   │                                                       │
│ Posture  │                                                       │
├──────────┴───────────────────────────────────────────────────────┤
│ ⚠ Tags are rewritable — testing configuration.  Pi queue: 0      │
└──────────────────────────────────────────────────────────────────┘
```

The posture bar at the bottom is permanent, and it is carried from v2's best idea: **the
operating configuration must never be something you have to remember.** If tag locking is
off, it says so in amber on every page, every time.

### 13.4 The assets table — "like a database, but safe"

This is the view the staff live in, and the one the brief calls *very customisable*. It
is a controlled database browser: everything you can do maps to an indexed query, and
nothing you can do is a raw SQL string.

**Filter bar.** Chips across the top, each a dropdown with live counts from the `facets`
in the response: Category, Department, Condition, Lifecycle, Location, Calibration,
Warranty, Custodian, Last seen. Click `Condition → Faulty (12)` and the table filters.
Chips combine with AND; multiple values inside one chip are OR. The URL updates, so any
filtered view is a link somebody can paste into a message.

**Search box.** One field, matches asset code, make, model and category name.

**Column chooser.** The available columns are the fixed ones **plus the selected
category's `field_spec` fields**, so filtering to `LAPTOP` offers RAM and CPU columns and
filtering to `DSO` offers bandwidth and channels. Drag to reorder, click to sort, toggle
density.

**Saved views (D10).** Name the current filter set, column layout and sort, and save it
as `private`, `dept` or `global`. Pinned views appear in the sidebar. Examples that
should ship as defaults: *Faulty in my lab*, *Calibration overdue*, *Not seen in 12
months*, *Out of warranty*, *Registered this month*, *Unresolved incidents*.

**Bulk actions.** Select rows → change location, custodian, lifecycle or condition for
all of them. Capped at 200, one audit row per asset, one confirmation dialog that names
the count and the change.

**Export.** Current view, current columns, current filters → CSV. Nobody will believe the
system until they can get their own data out of it.

**The Overview page is built from the same machinery:** each tile is a saved view's count
and clicking it opens that view. No separate reporting code path, so a tile can never
disagree with the table behind it.

### 13.5 Asset detail

Four tabs for one asset.

- **Details** — the form is **generated from `field_spec`** by `ui/form.js`, so a new
  category is editable the moment it is defined. Signed fields (asset code, serial,
  commissioned-on, lot) render read-only with a small *Correct…* affordance that is
  visible only to `admin` and routes to §9.6 with its mandatory reason.
- **History** — one merged timeline: sightings, state changes, profile changes,
  transfers, incidents. Each entry says who, when and what changed from what to what.
  This is the audit log made legible, and it is what an auditor will ask for.
- **Maintenance** — tickets and repair history (Phase F).
- **Documents** — invoice, warranty card, calibration certificate (Phase H).

Every editable control sends `If-Match` and handles `409` by showing what the other
person wrote, rather than silently overwriting it.

### 13.6 Verdict copy

`strings.js` is rewritten for the ten states, under rules carried from v2 with one
addition:

1. **Never "counterfeit", "fake", "stolen" or "theft".** The strongest negative is
   *"this tag's code has been seen on more than one item."*
2. **Never a bare failure.** Every negative state routes to the report form or to a
   named human.
3. **Localisation and accessibility are in scope.** English and Marathi/Hindi at
   minimum; `aria-live` on the verdict band; colour is never the only signal.
4. **New: never imply blame.** The copy for `SUSPECT_DUPLICATE` on an asset will be read
   by the lab assistant standing next to it. It describes the *tag*, not the person.

---

## 14. Operations — the college server

### 14.1 Topology

```
            :443 nginx ──┬── /          frontend/ static
                         ├── /c         frontend/scan.html
                         ├── /app       frontend/app/
                         └── /api/v3/*  ──► unix socket ──► gunicorn (2 workers, 4 threads)
                                                                 │
                                                           PostgreSQL 16 (local)
```

Workers stay pinned at **2**, as in v2. The reason is unchanged: the in-process rate
limiter keeps a separate counter per worker, so leaving the count to a default makes the
configured limits silently N times looser than reported.

### 14.2 systemd units and timers

| Unit | Schedule | Job |
|---|---|---|
| `gunicorn.service` + `.socket` | always | The app |
| `backup.timer` | nightly 01:30 | `pg_dump`, gzip, encrypt, copy off-box, keep 30 days, **verify the restore monthly** |
| `transparency.timer` | daily 02:00 | Build the Merkle tree over signed rows, chain in the audit head, sign, publish |
| `retention.timer` | nightly 02:30 | Scrub personal columns older than 90 days (§9.8) |
| `alerts.timer` | daily 07:30 | Warranty expiring in 30 days, calibration overdue, assets not seen in 12 months → email to each custodian |

`.github/workflows/ci.yml` stays and still runs the test suite on push. The other three
workflows are retired with the cloud deployment.

### 14.3 Backups

**A register with no backup is not a register.** Nightly encrypted `pg_dump` to a second
machine. The **KEK is not in the backup** — it is provisioned separately, and a backup
that contains both the wrapped keys and the key that unwraps them is a single file that
loses everything.

The transparency root is an independent integrity check: **if a restored backup's Merkle
root does not match the published one, something was changed.** That is worth saying to
the college explicitly, because it is a property their existing Excel register cannot
offer at any price.

### 14.4 Observability

Structured JSON logs with a request id on every line. `/metrics` behind a token.
Counters worth having: verify totals by verdict, enrolment totals and errors, state
changes by transition, login failures, `409` conflicts (a spike means two people are
fighting over the same assets, which is a process problem), drainer queue depth, and
incident open/close rates.

---

## 15. Error handling and consistency rules

### 15.1 The envelope

Unchanged (§10.4). One shape, every error, no exceptions.

### 15.2 Consistency rules the agent must not break

1. **When uncertain, never upgrade the answer.** Any unexpected failure in the verify
   path yields an indeterminate verdict, never a positive one and never a bare 500 to a
   person standing in front of the equipment.
2. **One source of truth per fact.** `warranty_until` is derived once at enrolment;
   `warranty_expired` is computed in a view; neither is stored twice.
3. **Mutable state never enters the signed row** (D3). If a field needs to change, it is
   in the wrong table.
4. **Every privileged mutation writes an audit row in the same transaction.** Not after.
   Not best-effort.
5. **Named transitions, never generic updates** (§9.5).
6. **Optimistic concurrency on every mutable write** (D9). Last-write-wins is not a
   simplification, it is data loss.
7. **No positive verdict is ever cached** (D8).
8. **`mta_status` is never set by a human except through incident resolution.**
9. **Nothing is deleted.** Supersede, archive, scrub personal columns — never `DELETE`
   a register row.

### 15.3 Degradation matrix

| Failure | Behaviour |
|---|---|
| Postgres unreachable | Verify returns `offline` copy; rate limiter fails **open** (it is the second layer, and a down consumer path is itself a security failure); console shows a banner |
| `NXP_ORIGINALITY_PUBKEY` unset | `originality.py` returns `UNAVAILABLE`, records `unverified`, **never `verified`**; `/health` says so |
| `CNT_BYTE_ORDER` unset | Both Pi and backend **refuse to start**. Not guessed anywhere. |
| LDAP unreachable | Local password path still works for accounts that have one; break-glass offline token always works |
| Pi offline | Outbox accumulates; nothing is reported as enrolled until it is durable; drainer catches up |
| Row signature invalid | `RECORD_INVALID`. Never a downgrade to a weaker positive. |
| Clock skew on the Pi | Enrolment refused by `clockcheck.py` |

---

## 16. Attack matrix — what changes

The v2 matrix (105 cases, eight classes) carries over. The deltas:

| Class | Change in v3 |
|---|---|
| **A — tag/physical** | **A7 (rewrite the NDEF) and A8 (write `NFC_CNT_EN=0`) move from *open* to *closed*** by locking (D6). A-transplant (move the inlay to another object) **stays open** and is the headline limitation (§19). |
| **B — NDEF/URL** | Homograph resistance improves if the college gives a real subdomain; worsens if the deployment is an IP address. Decide in §20. |
| **C — client/browser** | Larger XSS surface from user-editable `spec`, `notes` and category labels. Mitigation unchanged and doubled: CSP `script-src 'self'` **and** `textContent` everywhere. |
| **D — API/protocol** | New authenticated mutation surface. New cases: privilege escalation across departments, `If-Match` bypass, bulk-edit abuse, login brute force, saved-view injection (a view definition is validated as data, never interpolated into SQL). |
| **E — crypto** | Unchanged, plus: a correction (§9.6) must not be forgeable into a *downgrade* of `originality_status`. |
| **F — infrastructure** | **Worse on one box**: no provider separation for the KEK, one machine to lose. Mitigations in §14.3. |
| **G — business logic** | The interesting new class. **Stocktake fraud** — marking assets present without visiting them — is exactly what the counter catches. **Condition laundering** — quietly flipping `faulty` to `healthy` before an audit — is caught by the audit chain, which is why §9.5 has no generic update path. |
| **H — forward-looking** | Unchanged. Ed25519 with `alg` fields everywhere so ML-DSA can be added without a migration. |

---

## 17. Test scaffold

Layout unchanged: `tests/unit/`, `tests/integration/`, `tests/attacks/`, `tests/vectors/`.

**Must exist before any deployment:**

| Test | Asserts |
|---|---|
| `test_verdict_machine.py` | **Regenerated.** The full cross-product (~11,000 combinations). The one property: nothing yields `VERIFIED` unless every check passed. |
| `test_fieldspec.py` | Every `field_spec` rule in §8.2, including the reserved-key rejection and the size caps |
| `test_state_transitions.py` | Every legal transition succeeds, every illegal one is `422`, every one writes exactly one audit row |
| `test_concurrency.py` | Two simultaneous `PATCH`es: exactly one wins, the other gets `409`. Twelve simultaneous identical counters: exactly one advances. |
| `test_audit_chain.py` | The chain verifies, **and still verifies after a simulated retention scrub** (§9.8) |
| `test_row_versioning.py` | A correction supersedes cleanly, the partial unique index holds, counter state survives |
| `test_dept_scoping.py` | A `viewer` from one department gets `404`, not `403`, for another's asset |
| `test_tag_layout.py` | Unchanged from v2, exhaustive, and still the thing that stops the mirror landing in the wrong bytes |
| `test_cache_policy.py` | No positive verdict response ever carries a cacheable header (D8) |
| Shared vectors | Regenerated for the new sealed field set; both `backend/` and `pi/` copies pass them |

Attack tests stay scaffold until there is a deployment to point them at, and the
scoreboard must **not** be presented as measured results before they have actually run.
That rule was in v2 and it still applies.

---

## 18. Build order

Each phase ends in something that works end to end.

| Phase | Contents | Done when |
|---|---|---|
| **A — foundations** | Schema `001`–`006`; `fieldspec.py`; rewritten `verification.py`; regenerated verdict tests; new envelope vectors; the §1.3 docstring fix | Full unit suite green, verdict enumeration passes |
| **B — backend surface** | `assets.py`, `state.py`, `categories.py`, `lots.py`; `routes/admin/` split; verify re-aimed + sightings; two response tiers | Integration: enrol → scan → change condition → read history |
| **C — Pi** | `lot_session.py`, category-driven prompts, new sealed fields, `--rewrite` | A real tag written; the asset appears via the drainer |
| **D — frontend core** | Shell, router, api, table, form; Overview, Assets, Asset detail, Categories, Lots; the new scan page | A category added in the UI appears as Pi prompts **and** as table columns |
| **E — login and roles** | `/auth/login`, Argon2id or LDAP, role→scope, department scoping | A `viewer` cannot see another department; an `auditor` cannot write |
| **F — workflows** | Tickets, transfers, issue/return, stocktake runs, condemnation | A stocktake produces found / not-found / unexpected-location |
| **G — deployment** | nginx, systemd, Postgres, TLS, backups, timers | Load tested on the actual box; restore from backup verified |
| **H — the nice ones** | Alerts, CSV import, depreciation, label printing, documents, SSE, parent–child assets | — |

**A + B + C + D is the demonstrable milestone**: a working, flexible asset register with
NFC verification and a usable dashboard.

---

## 19. Threat model — the resolved version

**Assets:** the register's integrity, the audit trail, the device signing key, the field
recipient key, and staff credentials.

**In scope:** reading tags, writing arbitrary data to rewritable tags, modifying traffic,
calling endpoints, enumerating the API, a staff account used beyond its role, a staff
member quietly editing state to cover a loss, physical access to the equipment, and
compromise of the provisioning Pi.

**Out of scope:** full compromise of the running backend process, RF fingerprinting,
compromise of the college's server root, and a determined insider with database
superuser access — against whom the only defence is the published transparency root,
which is deliberately outside their reach.

**Limitations, stated plainly and not buried:**

1. **Tag transplant is open.** Peel the inlay off a working DSO, stick it on a dead one.
   The counter does not notice, because it is the same chip. Tamper-evident labels are
   the answer and that is a procurement decision, not a code one. This is the same
   limitation the paper states for medicine packaging and it does not go away here.
2. **The velocity bound loosens with age** (§1.2). MTA is weakest on a ten-year-old
   asset. Partly offset by a long, dense sighting history.
3. **Browser geolocation is a claim, not evidence** (§9.3).
4. **Key separation is weaker on one box** than it was across three providers (§7.1).
5. **The system detects inconsistency; it does not identify who caused it.** Every
   verdict string, log line and piece of console copy must keep respecting that
   distinction. Accusing a person on the strength of a counter is the failure mode this
   design exists to avoid.
6. **A staff member with `state:write` can record false state.** The audit chain makes it
   *attributable*, not impossible. That is the correct and achievable goal.

---

## 20. Manual steps — what the operator does

1. **Decide the hostname.** Before anything else. It is written physically into every
   tag (§1.2 Rule 1). Short, real, and with a certificate.
2. Provision the server: Debian/Ubuntu, PostgreSQL 16, Python 3.11+, nginx, certbot.
3. `scripts/gen_keys.py` → device keypair, field recipient X25519, row signing Ed25519,
   session signing Ed25519, tag index HMAC key, admin token keypair, IP hash seed,
   `TAG_PWD_MASTER`. **Wrap the private keys with `wrap_secret.py`; store the KEK
   separately** (§7.1).
4. Run `schema/001`–`006`.
5. Register the Pi in `device_registry`; mint the first `admin` token offline.
6. Create the location tree and the staff list (or point at LDAP).
7. Define the first categories through the console.
8. **Calibrate `CNT_BYTE_ORDER`** with `enroller.py --calibrate`. Nothing starts without
   it.
9. Obtain `NXP_ORIGINALITY_PUBKEY` from NXP's AN11350 and set it. Without it the
   originality gate reports `UNAVAILABLE` forever.
10. **Pilot one lab with `TAG_LOCK_ENABLED=false`**, so mistakes are recoverable.
11. Before the rollout: verify a backup restores, verify the transparency root matches,
    then turn locking **on** (§6.3) and re-read the amber bar on `/health` to confirm it
    went green.

---

## 21. Configuration reference

### 21.1 `backend/.env`

```
DATABASE_URL=                      postgresql://… (local socket preferred)
KEK=                               hex, loaded via systemd LoadCredential, NOT in backups
FIELD_RECIPIENT_KEY_WRAPPED=
FIELD_RECIPIENT_PUB=
ROW_SIGNING_KEY_WRAPPED=
ROW_SIGNING_PUBKEY=
ROW_KEY_VERSION=1
SESSION_SIGNING_KEY_WRAPPED=       NEW — mints login tokens (§9.7)
ADMIN_TOKEN_PUBKEY=                verifies both offline and login-minted tokens
TAG_INDEX_KEY=
IP_HASH_SEED=
RECEIPT_KEY=                       NEW — the EVR HMAC key (§9.4.1)
CNT_BYTE_ORDER=                    REQUIRED. App refuses to start without it.
PUBLIC_HOST=                       baked into every tag — see §20.1
ALLOWED_ORIGINS=
AUTH_SOURCE=local                  local | ldap
LDAP_URL=  LDAP_BIND_DN=  LDAP_BIND_PW=  LDAP_USER_FILTER=
MAX_TAPS_PER_DAY=50                per-category override in asset_category
VELOCITY_GRACE=20
RECEIPT_TTL_S=300
VERIFY_TIME_FLOOR_MS=120
TAG_LOCK_ENABLED=false             true for the rollout (D6)
ORIGINALITY_POLICY=reject
EDGE_EXPECTED=false                D7
AUDIT_RETENTION_DAYS=90            personal columns only; event rows are permanent
DB_POOL_MAX=6
LOG_LEVEL=INFO
```

### 21.2 `pi/.env`

```
BACKEND_URL=  DEVICE_ID=  DEVICE_KEY_PATH=  FIELD_RECIPIENT_PUB=
ADMIN_TOKEN=                       a lot:read token for the session
CNT_BYTE_ORDER=                    must match the backend
TAG_LOCK_ENABLED=false
TAG_PWD_MASTER=                    required only when locking
NXP_ORIGINALITY_PUBKEY=
OUTBOX_PATH=  PN532_DEBUG=
```

### 21.3 Removed from v2

`CF_*` and everything in `edge/wrangler.toml` (D7); `RENDER_*`; `NEG_CACHE_TTL`;
`POW_DIFFICULTY_BITS` stays but applies only to anonymous fault reports.

---

## 22. Open questions for the operator

These block Phase A or Phase E and need answers from the college, not from the code.

1. **The final hostname.** Blocks everything physical (§20.1).
2. **LDAP or local passwords?** LDAP is strongly preferred — no password store of ours,
   no reset flow to build, accounts die when staff leave. Needs a bind account.
3. **Is there an existing register** (Excel, Tally, a departmental file) to import? Its
   format drives `scripts/import_register.py` and may dictate the asset-code scheme.
4. **Does the college already have an asset numbering convention?** If yes, follow it. If
   no, `{dept}/{prefix}/{year}/{seq}`.
5. **Which lab is the pilot?** One lab, fully, beats the whole college partially.
6. **Who signs off a condemnation?** There is usually a committee and a form. The
   `disposed` transition should mirror whatever that process actually is, not invent one.
7. **Intranet-only or publicly reachable?** Intranet is safer; it also means nobody can
   check an asset from mobile data and that every visiting auditor needs campus Wi-Fi.
   Recommendation: public hostname, with everything except the thin anonymous scan view
   behind the login.
8. **Is the countersignature control real?** If one person types both names, it is
   theatre. This was open question 4 in v2 and it is a process problem, not a code one.
