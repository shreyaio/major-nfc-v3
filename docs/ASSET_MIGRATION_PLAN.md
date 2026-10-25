# From medicine authenticity to a college asset register — the plan

**Status:** the plain-language companion to `ARCHITECTURE.md` v3.
**`ARCHITECTURE.md` is normative.** Where the two differ, the architecture wins. It
refined this document in three places after the first review:

- **One login, not two** (its D1). There is no public user account — the public just
  taps. The role model in §7 below is unchanged; it is reached through a single door.
- **Mutable fields leave the `assets` table** (its D3, §5.4). This document sketched
  `spec`, `make`, `model` and cost as plaintext columns on `assets`; the architecture
  moves them to `asset_profile`, because a column on a signed row cannot be edited
  without making the signature ceremonial.
- **Tag locking is ON in production** (its D6), the opposite of the v2 default, and
  §1.2 there explains exactly what re-writing a tag does and does not do to MTA.

---

## 0. The one-line summary

Today the system answers *"is this medicine pack the one the register describes?"*
Tomorrow it answers *"what is this piece of lab equipment, who owns it, where does it
live, what condition is it in — and is this tag actually on the thing it claims to be
on?"*

The machinery that answers the second half of that question is **exactly the machinery
we already have**. We are not rebuilding it. We are changing *what the register
stores*, *what the verdict means*, and *what the screen looks like*.

---

## 1. What stays, what changes, what is new

### 1.1 Stays, untouched

These are the parts that took the longest to get right, and none of them care whether
the object is a tablet strip or a digital storage oscilloscope.

| Thing | Why it is unaffected |
|---|---|
| **MTA / the one-way counter** | The chip counts taps. A counter that does not strictly increase is still evidence that two physical tags are answering to one identity. Nothing about that reasoning is medical. |
| **CDD, incidents, sticky `suspect_duplicate`** | Same. A flagged tag still needs a human to clear it, with a note, audited. |
| **The tag pipeline** (`pi/ntag.py`, `tag_layout.py`, `tag_config.py`, `originality.py`) | NDEF layout, the 21-byte mirror placeholder, `NFC_CNT_EN`, `AUTH0 = E3h`, the ECC originality gate, the write-then-read-back-and-byte-compare rule, the power-cycle-and-confirm-the-mirror-is-live step. All of it, byte for byte. |
| **Request signing** | Ed25519 over the raw body, two-sided timestamp window, device registry, idempotency keys. The Pi still signs; the server still verifies before parsing. |
| **Field encryption** | AES-256-GCM per field, X25519-wrapped DEK, KEK outside the hosting dashboard. The *list of fields* changes; the envelope does not. |
| **Row signatures** | Every register row still carries an Ed25519 signature over its canonical immutable view. This actually becomes **more** important — see §4.4. |
| **Hash-chained audit log + daily Merkle root + transparency publication** | Unchanged, and for a college this is the single most useful inherited feature: it is an audit trail a NAAC/NBA inspector can verify without trusting us. |
| **RLS, the error envelope, CSP, no-`innerHTML`, rate limiting, the response-time floor, the uniform response shape** | All of it. These are properties of the API, not of the domain. |
| **Outbox → drainer durability** | The Pi still writes to SQLite before any network call. A lab with flaky Wi-Fi needs this more than a factory floor does. |

### 1.2 Changes

- The **register table** (`products` → `assets`): different columns, different meaning.
- The **grouping table** (`batches` → `procurement_lot`), plus a **new** orthogonal
  `asset_category` concept.
- The **verdict state machine**: same shape, same ordering discipline, same purity,
  different terminal states.
- The **consumer page**: from "is this safe to take?" to "asset passport".
- The **admin console**: from four panes to a real dashboard.
- **Who is allowed to do what**: from "anonymous public + one offline-minted admin
  token" to "anonymous read-lite + logged-in staff with roles".
- **Deployment**: from Cloudflare + Render + Supabase to one college server.

### 1.3 Genuinely new

Three things an asset register needs that a medicine register never did:

1. **Mutable state.** A medicine pack's record is written once and never changes. An
   asset's condition, location and custodian change constantly. That needs a separate,
   unsigned-but-audited state table — it cannot go in the signed row.
2. **Scans are events, not just questions.** Every tap on a lab instrument is a
   *sighting*: proof that this asset was in this place at this time. That is free
   stocktake data, and we already capture most of it.
3. **Workflows**: repairs, transfers, issue/return, condemnation. These are the reason
   people actually open the dashboard.

---

## 2. What a college asset management system normally has

Before designing, here is the survey — the standard feature set, and whether we are
doing it now, later, or not at all.

| Capability | What it means in a college | Phase |
|---|---|---|
| **Asset register** | Every item has one permanent ID, e.g. `EXTC/DSO/2026/0042`. One row per physical object. | 1 |
| **Categories / item types** | DSO, CRO, function generator, DSO probe, laptop, desktop, printer, projector, UPS, chair, almirah. Each type has *different* details worth recording. | 1 |
| **Hierarchy / parent–child** | A desktop has a monitor, keyboard, UPS. A lab bench has instruments on it. Each child is its own asset but belongs to a parent. | 2 |
| **Location** | Building → floor → room/lab → bench. Plus optional GPS for outdoor/large items. | 1 |
| **Custodian / owner** | Department, lab in-charge, the faculty member answerable for it. | 1 |
| **Condition & lifecycle** | Healthy / faulty / under repair / scrapped, and in-store / in-service / retired. | 1 |
| **Procurement & finance** | PO number, vendor, invoice, date, cost, funding source (college funds, TEQIP, DST grant, CSR). Depreciation. | 1 (fields), 3 (depreciation) |
| **Warranty & AMC** | When does the warranty end, who is the AMC vendor, when does the AMC expire. | 1 |
| **Calibration** | For measuring instruments this is mandatory for lab accreditation: last calibrated, due date, certificate. | 1 |
| **Maintenance / complaints** | "DSO in Lab 3 channel 2 is dead" → ticket → assigned → repaired → closed. Full repair history per asset. | 2 |
| **Issue / return** | A student or staff member borrows a multimeter and returns it. | 2 |
| **Transfer of custody** | Asset moves from Lab 3 to Lab 5, or from one department to another, with both sides acknowledging. | 2 |
| **Physical verification / stocktake** | Once a year somebody must walk the labs and confirm every asset is where the register says. **This is the killer feature for us** — tap-to-verify makes it an afternoon instead of a fortnight. | 1 |
| **Condemnation / disposal** | Committee declares an item dead, it is struck off the register, the record is kept. | 2 |
| **Reports & dashboards** | Count and value by department, by condition, by category; what is out of warranty; what is overdue for calibration; what went missing in the last audit. | 1 (basic), 3 (full) |
| **Alerts** | Warranty expiring in 30 days, calibration overdue, asset not seen in 12 months. | 2 |
| **Labels** | Barcode / QR / NFC. We have the best of the three already. | done |
| **Audit trail** | Who changed what, when. We already have a *hash-chained, published* one, which is better than what commercial systems ship. | done |

---

## 3. What MTA means once the object is a DSO

This section matters because it is the part a reviewer will ask about.

**In medicine:** a repeat counter value is suspicious because a pack is scanned a
handful of times in its life, by different people, in different shops.

**In a college:** the same DSO is tapped *deliberately and repeatedly* — every
stocktake, every time a complaint is raised, possibly weekly. **This does not break
MTA**, because the counter is advanced by the chip on every physical read. Twenty taps
produce twenty strictly-increasing values. What MTA still catches is exactly what we
want it to catch here:

- Somebody photographs the URL off a lab's DSO label and sticks a copy on a different
  box. Second tag, same identity, counter goes backwards → `SUSPECT_DUPLICATE`.
- A working instrument is quietly swapped for a dead one and the label moved. The label
  is NFC, not paper; moving it to another chip is impossible, and cloning it is
  detectable.
- A vendor delivers "the same model" at service time and swaps in a cheaper unit.
- Somebody types the URL from a screenshot during a stocktake to mark an asset
  "present" without walking to the lab. The counter does not advance → repeat →
  flagged. **This is the real fraud this system prevents in a college**, and it is worth
  saying out loud in the report.

**What changes in the tuning:**

- `MAX_TAPS_PER_DAY = 50` was sized for a medicine pack. For an asset in an active lab
  it should be configurable per category (a demo instrument used in a practical batch
  could legitimately be tapped by 60 students in one lab session). Make it a column on
  `asset_category`, defaulting to the global config value.
- The `velocity_bound` formula `B = c₀ + r·d + γ` stays exactly as is — only `r` moves
  from a constant to a per-category lookup.
- Assets live for 10+ years, so `d` (age in days) gets large and the bound gets loose
  over time. That is correct behaviour and should be stated as a known limitation: MTA
  on a 10-year-old asset is weaker than on a 10-day-old medicine pack.

---

## 4. The data model

New schema files. **Do not edit `001_core.sql` in place** — move the medicine schema to
`backend/schema/legacy-medicine/` so the paper's claims stay reproducible, and write a
fresh numbered set. The database is a fresh register either way; there is no migration
of real medicine rows to worry about.

```
backend/schema/
  001_core.sql           <- rewritten: assets, categories, lots, locations, people
  002_rls.sql            <- same policy, new table list
  003_state.sql          <- mutable state: condition, location, custody, sightings
  004_workflow.sql       <- tickets, transfers, issue/return, stocktake  (phase 2)
  005_seed_dev.sql       <- a couple of categories and a dev lot
  legacy-medicine/       <- the v2 medicine schema, kept verbatim
```

### 4.1 `asset_category` — the flexibility mechanism

This is the table that answers *"we must be able to add different items as well."*

```sql
CREATE TABLE asset_category (
    code             TEXT PRIMARY KEY,        -- 'DSO', 'LAPTOP', 'CRO', 'PROJECTOR'
    name             TEXT NOT NULL,           -- 'Digital Storage Oscilloscope'
    parent_code      TEXT REFERENCES asset_category(code),  -- 'INSTRUMENT' > 'DSO'
    id_prefix        TEXT NOT NULL,           -- used to mint asset codes: EXTC/DSO/...
    field_spec       JSONB NOT NULL DEFAULT '[]',   -- see below
    calibration_required  BOOLEAN NOT NULL DEFAULT FALSE,
    calibration_months    INTEGER,            -- NULL unless the above is true
    default_taps_per_day  INTEGER,            -- overrides MAX_TAPS_PER_DAY
    depreciation_pct_year NUMERIC(5,2),
    status           TEXT NOT NULL DEFAULT 'active',  -- active | archived
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

`field_spec` is a small, boring JSON array describing the *extra* fields this kind of
thing has. For `DSO`:

```json
[
  {"key":"make",        "label":"Make",            "type":"text",   "required":true},
  {"key":"model",       "label":"Model",           "type":"text",   "required":true},
  {"key":"serial_no",   "label":"Serial number",   "type":"text",   "required":true, "unique":true},
  {"key":"bandwidth_mhz","label":"Bandwidth (MHz)","type":"number"},
  {"key":"channels",    "label":"Channels",        "type":"select", "options":["2","4"]}
]
```

For `LAPTOP` it would be make, model, serial, CPU, RAM, storage, OS, MAC address. For
`CHAIR` it would be an empty list.

**Why this shape:** adding a new kind of item becomes *filling a form in the dashboard*,
not a schema migration and a redeploy. The backend validates submitted `spec` values
against `field_spec` (types, required, options, max length) — so it is flexible but not
a free-for-all. The frontend renders the add/edit form **from** `field_spec`, so the UI
supports new item types with zero frontend code.

**The rule we enforce:** nothing in `field_spec` may be security-relevant. It is
descriptive metadata only. No field there can affect a verdict.

### 4.2 `assets` — replaces `products`

Same discipline as before: the client cannot state anything the server can derive, the
immutable part is signed, the identity fields are encrypted.

```sql
CREATE TABLE assets (
    id                 BIGSERIAL PRIMARY KEY,
    tag_index          TEXT NOT NULL UNIQUE,   -- HMAC(TAG_INDEX_KEY, uid). Unchanged.
    binding_token_hash TEXT NOT NULL,          -- SHA-256 of the 128-bit tag token. Unchanged.

    -- the human-facing permanent identifier, plaintext because everything
    -- searches and sorts on it
    asset_code         TEXT NOT NULL UNIQUE,   -- 'EXTC/DSO/2026/0042'
    category_code      TEXT NOT NULL REFERENCES asset_category(code),

    -- encrypted identity fields (the envelope, re-aimed)
    asset_code_ct      TEXT NOT NULL,          -- so the signed+sealed copy is authoritative
    serial_no_ct       TEXT NOT NULL,
    commissioned_on_ct TEXT NOT NULL,
    tag_uid_ct         TEXT NOT NULL,
    enc_dek            TEXT NOT NULL,

    -- descriptive, plaintext, because the dashboard filters and groups on them
    spec               JSONB NOT NULL DEFAULT '{}',  -- validated against field_spec
    make               TEXT,
    model              TEXT,

    -- dates
    commissioned_on    DATE NOT NULL,          -- "start date" — in service from
    warranty_until     DATE,
    amc_until          DATE,
    calibration_due    DATE,

    -- money / provenance
    lot_ref            TEXT NOT NULL REFERENCES procurement_lot(lot_ref),
    purchase_cost      NUMERIC(12,2),
    funding_source     TEXT,

    -- ownership at registration (current values live in asset_state)
    owner_dept         TEXT NOT NULL,          -- 'EXTC'
    home_location_id   BIGINT REFERENCES location(id),

    -- unchanged plumbing
    enrol_counter      INTEGER NOT NULL,
    device_id          UUID NOT NULL REFERENCES device_registry(device_id),
    originality_status TEXT NOT NULL DEFAULT 'unverified',
    binding_class      TEXT NOT NULL DEFAULT 'counter',
    crypto_version     TEXT NOT NULL DEFAULT 'aes_gcm_v2',
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_by      BIGINT REFERENCES assets(id),
    row_sig            TEXT NOT NULL,
    row_sig_alg        TEXT NOT NULL DEFAULT 'ed25519',
    row_key_version    INTEGER NOT NULL DEFAULT 1
);
```

Note what is **not** here: condition, current location, current custodian, lifecycle
status. Those move — see §4.4.

### 4.3 `procurement_lot` — replaces `batches`

Keeps everything that made `batches` a security control, and adds the finance fields a
college needs.

```sql
CREATE TABLE procurement_lot (
    lot_ref          TEXT PRIMARY KEY,      -- 'EXTC/PO/2026-27/014'
    description      TEXT NOT NULL,         -- 'Tektronix TBS1052C x 10'
    vendor           TEXT NOT NULL,
    po_number        TEXT,
    invoice_number   TEXT,
    invoice_date     DATE,
    received_on      DATE NOT NULL,         -- replaces mfg_date
    warranty_months  INTEGER NOT NULL,      -- replaces shelf_life_days
    quota            INTEGER NOT NULL,      -- how many items this PO covers
    enrolled_count   INTEGER NOT NULL DEFAULT 0,
    total_value      NUMERIC(14,2),
    funding_source   TEXT,
    status           TEXT NOT NULL DEFAULT 'open',  -- open|closed|recalled|withdrawn
    opened_by        TEXT NOT NULL,
    countersigned_by TEXT NOT NULL,
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at        TIMESTAMPTZ,
    recall_notice    TEXT,                  -- vendor recall, or a condemnation order
    recalled_at      TIMESTAMPTZ,
    CONSTRAINT lot_two_person CHECK (countersigned_by <> opened_by),
    CONSTRAINT lot_quota_not_exceeded CHECK (enrolled_count <= quota)
);
```

**Why keep the quota and the two-person rule?** In medicine it bounded the damage from a
stolen Pi key. In a college the same constraint stops a different problem: somebody
tagging twelve oscilloscopes against a purchase order for ten. The quota *is* the
reconciliation between the invoice and the shelf, enforced by the database. Keep it.
`warranty_until` is derived server-side as `received_on + warranty_months`, exactly the
way `expiry_date` was derived from `mfg_date + shelf_life_days` — the Pi still cannot
state it, so it still cannot get it wrong.

### 4.4 `asset_state` — the new, mutable half

**This is the most important new idea in the plan.** The signed row is immutable, so
anything that changes must live elsewhere, and every change must land in the
hash-chained audit log.

```sql
CREATE TABLE asset_state (
    tag_index        TEXT PRIMARY KEY REFERENCES assets(tag_index) ON DELETE CASCADE,

    -- MTA, exactly as before
    max_counter       INTEGER NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mta_status        TEXT NOT NULL DEFAULT 'ok',   -- ok|suspect_duplicate|frozen

    -- the asset's own, human-managed state
    lifecycle        TEXT NOT NULL DEFAULT 'in_store',
        -- in_store | in_service | under_repair | issued_out | retired | lost | disposed
    condition        TEXT NOT NULL DEFAULT 'healthy',
        -- healthy | minor_issue | faulty | unserviceable
    current_location_id BIGINT REFERENCES location(id),
    custodian_id     BIGINT REFERENCES person(id),
    last_verified_at TIMESTAMPTZ,            -- last successful stocktake tap
    last_lat         NUMERIC(9,6),           -- optional geotag, from the scanning phone
    last_lon         NUMERIC(9,6),
    geo_accuracy_m   INTEGER,
    notes            TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by       TEXT
);
```

Two separate axes, deliberately:

- **lifecycle** = where it is in its life ("is it in use, being repaired, written off").
- **condition** = how healthy the thing is ("does it work").

Keeping them apart avoids the mess every ad-hoc asset register falls into, where
`status` ends up meaning five different things. A DSO can be `in_service` +
`minor_issue` (channel 2 is flaky but the lab still uses it) — one field cannot say
that.

`mta_status` keeps its own name so nobody confuses "this tag may be cloned" with "this
instrument is broken". They are unrelated facts and must never be collapsed.

### 4.5 `location`, `person`, `asset_sighting`

```sql
CREATE TABLE location (
    id        BIGSERIAL PRIMARY KEY,
    parent_id BIGINT REFERENCES location(id),   -- Campus > Building > Floor > Room
    kind      TEXT NOT NULL,                    -- campus|building|floor|room|bench|store
    code      TEXT NOT NULL UNIQUE,             -- 'EXTC-LAB-3'
    name      TEXT NOT NULL,                    -- 'Communication Lab'
    lat       NUMERIC(9,6),                     -- fixed geotag of the room itself
    lon       NUMERIC(9,6),
    dept      TEXT
);

CREATE TABLE person (
    id        BIGSERIAL PRIMARY KEY,
    emp_code  TEXT UNIQUE,
    name      TEXT NOT NULL,
    email     TEXT,
    dept      TEXT,
    role      TEXT NOT NULL DEFAULT 'viewer',
        -- viewer | lab_staff | custodian | dept_admin | admin | auditor
    status    TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE asset_sighting (
    id           BIGSERIAL PRIMARY KEY,
    tag_index    TEXT NOT NULL,
    counter      INTEGER NOT NULL,
    verdict      TEXT NOT NULL,
    location_id  BIGINT REFERENCES location(id),   -- claimed by the scanner
    lat          NUMERIC(9,6),
    lon          NUMERIC(9,6),
    accuracy_m   INTEGER,
    scanned_by   TEXT,                              -- person, or 'public'
    session_ref  TEXT,                              -- stocktake run this belongs to
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**On geotagging — be honest about what it is worth.** A GPS fix from a phone browser is
(a) only available over HTTPS, (b) only with the user's permission, (c) ±10–50 m
indoors, and (d) **entirely claimed by an untrusted client** — exactly like the
existing `live=1` flag. So the rule is the same rule: *a location claim can enrich the
record, it can never change a verdict.* The trustworthy location signal is the
`location_id` the logged-in scanner selects, cross-checked against where the register
says the asset lives. We also need a CSP change: the current
`Permissions-Policy: geolocation=()` **blocks geolocation outright** and must be
relaxed to `geolocation=(self)` on the scan page only.

### 4.6 Phase-2 workflow tables (sketch)

`maintenance_ticket`, `custody_transfer`, `issue_record`, `stocktake_run`,
`stocktake_line`, `disposal_record`. All follow the same pattern: an append-only table
plus an audit entry. Detailed in phase 2; not blocking anything in phase 1.

---

## 5. The verdict machine, re-aimed

`services/verification.py` keeps its structure exactly: a pure function, no Flask, no
database, no clock of its own, ordered steps where each assumes the previous passed, and
one property that `test_verdict_machine.py` enumerates exhaustively — **no combination
yields a positive verdict unless every check passed.**

What changes is the list of terminal states.

| Step | Condition | Old verdict | New verdict |
|---|---|---|---|
| 0 | placeholder mirror | `MIRROR_DISABLED` | `MIRROR_DISABLED` (same) |
| 2 | no row | `UNKNOWN` | `UNREGISTERED` |
| 3 | binding token mismatch | `UNKNOWN` | `UNREGISTERED` (same answer, deliberately) |
| 4 | row signature invalid | `RECORD_INVALID` | `RECORD_INVALID` (same) |
| 5 | sticky MTA flag | `SUSPECT_DUPLICATE` | `SUSPECT_DUPLICATE` (same) |
| 6 | counter ≤ high-water mark | `SUSPECT_DUPLICATE` | `SUSPECT_DUPLICATE` (same) |
| 7 | counter > velocity bound | `SUSPECT_DUPLICATE` | `SUSPECT_DUPLICATE` (same) |
| 8 | advance the counter | — | — |
| 9 | lot recalled / asset disposed | `RECALLED` / `WITHDRAWN` | `DISPOSED` / `CONDEMNED` |
| 9b | lifecycle = `lost` | — *(new)* | `REPORTED_LOST` |
| 10 | past expiry | `EXPIRED` | split into three, see below |
| 11 | everything passed | `AUTHENTIC` | `VERIFIED` |

Step 10 splits because an asset has several independent clocks, and unlike a medicine
expiry **none of them make the asset unusable**:

- `calibration_due < today` → verdict `CALIBRATION_OVERDUE`, tone amber. Genuine, in
  service, but its readings are not trustworthy for accredited work.
- `warranty_until < today` → **not a verdict at all.** A flag on the response, shown as
  an informational line. Out-of-warranty equipment is normal.
- condition is `faulty` / `unserviceable`, or lifecycle is `under_repair` → verdict
  `NEEDS_ATTENTION`, tone amber.

So the final verdict list is:

```
VERIFIED  CALIBRATION_OVERDUE  NEEDS_ATTENTION  CONDEMNED  DISPOSED
REPORTED_LOST  SUSPECT_DUPLICATE  MIRROR_DISABLED  RECORD_INVALID  UNREGISTERED
```

Ten states instead of eight; the combination count that the exhaustive test enumerates
goes up accordingly, and `test_verdict_machine.py` is regenerated, not rewritten.

**The naming rule carries over, re-stated for this domain:** the system never says
"stolen" or "fake". `SUSPECT_DUPLICATE` still means *"this identity has been seen on
more than one object; a human must look."* Accusing a lab assistant of theft on the
strength of a counter is exactly the mistake the medicine version refused to make, and
the reasoning is identical.

---

## 6. Backend changes, file by file

| File | Change |
|---|---|
| `schema/*` | New, per §4. |
| `services/verification.py` | New terminal states, per §5. Still pure. Still takes a snapshot, not a session. |
| `services/enrolment.py` | Validates against `asset_category.field_spec`; derives `warranty_until`, `calibration_due`, `asset_code` server-side; writes `assets` + `asset_state` + lot counter in **one** transaction, as now. |
| `services/counter.py` | Unchanged logic. Renamed references `tag_counter_state` → `asset_state`; `max_taps_per_day` now read per category. |
| `services/batches.py` → `services/lots.py` | Same functions, new fields. |
| **`services/assets.py`** *(new)* | Search, filter, paginate, aggregate. The dashboard's workhorse. |
| **`services/categories.py`** *(new)* | CRUD for categories, plus `field_spec` validation (the validator is shared with enrolment). |
| **`services/state.py`** *(new)* | The only place that mutates `asset_state`. Every mutation writes an audit row. One function per transition, no generic "update anything" endpoint. |
| **`services/stocktake.py`** *(new, phase 2)* | Open a run, record lines from scans, close it and produce the exception list. |
| `routes/verify.py` | Response gets asset fields instead of product fields; accepts optional `loc`/`lat`/`lon`; writes an `asset_sighting`. **The response-time floor and the uniform shape stay** — they still prevent an outsider from enumerating which tags exist. |
| `routes/enrol.py` | Unchanged except the schema string: `nfcmed.enrol.v2` → `colasset.enrol.v1`. |
| `routes/admin.py` | Splits into `routes/admin/` — `lots.py`, `assets.py`, `categories.py`, `state.py`, `incidents.py`, `reports.py`, `stocktake.py`. Same `@require_scope` guard, same audit-on-every-action rule. |
| **`routes/auth.py`** *(new)* | Login. See §7. |
| `auth_admin.py` | Gains a role→scope mapping; token format and verification untouched. |
| `routes/report.py` | Stays. "Report a problem with this asset" is the complaint intake; the proof-of-work gate can be dropped for logged-in users and kept for anonymous ones. |
| `routes/health.py` | Posture gains: category count, asset count, last stocktake, drainer backlog. |

### 6.1 Two response tiers on `/verify`

Right now `/verify` is fully public. For a college that is nearly right but not quite:
anyone who taps an asset should see enough to know what it is and report a fault, but
the purchase cost and the custodian's phone number are not public.

- **Anonymous:** verdict, category, make/model, asset code, department, home location,
  condition, calibration status, and a "report a problem" link.
- **Logged in (`asset:read`):** the above plus cost, vendor, PO, warranty/AMC, custodian,
  full sighting history, repair history, and the action buttons.

Both tiers return the **same response shape and the same size class** — the extra fields
are present as `null` for anonymous callers — so the anti-oracle property that the
medicine design worked hard for is not quietly thrown away.

---

## 7. People, roles and login

This is the one place where honest new work is needed, because "paste an offline-minted
token" does not scale past two operators.

**Keep the token.** The Ed25519-signed, scoped, 12-hour, in-memory-only admin token is
good and its verification path is well tested. What we add is a *second way to obtain
one*:

```
POST /api/v2/auth/login   { emp_code, password }   ->   the same token format
```

- The server authenticates against `person` + a password hash (Argon2id), or against the
  college LDAP/AD if they will give us a bind account — LDAP is the better answer and
  should be asked for early.
- On success the server mints **the identical token** the offline script mints, with
  scopes derived from `person.role`.
- `scripts/mint_admin_token.py` stays, as the break-glass path for when the database or
  LDAP is down.

Roles → scopes:

| Role | Can do |
|---|---|
| `viewer` | Read assets in their department. |
| `lab_staff` | The above + record a sighting, raise a fault ticket, run a stocktake scan. |
| `custodian` | The above + change condition/location, accept transfers, close tickets for their assets. |
| `dept_admin` | The above + register assets, open/close lots, define categories, initiate transfers out. |
| `admin` | Everything, including resolving MTA incidents and condemnation. |
| `auditor` | Read-only across **all** departments + the transparency log. Cannot change anything. |

Unchanged rules: every privileged action writes an audit row carrying the subject and
the token's `jti`; clearing a `suspect_duplicate` flag is still `admin` only, still needs
a written note, and is still the only path out of that state.

---

## 8. The Raspberry Pi enroller

Smallest change of any component — steps 0–17 of the enrolment sequence are untouched,
including the step-14 power-cycle-and-confirm-the-mirror-is-live check.

What changes:

```
python enroller.py --lot EXTC/PO/2026-27/014 --category DSO --location EXTC-LAB-3
```

1. `batch_session.py` → `lot_session.py`: fetches the lot the same way, shows a banner
   with vendor/PO/quota/remaining, still demands the countersignature.
2. The per-item prompt changes from one line (`product_id`) to a short prompt loop
   **generated from the category's `field_spec`** — the Pi fetches the category
   definition once when the session opens, so adding a new item type needs no change on
   the Pi either.
3. `asset_code` can be auto-minted (`{dept}/{id_prefix}/{year}/{seq}`) with the operator
   just pressing Enter, or typed if the college already has a numbering scheme.
4. The sealed payload's four fields become `asset_code`, `serial_no`, `commissioned_on`,
   `tag_uid`. `crypto_envelope.SEALED_FIELDS` changes in both copies (`backend/` and
   `pi/`) and the shared test vectors in `tests/vectors/` are regenerated — the rule that
   neither tree imports from the other still holds.
5. Payload `schema` string becomes `colasset.enrol.v1`.
6. Optional `--print-label` hook for a Brother/Dymo label printer so the physical sticker
   carries the human-readable asset code next to the NFC inlay. (Phase 3.)

**"Adding from the Pi should reflect in the frontend."** It already will, with one
caveat worth knowing: the Pi writes to its local SQLite outbox first and the drainer
pushes afterwards, so a newly tagged asset appears in the dashboard **after the next
drain**, not instantly. Three things make that feel live:

- run the drainer as a loop with a short interval while a session is open (it already
  supports this);
- the dashboard's "Recently registered" panel polls `/api/v2/admin/assets?since=…` every
  few seconds while the page is open;
- the posture bar shows the drainer backlog (`N queued on the Pi`), so an operator can
  see that something is pending rather than wondering whether it failed.

Server-Sent Events are the nicer version of this and are a phase-3 item; polling is
honest, trivial and enough.

---

## 9. The frontend

Constraints we keep, non-negotiably, because they are security controls and not style
choices: **no build step, no framework, ES modules only, strict CSP with no inline
scripts, everything rendered through `textContent`, the token in a module variable and
never in `localStorage`.** A bigger dashboard does not get to relax any of those.

What the dashboard needs that `admin.html`'s four static panes cannot give: navigation,
a reusable table with filters, a detail view, and forms generated from data. So we add a
tiny internal structure — a hash router and a handful of component modules — and no
dependencies.

```
frontend/
  index.html        landing / manual lookup / sign in
  scan.html         (was verify.html)  the tap landing page — the asset passport
  report.html       report a fault or a problem
  app/
    index.html      the dashboard shell (one page, hash-routed)
    router.js
    api.js          fetch wrapper, token handling, error envelope -> message
    ui/table.js     sortable, filterable, paginated table
    ui/form.js      renders and validates a form FROM a field_spec
    ui/chart.js     a couple of small inline-SVG charts, no library
    views/overview.js  assets.js  asset-detail.js  categories.js
                       lots.js  incidents.js  stocktake.js  tickets.js
                       reports.js  people.js  posture.js
```

### 9.1 The tap page (`/c`) — the asset passport

What a person sees after tapping a DSO. One screen, phone-shaped, no login required.

```
┌──────────────────────────────────────┐
│  ✅  Verified                        │   <- verdict band, colour-coded
│  Tektronix TBS1052C                  │
│  EXTC/DSO/2026/0042                  │
├──────────────────────────────────────┤
│  Where it lives   EXTC Lab 3, Bench 4│
│  Department       Electronics & Telecom
│  Custodian        Prof. ——           │
│  Condition        Healthy            │
│  In service since 12 Aug 2026        │
│  Warranty         until 11 Aug 2029  │
│  Calibration      due 12 Aug 2027    │
├──────────────────────────────────────┤
│  What was checked                    │
│   Record signature          pass     │
│   Tap counter               pass     │
│   Lifecycle                 pass     │
│   Calibration               pass     │
│   Physical binding: counter          │
├──────────────────────────────────────┤
│  [ Report a problem ]                │
│  [ Sign in to update this asset ]    │
└──────────────────────────────────────┘
```

Band 3 ("what was checked") stays, for the same reason it existed before: it is the
honesty requirement and it is the deployment metric for the paper — *what fraction of
real scans received the strong guarantee?* The four rows change meaning but not count.

A signed-in user sees extra buttons on this same page, which is what makes the system
pleasant to actually use: **Mark condition**, **Record location**, **Raise a fault**,
**Confirm for stocktake**. Tap the thing, press one button, done — no hunting for it in
a table.

### 9.2 The dashboard (`/app`)

**Overview** — the page the HOD opens. Six number tiles (total assets, in service, under
repair, faulty, calibration overdue, not seen in 12 months), a condition donut, a
department bar chart, open incidents, and recently registered items.

**Assets** — the register. Search by code/serial/make/model; filter by category,
department, location, condition, lifecycle, warranty state; sort any column; export CSV.
The table is generic: the columns shown are driven by the selected category's
`field_spec`, so a `LAPTOP` filter shows RAM and CPU columns and a `DSO` filter shows
bandwidth.

**Asset detail** — everything about one item in four tabs: *Details* (editable, form
generated from `field_spec`), *History* (sightings, condition changes, transfers — one
timeline), *Maintenance* (tickets and repair history), *Documents* (invoice, warranty
card, calibration certificate; phase 2).

**Categories** — the page that makes the system flexible. Add a category, give it a
name, a prefix, and a list of fields. Save. It is immediately usable on the Pi and in
every form, with no deployment. This page is the direct answer to *"we should be able to
add different items as well."*

**Lots** — purchase orders. Open (two people), see used/quota, close, attach invoice.

**Stocktake** — start a run, pick a scope (one lab / one department / everything), hand
phones to staff, watch the progress bar fill as taps arrive, and at the end get three
lists: *found*, *not found*, *found somewhere unexpected*. Export it; that is the
physical verification report.

**Incidents** — unchanged in function: the MTA triage queue, with the same warning text
and the same note-required resolution.

**Tickets** — fault complaints, assignment, status, close.

**Posture** — the health/config panel we already have, plus the new counters.

### 9.3 Mobile

Staff will do most of this on a phone, standing in a lab. The scan page must be
phone-first (it already is). The dashboard should be readable on a phone, and the three
actions that happen *while standing next to an asset* — update condition, raise a fault,
confirm for stocktake — must be reachable in one tap from the scan page, never only from
a desktop table. The existing PWA manifest and service worker stay; the service worker
still must never cache an API response.

---

## 10. Deploying on the college server

Today: Cloudflare Worker + Render + Supabase. Tomorrow: one Linux box the college owns.

| Layer | Now | On the college server |
|---|---|---|
| Edge / rate limit | Cloudflare Worker + KV | **nginx** (TLS termination, basic rate limit, static files) + the existing `rate_limit_bucket` table, which was built exactly for the case where the edge is bypassed. Set `EDGE_EXPECTED=false`. |
| App | Render, gunicorn | gunicorn under **systemd**, same pinned command, still 2 workers (the in-process rate-limiter correctness argument is unchanged). |
| Database | Supabase Postgres | Local PostgreSQL. **RLS and the `anon`/`authenticated` revokes become less critical** (there is no PostgREST), but keep them — they cost nothing and the deployment may move. |
| Nightly jobs | GitHub Actions | systemd timers or cron: audit retention, Merkle root publication, database backup to a second disk and off-site. |
| Secrets | Render env vars | A root-owned `.env` with `chmod 600`, or systemd `LoadCredential`. **The KEK must not sit next to the wrapped keys it unwraps** — on one box that separation gets weaker, and that is a limitation to write down, not to hide. |
| TLS | provided | A real certificate. **This is mandatory, not optional:** Web NFC, geolocation and service workers all require a secure context. If the college gives us a subdomain, use Let's Encrypt; if the server is intranet-only, an internal CA plus the certificate pushed to staff devices. |

**Three deployment decisions to make early, because they are hard to reverse:**

1. **The host name goes into every tag, physically.** `https://<host>/c?m=…&t=…` is
   written into the NDEF record at enrolment. Changing the domain later means
   re-writing every tag. Decide the final hostname **before** tagging anything.
   Shorter is better; the layout budget is in `pi/tag_layout.py`.
2. **Intranet-only or public?** Intranet-only is safer and simpler, but then nobody can
   check an asset from outside, and a phone on mobile data cannot either. Recommendation:
   publicly reachable hostname, everything except the thin anonymous scan view behind
   login.
3. **Backups.** A register with no backup is not a register. Nightly `pg_dump`,
   encrypted, to a second machine, plus the transparency root as an independent integrity
   check — if a restored backup's Merkle root does not match the published one, somebody
   changed something.

---

## 11. What a person can actually do, in plain words

**A student or anyone at all**, with no account, taps an instrument with their phone:
sees what it is, which lab it belongs to, whether it is healthy, and a button to report
that it is broken. No app, works on iPhone and Android.

**A lab assistant** signs in once on their phone. They walk the lab tapping things. Each
tap opens the asset and they press one button: *Healthy*, *Faulty*, or *Raise fault*.
At the end of the hour the register knows the true state of the lab and who recorded it.

**A lab in-charge / custodian** opens the dashboard and sees every asset they are
answerable for, what is broken, what is overdue for calibration, what tickets are open
against their lab, and what the last stocktake could not find.

**A department admin** registers new equipment: opens a purchase order lot (with a
second person countersigning), takes the Pi and a reel of tags to the store, taps each
new item, and the dashboard fills up. When a new *kind* of item arrives — say the
college buys 3D printers for the first time — they add a "3D Printer" category with the
fields that matter for it, and everything (Pi prompts, forms, tables, filters) adapts
with no code change.

**An HOD or the principal** opens the overview: how many assets, worth how much, in what
condition, by department. One click to the list behind any number.

**An auditor (NAAC/NBA, or the college's own)** gets read-only access to everything,
plus the stocktake reports, plus the published transparency log — which lets them check
that the register has not been quietly edited to make the numbers look better. Very few
asset systems can offer that; ours already does.

**And underneath all of it**, quietly: every tap advances a counter that cannot be
wound back, so if somebody copies an asset label onto a second box, or marks a stocktake
done from a screenshot without walking to the lab, the system notices and a human is
asked to look.

---

## 12. Build order

Each phase ends in something that works end to end. Nothing in a later phase is needed
to demo an earlier one.

**Phase A — foundations (schema + verdicts).**
New schema files; `asset_category` with `field_spec` and its validator; rewrite
`verification.py` terminal states; regenerate `test_verdict_machine.py`; update the
shared test vectors for the new sealed-field set. *Done when the full unit suite is green
and the exhaustive verdict enumeration passes.*

**Phase B — backend surface.**
`services/assets.py`, `categories.py`, `state.py`, `lots.py`; split `routes/admin.py`;
`/verify` returns asset fields and writes sightings; two response tiers. *Done when the
integration tests enrol an asset, scan it, change its condition and read the history
back.*

**Phase C — Pi.**
`lot_session.py`, category-driven prompts, new sealed fields, new schema string. *Done
when a real tag is written and the asset appears in the database through the drainer.*

**Phase D — frontend core.**
Dashboard shell, router, API module, table and form components; Overview, Assets, Asset
detail, Categories, Lots; the new scan page. *Done when a category added in the UI shows
up as prompts on the Pi and as columns in the table.*

**Phase E — login and roles.**
`/auth/login`, Argon2id or LDAP, role→scope mapping, per-department scoping. *Done when
a `viewer` cannot see another department and an `auditor` cannot write.*

**Phase F — workflows.**
Tickets, transfers, issue/return, stocktake runs and the exception report, condemnation.

**Phase G — deployment.**
nginx + systemd + local Postgres + TLS + backups + the nightly jobs ported off GitHub
Actions. Load test on the actual box.

**Phase H — the nice ones.**
Alerts and email digests, CSV import of the existing register, depreciation, label
printing, documents/attachments, SSE live updates, parent–child asset grouping.

A realistic first milestone is **A + B + C + D**: that is a working, flexible asset
register with NFC verification and a usable dashboard, and it is demonstrable.

---

## 13. Things to decide, and things to be honest about

**Decisions needed from you before Phase A:**

1. The final hostname (it is baked into every tag — see §10).
2. Does the college have LDAP/AD we can bind to, or do we manage passwords ourselves?
3. Is there an existing asset register (Excel, Tally, a department file) we must import?
   The format drives the CSV importer and possibly the `asset_code` scheme.
4. Does the college have an asset numbering convention already? If yes we follow it; if
   no, we mint `{dept}/{prefix}/{year}/{seq}`.
5. Which labs/departments are in the pilot. Starting with one lab is much better than
   starting with the whole college.

**Limitations to state plainly in the report, not bury:**

- Tag transplant is still open. Somebody can peel the inlay off a good DSO and stick it
  on a bad one. The counter does not notice, because it is the same chip. Tamper-evident
  labels are the answer, and that is a procurement decision, not a code one. This is the
  same limitation the paper already states for medicine packaging.
- The velocity bound loosens as an asset ages (§3). MTA is weakest on old assets.
- Geolocation from a browser is a claim, not evidence (§4.5).
- Key separation is weaker on a single college server than it was across three cloud
  providers (§10).
- The system detects inconsistency; it does not identify who did it. Every verdict string
  must keep respecting that distinction, exactly as it does now.
