# tests/attacks/ — the 96-attack suite

**Written (Phase 8).** One file per class, one function per §16 ID, each emitting
a JSONL evidence record. See ARCHITECTURE.md §16 and §17.3.

## What the suite does NOT do

The brief was explicit: **do not add code addressing each attack one by one** in
the *product*. The security has to already be in the system — §16 is a
*traceability matrix*, not a work list. These tests **exercise** the mechanisms
that already exist; none of them adds a per-attack special case to a route
handler. If you are about to do that, stop: either the mechanism is missing from
the design (flag it) or you are patching a symptom.

## Files

| Class | File | §16 IDs |
|---|---|---|
| A — tag / physical | `test_class_a_tag.py` | A1–A14 |
| B — NDEF / URL | `test_class_b_url.py` | B1–B10 |
| C — client / browser | `test_class_c_client.py` | C1–C10 |
| D — API / protocol | `test_class_d_api.py` | D1–D32 |
| E — cryptographic | `test_class_e_crypto.py` | E1–E13 |
| F — infra / supply chain | `test_class_f_infra.py` | F1a–F10a |
| G — business logic / abuse | `test_class_g_business.py` | G1–G9 |
| H — forward-looking / quantum | `test_class_h_quantum.py` | H1–H6 |

## Carried back from the v1 suite (D25–D32, E12–E13)

v1 had a seven-category suite (replay, clone, device impersonation, brute force,
SQL injection, MITM, birthday) that was deleted in 7e06ce2 when this matrix
replaced it. Sixteen of its twenty-two cases already map onto A–H IDs. Six did
not, and were silently lost in the move:

| v1 category | Now | Note |
|---|---|---|
| SQL injection ×6 | D25–D30 | retargeted: no `nonce` field, no UID-only lookup |
| Brute force ×2 | D31–D32 | D21 records the posture; D32 is the measurement |
| Birthday validation ×2 | E12–E13 | E4 only asserts the v1 nonce scheme is gone |

Three v1 expectations do **not** carry over, and the tests say so rather than
quietly asserting the old value:

- A verbatim replay returns the **stored response**, not `409` — idempotency
  replaced the nonce-uniqueness constraint (D5, §9.5 step 6).
- There is no 64-bit write nonce to extrapolate a collision bound to. The live
  spaces are a 122-bit uuid4 idempotency key, a 128-bit binding token and a
  256-bit `tag_index`. E13 reports those and records the retired 64-bit figure
  beside them, so the v1 number in the paper stays traceable.
- An injection payload against verify is a `400 malformed_parameters` from the
  strict `m`/`t` pattern, not an `unknown` verdict. Stronger, but different.

## How to run

Classes E, F and H are properties of the primitives, the committed artifacts and
the schema, so they run with the unit tests — no server needed:

```
pytest tests/attacks/test_class_e_crypto.py tests/attacks/test_class_f_infra.py \
       tests/attacks/test_class_h_quantum.py
```

Classes A, B, C, D and G drive a **live server** and skip unless `TEST_BASE_URL`
(and, for enrol/verify, `TEST_ADMIN_TOKEN`, `TEST_FIELD_RECIPIENT_PUB`, a
registered `TEST_DEVICE_*`) are set — see `docs/OPERATOR_RUNBOOK.md`. Run them
against a **pinned worker count** (§17.3):

```
TEST_BASE_URL=... TEST_WORKER_COUNT=2 pytest tests/attacks/
```

Each test appends to `tests/evidence/attacks-<timestamp>.jsonl` with
`{attack_id, outcome, expected, detail, worker_count, ...}` — the citable record
behind the §16.9 scoreboard. `outcome` is one of `blocked | detected | open |
inconclusive`.

### The floods must run last

D31 and D32 send 40 and 30 requests. They exhaust the rate limiter, so anything
after them sees spurious 429s. v1 encoded this in a filename
(`test_zz_bruteforce.py`) so alphabetical collection would put it last; that does
not survive one-file-per-class, because classes E–H collect after D and class G
drives the live server.

They therefore carry `@pytest.mark.flood`, and `conftest.py` sorts flood-marked
items to the end of the whole session. Run the suite normally — the ordering is
enforced, not a convention. To skip them while iterating:

```
pytest tests/attacks/ -m "not flood"
```

### Turning a run into results

```
python tests/report.py                                        # audit cross-reference
python tests/generate_attack_analytics.py --evidence-dir tests/evidence
```

`report.py` writes `evidence/report.md` and needs `DATABASE_URL` — the audit log
has no HTTP surface by design, so the cross-reference needs a direct connection.
Without it the script still runs and records the gap.
`generate_attack_analytics.py` writes `evidence/analytics_summary.json` and prints
a Markdown summary: malicious success rate, aggregate status distribution,
per-class breakdown, injection defense-layer split, birthday validation.

**Clear `evidence/` before a run you intend to cite.** Logging is append-only;
both scripts warn when an attack ID appears in more than one file, but the figures
are only clean if the directory is.

## Honesty rule (§16.9)

The known-open items do **not** get a green test. They record `outcome="open"`
and skip with the reason, so a reviewer sees them as open rather than as a curated
clean sweep.

## Rules for when they are written (§17.3)

- One file per class: `test_class_a_tag.py`, `test_class_b_url.py`, …
- One function per ID: `def test_a3_counter_freeze_replay():`
- Each writes a structured JSONL evidence record. Carry over v1's
  `tests/evidence/*.jsonl` + `report.py` approach — it was a genuinely good idea
  and it is what makes the results citable.
- Tests run against a **live server with a known, pinned worker count**. v1's
  rate-limit evaluation is not defensible without this: per-worker counters made
  the observed limit N times looser than the configured one (F16).
- Attack tests **never mutate production data**. A separate Supabase project, or
  a batch reserved for testing.

## What already covers part of this ground

Several attacks are already exercised by the tests that exist, because their
mechanism is a property of a unit rather than of a deployment:

| ID | Where it is already tested |
|---|---|
| A1, A3, A4, A5 | `unit/test_verdict_machine.py`, `integration/test_verify_flow.py` |
| B3, B4, B5, B6, B8 | `unit/test_mirror_parse.py` |
| B7 | `unit/test_verdict_machine.py`, `integration/test_verify_flow.py` |
| B10 | `unit/test_tag_layout.py` |
| D2, D4, D5, D7, D8, D9, D10 | `integration/test_enrol_flow.py` |
| D11, E1, E3 | `unit/test_cross_device.py` |
| D12, D13, E6 | `unit/test_rowsig.py` |
| D15, D16 | `integration/test_dead_routes.py` |
| D18, D19 | `integration/test_enrol_flow.py` |
| D22, F23, F24 | `integration/test_verify_flow.py` |
| E8 | `unit/test_cross_device.py`, `integration/test_enrol_flow.py` |
| F6a | `unit/test_errors.py` |
| F10a, F12, G5 | `integration/test_batch_quota.py` |
| F25 | `integration/test_audit_chain.py` |
| F30 | `integration/test_audit_chain.py` |
| G1 | `integration/test_verify_flow.py`, `integration/test_concurrency.py` |
| G2 | `integration/test_recall.py` |

## Known-open, by design or by constraint (§16.9)

Do not write a test that "passes" for these. They are open, and saying so is
worth more than a green tick that a reviewer suspects was curated.

| ID | Why |
|---|---|
| A11 | Tag transplant — irreducible without tamper-evident packaging |
| A7, A8 | `TAG_LOCK_ENABLED=false` for this phase; closes when the flag flips |
| B1 | No custom domain under the free-only constraint |
| E10, F5a, F10a | Partial — no HSM, no device attestation |
| H1, H5, H6 | Quantum explicitly out of scope (D4) |
