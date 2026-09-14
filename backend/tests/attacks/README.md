# tests/attacks/ — the 86-attack suite

**This is a scaffold. The attack tests themselves come later** — see
ARCHITECTURE.md §2 ("explicit non-goals") and §17.3.

## Why there is nothing here yet

The brief was explicit: **do not add code addressing each attack one by one.**
The security has to already be in the system. §16 is a *traceability matrix*, not
a work list: every one of the 86 attacks maps to a **mechanism that already
exists** in the design.

If you are about to add a special case in a route handler for one of these IDs,
stop. Either the mechanism is missing from the design — flag it — or you are
patching a symptom.

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
