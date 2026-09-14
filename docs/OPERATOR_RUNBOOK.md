# OPERATOR_RUNBOOK.md

Day-to-day procedures. ARCHITECTURE.md is the design; this is what you actually
do at the bench and when something goes wrong.

---

## 1. Before every batch

Run through this. It takes two minutes and it is the difference between a batch
of packs that verify and a batch that does not.

```bash
cd pi
python enroller.py --status          # outbox must read depth=0, failed=0
```

- [ ] `/health` posture reads the way you expect (open the admin console)
- [ ] `outbox depth = 0` — nothing from the last run is still owed to the backend
- [ ] `outbox failed = 0` — or you have already dealt with each failed row (§5)
- [ ] The Pi's clock is right. `enroller.py` checks this and refuses to start if
      it drifts more than 10 s, but knowing why beats being told.
- [ ] You have a second person for the countersignature. One operator typing two
      names is theatre, not a control.
- [ ] A scrap tag has survived the full flow today

---

## 2. Opening a batch

Two different people. `countersigned_by <> opened_by` is a **database CHECK**, so
there is no way to talk past it — but the point is a second human, not a second
string.

In the admin console → **Batches** → *Open a new batch*, or:

```bash
curl -X POST "$BACKEND/api/v2/admin/batches" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_ref":"AMX-2026-09-001","product_name":"Amoxicillin 500mg",
       "mfg_date":"2026-09-10","shelf_life_days":730,"quota":5000,
       "opened_by":"shreya","countersigned_by":"the-second-person"}'
```

**Set the quota to what you are actually going to make, not to a round number.**
The quota is what bounds the damage if the Pi's signing key is stolen (F1): an
attacker can only enrol into the remaining quota of an open batch. A quota of
50,000 "to be safe" is a 50,000-tag compromise waiting to happen.

`mfg_date` comes from here and **never from an operator typing it per pack**
(F8). One typo would otherwise put a wrong expiry date on a medicine pack,
signed and permanently recorded.

---

## 3. Running a batch

```bash
cd pi
python enroller.py --batch AMX-2026-09-001
```

The tool drains any backlog first, then prompts for `product_id` per pack.

**Watch the outbox depth in the prompt line.** Depth above zero for more than
15 minutes means genuine packs are shipping without records. That is the 3 a.m.
alert (§14.5) and it is the worst failure mode this system has: a consumer
holding real medicine being told it is not in the register.

### When a tag is rejected

| Message | What it means | What to do |
|---|---|---|
| `TAG REJECTED: vendor byte …` | Not NXP silicon (A12) | Bin it. If a run of these, stop and call procurement. |
| `originality check FAILED` | Chip failed NXP's signature (A2) | **Quarantine it, do not bin it quietly.** A run means counterfeit silicon in your supply. |
| `DISCARD THIS TAG: NDEF read-back mismatch` | Torn or bad write (A13) | Use a new tag. Never ship a tag that failed read-back. |
| `DISCARD THIS TAG: the mirror did not fire` | Config did not take | Use a new tag. This one would say `MIRROR_DISABLED` on every scan, forever. |
| `DISCARD THIS TAG: counter did not advance` | `NFC_CNT_EN` failed, or `CNT_BYTE_ORDER` is wrong | Use a new tag and re-run `--calibrate`. |

**There is no QR fallback any more** (F4, §12.2). v1 printed a QR of the same URL
when the NDEF write failed. A QR is static copyable data — a pack shipped with
one has *none* of the physical binding this system exists to provide, and the
consumer cannot tell the difference. If the write fails, the tag goes in the bin.

---

## 4. Closing a batch

```bash
python drainer.py --reconcile --admin-token "$ADMIN_TOKEN"
```

Then close it in the admin console.

Reconciliation walks every `acked` row and confirms the record is really in the
register. It catches the rare case where a 2xx was received but the row was later
lost. **Do not close a batch with unconfirmed rows.** The cost of missing one is
unverifiable packs in circulation.

---

## 5. When the outbox has failed rows

```bash
python enroller.py --status
```

A `failed` row is **terminal**: the server returned 400/403/409/413/415 and no
amount of retrying will change the answer. Each one is a pack with no record.

| Error code | Cause | Action |
|---|---|---|
| `batch_quota_exhausted` | You enrolled past the quota | Open a new batch; **quarantine those packs** |
| `batch_not_open` | Batch closed or recalled mid-run | Same |
| `tag_already_enrolled` | That UID is already in the register | Investigate — a duplicate UID is a supply problem |
| `mfg_date_invalid` | Batch metadata disagrees | Fix the batch record; those packs need re-enrolling on new tags |
| `bad_signature` | Clock drift, or a revoked device | Check the clock first; it is almost always the clock |
| `decrypt_failed` | Corrupted payload | Escalate — this should not happen |

**Quarantine the physical packs corresponding to failed rows.** The `payload`
column in `outbox.db` tells you which `product_id` each was.

---

## 6. Incident triage

Admin console → **Incidents**. Newest first.

A divergence means a pack's tap counter did not increase the way it should have.
**It is evidence of a duplicate in circulation. It is not proof of which pack is
the copy.** An attacker who pre-advances a clone's counter causes the *genuine*
pack to trip the alarm.

| Kind | Reading |
|---|---|
| `repeat` | The same counter value twice — a copied URL, or a genuine double-scan |
| `rollback` | A lower value than seen before — two objects with one identity |
| `velocity` | More taps than the pack's age allows — a fast-forwarded clone |
| `mirror_disabled` | The tag never mirrored — usually a manufacturing defect, not an attack |

### Resolving

- **`confirmed`** — you believe there is a real duplicate. The tag stays flagged.
- **`false_positive`** — **the only thing that un-flags a tag.** Use it when you
  know the cause (an operator scanned the same pack twice during testing, a
  demo unit, a consumer who tapped repeatedly).
- **`closed`** — dealt with, tag stays flagged.

A note is **mandatory**. This decision has to be explainable later.

**Do not clear flags to tidy the queue.** The stickiness is the control (G1): a
counterfeiter must not be able to discover which stolen identifiers are still
good by probing and watching a flag clear.

---

## 7. Issuing a recall

Admin console → **Batches** → *Recall*, or:

```bash
curl -X POST "$BACKEND/api/v2/admin/recall" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"batch_ref":"AMX-2026-09-001",
       "notice":"Recalled 2026-09-12: possible contamination. Return to your pharmacist."}'
```

**The notice is what a patient reads on their phone.** Write it for them, not for
a regulator. It is mandatory for that reason.

The recall re-signs every affected row inside the same transaction, because
`status` is inside the row signature. That is why a recalled pack says
**RECALLED — do not use** rather than the generic *"we could not confirm this
pack's record"*.

Verify it worked: scan one pack from the batch and read the screen.

---

## 8. Admin tokens

Mint offline, never on the server:

```bash
python backend/scripts/mint_admin_token.py \
  --key "$ADMIN_TOKEN_KEY" --sub shreya \
  --scopes batch:read batch:write incident:read incident:write --ttl 3600
```

- Maximum lifetime 12 hours, enforced at verification.
- Paste into the console's session-only field. **It is never stored** — an XSS
  would otherwise yield a token that can recall a batch.
- `ADMIN_TOKEN_KEY` never goes on the backend. The backend holds only the public
  half, so there is no admin secret on the server to steal (D14).

---

## 9. Edge failover

If the Cloudflare Worker is down or has to be abandoned:

1. The origin already serves every route the Worker does — `/c`,
   `/api/v2/verify`, `/api/v2/report`, `/api/v2/enrol`, `/api/v2/admin/*`.
2. Point `PUBLIC_HOST` at the Render origin **for tags written from now on**.
3. **Tags already in the field still point at the Worker host.** If that host is
   gone, they stop resolving and there is no way to fix them.

That last point is why open question 3 in §22 — *is the Worker host permanent?* —
has to be answered before the first real batch, not after.

While the Worker is down: rate limiting falls back to the Postgres limiter in
`backend/ratelimit.py`, negative-lookup caching stops, and the origin's cold
start becomes visible to consumers again.

---

## 10. Backups

Nightly, encrypted to an offline `age` key, uploaded as a GitHub Actions
artifact. The decryption key is on no server and in no CI secret (F8a).

**Test the restore quarterly.** An untested backup is not a backup.

| Quarter | Restored on | By | Result |
|---|---|---|---|
| | | | |
| | | | |

Restore procedure:

```bash
age -d -i backup-key.txt backup-2026-09-12.sql.age > restore.sql
createdb scratch_restore
psql scratch_restore < restore.sql
psql scratch_restore -c "SELECT COUNT(*) FROM products;"
```

Check the count against the transparency root for that date — that is the whole
point of publishing `record_count` alongside the Merkle root.

---

## 11. Checking the transparency log

Anyone can do this, including someone who does not trust us:

```bash
python backend/scripts/verify_transparency.py --log-dir log --latest
python backend/scripts/verify_transparency.py --check-audit-chain   # needs DATABASE_URL
```

Two things to watch for:

- **A bad signature** — the published root was not produced by the transparency
  key.
- **`record_count` going backwards** — rows were deleted from the register. The
  verifier reports this explicitly; the register only ever grows.

---

## 12. The four alert signals

Everything else is a dashboard number. Four signals that always mean something
beat twenty that mostly do not.

| Signal | Meaning | Urgency |
|---|---|---|
| Any `divergence_incident` row inserted | A possible clone is in circulation | **Security. Triage today.** |
| `originality_rejections > 0` on a production batch | Your supplier may have shipped counterfeit silicon | **Security. Call procurement.** |
| Outbox depth > 0 for more than 15 minutes | Genuine packs are shipping without records | **This is the 3 a.m. one.** |
| Verify error rate > 1% over 5 minutes | The consumer path is broken | Page someone |

---

## 13. Turning on tag locking

**Do not do this until you have decided the Worker host is permanent**, and not
until a scrap tag has survived the full locked flow.

Every step is **irreversible**. A mistake destroys the tag.

1. Set `TAG_LOCK_ENABLED=true` in `pi/.env`.
2. Set `TAG_PWD_MASTER` if it is not already set.
3. Run with the explicit acknowledgement:
   ```bash
   python enroller.py --batch <ref> --i-understand-this-is-permanent
   ```
4. Confirm `/health` now reports `"tag_locking": "enabled"` and the amber banner
   is gone from the admin console.

This closes A7 and A8, which are open by design while locking is off.
