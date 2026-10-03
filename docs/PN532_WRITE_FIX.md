# PN532 NDEF write failure — diagnosis, fixes, and how to run the pipeline

**Status:** fixed in code, **not yet confirmed on hardware.**
**Commit:** `9304a45` on `claude/gallant-cannon-htzqj8`
**Date:** 2026-10-03
**Scope:** `pi/ntag.py`, `pi/enroller.py`. No backend, Worker or frontend change.

---

## 1. One-paragraph summary

The multi-page NDEF write to NTAG216 over I²C failed intermittently — and by the
end of a night's testing, almost always — with CRC errors (`0x02`), timeouts
(`0x01`), RF protocol errors (`0x0B`) and twice a single-byte read-back mismatch.
Short commands (`GET_VERSION`, `READ_SIG`) succeeded every time. The cause was
**not** the RF link, the tags, the power rail or the bus speed. It was two
defects in how write failures were handled inside `pi/ntag.py` — a rejected
write was being recorded as a success, and a driver timeout silently
desynchronised the I²C frame stream — plus a third, unrelated bug that made
`READ_CNT` fail deterministically on any tag that had not already been through
`--calibrate`.

---

## 2. Symptoms as observed

| Run | Result |
|---|---|
| `--calibrate` | read-back mismatch, byte 0 = `0x3A` |
| round 3 (26 writes → `FAST_READ`) | clean |
| next run | `InCommunicateThru` status `0x0B` (RF protocol error) |
| earlier runs | status `0x02` (CRC), status `0x01` (timeout, usually during read-back) |

Two properties of this pattern turned out to be the whole diagnosis:

1. **Short commands never failed.** One frame per command, nothing queued behind
   it to desynchronise.
2. **`0x3A` is the `FAST_READ` opcode.** No RF fault, no amount of slowing the
   bus and no improvement in tag placement can put a command opcode at *data
   offset 0* of a read-back. That is frame misalignment in the driver, full stop.

---

## 3. What was ruled out first (all correctly)

These were each tested and eliminated before the code was examined. Recorded so
nobody repeats them:

- The physical tags — three different tags, same failure
- The I²C bus connection — stable via `i2cdetect`
- Pi power supply — clean via `vcgencmd get_throttled`
- I²C clock speed — confirmed at the 100 kHz default
- Timing around the originality check — settle delay added, no change
- The originality check itself — removed entirely, no change
- Leftover tag configuration — tag reset to factory defaults, same failure
- Command-mode switching mid-sequence — forced tag re-selection, no change
- PN532 power margin — re-powered from an independently supplied ESP32 with
  shared ground, no change (this is a real, documented issue with this chip, but
  it was not this)

**The conclusion drawn at the time** — "intermittent garbled frames and RF
protocol errors mean a marginal physical link" — was the reasonable reading of
that evidence. It was wrong, and the `0x3A` byte was the clue that contradicted
it.

---

## 4. Root causes

### 4.1 A rejected write was recorded as a success — `pi/ntag.py`

`write_page` called the Adafruit helper and **discarded its return value**:

```python
pn532.ntag2xx_write_block(page, list(data))   # return value ignored
last_err = None
break
```

In `adafruit-circuitpython-pn532==2.4.4`, that helper is:

```python
response = self.call_function(_COMMAND_INDATAEXCHANGE, params=params, response_length=1)
return response[0] == 0x00
```

It **returns `False`** — it does not raise — whenever the PN532 reports a
non-zero status. So when the reader said *"that write failed"* with status
`0x01`, `0x02` or `0x0B` — the exact three codes seen in testing — `write_page`
saw no exception, set `last_err = None`, broke out of the retry loop, slept the
settle delay, and reported success.

**Consequences:** the three configured retries were never spent on the failure
mode actually occurring; the page simply stayed unwritten; and the only thing
that noticed was the read-back byte-compare two steps later. That is the
single-byte "mismatch" with no preceding error.

### 4.2 A driver timeout silently desynchronised the I²C frame stream

`call_function` returns `None` on two paths — `send_command` failing to see the
ACK, and `process_response`'s `_wait_ready` expiring. The helper then evaluates
`response[0]` and raises `TypeError: 'NoneType' object is not subscriptable`.

`write_page` caught bare `Exception`, so that became an ordinary retry — **but
the response frame the PN532 posts a moment later was never read off the bus.**
Nothing drained it, re-selected the tag, or re-synced.

Why it then went undetected through a whole 24–26 page burst:

```python
# process_response, adafruit_pn532.py
if not (response[0] == _PN532TOHOST and response[1] == (command + 1)):
    raise RuntimeError("Received unexpected command response!")
```

Every write in the loop is the **same command**, so a stream running one frame
behind **passes that check**. The burst runs to completion consuming the previous
page's response as the current page's, and the trailing `FAST_READ` lands on a
misaligned frame. Hence `0x3A` at data offset 0, and hence the varying status
codes — whatever stale byte happened to land in the status position.

### 4.3 `READ_CNT` ran before the counter was enabled — `pi/enroller.py`

Enrolment step 10 read the counter; step 11 set `NFC_CNT_EN`. A virgin or
factory-reset NTAG216 ships with `NFC_CNT_EN = 0`, and the NXP datasheet is
explicit that **`READ_CNT` is NAKed while it is `0`** — the PN532 surfaces that
NAK as a bare `InCommunicateThru` status error.

The codebase already documented this trap, in `calibrate()`'s own docstring:

> A virgin NTAG216 ships with `NFC_CNT_EN = 0`, so `READ_CNT` is NAKed until the
> counter is switched on… An earlier version issued `READ_CNT` against an
> untouched tag and died on a bare `InCommunicateThru` status

`enrol_one` walked straight into it. This was not a code slip — `ARCHITECTURE.md`
§12.1 specified the inverted order too, so the design document was wrong and the
code faithfully implemented it.

**This explains two observations that previously looked random:**

- **"Round 3 was clean."** It stopped at `FAST_READ` and never reached
  `READ_CNT`. Not evidence of a good link that run — evidence that the run did
  not execute the step that always fails.
- **"Factory reset, same failure."** A factory reset sets `NFC_CNT_EN` back to
  `0`, which *re-armed* this bug. Any tag that had been through `--calibrate` had
  the counter on and got further.

### 4.4 `FAST_READ` had zero slack in the driver's read buffer

`read_ndef` read the whole record in one `FAST_READ`. A record *fits* in one
PN532 frame, but `_read_frame(length)` calls `_read_data(length + 7)`, which for
a 96-byte record is **exactly** the 106 bytes the frame occupies on the wire.
`_read_frame` then skips leading `0x00` bytes before looking for `0xFF`, and the
PN532 over I²C does not emit a fixed number of them. One extra preamble byte
still parses; **two, and the frame checksum is computed over a slice Python has
silently truncated** — so the read fails or comes back a byte short.

This is the one place where the Pi's weak I²C clock-stretching handling could
genuinely bite. It cannot produce an opcode byte in the data.

### 4.5 Latent: the irreversible lock path could not run

`tag_config.apply_lock_sequence` reads page `0x02` to preserve the two UID bytes
that share it with the static lock bytes. `fast_read`'s guard started at
`USER_PAGE_FIRST = 0x04`, so it raised `FAST_READ range 0x02-0x02 outside user
memory`. Harmless while `TAG_LOCK_ENABLED=false`, **fatal the first time it is
flipped** — on the one path in the build with no recovery.

---

## 5. Fixes applied

All in commit `9304a45`.

| # | Problem | Fix | Where |
|---|---|---|---|
| 1 | Rejected write accepted as success | `_write_page_once` issues the byte-identical `InDataExchange` frame directly and raises on any non-zero status, **with the code decoded** | `pi/ntag.py:316` |
| 2 | Driver timeout desyncs the bus silently | New `BusDesync` exception + `resync()`; `write_page` resyncs before every retry | `pi/ntag.py:106`, `:177`, `:360` |
| 3 | `READ_CNT` before `NFC_CNT_EN` | Steps 10 and 11 swapped | `pi/enroller.py:204`, `:220` |
| 4 | `FAST_READ` with no buffer slack | Chunked at `FAST_READ_CHUNK_PAGES` (16 pages / 64 bytes) | `pi/ntag.py:266` |
| 5 | Lock path cannot read page `0x02` | `READ_PAGE_FIRST = 0x00`; read guard and write guard no longer share a bound | `pi/ntag.py:80`, `:266` |
| 6 | Rewrite retried into a desynced/deselected state | Enroller resyncs before rewriting after a read-back mismatch | `pi/enroller.py:185` |
| 7 | Errors were uninformative and possibly truncated | Module logger, `exc_info=True` on every failed attempt, `PN532_DEBUG=1` for raw frames, command names and decoded statuses in every message | throughout |

### Why the write is issued directly

`_write_page_once` sends exactly what `ntag2xx_write_block` sends —
`InDataExchange`, target `0x01`, `0xA2`, page, four data bytes — and a test pins
those bytes so the direct call cannot drift from the library's. Issuing it
ourselves buys three things: `None` is handled explicitly instead of crashing,
a non-zero status raises instead of returning `False`, and the PN532's **real
status byte lands in the error message** instead of a bool.

### How `resync()` works

Orphaned frames are drained by probing `firmware_version()`: a desynced stream
makes it raise *while consuming one stale frame*, so probing until it parses
leaves the stream aligned. The tag is then re-selected with
`read_passive_target`, because a failed exchange may have left it deselected and
`InCommunicateThru` carries no target byte to re-establish one. Up to
`BUS_RESYNC_PROBES` (4) attempts; failure past that is logged as *"no longer a
framing problem — check wiring and power."*

### Diagnostics you now get

- `WRITE of page 0x0c rejected, status 0x02: CRC error in the tag's response` —
  names the page, decodes the status
- `... response frame is probably still pending on the bus. resync() before the
  next command.` — says it is framing, and that it is recoverable
- `... 0x3a is a COMMAND OPCODE, which means the frame stream is misaligned
  rather than the tag misread` — **names the trap that cost a night**
- `FAST_READ returned 28B, expected 32B — the response frame was misparsed` —
  a short frame is reported as framing, not as tag contents

---

## 6. Deliberately *not* changed

| Not done | Why |
|---|---|
| I²C bus → 50 kHz | A real mitigation for this pairing, but it fixes none of the above. Try it only after the code fixes, and on its own so you learn something. |
| `NDEF_PAGE_WRITE_DELAY` → `0.1` | Pacing does not help when the failure signal is discarded rather than retried. |
| SPI migration | Needs rewiring *and* a code change. Last resort, after everything else. |
| `tag_layout.MAX_NDEF_BYTES` | Left at 252. Reads are chunked now, but widening the record format is a separate decision. |
| Decoupling capacitor / tag placement | Still worth doing. Not the cause. |

---

## 7. Verification performed

```
pytest backend/tests/unit                 120 passed
pytest backend/tests/unit/test_ntag_write.py   24 passed  (22 functions, one parametrised x3)
ruff check pi/ backend/tests/unit/         clean
python -m compileall pi/                   clean
CI grep checks (deployable isolation, no v1 config)   all pass
```

`backend/tests/unit/test_ntag_write.py` drives a fake PN532 — `pi/ntag.py`
imports only `os`, `time`, `logging` and `tag_layout`, so it runs on a laptop
with no reader attached. Each root cause above has a named regression test.

**Pre-existing, not introduced here:** `ruff` reports 5 errors in
`backend/tests/attacks/` (unused imports, import ordering) from the
`attacks added` commit. Verified identical on untouched `HEAD`. **CI will fail on
them** — they want a separate cleanup commit.

### Not yet verified

None of this has touched a real PN532. The `resync()` drain in particular is
sound against the library source but unproven against genuinely desynced
hardware. First clean enrolment on real hardware is the actual confirmation.

---

## 8. How to run the whole pipeline

### 8.1 Machine roles

| Machine | Holds | Runs |
|---|---|---|
| Laptop (Windows) | `keys.local.json`, `ADMIN_TOKEN_KEY` | key generation, admin-token minting, batch admin, tests |
| Raspberry Pi | `pi/.env`, `DEVICE_PRIVATE_KEY`, the minted token | `enroller.py`, `drainer.py` |

**`ADMIN_TOKEN_KEY` must never reach the Pi or the backend.** The backend holds
only `ADMIN_TOKEN_PUBKEY` and verifies signatures with it (§9.10). Only the
short-lived minted token travels.

### 8.2 One-time setup

Skip if already done — see `ARCHITECTURE.md` §20 for the authoritative version.

```bash
# Local environment
python -m venv venv
source venv/bin/activate                 # Windows: .\venv\Scripts\activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pip install -r pi/requirements.txt       # on the Pi only

# Keys — offline, on a machine you trust
python backend/scripts/gen_keys.py --out keys.local.json
python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <FIELD_PRIV_HEX>
python backend/scripts/wrap_secret.py --kek <KEK_HEX> --secret <ROW_PRIV_HEX>
```

Supabase — **Session pooler** connection string, not Direct connection (the
direct hostname is IPv6-only and will not connect from Render):

```sql
-- SQL Editor, in order
-- paste backend/schema/001_core.sql
-- paste backend/schema/002_rls.sql

INSERT INTO device_registry (device_id, label, public_key)
VALUES ('<DEVICE_ID uuid>', 'pi-line-1', '<DEVICE_PUBLIC_KEY hex>');
```

Then Render (from `render.yaml`, set every §21 variable, health check `/health`),
Cloudflare (`npx wrangler deploy`, note the `*.workers.dev` host), and counter
calibration:

```bash
cd pi && python enroller.py --calibrate     # on a SCRAP tag
```

Record the answer as `CNT_BYTE_ORDER` in **both** `pi/.env` and `backend/.env`.
Both sides refuse to start without it.

> **`PUBLIC_HOST` is baked into every tag URL and cannot be changed after a pack
> ships.** Fix it before enrolling any tag you intend to keep.

### 8.3 Get the fix onto the Pi

```bash
cd ~/major-nfc-v3
git fetch origin claude/gallant-cannon-htzqj8
git checkout claude/gallant-cannon-htzqj8
git log --oneline -1                  # must show 9304a45
```

No `pip install` — dependencies unchanged. No redeploy — nothing outside `pi/`,
docs and tests changed. `enroller.py` is a CLI, not a service, so the next
invocation picks up the new code.

### 8.4 Per-session: mint an admin token (laptop)

```powershell
cd "C:\path\to\major-nfc-v3"
.\venv\Scripts\activate

$key = (Get-Content keys.local.json | ConvertFrom-Json).admin_token.ADMIN_TOKEN_KEY

python backend/scripts/mint_admin_token.py `
  --key $key `
  --sub shreya `
  --scopes batch:read batch:write `
  --ttl 14400
```

`batch:read batch:write` covers exactly the enrolment workflow — listing batches
(what the Pi calls to open a session), opening, closing, and `--reconcile`. Do
not add `recall` or `incident:write` to a bench token.

`--ttl` is seconds: default 3600, **hard maximum 43200 (12 h)**, enforced again at
verification. When it expires the Pi fails to open a batch session; re-mint.

The token prints on stdout; the advisory notes go to stderr.

### 8.5 Install the token on the Pi

```bash
nano ~/major-nfc-v3/pi/.env
```

```
ADMIN_TOKEN=<paste the token>
```

Leave everything else alone — in particular keep `NDEF_PAGE_WRITE_DELAY=0.05`,
and do **not** put `PN532_DEBUG` in `.env`.

### 8.6 Pre-flight (Pi)

```bash
cd ~/major-nfc-v3/pi
source ../venv/bin/activate          # if you use one
python enroller.py --status          # must read depth=0 failed=0
timedatectl status                   # clock: enroller refuses >10s drift
```

Needs neither reader nor token. If depth > 0:

```bash
python enroller.py --drain
```

### 8.7 Open a batch (laptop)

Check for one already open:

```powershell
$BACKEND = "https://<your-app>.onrender.com"
$TOKEN   = "<minted token>"

curl.exe -s "$BACKEND/api/v2/admin/batches?status=open" `
  -H "Authorization: Bearer $TOKEN"
```

Open a new one — **two different people**, `countersigned_by <> opened_by` is a
database CHECK:

```powershell
curl.exe -X POST "$BACKEND/api/v2/admin/batches" `
  -H "Authorization: Bearer $TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"batch_ref\":\"TEST-2026-10-001\",\"product_name\":\"Bench test\",\"mfg_date\":\"2026-10-03\",\"shelf_life_days\":730,\"quota\":20,\"opened_by\":\"shreya\",\"countersigned_by\":\"<second-person>\"}'
```

**Set `quota` to what you will actually make.** The quota is what bounds the
damage if the Pi's signing key is stolen (F1). For a debugging batch, 20.

### 8.8 Run enrolment (Pi)

```bash
cd ~/major-nfc-v3/pi
PN532_DEBUG=1 python enroller.py --batch TEST-2026-10-001 2>&1 | tee ~/pn532-debug.log
```

`cd pi` matters — `load_dotenv()` resolves `.env` from the working directory.

The `tee` is the point: the frame dump scrolls fast, and truncated terminal
output is part of what hid the detail last night.

Flow: drains any backlog → batch banner → countersignature prompt → `product_id`
per pack → present a tag → blank input finishes.

**For the first run, change nothing physical.** Leave `NDEF_PAGE_WRITE_DELAY` at
`0.05` and the bus at 100 kHz, so a clean result is unambiguous.

### 8.9 Close out

```bash
python enroller.py --status                 # depth should be 0
```

```powershell
curl.exe -X POST "$BACKEND/api/v2/admin/batches/TEST-2026-10-001/close" `
  -H "Authorization: Bearer $TOKEN"
```

Reconcile before closing a real batch:

```bash
python drainer.py --reconcile --admin-token "$ADMIN_TOKEN"
```

### 8.10 Laptop-only checks (no hardware)

```powershell
cd backend
python -m pytest tests/unit -q
```

120 tests including the 24 new write-path cases. If these pass, the checkout is
sound and anything failing afterwards is genuinely hardware.

---

## 9. Troubleshooting

### Diagnose in this order

1. **`PN532_DEBUG=1` and capture frames.** This is the measurement that settles
   it. Wandering preamble length, or a response arriving for the previous
   command, means framing — no rewiring will help.
2. **Check the error names a page and a decoded status.** If it does not, you are
   on a pre-`9304a45` build that discarded the status byte and reported failed
   writes as successes. Update first; observations before that are unreliable.
3. **Then the physical layer.** `dtparam=i2c_arm_baudrate=50000` in
   `/boot/firmware/config.txt` + reboot; `NDEF_PAGE_WRITE_DELAY=0.1`; a
   decoupling capacitor across the PN532's 3V3/GND; short, firmly seated jumpers.
4. **SPI last.** Rewiring plus a code change. Only after 1–3.

### Message reference

| Message | Meaning | Action |
|---|---|---|
| `WRITE of page … status 0x01` | Tag did not answer in time | Hold the tag flat and still; a 24-page write is 3–5 s of continuous RF |
| `WRITE of page … status 0x02` / `0x0B` | CRC or RF protocol error on one page | Retries + `resync()` handle isolated ones. A run of them on every tag is the reader, not the tags |
| `response frame is probably still pending on the bus` | Driver timeout, stream desynced | Recovered automatically. Frequent → bus is marginal, see step 3 |
| `is a COMMAND OPCODE … frame stream is misaligned` | **Not an RF fault** | Framing bug. Do not chase power or bus speed. Capture frames |
| `bus resync FAILED after 4 probes` | PN532 not answering `GetFirmwareVersion` at all | No longer framing — check wiring and power for real |
| `DISCARD THIS TAG: counter did not advance` | `NFC_CNT_EN` did not take, or `CNT_BYTE_ORDER` is wrong | New tag; re-run `--calibrate` |
| `403` on enrolment POST | `X-Device-Id` not in `device_registry`, or not `active` | Check you are pointed at the database holding that row |

**A short command succeeding reliably while the multi-page write fails is not
evidence of a marginal link.** It is what a framing or error-handling bug looks
like.

### Rollback

```bash
cd ~/major-nfc-v3 && git checkout main
```

One command back to the previous behaviour. No stashing, no reverting.

---

## 10. Related reading

- `ARCHITECTURE.md` §6.8, §6.8.1, §6.8.2 — raw NTAG commands, the write path, chunked reads
- `ARCHITECTURE.md` §12.1 — the enrolment sequence (step 10/11 ordering)
- `ARCHITECTURE.md` §6.4, §20.7 — counter byte-order calibration
- `docs/OPERATOR_RUNBOOK.md` §3 — bench triage, including the write-failure table
- `backend/tests/unit/test_ntag_write.py` — the regression tests
