# benchmarks/ — the four quantitative experiments

Implements `NFC_System_Quantitative_Attack_Test_Handoff`: four backend/test
experiments that produce measured, paper-ready analytics **without consuming
any additional NTAGs**. Everything here drives the live HTTP API of a
**test/staging** deployment — never production.

| # | Experiment | What's varied | Main measurement |
|---|---|---|---|
| 1 | Request-rate / latency saturation | RPS | p50/p95/p99 latency, throughput |
| 2 | Request-rate / error behavior | same RPS sweep (analysis of exp1's data) | 2xx/429/4xx/5xx/timeout rate |
| 3 | Database growth / scaling | registered-record count | verification latency vs DB size |
| 4 | Replay-storm attack | replay attempt count | first-detection point, detection rate |

Experiments 1 and 2 share one load sweep — exp2 does not send new traffic, it
re-classifies exp1's raw rows (handoff §2, §7.1).

## What this is NOT

This is **not** the pytest attack suite in `backend/tests/attacks/`. That
suite asserts pass/fail against the 96-attack matrix (`docs/ATTACK_MATRIX.md`)
and writes JSONL evidence per attack ID. These scripts measure **quantities**
(latency distributions, error rates, detection rates under scale) against a
live deployment over minutes, which is not what a pytest test is for — see
the handoff §1 and §13 ("do not claim a defense is effective just because a
pytest test passes").

The project's existing A3 (`test_a3_counter_freeze_replay_is_a_repeat`) and A4
(`test_a4_counter_rollback_is_detected`) tests are the qualitative,
single-shot version of what exp4 measures at scale — see
`backend/tests/attacks/test_class_a_tag.py`.

## 0. Golden rule (handoff §3)

Nothing here invents a route, a payload shape, an auth header, or a database
table. Every request in `scripts/common.py` reuses the exact construction
logic in `backend/tests/conftest.py` (`sign_request`, `make_tag`, `enrol`,
`verify`, `test_batch`) — same signing, same payload fields, same URL
parameters. If you change the enrol/verify contract, update both places.

## 1. Setup

### 1.1 Point at a TEST/STAGING deployment, never production

```bash
export TEST_BASE_URL=https://your-test-or-staging-host
```

### 1.2 Baseline sanity check — do this before any load

The handoff is explicit: **do not generate load if the basic verification
path is broken.** Fix the environment first.

```bash
cd backend
python -m pytest tests/attacks/test_class_a_tag.py -k "test_a3 or test_a4" -v -rs
```

This needs `TEST_ADMIN_TOKEN`, `TEST_FIELD_RECIPIENT_PUB`, and a registered
`TEST_DEVICE_*` identity — see `docs/OPERATOR_RUNBOOK.md` §8 for minting an
admin token (`backend/scripts/mint_admin_token.py`) and registering a device
public key in `device_registry`.

### 1.3 Environment variables this directory's scripts read

| Variable | Needed by | What it is |
|---|---|---|
| `TEST_BASE_URL` | all | the deployment under test |
| `TEST_ADMIN_TOKEN` | exp3, exp4, exp1 `--self-enrol` | opens a benchmark batch — mint with `backend/scripts/mint_admin_token.py`, scopes `batch:read batch:write` |
| `TEST_FIELD_RECIPIENT_PUB` | exp3, exp4, exp1 `--self-enrol` | the backend's public X25519 key (public by definition) |
| `TEST_DEVICE_PRIVATE_KEY` | exp3, exp4, exp1 `--self-enrol` | an Ed25519 private key hex whose public half is `active` in `device_registry` on the target — omit to generate one, but it must still be registered before enrolment succeeds |
| `TEST_DEVICE_ID` | same | the device id that key is registered under |
| `TEST_WORKER_COUNT` | all | **record this.** A rate-limit result without it is meaningless — see `backend/tests/attacks/README.md` |

If a required variable is missing, the scripts stop immediately and name the
exact variable — they never guess or silently skip.

### 1.4 Install dependencies

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pip install matplotlib   # only needed for plot_four_experiments.py
```

## 2. Running each experiment

All commands below assume the repo root as the working directory.

### Experiment 1 — request-rate vs latency saturation

```bash
python benchmarks/scripts/run_four_experiments.py exp1 \
    --rps 1 2 5 10 20 40 80 \
    --warmup-s 10 --measure-s 30 --cooldown-s 12 --repetitions 3 \
    --self-enrol
```

`--self-enrol` creates one fresh valid record and verifies it repeatedly at
each RPS tier (the EVR-absorbed repeat path, Sec. V-D of the paper — this is
what exercises the *normal* verification path under load, not the counter
divergence machinery). If you already have a known-good `(uid, counter,
token)` on the target, pass `--uid --token --counter` instead and skip the
admin env vars.

The sweep **stops automatically** if 5xx+timeout exceeds 1% in a tier
(`--unhealthy-threshold-pct`, default 1.0) — that tier IS the saturation
region; the script does not keep hammering a destabilised host (handoff §6.2,
§12).

Writes `raw/exp1_request_latency.csv` (one row per request) and
`summaries/exp1_summary.csv` (one row per RPS/repetition).

### Experiment 2 — request-rate vs error behavior

Pure analysis of exp1's raw CSV — **no new network traffic**:

```bash
python benchmarks/scripts/run_four_experiments.py exp2 \
    --from-exp1-raw benchmarks/raw/exp1_request_latency.csv
```

Writes `raw/exp2_error_behavior.csv` (the same rows, relabelled) and
`summaries/exp2_summary.csv` with a `protection_vs_failure` column that keeps
429 (rate limiting — intentional protection) separate from 5xx/timeout
(actual server failure), per handoff §7.2 rule 4.

### Experiment 3 — database growth vs verification latency

```bash
python benchmarks/scripts/run_four_experiments.py exp3 \
    --tiers 1000 5000 10000 25000 \
    --measured-requests 30 --warmup-requests 5
```

Opens one benchmark batch, fills it to each tier with synthetic enrolments
(concurrent, `--enrol-concurrency`, default 8 — enrolment itself is not the
measured quantity, so it is sped up), confirms the row count via
`GET /api/v2/admin/batches` (the same field `close_batch` reads —
`enrolled_count` — rather than a direct DB query, per the golden rule), then
measures the **same fixed record** at low, fixed concurrency (≈1 client, via
`--inter-request-delay-s`) so the only independent variable is DB size.
Closes the batch afterward unless `--no-cleanup` is passed.

**100,000 records is a lot of individually-signed HTTP enrolments** (there is
no bulk-insert admin route — enrolment is deliberately one Ed25519-signed,
AES-256-GCM-sealed record at a time, see ARCHITECTURE.md §9.5). At, say,
50-100 concurrent enrolments/sec this tier alone can take 15-30+ minutes.
Start with smaller tiers and extend `--tiers` once you know your staging
deployment's enrolment throughput; the handoff explicitly marks 100k as
"only if staging capacity is clearly sufficient" (§8.1).

### Experiment 4 — replay-storm / repeated-request detection

```bash
python benchmarks/scripts/run_four_experiments.py exp4 \
    --replay-counts 1 5 10 50 100 500 1000 \
    --trials-per-n 5
```

For each `N` in `--replay-counts`, runs `--trials-per-n` independent trials.
Each trial: enrol one fresh synthetic record, verify it once (the legitimate
baseline), then replay the *exact same* verification `N` times, recording
every attempt. The flag is never cleared inside a trial (handoff §9.2 step
8 — "do not clear incidents between attempts"), so later replays staying
flagged is itself part of what gets measured.

Writes `raw/exp4_replay_storm.csv` (every attempt) and
`summaries/exp4_summary.csv` (detection rate and first-detection-attempt
statistics per `N`).

## 3. Generating the figures

```bash
python benchmarks/scripts/plot_four_experiments.py
```

Regenerates all four PNGs (300 dpi) in `figures/` **from the saved CSVs
only** — it never re-runs an experiment, so every plotted point is traceable
back to a raw request-level row (handoff §11 figure discipline).

| Figure | X axis | Y axis |
|---|---|---|
| `fig1_request_rate_vs_latency.png` | RPS | p50/p95/p99 latency |
| `fig2_request_rate_vs_errors.png` | RPS | response-code shares + achieved throughput |
| `fig3_db_size_vs_latency.png` | DB record count (log) | p50/p95 verification latency |
| `fig4_replay_attempts_vs_detection.png` | replay count N (log) | detection rate + latency-by-verdict histogram |

## 4. Output layout

```
benchmarks/
  README.md                 (this file)
  run_manifest.json          auto-updated by every run — commit hash,
                              exact tiers, warm-up/measure/cooldown durations,
                              skipped tiers and why (handoff §10.3)
  raw/
    exp1_request_latency.csv
    exp2_error_behavior.csv
    exp3_db_scaling.csv
    exp4_replay_storm.csv
  summaries/
    exp1_summary.csv
    exp2_summary.csv
    exp3_summary.csv
    exp4_summary.csv
  figures/
    fig1_request_rate_vs_latency.png
    fig2_request_rate_vs_errors.png
    fig3_db_size_vs_latency.png
    fig4_replay_attempts_vs_detection.png
  scripts/
    common.py                   shared request/signing/stats plumbing
    run_four_experiments.py     exp1/exp2/exp3/exp4 CLI
    plot_four_experiments.py    CSV -> PNG, no network
```

`raw/`, `summaries/`, `figures/` and `run_manifest.json` are generated output
(gitignored except for the directories themselves) — they are evidence
against *your* test/staging deployment at a point in time, not source.

## 5. Discipline this directory follows (handoff §5, §12)

- Every HTTP attempt is one raw CSV row — timeouts and failures are recorded,
  never dropped.
- `time.perf_counter()` client-side elapsed time; `response_class` is
  separate from `logical_verdict` (HTTP 200 with `suspect_duplicate` is not
  the same thing as a transport failure).
- 429 is never treated as a crash — it is its own `response_class`, plotted
  separately from 5xx/timeout.
- Each measured tier has a warm-up period excluded from the final statistics.
- Nothing claims a defense "works" from a pytest pass; these scripts report
  measured quantities and the exact conditions they were measured under
  (`run_manifest.json`).
- Synthetic records only, isolated under a `BENCH-*`/`EXP{1,3,4}-*`
  `batch_ref` prefix; exp3/exp4 close their batch when done (`--cleanup`,
  the default).

## 6. Before you cite these numbers in a paper

1. Confirm `TEST_WORKER_COUNT` matches what the deployment actually ran with.
2. Confirm `TEST_BASE_URL` was genuinely test/staging, isolated from
   production traffic, for the whole run.
3. Keep `run_manifest.json` next to whatever CSVs/figures you cite — it is
   the record of exactly what was run, not a template to fill in by hand.
4. Report the saturation region as "the highest tier that stayed under the
   declared 5xx+timeout threshold," not as an absolute "requests before the
   server broke" — see handoff §6.3 step 8 and §12.
