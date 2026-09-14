# ATTACK_MATRIX.md — traceability, not a work list

Extracted verbatim from ARCHITECTURE.md §16 so the paper and the repository
cannot drift apart. Regenerate with:

    python -c "import pathlib; s=pathlib.Path('ARCHITECTURE.md').read_text(encoding='utf-8');       open('docs/ATTACK_MATRIX.md','w',encoding='utf-8').write(s[s.index('## 16.'):s.index('## 17.')])"

**How to read it.** "Mechanism" is *where the defence lives*. If you are about to
add a special case in a route handler for one of these IDs, stop — either the
mechanism is missing from the design (flag it) or you are patching a symptom.

**Where these are already tested** is listed in
`backend/tests/attacks/README.md`. The full 86-test suite is Phase 8 (§18); the
scaffold is in place and several classes are already covered by the unit and
integration tests that exist today.

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
