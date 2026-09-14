# THREAT_MODEL.md — NFC Medicine Authenticity System v2

Extracted from ARCHITECTURE.md §19 and §2, for the paper and for review.

---

## 1. The contradiction this document resolves

v1's threat model granted the adversary the ability to obtain **the backend's
entire configuration**, including every trusted public key. But that
configuration also contained `AES_MASTER_KEY` and `SHARED_SECRET` — so under its
own stated threat model, the adversary decrypted every record in the database and
the confidentiality claim was void.

That is Contradiction 1, and it had to be resolved one way or the other: either
narrow the adversary, or change the design.

**v2 takes the stronger option: keep the broad capability and change the design
so the claim holds.**

The mechanism is key separation (§7.1) plus envelope wrapping (§7.6):

- The Pi no longer holds any decryption key. It holds an Ed25519 *signing* key
  and an X25519 *public* encryption key. It can write records; it cannot read the
  register.
- The backend's two operational private keys are stored **wrapped under a KEK**.
  Reading the environment variables is no longer sufficient.
- `TAG_INDEX_KEY`, `ADMIN_TOKEN_KEY` and `TRANSPARENCY_KEY` each live in a
  different place, and no two of them are needed by the same component.

**The honest caveat:** this only holds if `KEK` lives somewhere with genuinely
different access control from the Render dashboard. If you put `KEK` next to the
wrapped blobs, you have gained nothing. That is an operational property, not a
code property, and no test can enforce it.

---

## 2. Adversary capabilities assumed

| # | Capability | v2 response |
|---|---|---|
| i | Read any tag, unlimited times | MTA — **reading advances the real counter**, so surveillance is self-defeating |
| ii | Write arbitrary blank or magic tags | Counter freeze / `000000` → divergence; originality gate at enrolment |
| iii | Intercept and modify any network traffic | TLS + Ed25519 request signatures over the raw body |
| iv | Craft arbitrary requests to any endpoint | Signature-before-parse, strict input contracts, one error envelope |
| v | **Read the backend's entire environment** | Operational keys are envelope-wrapped; `KEK` lives elsewhere (§7.6) |
| vi | **Full read/write access to the database** | Row signatures over every security-relevant field; chained audit log; no keys in the DB |
| vii | Physical access to a pack on a shelf | Lock bytes (when enabled); velocity bound; no verdict change from reads alone |
| viii | Steal the Pi and its SD card | Per-batch quota bounds the damage; the Pi cannot decrypt the register |

### Explicitly out of scope

- **A full host compromise of the running backend process.** It yields the
  unwrapped keys in memory. No free HSM exists. Stated, not designed around.
- **Physical-layer RF fingerprinting attacks.**
- **A compromised NXP signing key.** Their key, their curve (H5).

---

## 3. The two claims, stated precisely

> On commodity non-secure-element NFC hardware, a cloned tag that is **actually
> used in circulation** will be **detected**, with a computable and small expected
> number of consumer taps, without any app, on both Android and iOS, at zero
> additional per-tag cost.

> An adversary with **full read/write access to the product register** cannot
> alter any security-relevant field — expiry date, recall status, crypto version,
> binding token — without the alteration being **detected on the next
> verification**.

### What v2 does **not** claim

That cloning is prevented. The chip has no secret key and can prove nothing
cryptographically. Anyone who reads a genuine tag can write the same data to
another tag.

What is gained is **detection**, not **prevention** — and the detection latency is
quantifiable, which is what makes it a result rather than a hope. Moving the claim
from "prevention" to "bounded-latency detection" is not a weakening; **it is the
only version of the claim the hardware supports.**

### One consequence, enforced in code

**The system never emits the word "counterfeit" or "fake" as a verdict.**
Attribution is genuinely ambiguous: an attacker who pre-advances a clone's counter
causes the *genuine* pack to trip the alarm. The velocity bound handles the
realistic version of that, but the honest response to divergence is to flag both
readings, open an incident, and hand the decision to a human.

The strongest negative verdict is `SUSPECT_DUPLICATE`. Declaring the wrong pack
counterfeit is a worse failure than declaring an ambiguity — and it is a
defamation risk.

---

## 4. Trust boundaries

```
UNTRUSTED                    SEMI-TRUSTED                TRUSTED
─────────                    ────────────                ───────
The tag                      Cloudflare Worker           Backend process
  no secret, proves nothing    canonicalises, gates        holds unwrapped keys
  supplies DATA, never a       rate-limits, caches         makes EVERY verdict
  verdict                      NEGATIVES only              signs every row
                               decides nothing
The consumer's phone
  may be rooted, may run      The database                 KEK / admin key /
  a hostile extension           adversary has full          transparency key
  `live=1` is a CLAIM           read/write (vi)             held OUTSIDE the
                                row signatures are          runtime entirely
The Pi                          what make it safe
  can write records
  CANNOT read the register
  bounded by batch quota
```

**The tag influences data; it never influences verdict logic.** That decision was
right in v1 and is preserved absolutely.

**The client is untrusted by definition.** A browser extension can rewrite the
verification page to say anything (C8); the server-side incident record is
authoritative, and that is what a recall or an investigation acts on.

---

## 5. Residual risks this build does not close

These are in the README as well. They are stated, not quietly designed around.

1. **A11 — tag transplant / refill.** Peeling a genuine tag off an empty pack
   onto a counterfeit one defeats every mechanism here. Requires tamper-evident
   packaging. This is the most serious open risk and it is not a software problem.

2. **The counter is plaintext.** Anyone who observes one tap's URL knows that
   tag's counter at that instant. This is the irreducible gap versus NTAG 424
   DNA's CMAC, and it is the price of working on a phone with no app.
   `NFC_CNT_PWD_PROT` must be `0` precisely because a consumer's browser cannot
   perform a password authentication (§6.5).

3. **A7 / A8 while `TAG_LOCK_ENABLED=false`.** Deliberate for this phase (D5).
   An attacker with physical access can rewrite the NDEF area or disable the
   counter. `/health` reports the posture honestly so this is never ambiguous.

4. **Full host compromise of the backend** still yields the field-decryption key
   in memory. Envelope encryption raises the bar; it does not eliminate this
   (E10).

5. **B1 — homograph / look-alike domain.** Weak, because there is no custom
   domain under the free-only constraint (D6). An attacker can register a
   plausible `*.workers.dev` name as easily as we did.

---

## 6. Why a transparency log rather than a blockchain

A distributed ledger is usually proposed here to remove the need to **trust a
single custodian of the database**. That is a real concern and it deserves a real
answer.

The answer is a daily **signed Merkle root** over every row signature, published
to a public repository, plus a **hash-chained audit log** whose head is inside
that signed object (§14.3, §9.9).

What it delivers:

- Anyone can prove a record existed on a given date, via an inclusion proof.
- The custodian cannot silently rewrite history: deleting a row changes the root,
  and yesterday's root is already public and signed.
- Deleting an audit entry breaks the chain, and the break is **publicly
  provable** because the chain head was published.

What it costs: nothing. No consortium, no tokens, no per-transaction fee, no
node to run. `backend/scripts/verify_transparency.py` is the third-party verifier,
and it needs no access to any of our systems to check a root or an inclusion
proof.

The signing key is a GitHub Actions secret and **never reaches the runtime
backend** — so the origin serves a signed object it could not itself have
produced.

---

## 7. What an evaluator should check

Not "does it say it is secure", but:

1. **Is there any path to `authentic` that skips a check?**
   `backend/tests/unit/test_verdict_machine.py` enumerates all 2,304 combinations
   and asserts there is exactly one.
2. **Can the database adversary change an expiry date undetected?**
   `backend/tests/unit/test_rowsig.py` says no, field by field.
3. **Does a duplicate actually get caught under concurrency?**
   `backend/tests/integration/test_concurrency.py` fires 12 simultaneous
   identical counters and asserts exactly one wins.
4. **Is the rate-limit number meaningful?** Only if the worker count is stated.
   `render.yaml` pins `--workers 2` and the evidence recorder records it.
5. **Are the open risks in §5 above actually open in the scoreboard?**
   §16.9 lists them. A clean sweep would be the suspicious result.
