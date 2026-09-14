# edge/ — Cloudflare Worker

The edge layer. See ARCHITECTURE.md §11.

## The dependency you must understand before deploying

**The tag URL host is this Worker.** Every tag written by `pi/enroller.py` has
`https://<PUBLIC_HOST>/c?m=…&t=…` burned into its NDEF record, and `PUBLIC_HOST`
is normally this Worker's `*.workers.dev` hostname.

That makes the Worker **load-bearing**: if it is deleted or the account lapses,
every tag already on a shelf stops resolving. Tags cannot be rewritten once they
are in the field (and once `TAG_LOCK_ENABLED=true`, not even in principle).

Two mitigations, both required and both already built:

1. **The origin serves the identical routes.** `/c`, `/api/v2/verify`,
   `/api/v2/report`, `/api/v2/enrol` and `/api/v2/admin/*` all exist on the
   Render origin. Failing over is a DNS/host change, not a redeployment of tags.
2. **The runbook has the failover procedure.** See
   `docs/OPERATOR_RUNBOOK.md` → "Edge failover".

Open question 3 in §22 is exactly this: *is the Worker host permanent?* Decide it
before you enrol any tag you intend to keep.

## What the Worker does, and does not do

| Does | Does not |
|---|---|
| Distributed rate limiting in KV (per-IP-prefix **and per-tag**) | Decide any verdict |
| Negative-lookup caching | Cache a positive verdict — ever |
| Serve the instant page shell during origin cold start | Hold any key material |
| Method / size / Content-Type gates | Talk to the database |
| Parameter canonicalisation and duplicate rejection | Trust its own parse — the origin re-validates |

**Positive verdicts are never cached.** A cached `authentic` would defeat the
counter check entirely, which is the whole mechanism. Only `unknown` and
`mirror_disabled` are cacheable, and those are precisely the responses
enumeration is trying to harvest.

## Deploy

```bash
cd edge
npm install

# One-time: create the two KV namespaces and paste their ids into wrangler.toml
npx wrangler kv namespace create RL
npx wrangler kv namespace create NEG

# ORIGIN_URL is a secret, not a var — it is the only thing the Worker knows
npx wrangler secret put ORIGIN_URL      # e.g. https://nfc-med-backend.onrender.com

npx wrangler deploy
```

Note the deployed `*.workers.dev` hostname and put it in `PUBLIC_HOST` on the Pi
**and** in `PUBLIC_HOST` on the backend. **Fix it before enrolling any tag you
intend to keep.**

## Local development

```bash
npx wrangler dev          # http://localhost:8787
```

`wrangler dev` uses a local KV simulation, so rate limits reset when you restart
it. That is fine for wiring checks and useless for evaluating limits — the
numbers in §17.3 only mean something against the deployed Worker.

## The B1 caveat, stated rather than hidden

Running on `*.workers.dev` means the homograph / look-alike domain defence (B1)
stays **weak**: an attacker can register `nfc-med-verify.workers.dev` as easily
as we registered ours, and nothing about the URL tells a consumer which one is
real. The only real mitigation is a short custom domain, which is open question 1
in §22. Under the free-only constraint the answer is no for now; the printed host
on the pack is the only thing standing in for it.
