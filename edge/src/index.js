// Cloudflare Worker — the edge layer. ARCHITECTURE.md §11 (decision D1).
//
// KEEP THIS SMALL AND KEEP ALL BUSINESS LOGIC ON THE ORIGIN. The Worker's job is
// seven things and no more:
//
//   1. Distributed rate limiting in KV — global, not per-process   (F16, F21, D21)
//   2. PER-TAG rate limiting, not just per-IP                      (G1, D21)
//   3. Negative-lookup caching, so enumeration never reaches origin (F23, D21)
//   4. An instant page shell while the origin cold-starts          (F22)
//   5. Method / Content-Type / size gates before the origin        (D17-D20, B4)
//   6. Parameter canonicalisation and duplicate rejection          (B5, B8, B9)
//   7. Security headers on the shell                               (C3, F29)
//
// THE TAG URL HOST IS THIS WORKER. That makes it load-bearing: if it is removed,
// tags in the field stop resolving. Two mitigations, both required:
//   - the origin serves the identical routes, so a host change is a config edit
//     and not a redeployment of every tag already on a shelf;
//   - edge/README.md states the dependency, and the runbook has the failover.

import { BadRequest, canonicaliseVerify, isPlaceholder, methodAllowed } from './canonicalise.js';
import { checkAll } from './ratelimit.js';
import SHELL from './shell.html';

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; " +
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; " +
    "form-action 'self'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
};

// Verdicts that may be cached at the edge. `authentic` is deliberately absent:
// a cached positive verdict would defeat the counter check entirely, which is
// the whole mechanism (§11.4). Only "we have never heard of this" is cacheable,
// and that is exactly the response enumeration is trying to harvest.
const CACHEABLE_VERDICTS = new Set(['unknown', 'mirror_disabled']);

const MAX_BODY_BYTES = 64 * 1024;

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function errorEnvelope(code, message, status, retryAfter = null) {
  // Same envelope as backend/errors.py §15.2. One error shape on the wire,
  // whichever layer produced it.
  const headers = retryAfter ? { 'Retry-After': String(retryAfter) } : {};
  return json(
    { error: { code, message, request_id: crypto.randomUUID(), retry_after: retryAfter } },
    status,
    headers
  );
}

async function negCacheKey(m, t) {
  const data = new TextEncoder().encode(`${m}|${t}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return (
    'neg:' +
    [...new Uint8Array(digest).slice(0, 16)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

async function handleVerify(request, env, url) {
  let m;
  let t;
  try {
    ({ m, t } = canonicaliseVerify(url));
  } catch (err) {
    if (err instanceof BadRequest) {
      return errorEnvelope(err.code, 'The verification link is not valid.', 400);
    }
    throw err;
  }

  const limited = await checkAll(env.RL, request, m);
  if (!limited.ok) {
    return errorEnvelope(
      'rate_limited',
      'Too many requests. Please wait and try again.',
      429,
      limited.retryAfter
    );
  }

  const cacheKey = await negCacheKey(m, t);
  const cached = await env.NEG.get(cacheKey);
  if (cached) {
    return json(JSON.parse(cached), 200, { 'X-Edge-Cache': 'hit' });
  }

  // Rebuild the upstream URL from the CANONICAL values, never by forwarding the
  // client's raw query string. Anything the client smuggled past us in an
  // unnormalised form does not survive this step (B9).
  const upstream = new URL(`${env.ORIGIN_URL}/api/v2/verify`);
  upstream.searchParams.set('m', m);
  upstream.searchParams.set('t', t);
  if (url.searchParams.get('live') === '1') upstream.searchParams.set('live', '1');

  let originResponse;
  try {
    originResponse = await fetch(upstream.toString(), {
      method: 'GET',
      headers: {
        'CF-Connecting-IP': request.headers.get('CF-Connecting-IP') || '',
        'User-Agent': request.headers.get('User-Agent') || '',
        Accept: 'application/json',
      },
    });
  } catch (err) {
    // The origin is asleep, slow, or down. Say so honestly — never a verdict.
    return errorEnvelope(
      'service_unavailable',
      'We could not reach the verification service. Please try again.',
      503,
      5
    );
  }

  const body = await originResponse.text();
  if (originResponse.status === 200) {
    try {
      const parsed = JSON.parse(body);
      if (CACHEABLE_VERDICTS.has(parsed.verdict) && !isPlaceholder(m)) {
        await env.NEG.put(cacheKey, body, {
          expirationTtl: parseInt(env.NEG_CACHE_TTL || '300', 10),
        });
      }
    } catch (err) {
      // Unparseable body: pass it through untouched, cache nothing.
    }
  }

  return new Response(body, {
    status: originResponse.status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Edge-Cache': 'miss',
      ...SECURITY_HEADERS,
    },
  });
}

async function proxy(request, env, url) {
  // D19/D20 — size gate before the origin ever allocates for the body.
  const declared = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (declared > MAX_BODY_BYTES) {
    return errorEnvelope('payload_too_large', 'The request body is too large.', 413);
  }

  const upstream = new URL(url.pathname + url.search, env.ORIGIN_URL);
  const headers = new Headers(request.headers);
  headers.set('CF-Connecting-IP', request.headers.get('CF-Connecting-IP') || '');

  try {
    return await fetch(upstream.toString(), {
      method: request.method,
      headers,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    });
  } catch (err) {
    return errorEnvelope(
      'service_unavailable',
      'The service is temporarily unavailable.',
      503,
      5
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!methodAllowed(url.pathname, request.method)) {
      return errorEnvelope('method_not_allowed', 'That method is not allowed here.', 405);
    }

    // The shell renders INSTANTLY from the edge with a "Checking..." state, so
    // the consumer sees something in under 100 ms regardless of origin state.
    // Render's free tier sleeps after ~15 minutes idle and the first request
    // then takes 30-50 seconds; a consumer standing at a pharmacy counter will
    // not wait, and abandonment means the system provides no protection at all.
    // That makes this a security property, not a convenience one (F22).
    if (url.pathname === '/c' || url.pathname === '/') {
      return new Response(SHELL, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=300',
          ...SECURITY_HEADERS,
        },
      });
    }

    if (url.pathname === '/health') {
      return json({ status: 'ok', edge: true, origin: env.ORIGIN_URL ? 'configured' : 'missing' });
    }

    if (url.pathname === '/api/v2/verify') {
      return handleVerify(request, env, url);
    }

    // Everything else — enrol, admin, report, transparency — is proxied. The
    // origin authenticates and decides; the edge only gates size and method.
    return proxy(request, env, url);
  },
};
