// Distributed rate limiting in Workers KV. ARCHITECTURE.md §11.3.
//
// Three composite buckets, all checked:
//
//   ip:<prefix>   /24 for IPv4, /48 for IPv6 — NOT a single address.
//                 Carrier-grade NAT in India means an entire operator region can
//                 share addresses, and a busy pharmacy's Wi-Fi is one IP. Keying
//                 on a single address throttles real consumers before it
//                 throttles attackers (F21).
//
//   tag:<hash>    hash of the m parameter's UID portion. A single pack verified
//                 500 times in an hour from 500 addresses is the signal you
//                 actually want, and a per-IP limiter cannot see it (G1, D21).
//
//   sess:<cookie> soft throttle for real users — slow down, don't block.
//
// KV is eventually consistent, so these limits are approximate. That is fine: it
// is still far stronger than v1's per-process in-memory counters, which were
// silently N times looser than configured (F16). The Postgres limiter in
// backend/ratelimit.py is the second layer for direct-to-origin traffic.

export const LIMITS = {
  ip: { window: 60, max: 60 },
  tag: { window: 3600, max: 30 },
  sess: { window: 60, max: 30 },
};

export function ipPrefix(request) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  if (!ip) return 'unknown';
  if (ip.includes(':')) {
    // IPv6 -> /48, the first three hextets.
    return ip.split(':').slice(0, 3).join(':') + '::/48';
  }
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
}

export async function tagBucket(m) {
  // Hash the UID rather than keying on it directly, so the KV namespace itself
  // is not a list of every UID that has ever been scanned.
  const data = new TextEncoder().encode('nfcmed/v2/edge-tag:' + m.slice(0, 14));
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest).slice(0, 12)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function windowStart(seconds) {
  return Math.floor(Date.now() / 1000 / seconds) * seconds;
}

/**
 * Fixed-window counter in KV. Returns { ok, retryAfter, bucket }.
 * Fails OPEN when KV is unavailable — the origin's Postgres limiter is the
 * backstop, and a KV outage must not take the consumer path down. An unreachable
 * verification service IS a security failure (F22), not just an inconvenience.
 */
export async function checkBucket(kv, kind, identity) {
  const { window, max } = LIMITS[kind];
  const start = windowStart(window);
  const key = `rl:${kind}:${identity}:${start}`;
  try {
    const current = parseInt((await kv.get(key)) || '0', 10);
    if (current >= max) {
      const retryAfter = start + window - Math.floor(Date.now() / 1000);
      return { ok: false, retryAfter: Math.max(retryAfter, 1), bucket: kind };
    }
    // expirationTtl cleans up on its own, so the namespace never needs sweeping.
    await kv.put(key, String(current + 1), { expirationTtl: window + 60 });
    return { ok: true };
  } catch (err) {
    return { ok: true, degraded: true };
  }
}

export async function checkAll(kv, request, m) {
  const checks = [
    checkBucket(kv, 'ip', ipPrefix(request)),
    checkBucket(kv, 'tag', await tagBucket(m)),
  ];
  for (const result of await Promise.all(checks)) {
    if (!result.ok) return result;
  }
  return { ok: true };
}
