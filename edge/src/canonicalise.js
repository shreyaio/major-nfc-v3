// Parameter canonicalisation at the edge. ARCHITECTURE.md §11.3.
//
// THE ORIGIN RE-RUNS EQUIVALENT VALIDATION AND NEVER TRUSTS THIS PARSE.
// Two independent parsers that must agree is the defence against B9 (edge/origin
// differential smuggling). Trusting one of them would defeat the purpose — the
// point is not that the edge validates, it is that both do and a disagreement
// cannot be smuggled through.

export class BadRequest extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const M_PATTERN = /^[0-9A-F]{14}X[0-9A-F]{6}$/;
const T_PATTERN = /^[0-9A-F]{32}$/;
const MAX_PARAM_LEN = 64;

export function canonicaliseVerify(url) {
  const p = url.searchParams;

  // B8 — parameter pollution. A front layer that takes the first value and a
  // back layer that takes the last is the whole attack; rejecting duplicates
  // outright removes the disagreement rather than picking a side.
  for (const k of ['m', 't']) {
    if (p.getAll(k).length !== 1) throw new BadRequest('duplicate_parameter');
  }

  const rawM = p.get('m');
  const rawT = p.get('t');

  // B4 — length cap BEFORE the regex, so an oversized parameter never becomes a
  // regex DoS surface.
  if (rawM.length > MAX_PARAM_LEN || rawT.length > MAX_PARAM_LEN) {
    throw new BadRequest('parameter_too_long');
  }

  // B5 — NFKC-normalise then uppercase BEFORE matching, so full-width and
  // mixed-case inputs are rejected by the pattern rather than sneaking past it.
  const m = rawM.normalize('NFKC').trim().toUpperCase();
  const t = rawT.normalize('NFKC').trim().toUpperCase();

  if (!M_PATTERN.test(m)) throw new BadRequest('malformed_parameters');
  if (!T_PATTERN.test(t)) throw new BadRequest('malformed_parameters');

  return { m, t };
}

// The all-zero mirror means the chip never wrote its UID or counter into the
// URL. That is MIRROR_DISABLED, decided at the origin — the edge only needs to
// know not to cache it as a negative lookup (B7).
export function isPlaceholder(m) {
  return m.startsWith('00000000000000') && m.slice(15) === '000000';
}

export function methodAllowed(pathname, method) {
  // D17 — explicit method allow-list, enforced at both layers.
  if (pathname === '/c') return method === 'GET' || method === 'HEAD';
  if (pathname === '/api/v2/verify') return method === 'GET' || method === 'HEAD';
  if (pathname === '/api/v2/report') return method === 'POST' || method === 'GET';
  return true; // everything else is proxied and gated by the origin
}
