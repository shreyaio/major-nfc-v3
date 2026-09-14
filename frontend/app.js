// The consumer verification page. ARCHITECTURE.md §13.2, §13.5.
//
// WEB NFC IS NOW A BONUS, NOT THE PRIMARY PATH.
//
// In v1, a live Web NFC read was the only thing that made verification stronger
// than trusting a copyable URL — and it works on exactly one browser on one OS.
// Roughly half the market, and every iPhone, got no protection at all (F31, F32).
//
// In v2 the chip itself writes its UID and its one-way counter into the URL, so
// the strong check happens on any phone with no app, iOS included. If Web NFC
// happens to be available we offer it as an extra confirmation that upgrades the
// reported binding to `counter+liveread`. If the user declines the permission,
// or the read fails, THE VERDICT IS NOT DEGRADED — the counter path already ran
// (C7). Never block the result behind a permission prompt.
//
// Everything rendered here comes from the SERVER's decision. The client is
// untrusted by definition; a hostile browser extension can rewrite this page and
// the server-side incident record is still authoritative (C8).

import { common, pickLanguage, t } from './strings.js';

const LANG = pickLanguage();
const COPY = common(LANG);

const TONE_CLASS = { ok: 'ok', warn: 'warn', bad: 'bad', info: 'info' };

// ---------------------------------------------------------------- fetching ---

export function paramsFromLocation() {
  const url = new URL(window.location.href);
  return { m: url.searchParams.get('m'), t: url.searchParams.get('t') };
}

export async function fetchVerdict({ live = false } = {}) {
  const { m, t: token } = paramsFromLocation();
  if (!m || !token) return { verdict: 'unknown', binding: 'none', checks: {} };

  const query = new URLSearchParams({ m, t: token });
  if (live) query.set('live', '1');

  const response = await fetch(`/api/v2/verify?${query.toString()}`, {
    headers: { Accept: 'application/json' },
    cache: 'no-store',
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 429) return { verdict: 'offline', binding: 'none', checks: {}, rateLimited: true };
    if (body.error) return { verdict: 'offline', binding: 'none', checks: {}, error: body.error };
    return { verdict: 'offline', binding: 'none', checks: {} };
  }
  return response.json();
}

// --------------------------------------------------------------- rendering ---

function el(id) {
  return document.getElementById(id);
}

// Everything user-visible goes through textContent, never innerHTML. Combined
// with the CSP's script-src 'self', that makes C4 (XSS via a hostile product
// name) unexploitable twice over.
function setText(node, text) {
  node.textContent = text == null ? '' : String(text);
}

function fill(template, values) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) =>
    values[key] == null ? '' : String(values[key])
  );
}

export function render(result) {
  const verdict = result.verdict || 'unknown';
  const copy = t(LANG, verdict);
  const values = {
    expiry: (result.product && result.product.expiry) || '',
    notice: result.recall_notice || 'This batch has been recalled by the manufacturer.',
  };

  const heading = el('heading');
  setText(heading, copy.heading);
  heading.removeAttribute('aria-busy');

  const box = el('verdict');
  box.className = `verdict ${TONE_CLASS[copy.tone] || 'info'}`;
  setText(el('body'), fill(copy.body, values));

  renderAction(box, copy, verdict, result);
  renderDetails(result);
  renderChecks(result);
  renderBinding(result);
  renderLiveReadOffer(result);
}

function renderAction(box, copy, verdict, result) {
  let action = document.getElementById('action');
  if (!action) {
    action = document.createElement('p');
    action.id = 'action';
    action.className = 'action';
    box.appendChild(action);
  }
  setText(action, copy.action || '');
  action.hidden = !copy.action;

  // RULE 2: never a bare failure. Every negative verdict routes somewhere.
  let link = document.getElementById('report-link');
  if (!link) {
    link = document.createElement('a');
    link.id = 'report-link';
    link.className = 'report';
    box.appendChild(link);
  }
  const negative = verdict !== 'authentic' && verdict !== 'checking';
  link.hidden = !negative;
  if (negative) {
    setText(link, COPY.reportLink);
    const query = new URLSearchParams({ verdict });
    if (result.incident && result.incident.id) query.set('incident', result.incident.id);
    link.href = `/report?${query.toString()}`;
  }

  let ref = document.getElementById('incident-ref');
  if (result.incident && result.incident.id) {
    if (!ref) {
      ref = document.createElement('p');
      ref.id = 'incident-ref';
      ref.className = 'note';
      box.appendChild(ref);
    }
    setText(ref, fill(COPY.incidentRef, { id: result.incident.id }));
    ref.hidden = false;
  } else if (ref) {
    ref.hidden = true;
  }
}

function renderDetails(result) {
  const dl = el('details');
  dl.textContent = '';
  if (!result.product) {
    dl.hidden = true;
    return;
  }
  for (const [key, label] of Object.entries(COPY.details)) {
    if (!result.product[key]) continue;
    const dt = document.createElement('dt');
    const dd = document.createElement('dd');
    setText(dt, label);
    setText(dd, result.product[key]);
    dl.append(dt, dd);
  }
  dl.hidden = false;
}

// Band 3 — "what was checked". This is the transparency requirement, and it is
// four lines, not a dashboard. It is also the deployment metric for the paper:
// what fraction of real verifications received the strong guarantee?
function renderChecks(result) {
  const list = el('checks');
  list.textContent = '';
  const checks = result.checks || {};
  if (!Object.keys(checks).length) {
    list.hidden = true;
    return;
  }
  for (const key of ['record', 'counter', 'recall', 'expiry']) {
    if (!checks[key]) continue;
    const li = document.createElement('li');
    const name = document.createElement('span');
    const state = document.createElement('span');
    setText(name, COPY.checks[key]);
    setText(state, COPY.checks[checks[key]] || checks[key]);
    state.className = `check-${checks[key]}`;
    li.append(name, state);
    list.appendChild(li);
  }
  list.hidden = false;
}

function renderBinding(result) {
  const note = el('binding-note');
  const text = COPY.binding[result.binding];
  setText(note, text || '');
  note.hidden = !text;
}

// ------------------------------------------------------------- Web NFC bonus --

function renderLiveReadOffer(result) {
  if (!('NDEFReader' in window)) return;
  if (result.binding === 'counter+liveread') return;
  if (result.verdict === 'offline' || result.verdict === 'unknown') return;

  let button = document.getElementById('live-read');
  if (!button) {
    button = document.createElement('button');
    button.id = 'live-read';
    button.type = 'button';
    button.className = 'live-read';
    el('verdict').after(button);
    button.addEventListener('click', onLiveRead);
  }
  setText(button, COPY.liveReadButton);
  button.hidden = false;
}

async function onLiveRead() {
  const button = document.getElementById('live-read');
  button.disabled = true;
  try {
    const reader = new NDEFReader();
    await reader.scan();
    await new Promise((resolve, reject) => {
      reader.onreading = resolve;
      reader.onreadingerror = reject;
      setTimeout(() => reject(new Error('timeout')), 20000);
    });
    // The live read succeeded, so ask the server again with live=1. The server
    // still decides everything; `live` only changes the binding LABEL it reports.
    render(await fetchVerdict({ live: true }));
  } catch (err) {
    // Permission denied, unsupported, or timed out. DO NOT DEGRADE THE VERDICT
    // (C7) — the counter path already ran and its answer stands.
    button.hidden = true;
  } finally {
    button.disabled = false;
  }
}

// ------------------------------------------------------------------ startup --

export async function start() {
  try {
    render(await fetchVerdict());
  } catch (err) {
    render({ verdict: 'offline', binding: 'none', checks: {} });
  }
}

if (typeof document !== 'undefined' && document.getElementById('verdict')) {
  start();

  // The service worker provides an OFFLINE STATE ONLY. It must never cache an
  // API response — a cached positive verdict would defeat the counter check
  // permanently and is exactly attack C5.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}
