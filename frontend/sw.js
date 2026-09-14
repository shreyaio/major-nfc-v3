// Service worker — OFFLINE STATE ONLY. ARCHITECTURE.md §13.5.
//
// IT MUST NEVER CACHE AN API RESPONSE.
//
// A cached positive verdict would defeat the counter check permanently: the
// whole mechanism is that every tap produces a strictly greater counter value
// checked against server-side state. Serving a stored `authentic` from the
// device makes that check unreachable, and it is exactly attack C5.
//
// So this file does two things and nothing else:
//   1. Caches the shell and static assets, so the page loads when offline.
//   2. Turns a failed /api/ request into an explicit "offline" state rather than
//      a blank screen (C10) — the consumer must be told the check did not
//      happen, never left to assume it passed.

const SHELL_CACHE = 'nfcmed-shell-v2';
const SHELL_ASSETS = [
  '/verify.html',
  '/app.js',
  '/strings.js',
  '/style.css',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => cache.addAll(SHELL_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(names.filter((n) => n !== SHELL_CACHE).map((n) => caches.delete(n)))
      )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // API responses: network only, never cached, never read from a cache. The
  // catch produces an explicit offline verdict for the page to render.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(
        () =>
          new Response(JSON.stringify({ verdict: 'offline', binding: 'none', checks: {} }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          })
      )
    );
    return;
  }

  // Static assets: cache-first, so the page renders instantly and offline.
  // Scoped narrowly on purpose — same-origin GETs for our own shell files only.
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then((hit) => hit || fetch(event.request))
  );
});
