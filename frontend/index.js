// Manual entry, for testing without hardware. ARCHITECTURE.md §13.1.
//
// Clearly labelled as such on the page. A code typed in by hand has none of the
// physical binding a tap provides — that is the honest framing, and it belongs
// in front of the user rather than in a comment.

const form = document.getElementById('manual-form');
const status = document.getElementById('manual-status');

form.addEventListener('submit', (event) => {
  event.preventDefault();

  // Normalise exactly the way backend/mirror.py and edge/src/canonicalise.js do:
  // NFKC, trim, uppercase. Doing it here too means an honest typo is corrected
  // rather than bounced, while anything genuinely malformed still fails at both
  // of the real parsers.
  const m = document.getElementById('m').value.normalize('NFKC').trim().toUpperCase();
  const t = document.getElementById('t').value.normalize('NFKC').trim().toUpperCase();

  if (!/^[0-9A-F]{14}X[0-9A-F]{6}$/.test(m)) {
    status.textContent = 'The m value should be 14 hex characters, an x, then 6 hex characters.';
    return;
  }
  if (!/^[0-9A-F]{32}$/.test(t)) {
    status.textContent = 'The t value should be exactly 32 hex characters.';
    return;
  }

  window.location.href = `/c?m=${encodeURIComponent(m)}&t=${encodeURIComponent(t)}`;
});
