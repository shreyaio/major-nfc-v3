// Operator console. ARCHITECTURE.md §13.4.
//
// Vanilla JS against the scoped-token admin API. No framework, no build step.
//
// THE TOKEN IS NEVER STORED. It lives in one module-scoped variable for the
// lifetime of the tab. localStorage would mean an XSS anywhere on this origin
// yields a token that can recall a batch or clear a duplicate flag. Tokens are
// capped at 12 hours anyway, so re-pasting costs nothing.

let TOKEN = '';

const $ = (id) => document.getElementById(id);

function setText(node, text) {
  node.textContent = text == null ? '' : String(text);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = (body.error && body.error.message) || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body;
}

// ----------------------------------------------------------------- posture ---

async function loadPosture() {
  const banner = $('posture-banner');
  try {
    const health = await fetch('/health').then((r) => r.json());
    const posture = health.posture || {};

    // The operating posture must never be ambiguous. If tags are rewritable,
    // say so in amber every time someone opens this page (§6.7).
    if (posture.tag_locking === 'disabled') {
      banner.className = 'banner warn';
      setText(banner, 'Tags are rewritable — testing configuration. Attacks A7 and A8 are open until TAG_LOCK_ENABLED is turned on.');
    } else {
      banner.className = 'banner ok';
      setText(banner, 'Tags are locked — production configuration.');
    }

    const dl = $('posture-details');
    dl.textContent = '';
    const rows = {
      Status: health.status,
      Version: health.version,
      'Server time': health.server_time,
      'Tag locking': posture.tag_locking,
      'Originality policy': posture.originality_policy,
      'Crypto versions': (posture.crypto_versions || []).join(', '),
      'Row signing': posture.row_signing,
      Database: posture.database,
      'Edge expected': String(posture.edge_expected),
    };
    for (const [label, value] of Object.entries(rows)) {
      if (value == null) continue;
      const dt = document.createElement('dt');
      const dd = document.createElement('dd');
      setText(dt, label);
      setText(dd, value);
      dl.append(dt, dd);
    }
  } catch (err) {
    banner.className = 'banner bad';
    setText(banner, 'Could not reach the backend.');
  }
}

// ----------------------------------------------------------------- batches ---

function cell(row, text) {
  const td = document.createElement('td');
  setText(td, text);
  row.appendChild(td);
  return td;
}

async function loadBatches() {
  const { batches } = await api('/api/v2/admin/batches');
  const body = $('batches-table').querySelector('tbody');
  body.textContent = '';
  for (const batch of batches) {
    const row = document.createElement('tr');
    cell(row, batch.batch_ref);
    cell(row, batch.product_name);
    cell(row, batch.status);
    cell(row, `${batch.enrolled_count} / ${batch.quota}`);
    cell(row, `${batch.opened_by} + ${batch.countersigned_by}`);

    const actions = document.createElement('td');
    if (batch.status === 'open') {
      const close = document.createElement('button');
      setText(close, 'Close');
      close.addEventListener('click', async () => {
        await api(`/api/v2/admin/batches/${encodeURIComponent(batch.batch_ref)}/close`, {
          method: 'POST',
        });
        loadBatches();
      });
      actions.appendChild(close);
    }
    if (batch.status !== 'recalled') {
      const recall = document.createElement('button');
      recall.className = 'danger';
      setText(recall, 'Recall');
      recall.addEventListener('click', async () => {
        // The notice is what a patient reads on the verification page. A recall
        // with no explanation is a scary red screen with no instruction.
        const notice = prompt(
          'Recall notice — this text is shown to every consumer who scans a pack from this batch:'
        );
        if (!notice) return;
        await api('/api/v2/admin/recall', {
          method: 'POST',
          body: JSON.stringify({ batch_ref: batch.batch_ref, notice }),
        });
        loadBatches();
      });
      actions.appendChild(recall);
    }
    row.appendChild(actions);
    body.appendChild(row);
  }
}

async function openBatch(event) {
  event.preventDefault();
  try {
    await api('/api/v2/admin/batches', {
      method: 'POST',
      body: JSON.stringify({
        batch_ref: $('b-ref').value.trim(),
        product_name: $('b-name').value.trim(),
        mfg_date: $('b-mfg').value,
        shelf_life_days: Number($('b-shelf').value),
        quota: Number($('b-quota').value),
        opened_by: $('b-opened').value.trim(),
        countersigned_by: $('b-counter').value.trim(),
      }),
    });
    $('open-batch-form').reset();
    loadBatches();
  } catch (err) {
    alert(err.message);
  }
}

// --------------------------------------------------------------- incidents ---

async function loadIncidents() {
  const { incidents } = await api('/api/v2/admin/incidents?status=open');
  const body = $('incidents-table').querySelector('tbody');
  body.textContent = '';
  for (const incident of incidents) {
    const row = document.createElement('tr');
    cell(row, incident.created_at);
    cell(row, incident.kind);
    cell(row, incident.observed_counter);
    cell(row, incident.expected_min);
    cell(row, incident.velocity_bound ?? '—');

    const actions = document.createElement('td');
    for (const resolution of ['confirmed', 'false_positive', 'closed']) {
      const button = document.createElement('button');
      setText(button, resolution.replace('_', ' '));
      if (resolution === 'false_positive') button.className = 'danger';
      button.addEventListener('click', async () => {
        // A note is required by the API. This decision has to be explainable —
        // "false_positive" un-flags a tag that the system believes was cloned.
        const note = prompt(`Why are you marking incident ${incident.id} as ${resolution}?`);
        if (!note) return;
        await api(`/api/v2/admin/incidents/${incident.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ resolution, note }),
        });
        loadIncidents();
      });
      actions.appendChild(button);
    }
    row.appendChild(actions);
    body.appendChild(row);
  }
}

// ----------------------------------------------------------------- reports ---

async function loadReports() {
  const { reports } = await api('/api/v2/admin/reports?triage=new');
  const body = $('reports-table').querySelector('tbody');
  body.textContent = '';
  for (const report of reports) {
    const row = document.createElement('tr');
    cell(row, report.created_at);
    cell(row, report.verdict_shown || '—');
    cell(row, [report.pharmacy_name, report.city].filter(Boolean).join(', ') || '—');
    cell(row, report.note || '—');

    const actions = document.createElement('td');
    for (const state of ['reviewing', 'actioned', 'spam']) {
      const button = document.createElement('button');
      setText(button, state);
      button.addEventListener('click', async () => {
        await api(`/api/v2/admin/reports/${report.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ triage: state }),
        });
        loadReports();
      });
      actions.appendChild(button);
    }
    row.appendChild(actions);
    body.appendChild(row);
  }
}

// ------------------------------------------------------------------ startup --

async function useToken() {
  TOKEN = $('token').value.trim();
  $('token').value = '';
  if (!TOKEN) {
    setText($('auth-status'), 'Paste a token first.');
    return;
  }
  try {
    await loadBatches();
    for (const pane of ['batches-pane', 'incidents-pane', 'reports-pane']) {
      $(pane).hidden = false;
    }
    setText($('auth-status'), 'Token accepted. It is held in memory for this tab only.');
    await Promise.allSettled([loadIncidents(), loadReports()]);
  } catch (err) {
    TOKEN = '';
    setText($('auth-status'), `Rejected: ${err.message}`);
  }
}

$('use-token').addEventListener('click', useToken);
$('open-batch-form').addEventListener('submit', openBatch);
loadPosture();
