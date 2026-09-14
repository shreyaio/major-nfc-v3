// Consumer report form. ARCHITECTURE.md §10.4.
//
// PROOF-OF-WORK INSTEAD OF A CAPTCHA (G8).
//
// The page fetches a challenge, finds a nonce where sha256(challenge || nonce)
// has POW_DIFFICULTY_BITS leading zero bits, and submits it. That costs this
// phone about a second and a flooder a great deal more — with no third-party
// service, no tracking, and no cost.
//
// A CAPTCHA would put a Google dependency between a patient and a safety
// answer, and would ship their browsing to an ad company to do it. In this
// context that is the wrong trade.

const params = new URLSearchParams(window.location.search);

function setStatus(text) {
  document.getElementById('status').textContent = text;
}

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return new Uint8Array(digest);
}

function leadingZeroBits(bytes) {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    let b = byte;
    while ((b & 0x80) === 0) {
      bits += 1;
      b <<= 1;
    }
    break;
  }
  return bits;
}

async function solve(challenge, difficultyBits, onProgress) {
  // Yield to the event loop periodically so the page stays responsive and the
  // browser does not kill it as unresponsive on a slow device.
  for (let nonce = 0; ; nonce += 1) {
    if (leadingZeroBits(await sha256(`${challenge}${nonce}`)) >= difficultyBits) {
      return nonce;
    }
    if (nonce % 2000 === 0) {
      onProgress(nonce);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}

async function submit(event) {
  event.preventDefault();
  const button = document.getElementById('submit');
  const note = document.getElementById('note').value.trim();

  if (!note) {
    setStatus('Please describe what happened — that is the part we need.');
    return;
  }

  button.disabled = true;
  setStatus('Preparing…');

  try {
    const challengeResponse = await fetch('/api/v2/report/challenge', {
      headers: { Accept: 'application/json' },
    });
    if (!challengeResponse.ok) throw new Error('challenge');
    const { challenge, difficulty_bits: bits } = await challengeResponse.json();

    setStatus('Checking you are not a robot (this takes a moment)…');
    const nonce = await solve(challenge, bits, () => {});

    setStatus('Sending…');
    const response = await fetch('/api/v2/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tag_index: params.get('tag_index'),
        verdict_shown: params.get('verdict'),
        pharmacy_name: document.getElementById('pharmacy').value.trim() || null,
        city: document.getElementById('city').value.trim() || null,
        note,
        contact: document.getElementById('contact').value.trim() || null,
        pow: { challenge, nonce },
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      setStatus(
        (body.error && body.error.message) ||
          'We could not send the report. Please try again in a moment.'
      );
      button.disabled = false;
      return;
    }

    const { reference } = await response.json();
    document.getElementById('report-form').hidden = true;
    setStatus(
      `Report received. Your reference is ${reference}. Thank you — reports like ` +
        `this are how counterfeit medicine gets found.`
    );
  } catch (err) {
    setStatus('We could not reach the service. Please try again when you have a connection.');
    button.disabled = false;
  }
}

document.getElementById('report-form').addEventListener('submit', submit);
document.getElementById('back').addEventListener('click', () => history.back());
