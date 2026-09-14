// Verdict copy, keyed by language. ARCHITECTURE.md §13.3.
//
// IN A HEALTH CONTEXT, VERDICT WORDING IS A SAFETY CONTROL, NOT UX POLISH.
// v1's "UNKNOWN TAG" tells a worried patient nothing about what to do (F36).
//
// Three rules govern every line in this file:
//
//   1. NEVER the word "counterfeit" or "fake" as a verdict. Attribution is
//      genuinely ambiguous (§9.7): an attacker who pre-advances a clone's
//      counter causes the GENUINE pack to trip the alarm. "Fake" is a claim the
//      system cannot support and a defamation risk. The strongest negative
//      verdict this system emits is "seen on more than one item".
//   2. NEVER a bare failure. Every negative state routes to the report form or
//      to a human.
//   3. Localisation and accessibility are in scope. A patient who cannot read
//      the verdict is not protected by it.

export const STRINGS = {
  en: {
    checking: {
      heading: 'Checking this pack…',
      body: "Reading the code from the tag and checking it against the manufacturer's register.",
      tone: 'info',
    },
    authentic: {
      heading: 'Checks passed',
      body: "This pack matches the manufacturer's record.",
      action: null,
      tone: 'ok',
    },
    expired: {
      heading: 'Past its expiry date',
      body: 'Genuine, but expired on {expiry}. Do not use it.',
      action: 'Return it to your pharmacist.',
      tone: 'warn',
    },
    recalled: {
      heading: 'Recalled — do not use',
      body: '{notice}',
      action: 'Return it to your pharmacist, and report this pack.',
      tone: 'bad',
    },
    withdrawn: {
      heading: 'Withdrawn — do not use',
      body: 'This pack has been withdrawn from sale.',
      action: 'Return it to your pharmacist.',
      tone: 'bad',
    },
    suspect_duplicate: {
      heading: 'Do not use',
      body: "This pack's code has been seen on more than one item.",
      action: 'Report this pack, and speak to your pharmacist before using it.',
      tone: 'bad',
    },
    mirror_disabled: {
      heading: 'Cannot fully check',
      body: 'This tag did not return a live value from its chip, so we could only check the link.',
      action: 'Report this pack and ask your pharmacist.',
      tone: 'warn',
    },
    record_invalid: {
      heading: 'Cannot confirm',
      body: "We could not confirm this pack's record.",
      action: 'Do not use it until it has been checked. Please report it.',
      tone: 'bad',
    },
    unknown: {
      heading: 'Not found',
      body: 'This pack is not in our register. It may be counterfeit, or the pack may predate this system.',
      action: 'Do not use it without checking with your pharmacist.',
      tone: 'warn',
    },
    offline: {
      heading: 'Cannot verify — no connection',
      body: 'We could not reach the verification service.',
      action: 'Try again when you have a connection.',
      tone: 'info',
    },
    checks: {
      record: 'Record signature',
      counter: 'Tap counter',
      recall: 'Recall status',
      expiry: 'Expiry',
      pass: '✓ checked',
      fail: '✗ did not pass',
      not_checked: '— not checked',
    },
    binding: {
      'counter+liveread':
        'Checked against a live value read directly from the chip on this phone — the strongest check available.',
      counter:
        "Checked against a live value the chip wrote into this link when you tapped it.",
      none:
        'This check could not read a live value from the chip — the result is based on the link only, which is weaker.',
    },
    details: {
      name: 'Product',
      batch: 'Batch',
      mfg_date: 'Manufactured',
      expiry: 'Expires',
    },
    reportLink: 'Report this pack',
    liveReadButton: 'Read the chip directly',
    liveReadUnsupported: 'Direct chip reading is not available in this browser.',
    incidentRef: 'Reference {id} — quote this if you report the pack.',
  },

  // Hindi. Reviewed wording belongs here before this is used in the field; the
  // structure exists now so the strings are not hard-coded in the renderer.
  hi: {
    checking: {
      heading: 'जाँच की जा रही है…',
      body: 'टैग से कोड पढ़ा जा रहा है और निर्माता के रिकॉर्ड से मिलाया जा रहा है।',
      tone: 'info',
    },
    authentic: {
      heading: 'जाँच पूरी हुई',
      body: 'यह पैक निर्माता के रिकॉर्ड से मेल खाता है।',
      action: null,
      tone: 'ok',
    },
    expired: {
      heading: 'समय-सीमा समाप्त',
      body: 'असली है, लेकिन {expiry} को समय-सीमा समाप्त हो गई। इसका उपयोग न करें।',
      action: 'इसे अपने फार्मासिस्ट को लौटाएँ।',
      tone: 'warn',
    },
    unknown: {
      heading: 'नहीं मिला',
      body: 'यह पैक हमारे रजिस्टर में नहीं है।',
      action: 'फार्मासिस्ट से पूछे बिना इसका उपयोग न करें।',
      tone: 'warn',
    },
    offline: {
      heading: 'जाँच नहीं हो सकी — कनेक्शन नहीं',
      body: 'सत्यापन सेवा तक नहीं पहुँच सके।',
      action: 'कनेक्शन मिलने पर दोबारा प्रयास करें।',
      tone: 'info',
    },
  },
};

export function pickLanguage() {
  const requested = (navigator.language || 'en').slice(0, 2);
  return STRINGS[requested] ? requested : 'en';
}

export function t(lang, verdict) {
  // Fall back to English per-key rather than per-language, so a partial
  // translation degrades to a readable mix rather than to a missing verdict.
  return (STRINGS[lang] && STRINGS[lang][verdict]) || STRINGS.en[verdict] || STRINGS.en.unknown;
}

export function common(lang) {
  return { ...STRINGS.en, ...(STRINGS[lang] || {}) };
}
