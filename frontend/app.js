(function () {
  var STATUS_TEXT = {
    authentic: "AUTHENTIC",
    expired: "EXPIRED",
    tampered: "TAMPERED — DO NOT USE",
    unknown: "UNKNOWN TAG",
  };

  var STATUS_SUB = {
    authentic: "This product matches a genuine record on file.",
    expired: "This product is genuine but past its expiry date. Do not use.",
    tampered: "This record does not match what was originally written. Do not trust this product.",
    unknown: "We have no record of this tag. It may be fake, or not yet registered.",
  };

  function qs(name) {
    var params = new URLSearchParams(window.location.search);
    return params.get(name);
  }

  function escapeHtml(s) {
    var div = document.createElement("div");
    div.textContent = s == null ? "" : s;
    return div.innerHTML;
  }

  // Matches the backend's hashlib.sha256(uid.encode('latin-1')).hexdigest() --
  // safe because the UID string is always plain hex characters (0-9, A-F),
  // which UTF-8 and latin-1 encode identically.
  function sha256Hex(str) {
    var bytes = new TextEncoder().encode(str);
    return crypto.subtle.digest("SHA-256", bytes).then(function (buf) {
      var out = "";
      var view = new Uint8Array(buf);
      for (var i = 0; i < view.length; i++) {
        out += view[i].toString(16).padStart(2, "0");
      }
      return out;
    });
  }

  function render(status, data) {
    var area = document.getElementById("result-area");
    var label = STATUS_TEXT[status] || STATUS_TEXT.unknown;
    var sub = STATUS_SUB[status] || STATUS_SUB.unknown;

    var html = '<div class="status-banner ' + status + '">' + label + '</div>';
    html += '<p class="status-sub">' + escapeHtml(sub) + '</p>';

    if ((status === "authentic" || status === "expired") && data) {
      html += '<div class="card"><dl class="details">' +
        '<dt>Product</dt><dd>' + escapeHtml(data.product_id) + '</dd>' +
        '<dt>Batch</dt><dd>' + escapeHtml(data.batch_id) + '</dd>' +
        '<dt>Manufactured</dt><dd>' + escapeHtml(data.mfg_date) + '</dd>' +
        '<dt>Expires</dt><dd>' + escapeHtml(data.expiry_date) + '</dd>' +
        '</dl></div>';
    }

    area.innerHTML = html;
  }

  function renderError(message) {
    var area = document.getElementById("result-area");
    area.innerHTML = '<div class="status-banner unknown">CHECK FAILED</div>' +
      '<p class="status-sub">' + escapeHtml(message ||
        "Could not reach the verification server. Check your connection and try again.") + '</p>';
  }

  function renderScanPrompt(onScan) {
    var area = document.getElementById("result-area");
    area.innerHTML =
      '<div class="status-banner loading">Ready to verify</div>' +
      '<p class="status-sub">Tap your product’s NFC tag now. This reads the physical tag live &mdash; ' +
      'safer than trusting a saved link, which can be copied onto a different tag.</p>' +
      '<button class="btn btn-full" id="scan-btn" type="button">Tap to Scan</button>';
    document.getElementById("scan-btn").addEventListener("click", onScan);
  }

  function renderScanning() {
    document.getElementById("result-area").innerHTML =
      '<div class="status-banner loading">Hold your phone near the tag&hellip;</div>';
  }

  function verifyByHash(hash) {
    fetch("/api/verify/" + encodeURIComponent(hash))
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) { render(data.status, data); })
      .catch(function () { renderError(); });
  }

  function startLiveScan() {
    renderScanning();
    var reader = new NDEFReader();
    reader.scan()
      .then(function () {
        reader.onreading = function (event) {
          var uid = (event.serialNumber || "").split(":").join("").toUpperCase();
          if (!uid) {
            renderError("Could not read a UID from this tag. Try tapping again.");
            return;
          }
          sha256Hex(uid).then(verifyByHash);
        };
        reader.onreadingerror = function () {
          renderError("Could not read the tag. Hold it steady against your phone and try again.");
        };
      })
      .catch(function (err) {
        renderError("NFC scan unavailable: " + (err && err.message ? err.message : err) +
          ". Check that NFC is turned on and permission was granted.");
      });
  }

  var tagId = qs("t");
  var echo = document.getElementById("tag-echo");
  if (echo) echo.textContent = tagId ? ("Tag: " + tagId) : "";

  if ("NDEFReader" in window) {
    // Live scan is the trustworthy path: it reads whatever physical tag is
    // actually touching the phone right now. A t= URL parameter is just
    // static text baked into an NDEF record at write time -- copyable onto
    // any other tag -- so when a live read is possible, it's used exclusively
    // instead of trusting the URL, regardless of whether t= is present.
    renderScanPrompt(startLiveScan);
  } else if (tagId) {
    // No Web NFC on this browser (iOS, desktop, older Android): there's no
    // way to read the tag live, so fall back to trusting the URL parameter.
    var note = document.createElement("p");
    note.className = "status-sub";
    note.textContent = "Live tag verification isn't available in this browser — showing the result for the scanned link instead.";
    echo.insertAdjacentElement("afterend", note);
    verifyByHash(tagId);
  } else {
    render("unknown", null);
  }
})();
