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

  function renderError() {
    var area = document.getElementById("result-area");
    area.innerHTML = '<div class="status-banner unknown">CHECK FAILED</div>' +
      '<p class="status-sub">Could not reach the verification server. Check your connection and try again.</p>';
  }

  var tagId = qs("t");
  var echo = document.getElementById("tag-echo");

  if (!tagId) {
    if (echo) echo.textContent = "No tag ID provided.";
    render("unknown", null);
    return;
  }

  if (echo) echo.textContent = "Tag: " + tagId;

  fetch("/api/verify/" + encodeURIComponent(tagId))
    .then(function (res) {
      if (!res.ok) throw new Error("HTTP " + res.status);
      return res.json();
    })
    .then(function (data) { render(data.status, data); })
    .catch(renderError);
})();
