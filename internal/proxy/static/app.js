(function () {
  "use strict";

  const entriesEl = document.getElementById("entries");
  const emptyEl = document.getElementById("empty");
  const statusEl = document.getElementById("status");
  const clearBtn = document.getElementById("clear-btn");
  const themeToggle = document.getElementById("theme-toggle");
  const showAllCheckbox = document.getElementById("show-all");

  let entries = [];
  let showAll = false;

  // Theme toggle
  const savedTheme = localStorage.getItem("proxy-theme") || "dark";
  if (savedTheme === "light") document.documentElement.setAttribute("data-theme", "light");

  themeToggle.addEventListener("click", function () {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    if (isLight) {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("proxy-theme", "dark");
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      localStorage.setItem("proxy-theme", "light");
    }
  });

  // Show all toggle
  showAllCheckbox.checked = localStorage.getItem("proxy-show-all") === "true";
  showAll = showAllCheckbox.checked;

  showAllCheckbox.addEventListener("change", function () {
    showAll = showAllCheckbox.checked;
    localStorage.setItem("proxy-show-all", showAll);
    renderEntries();
  });

  // Clear
  clearBtn.addEventListener("click", function () {
    entries = [];
    renderEntries();
  });

  function isVisible(entry) {
    return showAll || entry.classLabel !== "Unknown";
  }

  function badgeClass(classLabel) {
    if (classLabel.startsWith("VP")) return "badge-vp";
    if (classLabel.startsWith("VCI")) return "badge-vci";
    return "badge-unknown";
  }

  function statusClass(code) {
    if (code < 300) return "ok";
    if (code < 400) return "redirect";
    if (code < 500) return "client-error";
    return "server-error";
  }

  function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  }

  function escapeHtml(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }

  function renderDecoded(decoded) {
    if (!decoded) return "";
    let html = '<div class="decoded-fields">';
    for (const [key, val] of Object.entries(decoded)) {
      html += '<span class="decoded-key">' + escapeHtml(key) + '</span>';
      if (typeof val === "object" && val !== null) {
        html += '<span class="decoded-value"><pre>' + escapeHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="decoded-value">' + escapeHtml(String(val)) + '</span>';
      }
    }
    html += "</div>";
    return html;
  }

  function renderHeaders(headers) {
    if (!headers) return "";
    let lines = [];
    for (const [key, vals] of Object.entries(headers)) {
      for (const v of vals) {
        lines.push(escapeHtml(key + ": " + v));
      }
    }
    return lines.join("\n");
  }

  function renderCredentialLinks(credentials) {
    if (!credentials || credentials.length === 0) return "";
    var html = '<div class="detail-section"><h3>Credentials</h3><div class="credential-links">';
    for (var i = 0; i < credentials.length; i++) {
      var label = credentials.length === 1 ? "View in Decoder" : "View Credential " + (i + 1) + " in Decoder";
      var href = "/decode/?credential=" + encodeURIComponent(credentials[i]);
      html += '<a class="btn credential-link" href="' + escapeHtml(href) + '" target="_blank">' + label + '</a>';
    }
    html += '</div></div>';
    return html;
  }

  function renderEntry(entry) {
    const el = document.createElement("div");
    el.className = "entry";
    el.dataset.id = entry.id;

    const urlPath = entry.url.length > 100 ? entry.url.substring(0, 100) + "..." : entry.url;

    el.innerHTML =
      '<div class="entry-header">' +
        '<span class="entry-time">' + formatTime(entry.timestamp) + '</span>' +
        '<span class="entry-method ' + entry.method + '">' + entry.method + '</span>' +
        '<span class="entry-url" title="' + escapeHtml(entry.url) + '">' + escapeHtml(urlPath) + '</span>' +
        '<span class="entry-status ' + statusClass(entry.statusCode) + '">' + entry.statusCode + '</span>' +
        '<span class="entry-duration">' + entry.durationMs + 'ms</span>' +
        '<span class="entry-badge ' + badgeClass(entry.classLabel) + '">' + escapeHtml(entry.classLabel) + '</span>' +
      '</div>' +
      '<div class="entry-details">' +
        renderCredentialLinks(entry.credentials) +
        (entry.decoded ? '<div class="detail-section"><h3>Decoded</h3>' + renderDecoded(entry.decoded) + '</div>' : '') +
        '<div class="detail-section"><h3>Request Headers</h3><pre>' + renderHeaders(entry.requestHeaders) + '</pre></div>' +
        (entry.requestBody ? '<div class="detail-section"><h3>Request Body</h3><pre>' + escapeHtml(entry.requestBody) + '</pre></div>' : '') +
        '<div class="detail-section"><h3>Response Headers</h3><pre>' + renderHeaders(entry.responseHeaders) + '</pre></div>' +
        (entry.responseBody ? '<div class="detail-section"><h3>Response Body</h3><pre>' + escapeHtml(entry.responseBody) + '</pre></div>' : '') +
      '</div>';

    el.querySelector(".entry-header").addEventListener("click", function () {
      el.classList.toggle("expanded");
    });

    return el;
  }

  function renderEntries() {
    entriesEl.innerHTML = "";
    var visible = entries.filter(isVisible);
    if (visible.length === 0) {
      entriesEl.appendChild(emptyEl);
      emptyEl.style.display = "";
      return;
    }
    emptyEl.style.display = "none";
    for (const entry of visible) {
      entriesEl.appendChild(renderEntry(entry));
    }
    entriesEl.scrollTop = entriesEl.scrollHeight;
  }

  function addEntry(entry) {
    entries.push(entry);
    if (!isVisible(entry)) return;

    if (emptyEl.style.display !== "none") {
      emptyEl.style.display = "none";
      entriesEl.innerHTML = "";
    }
    entriesEl.appendChild(renderEntry(entry));
    entriesEl.scrollTop = entriesEl.scrollHeight;
  }

  // Load initial entries
  fetch("/api/entries")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.length > 0) {
        entries = data;
        renderEntries();
      }
    })
    .catch(function (err) {
      console.error("Failed to load entries:", err);
    });

  // SSE for live updates
  function connectSSE() {
    const es = new EventSource("/api/stream");

    es.onmessage = function (event) {
      try {
        const entry = JSON.parse(event.data);
        addEntry(entry);
      } catch (err) {
        console.error("Failed to parse SSE event:", err);
      }
    };

    es.onopen = function () {
      statusEl.textContent = "Connected";
      statusEl.className = "status";
    };

    es.onerror = function () {
      statusEl.textContent = "Disconnected";
      statusEl.className = "status disconnected";
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  connectSSE();
})();
