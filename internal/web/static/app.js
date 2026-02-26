(() => {
  "use strict";

  const input = document.getElementById("input");
  const outputEl = document.getElementById("output");
  const formatBadge = document.getElementById("format-badge");
  const clearBtn = document.getElementById("clear-btn");
  const themeBtn = document.getElementById("theme-btn");

  let debounceTimer = null;

  // Theme
  function getPreferredTheme() {
    const stored = localStorage.getItem("ssi-debugger-theme");
    if (stored) return stored;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("ssi-debugger-theme", theme);
    themeBtn.textContent = theme === "dark" ? "Light" : "Dark";
  }

  setTheme(getPreferredTheme());

  themeBtn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    setTheme(current === "dark" ? "light" : "dark");
  });

  // Clear
  clearBtn.addEventListener("click", () => {
    input.value = "";
    outputEl.innerHTML = '<div class="placeholder">Paste a credential to see decoded output</div>';
    formatBadge.className = "badge hidden";
    input.focus();
  });

  // Decode
  function decode() {
    const text = input.value.trim();
    if (!text) {
      outputEl.innerHTML = '<div class="placeholder">Paste a credential to see decoded output</div>';
      formatBadge.className = "badge hidden";
      return;
    }

    fetch("/api/decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: text }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          showError(data.error);
          formatBadge.className = "badge hidden";
          return;
        }
        showResult(data);
      })
      .catch((err) => {
        showError("Request failed: " + err.message);
      });
  }

  function scheduleDecde() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(decode, 300);
  }

  input.addEventListener("input", scheduleDecde);
  input.addEventListener("paste", () => {
    // Decode immediately on paste
    clearTimeout(debounceTimer);
    setTimeout(decode, 10);
  });

  function showError(msg) {
    outputEl.innerHTML = '<div class="error">' + escapeHtml(msg) + "</div>";
  }

  // Render result
  function showResult(data) {
    updateBadge(data.format);
    outputEl.innerHTML = "";

    const fmt = data.format;

    if (fmt === "dc+sd-jwt") {
      renderSDJWT(data);
    } else if (fmt === "jwt") {
      renderJWT(data);
    } else if (fmt === "mso_mdoc") {
      renderMDOC(data);
    } else {
      outputEl.innerHTML = renderJSON(data);
    }
  }

  function updateBadge(format) {
    if (format === "dc+sd-jwt") {
      formatBadge.textContent = "SD-JWT";
      formatBadge.className = "badge sd-jwt";
    } else if (format === "jwt") {
      formatBadge.textContent = "JWT";
      formatBadge.className = "badge jwt";
    } else if (format === "mso_mdoc") {
      formatBadge.textContent = "mDOC";
      formatBadge.className = "badge mdoc";
    } else {
      formatBadge.className = "badge hidden";
    }
  }

  function renderSDJWT(data) {
    appendSection("Header", renderJSONBlock(data.header));
    appendSection("Payload (signed claims)", renderJSONBlock(data.payload));

    if (data.disclosures && data.disclosures.length > 0) {
      const disc = document.createElement("div");
      data.disclosures.forEach((d, i) => {
        const item = document.createElement("div");
        item.className = "disclosure-item";
        const name = d.isArrayEntry ? "(array element)" : d.name;
        const valStr = typeof d.value === "object" ? JSON.stringify(d.value) : String(d.value);
        item.innerHTML =
          '<span class="disclosure-name">' + escapeHtml(name) + '</span>: <span class="disclosure-value">' + escapeHtml(valStr) + "</span>" +
          '<div class="disclosure-meta">salt: ' + escapeHtml(d.salt) + " | digest: " + escapeHtml(d.digest) + "</div>";
        disc.appendChild(item);
      });
      appendSection("Disclosures (" + data.disclosures.length + ")", disc);
    }

    appendSection("Resolved Claims", renderJSONBlock(data.resolvedClaims));

    if (data.keyBindingJWT) {
      const kb = document.createElement("div");
      kb.appendChild(createSubSection("Header", renderJSONBlock(data.keyBindingJWT.header)));
      kb.appendChild(createSubSection("Payload", renderJSONBlock(data.keyBindingJWT.payload)));
      appendSection("Key Binding JWT", kb);
    }

    if (data.warnings && data.warnings.length > 0) {
      const w = document.createElement("div");
      data.warnings.forEach((msg) => {
        const p = document.createElement("div");
        p.style.color = "var(--yellow)";
        p.textContent = "\u26A0 " + msg;
        w.appendChild(p);
      });
      appendSection("Warnings", w);
    }
  }

  function renderJWT(data) {
    appendSection("Header", renderJSONBlock(data.header));
    appendSection("Payload", renderJSONBlock(data.payload));
  }

  function renderMDOC(data) {
    // Document info
    const info = document.createElement("div");
    info.appendChild(renderKV("DocType", data.docType));
    appendSection("Document Info", info);

    // MSO
    if (data.mso) {
      const mso = data.mso;
      const el = document.createElement("div");
      if (mso.version) el.appendChild(renderKV("Version", mso.version));
      if (mso.digestAlgorithm) el.appendChild(renderKV("Digest Algorithm", mso.digestAlgorithm));
      if (mso.validityInfo) {
        const vi = mso.validityInfo;
        if (vi.signed) el.appendChild(renderKV("Signed", vi.signed));
        if (vi.validFrom) el.appendChild(renderKV("Valid From", vi.validFrom));
        if (vi.validUntil) el.appendChild(renderKV("Valid Until", vi.validUntil));
      }
      if (mso.status) {
        el.appendChild(createSubSection("Status", renderJSONBlock(mso.status)));
      }
      appendSection("Mobile Security Object", el);
    }

    // Claims by namespace
    if (data.claims) {
      Object.keys(data.claims).sort().forEach((ns) => {
        const claims = data.claims[ns];
        const keys = Object.keys(claims).sort();
        const el = document.createElement("div");
        keys.forEach((k) => {
          const val = claims[k];
          const valStr = typeof val === "object" && val !== null ? JSON.stringify(val, null, 2) : String(val);
          const item = document.createElement("div");
          item.className = "claim-item";
          item.innerHTML =
            '<span class="claim-name">' + escapeHtml(k) + '</span>: <span class="claim-value">' + escapeHtml(valStr) + "</span>";
          el.appendChild(item);
        });
        appendSection(ns + " (" + keys.length + " claims)", el);
      });
    }

    // Device Auth
    if (data.deviceAuth) {
      appendSection("Device Auth", renderJSONBlock(data.deviceAuth));
    }
  }

  // UI helpers
  function appendSection(title, contentEl) {
    const section = document.createElement("div");
    section.className = "section";

    const header = document.createElement("div");
    header.className = "section-header";

    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.textContent = "\u25BC";

    const titleSpan = document.createElement("span");
    titleSpan.textContent = title;

    header.appendChild(arrow);
    header.appendChild(titleSpan);

    const body = document.createElement("div");
    body.className = "section-body";
    body.appendChild(contentEl);

    header.addEventListener("click", () => {
      const collapsed = body.classList.toggle("collapsed");
      arrow.classList.toggle("collapsed", collapsed);
    });

    section.appendChild(header);
    section.appendChild(body);
    outputEl.appendChild(section);
  }

  function createSubSection(title, contentEl) {
    const wrap = document.createElement("div");
    wrap.style.margin = "6px 0";
    const label = document.createElement("div");
    label.style.color = "var(--cyan)";
    label.style.fontWeight = "600";
    label.style.marginBottom = "4px";
    label.textContent = title;
    wrap.appendChild(label);
    wrap.appendChild(contentEl);
    return wrap;
  }

  function renderKV(key, value) {
    const line = document.createElement("div");
    line.className = "json-line";
    line.innerHTML = '<span class="json-key">' + escapeHtml(key) + '</span>: <span class="json-string">' + escapeHtml(String(value)) + "</span>";
    return line;
  }

  function renderJSONBlock(obj) {
    const el = document.createElement("pre");
    el.className = "json-block";
    el.innerHTML = syntaxHighlight(JSON.stringify(obj, null, 2));
    return el;
  }

  function syntaxHighlight(json) {
    if (!json) return "";
    json = escapeHtml(json);
    return json.replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      (match) => {
        let cls = "json-number";
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = "json-key";
          } else {
            cls = "json-string";
          }
        } else if (/true|false/.test(match)) {
          cls = "json-bool";
        } else if (/null/.test(match)) {
          cls = "json-null";
        }
        return '<span class="' + cls + '">' + match + "</span>";
      }
    );
  }

  function renderJSON(obj) {
    return '<pre style="margin:0">' + syntaxHighlight(JSON.stringify(obj, null, 2)) + "</pre>";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // Pre-fill: check ?credential= query param, then /api/prefill
  function prefill(credential) {
    input.value = credential;
    decode();
  }

  const urlCredential = new URLSearchParams(window.location.search).get("credential");
  if (urlCredential) {
    prefill(urlCredential);
  } else {
    fetch("/api/prefill")
      .then((res) => res.json())
      .then((data) => {
        if (data.credential) {
          prefill(data.credential);
        }
      })
      .catch(() => {});
  }
})();
