(() => {
  "use strict";

  const input = document.getElementById("input");
  const outputEl = document.getElementById("output");
  const formatBadge = document.getElementById("format-badge");
  const clearBtn = document.getElementById("clear-btn");
  const shareBtn = document.getElementById("share-btn");
  const themeBtn = document.getElementById("theme-btn");
  const rawView = document.getElementById("raw-view");

  let debounceTimer = null;
  let lastData = null;
  let lastValidation = null;
  let colorized = false; // true when showing colorized view instead of textarea

  // Disclosure color palette size
  const DISC_COLORS = 8;

  // Well-known timestamp fields in JWT/SD-JWT payloads
  const TIMESTAMP_FIELDS = new Set(["exp", "iat", "nbf", "auth_time", "updated_at"]);

  // SD-JWT internal fields to dim
  const SD_INTERNAL_FIELDS = new Set(["_sd", "_sd_alg"]);

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
    history.replaceState(null, "", window.location.pathname);
    lastData = null;
    lastValidation = null;
    showTextarea();
    input.focus();
  });

  // Share — copy URL with ?credential= query param
  shareBtn.addEventListener("click", copyShareLink);

  function copyShareLink() {
    const text = input.value.trim();
    if (!text) return;
    const url = window.location.origin + window.location.pathname + "?credential=" + encodeURIComponent(text);
    navigator.clipboard.writeText(url).then(() => {
      showToast("Link copied to clipboard");
    }).catch(() => {
      showToast("Failed to copy link");
    });
  }

  // Colorized input view — shown automatically after decode, click to edit
  rawView.addEventListener("click", () => showTextarea());

  function showColorized() {
    if (colorized) return;
    colorized = true;
    input.style.display = "none";
    rawView.style.display = "block";
    updateRawView();
  }

  function showTextarea() {
    if (!colorized) return;
    colorized = false;
    input.style.display = "";
    rawView.style.display = "none";
    input.focus();
  }

  function updateRawView() {
    const text = input.value.trim();
    if (!text) {
      rawView.innerHTML = '<span style="color:var(--text-dim);font-style:italic">No input</span>';
      return;
    }

    // Try to colorize as JWT/SD-JWT
    const parts = text.split("~");
    const jwtPart = parts[0];
    const jwtSegments = jwtPart.split(".");

    if (jwtSegments.length >= 2) {
      let html = "";
      html += '<span class="jwt-header" data-section="header">' + escapeHtml(jwtSegments[0]) + "</span>";
      html += '<span class="jwt-separator">.</span>';
      html += '<span class="jwt-payload" data-section="payload">' + escapeHtml(jwtSegments[1]) + "</span>";
      if (jwtSegments.length > 2) {
        html += '<span class="jwt-separator">.</span>';
        html += '<span class="jwt-signature" data-section="signature">' + escapeHtml(jwtSegments.slice(2).join(".")) + "</span>";
      }

      // SD-JWT disclosures — each gets a unique color
      // Detect KB-JWT: last non-empty part that contains dots (JWT structure)
      let kbJwtIndex = -1;
      if (parts.length > 1) {
        for (let i = parts.length - 1; i >= 1; i--) {
          if (parts[i] && parts[i].includes(".")) {
            kbJwtIndex = i;
            break;
          }
        }
      }

      let discIdx = 0;
      for (let i = 1; i < parts.length; i++) {
        html += '<span class="jwt-separator">~</span>';
        if (parts[i]) {
          if (i === kbJwtIndex) {
            // KB-JWT — colorize its internal structure
            const kbSegs = parts[i].split(".");
            html += '<span data-section="kb-jwt">';
            html += '<span class="jwt-header">' + escapeHtml(kbSegs[0]) + "</span>";
            if (kbSegs.length > 1) {
              html += '<span class="jwt-separator">.</span>';
              html += '<span class="jwt-payload">' + escapeHtml(kbSegs[1]) + "</span>";
            }
            if (kbSegs.length > 2) {
              html += '<span class="jwt-separator">.</span>';
              html += '<span class="jwt-signature">' + escapeHtml(kbSegs.slice(2).join(".")) + "</span>";
            }
            html += "</span>";
          } else {
            const colorIdx = discIdx % DISC_COLORS;
            html += '<span class="jwt-disc-' + colorIdx + '" data-section="disc-' + discIdx + '">' + escapeHtml(parts[i]) + "</span>";
            discIdx++;
          }
        }
      }

      rawView.innerHTML = html;
      attachRawViewHover();
    } else {
      // Non-JWT (e.g. mDOC hex/base64)
      rawView.innerHTML = escapeHtml(text);
    }
  }

  // Cross-highlight: hovering input parts highlights decoded sections
  function attachRawViewHover() {
    rawView.querySelectorAll("[data-section]").forEach((span) => {
      span.addEventListener("mouseenter", () => {
        const sec = span.getAttribute("data-section");
        span.classList.add("highlight");

        // Individual disclosure → highlight specific disclosure item
        if (sec.startsWith("disc-")) {
          const idx = sec.replace("disc-", "");
          const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
          if (item) {
            item.classList.add("highlight");
            item.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        } else {
          // Header/payload/signature → highlight whole section
          const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
          if (target) {
            target.classList.add("highlight");
            target.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
      });
      span.addEventListener("mouseleave", () => {
        const sec = span.getAttribute("data-section");
        span.classList.remove("highlight");

        if (sec.startsWith("disc-")) {
          const idx = sec.replace("disc-", "");
          const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
          if (item) item.classList.remove("highlight");
        } else {
          const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
          if (target) target.classList.remove("highlight");
        }
      });
    });
  }

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    // Ctrl+L or Ctrl+K — focus input
    if ((e.ctrlKey || e.metaKey) && (e.key === "l" || e.key === "k")) {
      e.preventDefault();
      if (colorized) showTextarea();
      input.focus();
      input.select();
    }
    // Ctrl+Shift+C — copy share link (only when not in text selection)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "C") {
      e.preventDefault();
      copyShareLink();
    }
  });

  function showToast(msg) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2000);
  }

  // Decode — calls /api/validate to get both decode result and validation checks
  // (integrity, expiry, status run automatically; signature is skipped without key)
  function decode() {
    const text = input.value.trim();
    if (!text) {
      outputEl.innerHTML = '<div class="placeholder">Paste a credential to see decoded output</div>';
      formatBadge.className = "badge hidden";
      lastData = null;
      lastValidation = null;
      return;
    }

    fetch("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: text, checkStatus: true }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          showError(data.error);
          formatBadge.className = "badge hidden";
          lastData = null;
          lastValidation = null;
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        showResult(data);
        showColorized();
      })
      .catch((err) => {
        showError("Request failed: " + err.message);
      });
  }

  // Re-validate with a public key or trust list for signature verification
  function verifySignature(keyText, trustListURL) {
    const text = input.value.trim();
    if (!text) return;

    const body = { input: text, checkStatus: true };
    if (keyText) body.key = keyText;
    if (trustListURL) body.trustListURL = trustListURL;

    fetch("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          showToast("Verification error: " + data.error);
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        showResult(data);
        showColorized();
      })
      .catch((err) => {
        showToast("Verification failed: " + err.message);
      });
  }

  function scheduleDecode() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(decode, 300);
  }

  input.addEventListener("input", scheduleDecode);
  input.addEventListener("paste", () => {
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

    // Issuer/subject summary line
    const summary = extractSummary(data);
    if (summary) {
      outputEl.appendChild(renderSummaryLine(summary));
    }

    // Validation banner (always from server checks now)
    if (data.validation && data.validation.checks) {
      outputEl.appendChild(renderValidationBanner(data.validation.checks));
    }

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

  // Issuer/subject summary
  function extractSummary(data) {
    const parts = [];
    if (data.format === "mso_mdoc") {
      if (data.docType) parts.push({ label: "DocType", value: data.docType });
      // Look for issuing_authority or issuing_country in mDOC claims
      if (data.claims) {
        for (const ns of Object.keys(data.claims)) {
          const c = data.claims[ns];
          if (c.issuing_authority) parts.push({ label: "Issuer", value: String(c.issuing_authority) });
          if (c.issuing_country) parts.push({ label: "Country", value: String(c.issuing_country) });
        }
      }
    } else if (data.payload) {
      if (data.payload.iss) parts.push({ label: "Issuer", value: data.payload.iss });
      if (data.payload.sub) parts.push({ label: "Subject", value: data.payload.sub });
      if (data.payload.vct) parts.push({ label: "Type", value: data.payload.vct });
    }
    return parts.length ? parts : null;
  }

  function renderSummaryLine(parts) {
    const el = document.createElement("div");
    el.className = "issuer-summary";
    parts.forEach((p) => {
      const chip = document.createElement("span");
      chip.className = "summary-chip";
      const label = document.createElement("span");
      label.className = "summary-chip-label";
      label.textContent = p.label;
      const value = document.createElement("span");
      value.className = "summary-chip-value";
      value.textContent = p.value;
      value.title = p.value;
      chip.appendChild(label);
      chip.appendChild(value);
      el.appendChild(chip);
    });
    return el;
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

  // Validation banner with hover checklist + clickable signature verify popover
  function renderValidationBanner(checks) {
    const banner = document.createElement("div");
    banner.className = "validity-banner";

    const hasFailure = checks.some((c) => c.status === "fail");
    const sigCheck = checks.find((c) => c.name === "signature");
    const sigSkipped = sigCheck && sigCheck.status === "skipped";
    const nonSkipped = checks.filter((c) => c.status !== "skipped");
    const allNonSkippedPass = nonSkipped.length > 0 && nonSkipped.every((c) => c.status === "pass");

    let icon, label, cls;
    if (hasFailure) {
      icon = "\u2717";
      label = "Invalid";
      cls = "expired"; // red
    } else if (sigSkipped) {
      icon = "\u26A0";
      label = "Unverified";
      cls = "unverified"; // yellow
    } else if (allNonSkippedPass) {
      icon = "\u2713";
      label = "Valid";
      cls = "valid"; // green
    } else {
      icon = "\u26A0";
      label = "Unverified";
      cls = "unverified";
    }

    banner.classList.add(cls);

    // Build summary detail from first relevant check
    let detail = "";
    const expiryCheck = checks.find((c) => c.name === "expiry");
    if (expiryCheck && expiryCheck.status !== "skipped") {
      detail = expiryCheck.detail;
    }

    let html = '<span class="validity-banner-text">' + icon + " " + label;
    if (detail) {
      html += '<span class="validity-detail"> \u2014 ' + escapeHtml(detail) + "</span>";
    }
    html += "</span>";

    // Hover checklist
    html += '<div class="validity-checks">';
    checks.forEach((c) => {
      let cIcon, cCls;
      if (c.status === "pass") { cIcon = "\u2713"; cCls = "check-pass"; }
      else if (c.status === "fail") { cIcon = "\u2717"; cCls = "check-fail"; }
      else { cIcon = "\u2014"; cCls = "check-skipped"; }

      html += '<div class="validity-check-item ' + cCls + '">';
      html += '<span class="check-icon">' + cIcon + "</span>";
      html += '<span class="check-name">' + escapeHtml(c.name) + "</span>";
      html += '<span class="check-detail">' + escapeHtml(c.detail) + "</span>";
      html += "</div>";
    });

    // Always show the inline verify form so users can (re-)verify with different keys
    const verifyLabel = sigSkipped ? "Verify Signature" : "Re-verify Signature";
    html += '<div class="verify-inline-sep"></div>';
    html += '<div class="verify-inline">';
    html += '<label class="verify-label">Public Key (PEM or JWK)</label>';
    html += '<textarea class="verify-input verify-inline-key" rows="3" placeholder="Paste PEM or JWK..." spellcheck="false"></textarea>';
    html += '<label class="verify-label">Trust List URL</label>';
    html += '<input class="verify-input verify-inline-tl" type="text" placeholder="https://...">';
    html += '<button class="btn verify-btn verify-inline-btn">' + verifyLabel + '</button>';
    html += "</div>";

    html += "</div>";

    banner.innerHTML = html;

    // Wire up the inline verify button
    {
      const verifyInlineBtn = banner.querySelector(".verify-inline-btn");
      const keyInput = banner.querySelector(".verify-inline-key");
      const tlInput = banner.querySelector(".verify-inline-tl");

      // Prevent clicks on the form from closing the popover
      banner.querySelector(".validity-checks").addEventListener("click", (e) => {
        e.stopPropagation();
      });

      verifyInlineBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const keyText = keyInput.value.trim();
        const tlUrl = tlInput.value.trim();
        if (!keyText && !tlUrl) {
          showToast("Provide a public key or trust list URL");
          return;
        }
        verifyInlineBtn.disabled = true;
        verifyInlineBtn.textContent = "Verifying...";
        verifySignature(keyText, tlUrl);
      });
    }

    // Click banner to toggle the popover open (for non-hover devices / to pin it)
    banner.addEventListener("click", () => {
      banner.classList.toggle("popover-pinned");
    });

    return banner;
  }

  function relativeTime(date) {
    const now = Date.now();
    let diff = date.getTime() - now;
    const future = diff > 0;
    diff = Math.abs(diff);

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    const months = Math.floor(days / 30);

    let str;
    if (months >= 2) str = months + " months";
    else if (months === 1) str = "1 month";
    else if (days >= 2) str = days + " days";
    else if (days === 1) str = "1 day";
    else if (hours >= 2) str = hours + " hours";
    else if (hours === 1) str = "1 hour";
    else if (minutes >= 2) str = minutes + " minutes";
    else str = "1 minute";

    return future ? "in " + str : str + " ago";
  }

  function renderSDJWT(data) {
    appendSection("Header", renderJSONBlock(data.header), data.header, "header");
    appendSection("Payload (signed claims)", renderJSONBlock(data.payload, { dimKeys: SD_INTERNAL_FIELDS, timestampKeys: TIMESTAMP_FIELDS }), data.payload, "payload");

    if (data.disclosures && data.disclosures.length > 0) {
      const disc = document.createElement("div");
      data.disclosures.forEach((d, idx) => {
        const item = document.createElement("div");
        item.className = "disclosure-item";
        item.setAttribute("data-disc-index", idx);
        // Color-code the left border to match colorized input
        const colorIdx = idx % DISC_COLORS;
        item.style.borderLeftColor = "var(--disc-color-" + colorIdx + ", var(--accent))";
        const name = d.isArrayEntry ? "(array element)" : d.name;
        const valStr = typeof d.value === "object" ? JSON.stringify(d.value) : String(d.value);
        const truncatedDigest = d.digest ? d.digest.substring(0, 16) + "\u2026" : "";
        item.innerHTML =
          '<span class="disclosure-name">' + escapeHtml(name) + '</span>: <span class="disclosure-value">' + escapeHtml(valStr) + "</span>" +
          '<div class="disclosure-meta">salt: ' + escapeHtml(d.salt) +
          ' | digest: <span class="digest-truncated" title="' + escapeHtml(d.digest) + '">' + escapeHtml(truncatedDigest) + "</span></div>";
        disc.appendChild(item);
      });
      appendSection("Disclosures (" + data.disclosures.length + ")", disc, data.disclosures, "disclosures");

      // Bidirectional hover: disclosure items <-> colorized input spans
      disc.querySelectorAll(".disclosure-item[data-disc-index]").forEach((item) => {
        const idx = item.getAttribute("data-disc-index");
        item.addEventListener("mouseenter", () => {
          item.classList.add("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        });
        item.addEventListener("mouseleave", () => {
          item.classList.remove("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) span.classList.remove("highlight");
        });
      });
    }

    // Resolved Claims with disclosed vs standard separation
    if (data.resolvedClaims) {
      const disclosedNames = new Set();
      if (data.disclosures) {
        data.disclosures.forEach((d) => {
          if (d.name) disclosedNames.add(d.name);
        });
      }
      appendSection("Resolved Claims", renderResolvedClaims(data.resolvedClaims, disclosedNames), data.resolvedClaims);
    }

    if (data.keyBindingJWT) {
      const kb = document.createElement("div");
      kb.appendChild(createSubSection("Header", renderJSONBlock(data.keyBindingJWT.header)));
      kb.appendChild(createSubSection("Payload", renderJSONBlock(data.keyBindingJWT.payload, { timestampKeys: TIMESTAMP_FIELDS })));
      appendSection("Key Binding JWT", kb, data.keyBindingJWT, "kb-jwt");
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

  function renderResolvedClaims(claims, disclosedNames) {
    const el = document.createElement("div");
    el.className = "resolved-claims-list";

    // Separate disclosed vs standard claims
    const disclosed = [];
    const standard = [];
    const keys = Object.keys(claims).sort();
    keys.forEach((k) => {
      const val = claims[k];
      const valStr = typeof val === "object" && val !== null ? JSON.stringify(val) : String(val);
      if (disclosedNames.has(k)) {
        disclosed.push({ key: k, value: valStr });
      } else {
        standard.push({ key: k, value: valStr });
      }
    });

    if (disclosed.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label disclosed";
      label.textContent = "Disclosed (" + disclosed.length + ")";
      el.appendChild(label);
      disclosed.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "disclosed"));
      });
    }

    if (standard.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label";
      label.textContent = "Standard (" + standard.length + ")";
      el.appendChild(label);
      standard.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "standard"));
      });
    }

    return el;
  }

  function renderClaimCard(key, value, type) {
    const item = document.createElement("div");
    item.className = "claim-item" + (type === "disclosed" ? " claim-disclosed" : "");
    item.innerHTML =
      '<span class="claim-name">' + escapeHtml(key) + '</span>: <span class="claim-value">' + escapeHtml(value) + "</span>";
    return item;
  }

  function renderJWT(data) {
    appendSection("Header", renderJSONBlock(data.header), data.header, "header");
    appendSection("Payload", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }), data.payload, "payload");
  }

  function renderMDOC(data) {
    const info = document.createElement("div");
    info.appendChild(renderKV("DocType", data.docType));
    appendSection("Document Info", info, { docType: data.docType });

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
      appendSection("Mobile Security Object", el, mso);
    }

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
        appendSection(ns + " (" + keys.length + " claims)", el, claims);
      });
    }

    if (data.deviceAuth) {
      appendSection("Device Auth", renderJSONBlock(data.deviceAuth), data.deviceAuth);
    }
  }

  // UI helpers
  function appendSection(title, contentEl, copyData, sectionId) {
    const section = document.createElement("div");
    section.className = "section";
    if (sectionId) section.setAttribute("data-section", sectionId);

    const header = document.createElement("div");
    header.className = "section-header";

    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.textContent = "\u25BC";

    const titleSpan = document.createElement("span");
    titleSpan.textContent = title;

    header.appendChild(arrow);
    header.appendChild(titleSpan);

    // Copy button
    if (copyData !== undefined) {
      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.textContent = "Copy";
      copyBtn.title = "Copy section as JSON";
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const text = JSON.stringify(copyData, null, 2);
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = "Copied!";
          copyBtn.classList.add("copied");
          setTimeout(() => {
            copyBtn.textContent = "Copy";
            copyBtn.classList.remove("copied");
          }, 1500);
        }).catch(() => {
          showToast("Failed to copy");
        });
      });
      header.appendChild(copyBtn);
    }

    const body = document.createElement("div");
    body.className = "section-body";
    body.appendChild(contentEl);

    header.addEventListener("click", (e) => {
      if (e.target.closest(".copy-btn")) return;
      const collapsed = body.classList.toggle("collapsed");
      arrow.classList.toggle("collapsed", collapsed);
    });

    // Bidirectional hover: output section → colorized input span(s)
    if (sectionId) {
      section.addEventListener("mouseenter", () => {
        section.classList.add("highlight");
        if (sectionId === "disclosures") {
          const spans = rawView.querySelectorAll('[data-section^="disc-"]');
          spans.forEach((s) => s.classList.add("highlight"));
          if (spans.length) spans[0].scrollIntoView({ behavior: "smooth", block: "nearest" });
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
      });
      section.addEventListener("mouseleave", () => {
        section.classList.remove("highlight");
        if (sectionId === "disclosures") {
          rawView.querySelectorAll('[data-section^="disc-"]').forEach((s) => s.classList.remove("highlight"));
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) span.classList.remove("highlight");
        }
      });
    }

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

  function renderJSONBlock(obj, opts) {
    const el = document.createElement("pre");
    el.className = "json-block";
    const json = JSON.stringify(obj, null, 2);
    el.innerHTML = syntaxHighlightFull(json, opts);
    return el;
  }

  // JSON syntax highlighting regex — matches strings, keys, booleans, null, numbers
  var JSON_TOKEN_RE = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g;

  function syntaxHighlight(json) {
    if (!json) return "";
    json = escapeHtml(json);
    return json.replace(JSON_TOKEN_RE, (match) => {
      let cls = "json-number";
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "json-key" : "json-string";
      } else if (/true|false/.test(match)) {
        cls = "json-bool";
      } else if (/null/.test(match)) {
        cls = "json-null";
      }
      return '<span class="' + cls + '">' + match + "</span>";
    });
  }

  // Enhanced syntax highlighting with timestamp hover and field dimming
  function syntaxHighlightFull(json, opts) {
    if (!json) return "";
    const dimKeys = (opts && opts.dimKeys) || null;
    const tsKeys = (opts && opts.timestampKeys) || null;

    // Process line by line for context-aware highlighting
    const lines = json.split("\n");
    return lines.map((line) => {
      // Extract key name from this line (before escaping)
      const keyMatch = line.match(/^\s*"([\w_]+)"\s*:/);
      const currentKey = keyMatch ? keyMatch[1] : null;

      // Dim SD-JWT internal fields
      if (dimKeys && currentKey && dimKeys.has(currentKey)) {
        return '<span class="json-dimmed">' + syntaxHighlightLineWithTimestamps(line, null) + "</span>";
      }
      return syntaxHighlightLineWithTimestamps(line, currentKey && tsKeys && tsKeys.has(currentKey) ? currentKey : null);
    }).join("\n");
  }

  function syntaxHighlightLineWithTimestamps(line, tsKey) {
    var escaped = escapeHtml(line);
    return escaped.replace(JSON_TOKEN_RE, (match) => {
      let cls = "json-number";
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "json-key" : "json-string";
      } else if (/true|false/.test(match)) {
        cls = "json-bool";
      } else if (/null/.test(match)) {
        cls = "json-null";
      }

      // Timestamp hover: number value on a known timestamp key line
      if (cls === "json-number" && tsKey) {
        const num = parseFloat(match);
        if (num > 1000000000 && num < 4102444800) {
          const date = new Date(num * 1000);
          const iso = date.toISOString().replace(/\.\d+Z$/, "Z");
          const rel = relativeTime(date);
          const title = iso + " (" + rel + ")";
          return '<span class="' + cls + ' timestamp-hover" title="' + escapeHtml(title) + '">' + match + "</span>";
        }
      }

      return '<span class="' + cls + '">' + match + "</span>";
    });
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

  // Update keyboard shortcut hints for platform
  const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  const mod = isMac ? "\u2318" : "Ctrl";
  const hintEl = document.querySelector(".shortcut-hint");
  if (hintEl) {
    hintEl.innerHTML =
      "<kbd>" + mod + "+L</kbd> Focus input &nbsp;&middot;&nbsp; " +
      "<kbd>" + mod + "+Shift+C</kbd> Copy share link &nbsp;&middot;&nbsp; " +
      "Hover timestamps for human-readable dates";
  }

  const queryCredential = new URLSearchParams(window.location.search).get("credential");

  if (queryCredential) {
    prefill(queryCredential);
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
