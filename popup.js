// popup.js
// Dual-Mode Popup Controller
// Strictly isolates Mode 1 (Website Security Scan) and Mode 2 (IoT Network Anomaly Audit).

(function () {
  "use strict";

  let activeMode = "website";
  let websiteReport = null;
  let iotReport = null;
  let websiteFilter = "all";
  let iotFilter = "all";
  let exportTargetMode = "website";

  document.addEventListener("DOMContentLoaded", async () => {
    setupModeSwitcher();
    setupConfigListeners();
    setupWebsiteModeListeners();
    setupIoTModeListeners();
    setupFilterListeners();
    setupExportAndFooterListeners();

    await refreshManagingUrlHeader();
    await loadInitialModeStates();
  });

  // ---------------------------------------------------------------------------
  // 1. Top Header Bar & Dynamic Managing URL Configurator
  // ---------------------------------------------------------------------------
  async function refreshManagingUrlHeader() {
    const urlDisplay = document.getElementById("managing-url-display");
    const iotServerDisplay = document.getElementById("iot-server-url");
    const unconfiguredPrompt = document.getElementById("iot-unconfigured-prompt");
    const urlInput = document.getElementById("input-managing-url");

    const managingUrl = await window.ConfigManager.getManagingUrl();

    if (!managingUrl) {
      if (urlDisplay) urlDisplay.textContent = "Not Configured";
      if (iotServerDisplay) iotServerDisplay.textContent = "Not Configured";
      if (unconfiguredPrompt) unconfiguredPrompt.style.display = "block";
      updateConnectionBadge({ status: "not_configured", label: "Not Configured" });
      toggleLogoutButton(null);
      return null;
    }

    if (urlDisplay) urlDisplay.textContent = managingUrl;
    if (iotServerDisplay) iotServerDisplay.textContent = managingUrl;
    if (urlInput) urlInput.value = managingUrl;
    if (unconfiguredPrompt) unconfiguredPrompt.style.display = "none";

    const health = await window.ConfigManager.checkServerHealth(managingUrl);
    updateConnectionBadge(health);
    await toggleLogoutButton(managingUrl);
    return managingUrl;
  }

  function updateConnectionBadge(health) {
    const badge = document.getElementById("connection-status-badge");
    const textEl = document.getElementById("connection-status-text");
    if (!badge || !textEl) return;

    badge.classList.remove("status-connected", "status-disconnected", "status-not-configured");
    if (health?.status === "connected") {
      badge.classList.add("status-connected");
      textEl.textContent = "Connected";
      badge.title = health.message || "Connected to IoT Managing Server";
    } else if (health?.status === "disconnected") {
      badge.classList.add("status-disconnected");
      textEl.textContent = "Disconnected";
      badge.title = health.message || "Server unreachable";
    } else {
      badge.classList.add("status-not-configured");
      textEl.textContent = "Not Configured";
      badge.title = "No managing server URL configured";
    }
  }

  function openUrlSettingsPanel() {
    const panel = document.getElementById("url-settings-panel");
    const feedback = document.getElementById("url-settings-feedback");
    const input = document.getElementById("input-managing-url");
    if (feedback) {
      feedback.textContent = "";
      feedback.className = "settings-feedback";
    }
    if (panel) panel.style.display = "block";
    if (input) input.focus();
  }

  function closeUrlSettingsPanel() {
    const panel = document.getElementById("url-settings-panel");
    if (panel) panel.style.display = "none";
  }

  function setupConfigListeners() {
    const changeBtn = document.getElementById("btn-change-url");
    const cancelBtn = document.getElementById("btn-cancel-url");
    const saveBtn = document.getElementById("btn-save-url");
    const testBtn = document.getElementById("btn-test-url");
    const clearBtn = document.getElementById("btn-clear-url");
    const input = document.getElementById("input-managing-url");
    const feedback = document.getElementById("url-settings-feedback");

    if (changeBtn) {
      changeBtn.addEventListener("click", () => {
        const panel = document.getElementById("url-settings-panel");
        if (panel && panel.style.display === "block") {
          closeUrlSettingsPanel();
        } else {
          openUrlSettingsPanel();
        }
      });
    }

    if (cancelBtn) {
      cancelBtn.addEventListener("click", closeUrlSettingsPanel);
    }

    const handleSaveAndConnect = async () => {
      const rawUrl = input ? input.value : "";
      if (feedback) {
        feedback.textContent = "Requesting host access & verifying server...";
        feedback.className = "settings-feedback";
      }

      const result = await window.ConfigManager.setAndConnectManagingUrl(rawUrl);
      if (!result.ok) {
        if (feedback) {
          feedback.textContent = result.error || "Failed to configure URL.";
          feedback.className = "settings-feedback error";
        }
        updateConnectionBadge(result.health);
        return;
      }

      if (feedback) {
        feedback.textContent = result.health.reachable
          ? `Saved! ${result.health.message}`
          : `URL saved, but server check failed: ${result.health.message}`;
        feedback.className = `settings-feedback ${result.health.reachable ? "success" : "error"}`;
      }

      await refreshManagingUrlHeader();
      if (result.health.reachable) {
        setTimeout(closeUrlSettingsPanel, 700);
      }
    };

    if (saveBtn) {
      saveBtn.addEventListener("click", handleSaveAndConnect);
    }

    if (input) {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          handleSaveAndConnect();
        }
      });
    }

    if (testBtn) {
      testBtn.addEventListener("click", async () => {
        const rawUrl = input ? input.value : "";
        const validation = window.ConfigManager.validateAndNormalizeUrl(rawUrl);
        if (!validation.valid) {
          if (feedback) {
            feedback.textContent = validation.error;
            feedback.className = "settings-feedback error";
          }
          return;
        }
        if (feedback) {
          feedback.textContent = "Testing connection...";
          feedback.className = "settings-feedback";
        }
        const granted = await window.ConfigManager.requestHostPermission(validation.originPattern);
        if (!granted) {
          if (feedback) {
            feedback.textContent = "Host permission denied.";
            feedback.className = "settings-feedback error";
          }
          return;
        }
        const health = await window.ConfigManager.checkServerHealth(validation.normalizedUrl);
        updateConnectionBadge(health);
        if (feedback) {
          feedback.textContent = health.message;
          feedback.className = `settings-feedback ${health.reachable ? "success" : "error"}`;
        }
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", async () => {
        await window.ConfigManager.clearManagingUrl();
        if (input) input.value = "";
        if (feedback) {
          feedback.textContent = "Managing URL cleared.";
          feedback.className = "settings-feedback";
        }
        await refreshManagingUrlHeader();
      });
    }
  }

  // ---------------------------------------------------------------------------
  // 2. Dual-Mode Switcher
  // ---------------------------------------------------------------------------
  function setupModeSwitcher() {
    const cards = document.querySelectorAll(".mode-card");
    cards.forEach((card) => {
      card.addEventListener("click", () => {
        switchMode(card.dataset.mode || "website");
      });
    });
  }

  function switchMode(mode) {
    activeMode = mode === "iot" ? "iot" : "website";
    document.querySelectorAll(".mode-card").forEach((c) => {
      c.classList.toggle("active", c.dataset.mode === activeMode);
    });
    document.querySelectorAll(".mode-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `panel-${activeMode}`);
    });
  }

  async function loadInitialModeStates() {
    // Load active tab URL for Mode 1 display (isolated, does not auto-scan)
    if (typeof chrome !== "undefined" && chrome.tabs) {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const webTargetEl = document.getElementById("web-target-url");
        if (webTargetEl) {
          webTargetEl.textContent = tab?.url || "Unavailable";
        }
      } catch (_err) {}
    }

    const savedWeb = await window.WebScanner.getSavedWebsiteScanForActiveTab();
    if (savedWeb) {
      websiteReport = savedWeb;
      renderWebsiteView(websiteReport);
    }

    const savedIot = await window.IoTAuditor.getSavedIoTAudit();
    if (savedIot) {
      iotReport = savedIot;
      renderIoTView(iotReport);
    }
  }

  // ---------------------------------------------------------------------------
  // 3. Mode 1: Website Security Scan (Isolated)
  // ---------------------------------------------------------------------------
  function setupWebsiteModeListeners() {
    const runBtn = document.getElementById("btn-run-web-scan");
    if (runBtn) {
      runBtn.addEventListener("click", executeWebsiteScan);
    }
  }

  async function executeWebsiteScan() {
    const btn = document.getElementById("btn-run-web-scan");
    const errBanner = document.getElementById("web-error-banner");
    const progressBox = document.getElementById("web-scan-progress");
    const progressFill = document.getElementById("web-progress-fill");
    const progressStatus = document.getElementById("web-progress-status");
    const progressPct = document.getElementById("web-progress-percent");

    if (errBanner) {
      errBanner.style.display = "none";
      errBanner.textContent = "";
    }
    if (btn) {
      btn.disabled = true;
      btn.classList.add("loading");
      btn.innerHTML = "<span>🔄</span> Scanning Active Tab...";
    }
    if (progressBox) progressBox.style.display = "block";

    try {
      const result = await window.WebScanner.runWebsiteScan((pct, msg) => {
        if (progressFill) progressFill.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct}%`;
        if (progressStatus) progressStatus.textContent = msg;
      });

      websiteReport = result;
      renderWebsiteView(websiteReport);
    } catch (err) {
      if (errBanner) {
        errBanner.textContent = err?.message || "Website scan failed.";
        errBanner.style.display = "block";
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("loading");
        btn.innerHTML = "<span>🌐</span> Run Website Scan";
      }
      setTimeout(() => {
        if (progressBox) progressBox.style.display = "none";
        if (progressFill) progressFill.style.width = "0%";
      }, 1500);
    }
  }

  function renderWebsiteView(data) {
    if (!data) return;

    const targetEl = document.getElementById("web-target-url");
    if (targetEl && data.targetUrl) targetEl.textContent = data.targetUrl;

    updateScoreRing(
      data.score,
      "web-security-score",
      "web-score-ring-fill",
      "web-score-rating",
      "web-score-subtext"
    );

    updateCounts(data.counts, "web");

    updateDefenseBadge("web-chk-https", data.headers?.https, "HTTPS Enforced", "Insecure HTTP");
    updateDefenseBadge("web-chk-csp", data.headers?.csp, "CSP Active", "Missing CSP");
    updateDefenseBadge("web-chk-xframe", data.headers?.xframe, "X-Frame Protected", "Missing X-Frame");
    updateDefenseBadge("web-chk-cookies", data.headers?.secureCookies, "Secure Cookies", "Cookie Exposure");

    const metricsStrip = document.getElementById("web-metrics-strip");
    if (metricsStrip && data.metrics) {
      metricsStrip.style.display = "flex";
      metricsStrip.innerHTML = `
        <span class="metric-chip">Scripts: ${data.metrics.totalScripts || 0}</span>
        <span class="metric-chip">Inline (no nonce): ${data.metrics.inlineWithoutNonce || 0}</span>
        <span class="metric-chip">JS Cookies: ${data.metrics.jsAccessibleCookies || 0}</span>
      `;
    }

    renderFindingsList("web-findings-container", data.findings || [], websiteFilter, "website");

    const exportBtn = document.getElementById("btn-export-web");
    if (exportBtn) exportBtn.disabled = false;
  }

  // ---------------------------------------------------------------------------
  // 4. Mode 2: IoT Network Anomaly Audit (Isolated)
  // ---------------------------------------------------------------------------
  function setupIoTModeListeners() {
    const runBtn = document.getElementById("btn-run-iot-audit");
    const openUrlBtn = document.getElementById("btn-open-url-from-iot");
    const loginSubmitBtn = document.getElementById("btn-tb-login-submit");
    const closeLoginBtn = document.getElementById("btn-close-tb-login");
    const logoutBtn = document.getElementById("btn-iot-logout");
    const passInput = document.getElementById("tb-password");

    if (runBtn) {
      runBtn.addEventListener("click", () => executeIoTAudit());
    }

    if (openUrlBtn) {
      openUrlBtn.addEventListener("click", openUrlSettingsPanel);
    }

    if (closeLoginBtn) {
      closeLoginBtn.addEventListener("click", () => {
        const loginPanel = document.getElementById("tb-login-panel");
        if (loginPanel) loginPanel.style.display = "none";
      });
    }

    const submitLogin = () => {
      const username = document.getElementById("tb-username")?.value || "";
      const password = document.getElementById("tb-password")?.value || "";
      const loginErr = document.getElementById("tb-login-error");
      if (!username.trim() || !password) {
        if (loginErr) loginErr.textContent = "Enter both username and password.";
        return;
      }
      if (loginErr) loginErr.textContent = "";
      executeIoTAudit({ username, password });
    };

    if (loginSubmitBtn) {
      loginSubmitBtn.addEventListener("click", submitLogin);
    }

    if (passInput) {
      passInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          submitLogin();
        }
      });
    }

    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        const url = await window.ConfigManager.getManagingUrl();
        if (url) {
          await window.IoTAuditor.clearCachedToken(url);
          await toggleLogoutButton(url);
        }
      });
    }
  }

  async function toggleLogoutButton(managingUrl) {
    const btn = document.getElementById("btn-iot-logout");
    if (!btn) return;
    if (!managingUrl || typeof chrome === "undefined" || !chrome.storage?.local) {
      btn.style.display = "none";
      return;
    }
    try {
      const origin = new URL(managingUrl).origin;
      const key = `${window.IoTAuditor.STORAGE_KEYS.TOKEN_PREFIX}${origin}`;
      const res = await chrome.storage.local.get([key]);
      btn.style.display = res[key] ? "inline-block" : "none";
    } catch (_e) {
      btn.style.display = "none";
    }
  }

  async function executeIoTAudit(credentials) {
    const btn = document.getElementById("btn-run-iot-audit");
    const errBanner = document.getElementById("iot-error-banner");
    const loginPanel = document.getElementById("tb-login-panel");
    const loginErr = document.getElementById("tb-login-error");
    const progressBox = document.getElementById("iot-scan-progress");
    const progressFill = document.getElementById("iot-progress-fill");
    const progressStatus = document.getElementById("iot-progress-status");
    const progressPct = document.getElementById("iot-progress-percent");

    if (errBanner) {
      errBanner.style.display = "none";
      errBanner.textContent = "";
    }
    if (btn) {
      btn.disabled = true;
      btn.classList.add("loading");
      btn.innerHTML = "<span>🔄</span> Auditing IoT Fleet...";
    }
    if (progressBox) progressBox.style.display = "block";

    try {
      const result = await window.IoTAuditor.runIoTAnomalyAudit({
        credentials,
        onProgress: (pct, msg) => {
          if (progressFill) progressFill.style.width = `${pct}%`;
          if (progressPct) progressPct.textContent = `${pct}%`;
          if (progressStatus) progressStatus.textContent = msg;
        }
      });

      if (result.status === "NOT_CONFIGURED") {
        const prompt = document.getElementById("iot-unconfigured-prompt");
        if (prompt) prompt.style.display = "block";
        openUrlSettingsPanel();
        return;
      }

      if (result.status === "PERMISSION_REQUIRED") {
        if (errBanner) {
          errBanner.textContent = result.message;
          errBanner.style.display = "block";
        }
        openUrlSettingsPanel();
        return;
      }

      if (result.status === "AUTH_REQUIRED") {
        if (loginPanel) loginPanel.style.display = "block";
        if (loginErr) loginErr.textContent = result.message || "";
        return;
      }

      // Success
      if (loginPanel) loginPanel.style.display = "none";
      if (document.getElementById("tb-password")) {
        document.getElementById("tb-password").value = "";
      }
      iotReport = result;
      renderIoTView(iotReport);
      await toggleLogoutButton(result.managingServer);
      updateConnectionBadge({ status: "connected", label: "Connected", message: "Authenticated & Audited" });
    } catch (err) {
      if (loginPanel && loginPanel.style.display === "block" && loginErr && credentials) {
        loginErr.textContent = err?.message || "Login failed.";
      } else if (errBanner) {
        errBanner.textContent = err?.message || "IoT Anomaly Audit failed.";
        errBanner.style.display = "block";
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("loading");
        btn.innerHTML = "<span>📡</span> Run IoT Anomaly Audit";
      }
      setTimeout(() => {
        if (progressBox) progressBox.style.display = "none";
        if (progressFill) progressFill.style.width = "0%";
      }, 1500);
    }
  }

  function renderIoTView(data) {
    if (!data) return;

    const serverEl = document.getElementById("iot-server-url");
    if (serverEl && data.managingServer) serverEl.textContent = data.managingServer;

    updateScoreRing(
      data.score,
      "iot-security-score",
      "iot-score-ring-fill",
      "iot-score-rating",
      "iot-score-subtext"
    );

    updateCounts(data.counts, "iot");

    const devicesSec = document.getElementById("iot-devices-section");
    const devicesCount = document.getElementById("iot-devices-count");
    const devicesList = document.getElementById("iot-devices-list");
    const owaspStrip = document.getElementById("iot-owasp-strip");
    const devices = data.devicesAudited || [];

    if (devicesSec && devicesList) {
      devicesSec.style.display = "block";
      if (devicesCount) {
        devicesCount.textContent = `${devices.length} device${devices.length === 1 ? "" : "s"}`;
      }

      if (devices.length === 0) {
        devicesList.innerHTML = `<div class="device-mini-row"><span class="device-mini-sub">0 devices returned by managing server</span></div>`;
      } else {
        devicesList.innerHTML = devices
          .map((d) => {
            const sevClass = d.score >= 80 ? "tag-low" : d.score >= 50 ? "tag-medium" : "tag-critical";
            const netMeta = [
              d.type || "IoT",
              d.ip && d.ip !== "N/A" ? `IP: ${d.ip}` : null,
              d.mac && d.mac !== "N/A" ? `MAC: ${d.mac}` : null
            ]
              .filter(Boolean)
              .join(" • ");
            return `
              <div class="device-mini-row">
                <div class="device-mini-meta">
                  <span class="device-mini-name">${escapeHtml(d.name)}</span>
                  <span class="device-mini-sub">${escapeHtml(netMeta)}</span>
                </div>
                <span class="vuln-tag ${sevClass}">${d.score}/100</span>
              </div>
            `;
          })
          .join("");
      }

      if (owaspStrip && Array.isArray(data.owaspMatrix)) {
        owaspStrip.innerHTML = data.owaspMatrix
          .map((m) => {
            const cls =
              m.status === "critical" || m.status === "high"
                ? "flagged"
                : m.status === "medium" || m.status === "low"
                  ? "medium"
                  : "";
            const state = m.status === "passed" ? "✓" : `${m.findingsCount}`;
            return `<div class="owasp-pill-item ${cls}" title="${escapeHtml(m.fullTitle)} (${escapeHtml(m.status)})">${escapeHtml(m.id)}: ${escapeHtml(state)}</div>`;
          })
          .join("");
      }
    }

    renderFindingsList("iot-findings-container", data.findings || [], iotFilter, "iot");

    const exportBtn = document.getElementById("btn-export-iot");
    if (exportBtn) exportBtn.disabled = false;
  }

  // ---------------------------------------------------------------------------
  // 5. Shared UI Render Helpers (Pure presentation, zero cross-mode state)
  // ---------------------------------------------------------------------------
  function updateScoreRing(score, scoreId, ringId, ratingId, subtextId) {
    const scoreEl = document.getElementById(scoreId);
    const ringFill = document.getElementById(ringId);
    const ratingEl = document.getElementById(ratingId);
    const subtextEl = document.getElementById(subtextId);

    const scoreVal = typeof score === "number" ? score : parseInt(score, 10) || 0;
    if (scoreEl) scoreEl.textContent = scoreVal;

    const radius = 25;
    const circumference = 2 * Math.PI * radius;
    const clamped = Math.max(0, Math.min(100, scoreVal));
    const offset = circumference - (clamped / 100) * circumference;

    if (ringFill) {
      ringFill.style.strokeDasharray = circumference;
      ringFill.style.strokeDashoffset = offset;
      ringFill.style.stroke =
        scoreVal >= 80
          ? "var(--color-low)"
          : scoreVal >= 50
            ? "var(--color-medium)"
            : "var(--color-critical)";
    }

    if (ratingEl && subtextEl) {
      if (scoreVal >= 80) {
        ratingEl.textContent = "Low Risk Posture";
        subtextEl.textContent = "Security baselines satisfied";
      } else if (scoreVal >= 50) {
        ratingEl.textContent = "Moderate Risk Posture";
        subtextEl.textContent = "Security mitigations advised";
      } else {
        ratingEl.textContent = "High Risk Posture";
        subtextEl.textContent = "Immediate remediation required";
      }
    }
  }

  function updateCounts(counts, prefix) {
    const c = counts || { critical: 0, high: 0, medium: 0, low: 0 };
    const setVal = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = v ?? 0;
    };
    setVal(`${prefix}-count-critical`, c.critical);
    setVal(`${prefix}-count-high`, c.high);
    setVal(`${prefix}-count-medium`, c.medium);
    setVal(`${prefix}-count-low`, c.low);
  }

  function updateDefenseBadge(id, isPass, passText, failText) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `integrity-badge ${isPass ? "pass" : "fail"}`;
    el.innerHTML = `<span class="badge-icon">${isPass ? "✓" : "✕"}</span> ${escapeHtml(isPass ? passText : failText)}`;
  }

  function matchesFilter(findingSeverity, filter) {
    if (!filter || filter === "all") return true;
    const fSev = (findingSeverity || "").toLowerCase().trim();
    const flt = filter.toLowerCase().trim();
    if (flt === "medium" || flt === "med") return fSev === "medium" || fSev === "med";
    if (flt === "critical" || flt === "crit") return fSev === "critical" || fSev === "crit";
    return fSev === flt;
  }

  function renderFindingsList(containerId, findings, filter, mode) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";

    const filtered = (findings || []).filter((f) => matchesFilter(f.severity, filter));
    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">✓</div>
          No <strong>${escapeHtml(filter === "all" ? "" : filter + " ")}</strong>findings detected in ${mode === "iot" ? "IoT Anomaly Audit" : "Website Security Scan"}.
        </div>
      `;
      return;
    }

    filtered.forEach((f) => {
      const card = document.createElement("article");
      const rawSev = (f.severity || "low").toLowerCase();
      const normSev = rawSev.startsWith("crit")
        ? "critical"
        : rawSev.startsWith("med")
          ? "medium"
          : rawSev;

      card.className = `vuln-card ${normSev}-border`;

      let shapHTML = "";
      if (f.shap && f.shap.length > 0) {
        const items = f.shap
          .map(
            (s) =>
              `<li><span>${escapeHtml(s.feature)}</span><code class="shap-val">${escapeHtml(String(s.weight))}</code></li>`
          )
          .join("");
        shapHTML = `
          <div class="shap-attribution">
            <span class="shap-header">💡 SHAP Feature Attribution:</span>
            <ul class="shap-list">${items}</ul>
          </div>
        `;
      }

      const owaspHTML = f.owaspName
        ? `<div class="owasp-badge">${escapeHtml(f.owaspName)}</div>`
        : "";

      card.innerHTML = `
        ${owaspHTML}
        <div class="vuln-top">
          <span class="vuln-title">${escapeHtml(f.type || f.title || "Security Finding")}</span>
          <span class="vuln-tag tag-${normSev}">${escapeHtml(normSev.toUpperCase())}</span>
        </div>
        <p class="vuln-detail">${escapeHtml(f.detail || "")} ${
          f.selector ? `<code class="code-target">${escapeHtml(f.selector)}</code>` : ""
        }</p>
        <div class="impact-box">
          <strong>Impact:</strong> ${escapeHtml(f.impact || "Security integrity risk")}
        </div>
        ${shapHTML}
      `;
      container.appendChild(card);
    });
  }

  function setupFilterListeners() {
    document.querySelectorAll(".filter-group").forEach((group) => {
      const mode = group.dataset.modeFilter;
      const buttons = group.querySelectorAll(".filter-btn");
      buttons.forEach((btn) => {
        btn.addEventListener("click", () => {
          buttons.forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          const chosen = btn.dataset.filter || "all";
          if (mode === "website") {
            websiteFilter = chosen;
            if (websiteReport) {
              renderFindingsList("web-findings-container", websiteReport.findings, websiteFilter, "website");
            }
          } else if (mode === "iot") {
            iotFilter = chosen;
            if (iotReport) {
              renderFindingsList("iot-findings-container", iotReport.findings, iotFilter, "iot");
            }
          }
        });
      });
    });
  }

  // ---------------------------------------------------------------------------
  // 6. Mode-Specific Report Export & Dashboard Link
  // ---------------------------------------------------------------------------
  function setupExportAndFooterListeners() {
    const exportWebBtn = document.getElementById("btn-export-web");
    const exportIotBtn = document.getElementById("btn-export-iot");
    const exportModal = document.getElementById("export-modal");
    const closeExportBtn = document.getElementById("btn-close-export-modal");
    const modalHeading = document.getElementById("export-modal-heading");
    const modalDesc = document.getElementById("export-modal-desc");

    const openExportModal = (mode) => {
      exportTargetMode = mode;
      if (modalHeading) {
        modalHeading.textContent =
          mode === "iot" ? "Export IoT Anomaly Audit Report" : "Export Website Security Report";
      }
      if (modalDesc) {
        modalDesc.textContent =
          mode === "iot"
            ? "Includes OWASP IoT Top 10 metadata, Managing Server, and audited devices:"
            : "Includes Website Security Scan metadata, Target URL, headers, and findings:";
      }
      if (exportModal) exportModal.style.display = "flex";
    };

    if (exportWebBtn) exportWebBtn.addEventListener("click", () => openExportModal("website"));
    if (exportIotBtn) exportIotBtn.addEventListener("click", () => openExportModal("iot"));

    if (closeExportBtn && exportModal) {
      closeExportBtn.addEventListener("click", () => {
        exportModal.style.display = "none";
      });
    }

    if (exportModal) {
      exportModal.addEventListener("click", (e) => {
        if (e.target === exportModal) exportModal.style.display = "none";
      });
    }

    document.querySelectorAll(".export-opt-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const format = btn.dataset.format || "json";
        executeModeExport(exportTargetMode, format);
        if (exportModal) exportModal.style.display = "none";
      });
    });

    const fullDashLink = document.getElementById("link-expanded-view");
    if (fullDashLink) {
      fullDashLink.addEventListener("click", (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
      });
    }
  }

  function executeModeExport(mode, format) {
    if (mode === "iot" && iotReport) {
      const devices = iotReport.devicesAudited || [];
      const deviceListSummary = devices.map((d) => {
        const netParts = [
          d.ip && d.ip !== "N/A" ? `IP:${d.ip}` : null,
          d.mac && d.mac !== "N/A" ? `MAC:${d.mac}` : null
        ].filter(Boolean);
        return netParts.length > 0 ? `${d.name} (${netParts.join(", ")})` : d.name;
      });
      const devicesAuditedLabel = `${devices.length}${deviceListSummary.length ? " — " + deviceListSummary.join("; ") : ""}`;

      const payload = {
        mode: "iot",
        auditType: "IoT Network Anomaly Audit (OWASP IoT Top 10)",
        managingServer: iotReport.managingServer,
        devicesAudited: devicesAuditedLabel,
        timestamp: iotReport.timestampDisplay || new Date().toLocaleString(),
        title: "IoT Network Anomaly Audit Report (OWASP IoT Top 10)",
        engine: iotReport.engineUsed || "Rust / Wasm + SHAP",
        score: iotReport.score,
        counts: iotReport.counts,
        overallPosture: {
          averageScore: iotReport.score,
          monitoredDevices: devices.length,
          criticalFlaws: (iotReport.counts?.critical || 0) + (iotReport.counts?.high || 0)
        },
        deviceInventory: devices,
        owaspBreakdown: iotReport.owaspBreakdown,
        findings: iotReport.findings || []
      };

      window.IoTReportExporter.exportAuditReport(format, payload, "iot-network-anomaly-audit");
      return;
    }

    if (mode === "website" && websiteReport) {
      const payload = {
        mode: "website",
        auditType: "Website Security Scan",
        targetUrl: websiteReport.targetUrl,
        timestamp: websiteReport.timestampDisplay || new Date().toLocaleString(),
        title: "Website Security Scan Report",
        score: websiteReport.score,
        counts: websiteReport.counts,
        headers: websiteReport.headers,
        metrics: websiteReport.metrics,
        findings: websiteReport.findings || []
      };

      window.IoTReportExporter.exportAuditReport(format, payload, "website-security-scan");
    }
  }

  function escapeHtml(text) {
    if (text === undefined || text === null) return "";
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();
