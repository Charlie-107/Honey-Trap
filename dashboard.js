// dashboard.js
// Dual-Mode Executive Security Dashboard
// Strictly isolates Mode 1 (Website Security Scan) and Mode 2 (IoT Network Anomaly Audit - OWASP IoT Top 10)
// Syncs live with chrome.storage.local and popup actions.

(function () {
  "use strict";

  let websiteReport = null;
  let iotReport = null;
  let webFilter = "all";
  let iotFilter = "all";
  let selectedExportMode = "iot";
  let auditLogs = [];

  const baselineXaiModels = [
    {
      vulnerability: "DOM-Based Cross-Site Scripting (Mode 1)",
      modelType: "TreeSHAP Decision Forest",
      baseScore: "+0.85 (Critical)",
      features: [
        { name: "Unescaped Payload Pattern (<script>, onerror=)", impact: 0.74, positive: true },
        { name: "DOM Sink Proximity (innerHTML / inline-event)", impact: 0.58, positive: true },
        { name: "Strict CSP Nonces Detected", impact: -0.65, positive: false }
      ]
    },
    {
      vulnerability: "OWASP IoT Top 10 Telemetry Anomaly (Mode 2)",
      modelType: "Rust / Wasm SHAP Anomaly Scorer",
      baseScore: "+0.81 (Critical)",
      features: [
        { name: "Physical Tamper / Exposed Service Port (I2/I10)", impact: 0.76, positive: true },
        { name: "Telemetry Z-Score Drift / Packet Loss (I7)", impact: 0.67, positive: true },
        { name: "TLS + Signed OTA Firmware Verified (I3/I4)", impact: -0.62, positive: false }
      ]
    }
  ];

  document.addEventListener("DOMContentLoaded", async () => {
    initNavigation();
    setupManagingUrlControls();
    setupWebsiteModeControls();
    setupIoTModeControls();
    setupExportControls();
    setupModalControls();
    setupStorageSyncListener();

    addAuditLog("INFO", "Dual-Mode Executive Dashboard initialized.");
    await refreshManagingUrlHeader();
    await loadIsolatedReportsFromStorage();
    await populateWebsiteTabSelector();
  });

  // ---------------------------------------------------------------------------
  // Navigation
  // ---------------------------------------------------------------------------
  function initNavigation() {
    const titles = {
      overview: "Dual-Mode Security Overview",
      website: "Mode 1: Active Website Security Scan",
      iot: "Mode 2: IoT Network Anomaly Audit (OWASP IoT Top 10)",
      owasp: "OWASP IoT Top 10 Compliance Matrix (I1 – I10)",
      xai: "Explainable AI (SHAP) Feature Decomposition",
      logs: "Real-Time Security Audit Log Stream"
    };

    document.querySelectorAll(".nav-item").forEach((item) => {
      item.addEventListener("click", (e) => {
        e.preventDefault();
        jumpToTab(item.dataset.tab || "overview", titles);
      });
    });

    document.querySelectorAll("[data-jump-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        jumpToTab(btn.dataset.jumpTab || "overview", titles);
      });
    });
  }

  function jumpToTab(tabName, customTitles) {
    const titles = customTitles || {
      overview: "Dual-Mode Security Overview",
      website: "Mode 1: Active Website Security Scan",
      iot: "Mode 2: IoT Network Anomaly Audit (OWASP IoT Top 10)",
      owasp: "OWASP IoT Top 10 Compliance Matrix (I1 – I10)",
      xai: "Explainable AI (SHAP) Feature Decomposition",
      logs: "Real-Time Security Audit Log Stream"
    };

    document.querySelectorAll(".nav-item").forEach((n) => {
      n.classList.toggle("active", n.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-pane").forEach((p) => {
      p.classList.toggle("active", p.id === `tab-${tabName}`);
    });
    const titleEl = document.getElementById("tab-title");
    if (titleEl) titleEl.textContent = titles[tabName] || "Security Dashboard";
  }

  // ---------------------------------------------------------------------------
  // Dynamic Managing URL Switcher
  // ---------------------------------------------------------------------------
  async function refreshManagingUrlHeader() {
    const urlDisplay = document.getElementById("dash-managing-url-display");
    const ovServer = document.getElementById("ov-iot-server");
    const input = document.getElementById("dash-input-managing-url");
    const unconfigBanner = document.getElementById("dash-iot-unconfigured");

    const managingUrl = await window.ConfigManager.getManagingUrl();
    if (!managingUrl) {
      if (urlDisplay) urlDisplay.textContent = "Not Configured";
      if (ovServer) ovServer.textContent = "Not Configured";
      if (unconfigBanner) unconfigBanner.style.display = "block";
      updateDashConnectionBadge({ status: "not_configured", label: "Not Configured" });
      return null;
    }

    if (urlDisplay) urlDisplay.textContent = managingUrl;
    if (ovServer) ovServer.textContent = managingUrl;
    if (input) input.value = managingUrl;
    if (unconfigBanner) unconfigBanner.style.display = "none";

    const health = await window.ConfigManager.checkServerHealth(managingUrl);
    updateDashConnectionBadge(health);
    return managingUrl;
  }

  function updateDashConnectionBadge(health) {
    const badge = document.getElementById("dash-conn-badge");
    const text = document.getElementById("dash-conn-text");
    if (!badge || !text) return;

    badge.classList.remove("status-connected", "status-disconnected", "status-not-configured");
    if (health?.status === "connected") {
      badge.classList.add("status-connected");
      text.textContent = "Connected";
      badge.title = health.message || "Connected";
    } else if (health?.status === "disconnected") {
      badge.classList.add("status-disconnected");
      text.textContent = "Disconnected";
      badge.title = health.message || "Disconnected";
    } else {
      badge.classList.add("status-not-configured");
      text.textContent = "Not Configured";
    }
  }

  function openDashUrlPanel() {
    const panel = document.getElementById("dash-url-settings-panel");
    const feedback = document.getElementById("dash-url-feedback");
    if (feedback) {
      feedback.textContent = "";
      feedback.className = "dash-feedback";
    }
    if (panel) panel.style.display = "block";
    document.getElementById("dash-input-managing-url")?.focus();
  }

  function closeDashUrlPanel() {
    const panel = document.getElementById("dash-url-settings-panel");
    if (panel) panel.style.display = "none";
  }

  function setupManagingUrlControls() {
    document.getElementById("btn-dash-change-url")?.addEventListener("click", () => {
      const panel = document.getElementById("dash-url-settings-panel");
      if (panel && panel.style.display === "block") closeDashUrlPanel();
      else openDashUrlPanel();
    });
    document.getElementById("btn-dash-cancel-url")?.addEventListener("click", closeDashUrlPanel);
    document.getElementById("btn-dash-open-url-from-iot")?.addEventListener("click", openDashUrlPanel);

    const handleSave = async () => {
      const rawUrl = document.getElementById("dash-input-managing-url")?.value || "";
      const fb = document.getElementById("dash-url-feedback");
      if (fb) {
        fb.textContent = "Requesting runtime host permission & checking server...";
        fb.className = "dash-feedback";
      }

      const res = await window.ConfigManager.setAndConnectManagingUrl(rawUrl);
      if (!res.ok) {
        if (fb) {
          fb.textContent = res.error || "Failed to save URL.";
          fb.className = "dash-feedback error";
        }
        updateDashConnectionBadge(res.health);
        return;
      }

      if (fb) {
        fb.textContent = res.health.reachable
          ? `Connected: ${res.health.message}`
          : `Saved, but server unreachable: ${res.health.message}`;
        fb.className = `dash-feedback ${res.health.reachable ? "success" : "error"}`;
      }
      addAuditLog("INFO", `Configured IoT Managing Server URL: ${res.managingUrl} (${res.health.label})`);
      await refreshManagingUrlHeader();
      if (res.health.reachable) setTimeout(closeDashUrlPanel, 700);
    };

    document.getElementById("btn-dash-save-url")?.addEventListener("click", handleSave);
    document.getElementById("dash-input-managing-url")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleSave();
      }
    });

    document.getElementById("btn-dash-test-url")?.addEventListener("click", async () => {
      const rawUrl = document.getElementById("dash-input-managing-url")?.value || "";
      const fb = document.getElementById("dash-url-feedback");
      const v = window.ConfigManager.validateAndNormalizeUrl(rawUrl);
      if (!v.valid) {
        if (fb) {
          fb.textContent = v.error;
          fb.className = "dash-feedback error";
        }
        return;
      }
      const granted = await window.ConfigManager.requestHostPermission(v.originPattern);
      if (!granted) {
        if (fb) {
          fb.textContent = "Host permission denied.";
          fb.className = "dash-feedback error";
        }
        return;
      }
      const health = await window.ConfigManager.checkServerHealth(v.normalizedUrl);
      updateDashConnectionBadge(health);
      if (fb) {
        fb.textContent = health.message;
        fb.className = `dash-feedback ${health.reachable ? "success" : "error"}`;
      }
    });

    document.getElementById("btn-dash-clear-url")?.addEventListener("click", async () => {
      await window.ConfigManager.clearManagingUrl();
      const input = document.getElementById("dash-input-managing-url");
      const fb = document.getElementById("dash-url-feedback");
      if (input) input.value = "";
      if (fb) {
        fb.textContent = "Managing URL cleared.";
        fb.className = "dash-feedback";
      }
      addAuditLog("WARN", "Cleared IoT Managing Server URL.");
      await refreshManagingUrlHeader();
    });
  }

  // ---------------------------------------------------------------------------
  // Mode 1: Website Security Scan (Strictly Isolated)
  // ---------------------------------------------------------------------------
  async function populateWebsiteTabSelector() {
    const select = document.getElementById("dash-web-tab-select");
    if (!select || typeof chrome === "undefined" || !chrome.tabs) return;

    const tabs = await chrome.tabs.query({});
    const httpTabs = tabs.filter((t) => t.id && t.url && /^https?:\/\//i.test(t.url));
    select.innerHTML = "";

    if (httpTabs.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No open http:// or https:// tabs found";
      select.appendChild(opt);
      return;
    }

    httpTabs.forEach((t) => {
      const opt = document.createElement("option");
      opt.value = String(t.id);
      opt.textContent = `${t.title ? t.title.slice(0, 45) + " — " : ""}${t.url}`;
      if (websiteReport && websiteReport.targetUrl === t.url) {
        opt.selected = true;
      }
      select.appendChild(opt);
    });
  }

  function setupWebsiteModeControls() {
    document.getElementById("btn-web-refresh-tabs")?.addEventListener("click", populateWebsiteTabSelector);
    document.getElementById("btn-web-tab-scan")?.addEventListener("click", runDashboardWebsiteScan);
    document.getElementById("btn-dash-run-web")?.addEventListener("click", runDashboardWebsiteScan);
    document.getElementById("btn-ov-run-web")?.addEventListener("click", runDashboardWebsiteScan);

    document.getElementById("btn-dash-export-web")?.addEventListener("click", () => {
      openExportModalForMode("website");
    });

    document.querySelectorAll("#dash-web-filter-group .filter-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#dash-web-filter-group .filter-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        webFilter = btn.dataset.filter || "all";
        if (websiteReport) renderWebsiteModeViews(websiteReport);
      });
    });
  }

  async function runDashboardWebsiteScan() {
    const select = document.getElementById("dash-web-tab-select");
    const errEl = document.getElementById("dash-web-error");
    if (errEl) errEl.textContent = "";

    const rawId = select?.value;
    if (!rawId) {
      await populateWebsiteTabSelector();
    }
    const targetTabId = parseInt(document.getElementById("dash-web-tab-select")?.value || "", 10);
    if (!Number.isFinite(targetTabId)) {
      if (errEl) errEl.textContent = "Open an http:// or https:// browser tab first, then click Refresh Tabs.";
      jumpToTab("website");
      return;
    }

    // Request host permission for selected tab origin on user click
    try {
      const tab = await chrome.tabs.get(targetTabId);
      if (tab?.url && /^https?:\/\//i.test(tab.url)) {
        const originPattern = `${new URL(tab.url).origin}/*`;
        const granted = await window.ConfigManager.requestHostPermission(originPattern);
        if (!granted) {
          if (errEl) errEl.textContent = `Host access denied for ${new URL(tab.url).origin}.`;
          return;
        }
      }
    } catch (permErr) {
      if (errEl) errEl.textContent = permErr?.message || "Could not verify tab access.";
      return;
    }

    showGlobalProgress(15, "Running Mode 1 Website Security Scan...");
    try {
      const result = await window.WebScanner.runWebsiteScan((pct, msg) => {
        showGlobalProgress(pct, msg);
      }, targetTabId);

      websiteReport = result;
      renderWebsiteModeViews(websiteReport);
      renderXAISection();
      addAuditLog("INFO", `Mode 1 Website Scan complete on ${result.targetUrl} (Score: ${result.score}/100)`);
    } catch (err) {
      if (errEl) errEl.textContent = err?.message || "Website scan failed.";
      addAuditLog("CRIT", `Mode 1 Website Scan error: ${err?.message || err}`);
    } finally {
      hideGlobalProgressSoon();
    }
  }

  function renderWebsiteModeViews(data) {
    if (!data) return;

    // Overview card
    setText("ov-web-score", data.score);
    setRing("ov-web-ring", data.score);
    setText("ov-web-url", data.targetUrl || "Active Tab");
    setText(
      "ov-web-summary",
      `Crit: ${data.counts?.critical || 0}, High: ${data.counts?.high || 0}, Med: ${data.counts?.medium || 0}, Low: ${data.counts?.low || 0}`
    );

    // Tab 2 Metrics
    setText("web-tab-score", data.score);
    const ratingEl = document.getElementById("web-tab-rating");
    if (ratingEl) {
      ratingEl.textContent = data.score >= 80 ? "Low Risk Posture" : data.score >= 50 ? "Moderate Risk Posture" : "High Risk Posture";
      ratingEl.className = `metric-sub ${data.score >= 80 ? "text-safe" : data.score >= 50 ? "text-warning" : "text-critical"}`;
    }
    setText("web-tab-crit-high", (data.counts?.critical || 0) + (data.counts?.high || 0));
    setText("web-tab-med-low", `${data.counts?.medium || 0} Medium / ${data.counts?.low || 0} Low`);

    const m = data.metrics || {};
    setText("web-tab-scripts", m.totalScripts || 0);
    setText("web-tab-scripts-sub", `${m.inlineWithoutNonce || 0} inline w/o nonce • ${m.mixedContentScripts || 0} mixed`);
    setText("web-tab-cookies", m.jsAccessibleCookies || 0);
    setText("web-tab-cookies-sub", `${m.sensitiveJsCookies || 0} sensitive exposed to JS`);

    // Headers checklist
    const headersList = document.getElementById("dash-web-headers-list");
    if (headersList && data.headers) {
      const checks = [
        ["HTTPS / TLS Transport", data.headers.https],
        ["Strict-Transport-Security (HSTS)", data.headers.hsts],
        ["Content-Security-Policy (CSP)", data.headers.csp],
        ["X-Frame-Options / frame-ancestors", data.headers.xframe],
        ["X-Content-Type-Options: nosniff", data.headers.xContentType],
        ["Secure & HttpOnly Cookie Posture", data.headers.secureCookies]
      ];
      headersList.innerHTML = checks
        .map(
          ([label, pass]) => `
          <div class="header-check-row">
            <span>${escapeHtml(label)}</span>
            <span class="badge ${pass ? "badge-low" : "badge-critical"}">${pass ? "✓ Enforced" : "✕ Missing / Risk"}</span>
          </div>
        `
        )
        .join("");
    }

    renderFindingsInto("dash-web-findings-list", data.findings || [], webFilter);
    const exportWebBtn = document.getElementById("btn-dash-export-web");
    if (exportWebBtn) exportWebBtn.disabled = false;
  }

  // ---------------------------------------------------------------------------
  // Mode 2: IoT Network Anomaly Audit (OWASP IoT Top 10 + SHAP)
  // ---------------------------------------------------------------------------
  function setupIoTModeControls() {
    document.getElementById("btn-dash-run-iot")?.addEventListener("click", () => runDashboardIoTAudit());
    document.getElementById("btn-ov-run-iot")?.addEventListener("click", () => runDashboardIoTAudit());
    document.getElementById("btn-iot-tab-run")?.addEventListener("click", () => runDashboardIoTAudit());
    document.getElementById("btn-owasp-run-iot")?.addEventListener("click", () => runDashboardIoTAudit());

    document.getElementById("btn-dash-export-iot")?.addEventListener("click", () => {
      openExportModalForMode("iot");
    });

    document.getElementById("btn-dash-close-login")?.addEventListener("click", () => {
      const card = document.getElementById("dash-tb-login-card");
      if (card) card.style.display = "none";
    });

    const submitLogin = () => {
      const username = document.getElementById("dash-tb-username")?.value || "";
      const password = document.getElementById("dash-tb-password")?.value || "";
      const errEl = document.getElementById("dash-tb-login-error");
      if (!username.trim() || !password) {
        if (errEl) errEl.textContent = "Enter both username and password.";
        return;
      }
      if (errEl) errEl.textContent = "";
      runDashboardIoTAudit({ username, password });
    };

    document.getElementById("btn-dash-tb-login")?.addEventListener("click", submitLogin);
    document.getElementById("dash-tb-password")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitLogin();
      }
    });

    document.getElementById("device-search")?.addEventListener("input", (e) => {
      const q = (e.target.value || "").toLowerCase();
      const devs = iotReport?.devicesAudited || [];
      const filtered = devs.filter(
        (d) =>
          (d.name || "").toLowerCase().includes(q) ||
          (d.ip || "").toLowerCase().includes(q) ||
          (d.mac || "").toLowerCase().includes(q) ||
          (d.type || "").toLowerCase().includes(q)
      );
      renderDevicesTable(filtered);
    });

    document.querySelectorAll("#dash-iot-filter-group .filter-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#dash-iot-filter-group .filter-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        iotFilter = btn.dataset.filter || "all";
        if (iotReport) renderFindingsInto("dash-iot-findings-list", iotReport.findings || [], iotFilter);
      });
    });

    // Optional local Rust scanner daemon button
    document.getElementById("btn-scan-network")?.addEventListener("click", runOptionalLocalRustScan);
  }

  async function runDashboardIoTAudit(credentials) {
    const errEl = document.getElementById("dash-iot-error");
    const loginCard = document.getElementById("dash-tb-login-card");
    const loginErr = document.getElementById("dash-tb-login-error");
    if (errEl) errEl.textContent = "";

    showGlobalProgress(10, "Starting Mode 2 IoT Network Anomaly Audit...");
    try {
      const result = await window.IoTAuditor.runIoTAnomalyAudit({
        credentials,
        onProgress: (pct, msg) => showGlobalProgress(pct, msg)
      });

      if (result.status === "NOT_CONFIGURED") {
        jumpToTab("iot");
        openDashUrlPanel();
        return;
      }
      if (result.status === "PERMISSION_REQUIRED") {
        if (errEl) errEl.textContent = result.message;
        jumpToTab("iot");
        openDashUrlPanel();
        return;
      }
      if (result.status === "AUTH_REQUIRED") {
        if (loginCard) loginCard.style.display = "block";
        if (loginErr) loginErr.textContent = result.message || "";
        jumpToTab("iot");
        return;
      }

      if (loginCard) loginCard.style.display = "none";
      const passEl = document.getElementById("dash-tb-password");
      if (passEl) passEl.value = "";

      iotReport = result;
      renderIoTModeViews(iotReport);
      renderXAISection();
      updateDashConnectionBadge({ status: "connected", label: "Connected", message: "Authenticated & Audited" });
      addAuditLog(
        "INFO",
        `Mode 2 IoT Anomaly Audit completed on ${result.managingServer} (${(result.devicesAudited || []).length} devices, Score: ${result.score}/100).`
      );
    } catch (err) {
      if (credentials && loginErr) {
        loginErr.textContent = err?.message || "Authentication failed.";
      } else if (errEl) {
        errEl.textContent = err?.message || "IoT Anomaly Audit failed.";
      }
      addAuditLog("CRIT", `Mode 2 IoT Audit error: ${err?.message || err}`);
    } finally {
      hideGlobalProgressSoon();
    }
  }

  function renderIoTModeViews(data) {
    if (!data) return;

    const devs = data.devicesAudited || [];
    setText("ov-iot-score", data.score);
    setRing("ov-iot-ring", data.score);
    setText("ov-iot-server", data.managingServer || "Not Configured");
    setText(
      "ov-iot-summary",
      `${devs.length} device(s) audited • Crit: ${data.counts?.critical || 0}, High: ${data.counts?.high || 0}, Med: ${data.counts?.medium || 0}`
    );

    setText("iot-tab-score", data.score);
    const ratingEl = document.getElementById("iot-tab-rating");
    if (ratingEl) {
      ratingEl.textContent = data.score >= 80 ? "Low Risk Posture" : data.score >= 50 ? "Moderate Risk Posture" : "High Risk Posture";
      ratingEl.className = `metric-sub ${data.score >= 80 ? "text-safe" : data.score >= 50 ? "text-warning" : "text-critical"}`;
    }
    setText("iot-tab-device-count", devs.length);
    setText("iot-tab-server-sub", data.managingServer || "Configured Server");
    setText("iot-tab-crit-high", (data.counts?.critical || 0) + (data.counts?.high || 0));
    setText("iot-tab-med-low", `${data.counts?.medium || 0} Medium / ${data.counts?.low || 0} Low`);
    setText("iot-tab-engine", data.engineUsed || "Wasm / SHAP");

    renderDevicesTable(devs);
    renderFindingsInto("dash-iot-findings-list", data.findings || [], iotFilter);
    renderOwaspViews(data);

    const exportIotBtn = document.getElementById("btn-dash-export-iot");
    if (exportIotBtn) exportIotBtn.disabled = false;
  }

  function renderDevicesTable(devices) {
    const tbody = document.getElementById("devices-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!devices || devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:24px; color:var(--text-secondary);">No audited IoT devices yet. Configure your managing server URL and click <strong>Run IoT Audit</strong>.</td></tr>`;
      return;
    }

    devices.forEach((dev) => {
      const tr = document.createElement("tr");
      const scoreBadge = dev.score >= 80 ? "badge-low" : dev.score >= 50 ? "badge-medium" : "badge-critical";
      const owaspTags = (dev.owaspCategories || []).length
        ? dev.owaspCategories.map((c) => `<span class="badge badge-high" style="margin-right:3px;">${escapeHtml(c)}</span>`).join("")
        : `<span class="badge badge-low">Compliant</span>`;

      tr.innerHTML = `
        <td><span class="online-dot" title="${escapeHtml(dev.status || "online")}"></span></td>
        <td><strong>${escapeHtml(dev.name)}</strong></td>
        <td><span class="badge badge-blue">${escapeHtml(dev.type || "IoT")}</span></td>
        <td class="code-cell">${escapeHtml(dev.ip || "N/A")}</td>
        <td class="code-cell">${escapeHtml(dev.mac || "N/A")}</td>
        <td class="code-cell">${dev.telemetryKeysCount ?? 0}</td>
        <td><span class="badge ${scoreBadge}">${dev.score}/100</span></td>
        <td>${owaspTags}</td>
        <td><button type="button" class="btn btn-secondary btn-device-inspect" style="padding:4px 8px; font-size:11px;" data-device-id="${escapeHtml(dev.id)}">Details</button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------------------
  // OWASP IoT Top 10 (I1 - I10) Matrix Views
  // ---------------------------------------------------------------------------
  function getDefaultOwaspMatrix() {
    return Object.entries(window.IoTAuditor.OWASP_IOT_TOP_10).map(([id, fullTitle]) => ({
      id,
      title: fullTitle.replace(`${id}: `, ""),
      fullTitle,
      status: "not_audited",
      findingsCount: 0,
      affectedNodes: [],
      remediation: window.IoTAuditor.OWASP_REMEDIATIONS[id]
    }));
  }

  function renderOwaspViews(data) {
    const matrix = data?.owaspMatrix || getDefaultOwaspMatrix();

    // Overview mini grid
    const miniGrid = document.getElementById("ov-owasp-mini-grid");
    if (miniGrid) {
      miniGrid.innerHTML = matrix
        .map((m) => {
          const badgeCls =
            m.status === "critical"
              ? "badge-critical"
              : m.status === "high"
                ? "badge-high"
                : m.status === "medium"
                  ? "badge-medium"
                  : m.status === "low"
                    ? "badge-blue"
                    : m.status === "passed"
                      ? "badge-low"
                      : "badge-blue";
          const label = m.status === "not_audited" ? "Pending" : m.status === "passed" ? "Pass" : `${m.findingsCount} Flag`;
          return `
            <div class="owasp-mini-card">
              <div class="owasp-mini-top">
                <span class="owasp-mini-id">${escapeHtml(m.id)}</span>
                <span class="badge ${badgeCls}" style="font-size:10px;">${escapeHtml(label)}</span>
              </div>
              <div class="owasp-mini-title">${escapeHtml(m.title)}</div>
            </div>
          `;
        })
        .join("");
    }

    // Tab 4 full matrix grid
    const fullGrid = document.getElementById("dash-owasp-matrix-grid");
    if (fullGrid) {
      fullGrid.innerHTML = matrix
        .map((m) => {
          const sevCls = m.status === "passed" || m.status === "not_audited" ? "" : `sev-${m.status}`;
          const badgeCls =
            m.status === "critical"
              ? "badge-critical"
              : m.status === "high"
                ? "badge-high"
                : m.status === "medium"
                  ? "badge-medium"
                  : m.status === "low"
                    ? "badge-blue"
                    : m.status === "passed"
                      ? "badge-low"
                      : "badge-blue";
          const statusText =
            m.status === "not_audited"
              ? "Not Audited Yet"
              : m.status === "passed"
                ? "✓ Passed"
                : `${m.status.toUpperCase()} (${m.findingsCount})`;

          const affectedHtml =
            m.affectedNodes && m.affectedNodes.length > 0
              ? `<div style="font-size:11px; color:var(--accent-blue); margin-top:6px;">Affected: ${escapeHtml(m.affectedNodes.join(", "))}</div>`
              : "";

          return `
            <div class="owasp-card ${sevCls}">
              <div class="owasp-card-head">
                <span class="owasp-card-title">${escapeHtml(m.fullTitle)}</span>
                <span class="badge ${badgeCls}">${escapeHtml(statusText)}</span>
              </div>
              ${affectedHtml}
              <div class="owasp-card-remed">
                <strong>Remediation:</strong> ${escapeHtml(m.remediation)}
              </div>
            </div>
          `;
        })
        .join("");
    }
  }

  // ---------------------------------------------------------------------------
  // Optional Local Rust Subnet Scanner (User-entered URL & CIDR only)
  // ---------------------------------------------------------------------------
  async function runOptionalLocalRustScan() {
    const urlInput = document.getElementById("rust-daemon-url")?.value?.trim() || "";
    const subnet = document.getElementById("scanner-subnet")?.value?.trim() || "";
    const statusEl = document.getElementById("rust-local-status");

    const v = window.ConfigManager.validateAndNormalizeUrl(urlInput);
    if (!v.valid) {
      if (statusEl) {
        statusEl.textContent = v.error;
        statusEl.className = "dash-feedback error";
      }
      return;
    }
    if (!subnet) {
      if (statusEl) {
        statusEl.textContent = "Enter a target CIDR subnet range.";
        statusEl.className = "dash-feedback error";
      }
      return;
    }

    const granted = await window.ConfigManager.requestHostPermission(v.originPattern);
    if (!granted) {
      if (statusEl) {
        statusEl.textContent = "Host permission denied for Rust daemon URL.";
        statusEl.className = "dash-feedback error";
      }
      return;
    }

    if (statusEl) {
      statusEl.textContent = `Running local Rust scan on ${subnet}...`;
      statusEl.className = "dash-feedback";
    }

    try {
      const resp = await fetch(`${v.normalizedUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subnet, mode: "auto" }),
        signal: AbortSignal.timeout(15000)
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const devices = await resp.json();
      if (statusEl) {
        statusEl.textContent = `Local Rust scan returned ${devices.length} endpoint(s).`;
        statusEl.className = "dash-feedback success";
      }
      addAuditLog("INFO", `Optional Rust scanner (${v.normalizedUrl}) discovered ${devices.length} devices on ${subnet}.`);
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = `Could not reach Rust daemon: ${err?.message || err}`;
        statusEl.className = "dash-feedback error";
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Dynamic XAI SHAP Decomposition
  // ---------------------------------------------------------------------------
  function renderXAISection() {
    const container = document.getElementById("xai-container");
    if (!container) return;
    container.innerHTML = "";

    const dynamicCards = [];
    const combinedFindings = [
      ...(websiteReport?.findings || []).map((f) => ({ ...f, sourceMode: "Mode 1: Website Scan" })),
      ...(iotReport?.findings || []).map((f) => ({ ...f, sourceMode: "Mode 2: IoT Anomaly Audit" }))
    ];

    combinedFindings.slice(0, 8).forEach((f) => {
      if (f.shap && f.shap.length > 0) {
        dynamicCards.push({
          vulnerability: f.type,
          modelType: `${f.sourceMode}${f.owaspId ? " • " + f.owaspId : ""}`,
          baseScore: (f.severity || "medium").toUpperCase(),
          features: f.shap.map((s) => {
            const num = parseFloat(String(s.weight).replace("+", "")) || 0.25;
            return { name: s.feature, impact: num, positive: num >= 0 };
          })
        });
      }
    });

    const modelsToRender = dynamicCards.length > 0 ? dynamicCards : baselineXaiModels;
    modelsToRender.forEach((m) => {
      const card = document.createElement("div");
      card.className = "xai-card";

      const featuresHTML = m.features
        .map((f) => {
          const widthPct = Math.min(100, Math.abs(f.impact) * 100);
          const color = f.positive ? "var(--color-critical)" : "var(--color-low)";
          const sign = f.positive ? "+" : "";
          return `
            <div class="xai-feature-row">
              <div style="flex:1;">
                <div style="font-size:12px; font-weight:600; color:#e2e8f0;">${escapeHtml(f.name)}</div>
                <div style="font-size:10px; color:#94a3b8;">SHAP weight attribution</div>
              </div>
              <div class="shap-impact-bar" style="width: 140px;">
                <div style="flex:1; height:6px; background:#334155; border-radius:3px; overflow:hidden;">
                  <div style="width:${widthPct}%; height:100%; background:${color};"></div>
                </div>
                <span style="font-family:monospace; font-size:11px; font-weight:700; color:${color}; width:45px; text-align:right;">
                  ${sign}${f.impact}
                </span>
              </div>
            </div>
          `;
        })
        .join("");

      card.innerHTML = `
        <div class="xai-card-title">${escapeHtml(m.vulnerability)}</div>
        <div style="font-size:11px; color:var(--accent-blue); margin-bottom:12px;">${escapeHtml(m.modelType)} | Severity: <strong>${escapeHtml(m.baseScore)}</strong></div>
        <div class="xai-feature-list">${featuresHTML}</div>
      `;
      container.appendChild(card);
    });
  }

  // ---------------------------------------------------------------------------
  // Shared Rendering, Storage Sync & Modals
  // ---------------------------------------------------------------------------
  function renderFindingsInto(containerId, findings, filter) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";

    const filtered = (findings || []).filter((f) => {
      if (!filter || filter === "all") return true;
      return (f.severity || "").toLowerCase() === filter.toLowerCase();
    });

    if (filtered.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:24px; color:var(--text-secondary);">No findings match the current filter.</div>`;
      return;
    }

    filtered.forEach((f) => {
      const sev = (f.severity || "low").toLowerCase();
      const card = document.createElement("div");
      card.className = `dash-finding-card sev-${sev}`;

      const shapHtml =
        f.shap && f.shap.length
          ? `<div class="dash-shap-box"><strong>SHAP Attribution:</strong> ${f.shap
              .map((s) => `${escapeHtml(s.feature)} (<code>${escapeHtml(String(s.weight))}</code>)`)
              .join(" • ")}</div>`
          : "";

      card.innerHTML = `
        <div class="dash-finding-top">
          <span class="dash-finding-title">${f.owaspId ? `[${escapeHtml(f.owaspId)}] ` : ""}${escapeHtml(f.type || "Finding")}</span>
          <span class="badge badge-${sev}">${escapeHtml(sev.toUpperCase())}</span>
        </div>
        <div class="dash-finding-detail">${escapeHtml(f.detail || "")} ${
          f.selector ? `<code>${escapeHtml(f.selector)}</code>` : ""
        }</div>
        <div class="dash-finding-impact"><strong>Impact:</strong> ${escapeHtml(f.impact || "")}</div>
        ${shapHtml}
      `;
      container.appendChild(card);
    });
  }

  function setupModalControls() {
    document.addEventListener("click", (e) => {
      const btn = e.target.closest(".btn-device-inspect");
      if (!btn) return;
      const devId = btn.dataset.deviceId;
      const dev = (iotReport?.devicesAudited || []).find((d) => d.id === devId);
      if (dev) openDeviceModal(dev);
    });

    document.getElementById("btn-close-modal")?.addEventListener("click", () => {
      document.getElementById("audit-modal").style.display = "none";
    });
    document.getElementById("btn-modal-done")?.addEventListener("click", () => {
      document.getElementById("audit-modal").style.display = "none";
    });
    document.getElementById("audit-modal")?.addEventListener("click", (e) => {
      if (e.target.id === "audit-modal") e.target.style.display = "none";
    });
  }

  function openDeviceModal(dev) {
    setText("modal-device-name", dev.name);
    setText("modal-device-ip", dev.ip || "N/A");
    setText("modal-device-mac", dev.mac || "N/A");
    setText("modal-device-cat", dev.type || "IoT");
    setText("modal-device-score", `${dev.score}/100`);

    const list = document.getElementById("modal-stages-list");
    if (list) {
      const devFindings = (iotReport?.findings || []).filter((f) =>
        (f.selector || "").includes(dev.name) || (f.selector || "").includes(dev.id)
      );
      if (devFindings.length === 0) {
        list.innerHTML = `<div class="stage-card">No OWASP IoT Top 10 flaws or telemetry anomalies detected for this device.</div>`;
      } else {
        list.innerHTML = devFindings
          .map(
            (f) => `
            <div class="stage-card">
              <div class="stage-card-header">
                <strong>${escapeHtml(f.owaspName || f.type)}</strong>
                <span class="badge badge-${escapeHtml((f.severity || "medium").toLowerCase())}">${escapeHtml((f.severity || "medium").toUpperCase())}</span>
              </div>
              <p style="font-size:12px; color:var(--text-secondary); margin-bottom:6px;">${escapeHtml(f.detail)}</p>
              <p style="font-size:11px; color:#fca5a5;"><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>
            </div>
          `
          )
          .join("");
      }
    }

    document.getElementById("audit-modal").style.display = "flex";
  }

  function setupExportControls() {
    document.getElementById("btn-export-full-report")?.addEventListener("click", () => {
      openExportModalForMode(iotReport ? "iot" : "website");
    });

    const closeModal = () => {
      document.getElementById("dash-export-modal").style.display = "none";
    };
    document.getElementById("btn-close-dash-export")?.addEventListener("click", closeModal);
    document.getElementById("btn-cancel-dash-export")?.addEventListener("click", closeModal);
    document.getElementById("dash-export-modal")?.addEventListener("click", (e) => {
      if (e.target.id === "dash-export-modal") closeModal();
    });

    document.querySelectorAll("#dash-export-mode-toggle [data-export-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        setExportModeSelection(btn.dataset.exportMode || "iot");
      });
    });

    document.querySelectorAll(".btn-dash-download").forEach((btn) => {
      btn.addEventListener("click", () => {
        const format = btn.dataset.format || "json";
        executeDashboardExport(selectedExportMode, format);
        closeModal();
      });
    });
  }

  function openExportModalForMode(mode) {
    setExportModeSelection(mode);
    document.getElementById("dash-export-modal").style.display = "flex";
  }

  function setExportModeSelection(mode) {
    selectedExportMode = mode === "website" ? "website" : "iot";
    document.querySelectorAll("#dash-export-mode-toggle [data-export-mode]").forEach((b) => {
      b.classList.toggle("active", b.dataset.exportMode === selectedExportMode);
    });
    const note = document.getElementById("dash-export-mode-note");
    if (note) {
      if (selectedExportMode === "iot") {
        note.textContent = iotReport
          ? `Ready: IoT Network Anomaly Audit (${iotReport.managingServer}, ${(iotReport.devicesAudited || []).length} device(s))`
          : "No IoT Anomaly Audit run yet. Run Mode 2 first.";
        note.className = `dash-feedback ${iotReport ? "success" : "error"}`;
      } else {
        note.textContent = websiteReport
          ? `Ready: Website Security Scan (${websiteReport.targetUrl})`
          : "No Website Security Scan run yet. Run Mode 1 first.";
        note.className = `dash-feedback ${websiteReport ? "success" : "error"}`;
      }
    }
  }

  function executeDashboardExport(mode, format) {
    if (mode === "website") {
      if (!websiteReport) {
        alert("Run Mode 1 (Website Security Scan) before exporting a Website report.");
        return;
      }
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
      addAuditLog("INFO", `Exported Mode 1 Website Security Scan report (.${format.toUpperCase()}).`);
      return;
    }

    if (!iotReport) {
      alert("Run Mode 2 (IoT Network Anomaly Audit) before exporting an IoT report.");
      return;
    }
    const devices = iotReport.devicesAudited || [];
    const summaryList = devices.map((d) => {
      const parts = [
        d.ip && d.ip !== "N/A" ? `IP:${d.ip}` : null,
        d.mac && d.mac !== "N/A" ? `MAC:${d.mac}` : null
      ].filter(Boolean);
      return parts.length ? `${d.name} (${parts.join(", ")})` : d.name;
    });
    const payload = {
      mode: "iot",
      auditType: "IoT Network Anomaly Audit (OWASP IoT Top 10)",
      managingServer: iotReport.managingServer,
      devicesAudited: `${devices.length}${summaryList.length ? " — " + summaryList.join("; ") : ""}`,
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
      owaspMatrix: iotReport.owaspMatrix,
      findings: iotReport.findings || []
    };
    window.IoTReportExporter.exportAuditReport(format, payload, "iot-network-anomaly-audit");
    addAuditLog("INFO", `Exported Mode 2 IoT OWASP Anomaly Audit report (.${format.toUpperCase()}).`);
  }

  async function loadIsolatedReportsFromStorage() {
    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      renderOwaspViews(null);
      renderXAISection();
      return;
    }

    const res = await chrome.storage.local.get(["lastWebsiteScan", "lastIotAudit"]);
    if (res.lastWebsiteScan && res.lastWebsiteScan.mode === "website") {
      websiteReport = res.lastWebsiteScan;
      renderWebsiteModeViews(websiteReport);
    }
    if (res.lastIotAudit && res.lastIotAudit.mode === "iot") {
      iotReport = res.lastIotAudit;
      renderIoTModeViews(iotReport);
    } else {
      renderDevicesTable([]);
      renderOwaspViews(null);
    }
    renderXAISection();
  }

  function setupStorageSyncListener() {
    if (typeof chrome === "undefined" || !chrome.storage?.onChanged) return;
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local") return;
      if (changes.managingUrl) {
        refreshManagingUrlHeader();
      }
      if (changes.lastWebsiteScan?.newValue?.mode === "website") {
        websiteReport = changes.lastWebsiteScan.newValue;
        renderWebsiteModeViews(websiteReport);
        renderXAISection();
      }
      if (changes.lastIotAudit?.newValue?.mode === "iot") {
        iotReport = changes.lastIotAudit.newValue;
        renderIoTModeViews(iotReport);
        renderXAISection();
      }
    });

    document.getElementById("btn-clear-logs")?.addEventListener("click", () => {
      auditLogs = [];
      renderAuditLogs();
    });
  }

  function addAuditLog(level, msg) {
    auditLogs.unshift({
      time: new Date().toLocaleTimeString(),
      level,
      msg
    });
    if (auditLogs.length > 60) auditLogs.pop();
    renderAuditLogs();
  }

  function renderAuditLogs() {
    const stream = document.getElementById("log-stream-container");
    if (!stream) return;
    stream.innerHTML = auditLogs
      .map(
        (l) => `
      <div class="log-entry">
        <span class="log-time">[${escapeHtml(l.time)}]</span>
        <span class="log-level-${escapeHtml(l.level)}">[${escapeHtml(l.level)}]</span>
        <span class="log-msg">${escapeHtml(l.msg)}</span>
      </div>
    `
      )
      .join("");
  }

  function showGlobalProgress(pct, msg) {
    const box = document.getElementById("dash-global-progress");
    const fill = document.getElementById("global-progress-fill");
    const status = document.getElementById("global-audit-status");
    const pctEl = document.getElementById("global-audit-percent");
    if (box) box.style.display = "block";
    if (fill) fill.style.width = `${pct}%`;
    if (status) status.textContent = msg;
    if (pctEl) pctEl.textContent = `${pct}%`;
  }

  function hideGlobalProgressSoon() {
    setTimeout(() => {
      const box = document.getElementById("dash-global-progress");
      const fill = document.getElementById("global-progress-fill");
      if (box) box.style.display = "none";
      if (fill) fill.style.width = "0%";
    }, 1500);
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setRing(ringId, score) {
    const ring = document.getElementById(ringId);
    if (!ring) return;
    const r = 32;
    const c = 2 * Math.PI * r;
    const val = Math.max(0, Math.min(100, Number(score) || 0));
    ring.style.strokeDasharray = c;
    ring.style.strokeDashoffset = c - (val / 100) * c;
    ring.style.stroke = val >= 80 ? "var(--color-low)" : val >= 50 ? "var(--color-medium)" : "var(--color-critical)";
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
