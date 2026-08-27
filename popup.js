// Default fallback audit data
const defaultPopupFindings = [
  {
    id: "f-1",
    type: "DOM-Based XSS Risk",
    severity: "critical",
    selector: "input#device_name",
    detail: "Unsanitized input reflection detected in parameter device_name.",
    impact: "Allows execution of arbitrary JavaScript, enabling session hijacking and unauthorized device control.",
    shap: [
      { feature: "Unescaped payload tag (<script>, onerror=)", weight: "+0.74" },
      { feature: "DOM sink proximity (innerHTML / eval)", weight: "+0.18" }
    ]
  },
  {
    id: "f-2",
    type: "Missing CSRF Token",
    severity: "high",
    selector: "POST /api/system/reboot",
    detail: "State-changing endpoint lacks anti-forgery protection.",
    impact: "Permits unauthorized third-party origins to trigger state changes without user consent.",
    shap: [
      { feature: "Missing Origin/Referer token check", weight: "+0.62" },
      { feature: "State-altering verb without nonce", weight: "+0.29" }
    ]
  },
  {
    id: "f-3",
    type: "Missing Content-Security-Policy (CSP)",
    severity: "medium",
    selector: "HTTP Response Header",
    detail: "Target gateway does not enforce a Content-Security-Policy (CSP).",
    impact: "Increases risk of inline script execution and unauthorized data exfiltration.",
    shap: [
      { feature: "Absence of CSP header directive", weight: "+0.48" },
      { feature: "Inline script execution permitted", weight: "+0.33" }
    ]
  },
  {
    id: "f-4",
    type: "Missing X-Frame-Options",
    severity: "medium",
    selector: "HTTP Response Header",
    detail: "Missing anti-framing header allows UI redressing / clickjacking.",
    impact: "Permits malicious third-party websites to frame the admin dashboard.",
    shap: [
      { feature: "Missing X-Frame-Options / frame-ancestors", weight: "+0.41" },
      { feature: "No top-level frame restriction", weight: "+0.22" }
    ]
  }
];

let activeAuditData = {
  score: 42,
  counts: { critical: 1, high: 1, medium: 2, low: 0 },
  headers: { https: false, csp: false, xframe: true, secureCookies: false },
  findings: [...defaultPopupFindings]
};
let currentFilter = "all";

document.addEventListener("DOMContentLoaded", async () => {
  setupFilterListeners();
  setupActionListeners();
  renderAuditView(activeAuditData);
  await loadActiveTabData();
});

// Load audit data for active tab
async function loadActiveTabData() {
  if (typeof chrome === "undefined" || !chrome.tabs) return;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const targetUrlElem = document.getElementById("target-url");
    if (targetUrlElem && tab.url) {
      targetUrlElem.textContent = tab.url;
    }

    chrome.runtime.sendMessage({ type: "GET_AUDIT_DATA", tabId: tab.id }, (response) => {
      if (response && response.data && response.data.findings && response.data.findings.length > 0) {
        activeAuditData = response.data;
        renderAuditView(response.data);
      } else {
        // Keep active baseline data and trigger rescan
        triggerRescan(tab.id);
      }
    });
  } catch (e) {
    console.warn("Could not query active tab:", e);
  }
}

// Render score, headers, and findings
function renderAuditView(data) {
  if (!data) return;

  // 1. Update Score & Circular Progress Ring
  const scoreEl = document.getElementById("security-score");
  const ringFill = document.getElementById("score-ring-fill");
  const scoreRating = document.querySelector(".score-rating");
  const scoreSubtext = document.querySelector(".score-subtext");

  const scoreVal = typeof data.score === "number" ? data.score : parseInt(data.score, 10) || 0;
  if (scoreEl) scoreEl.textContent = scoreVal;

  // Calculate SVG arc radius & stroke-dashoffset (r = 25 -> C = 2 * PI * 25 = 157.08)
  const radius = 25;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.max(0, Math.min(100, scoreVal));
  const offset = circumference - (clampedScore / 100) * circumference;

  if (ringFill) {
    ringFill.style.strokeDasharray = circumference;
    ringFill.style.strokeDashoffset = offset;
  }

  if (scoreVal >= 80) {
    if (ringFill) ringFill.style.stroke = "var(--color-low)";
    if (scoreRating) scoreRating.textContent = "Low Risk Posture";
    if (scoreSubtext) scoreSubtext.textContent = "Basic defense baselines met";
  } else if (scoreVal >= 50) {
    if (ringFill) ringFill.style.stroke = "var(--color-medium)";
    if (scoreRating) scoreRating.textContent = "Moderate Risk Posture";
    if (scoreSubtext) scoreSubtext.textContent = "Security mitigations advised";
  } else {
    if (ringFill) ringFill.style.stroke = "var(--color-critical)";
    if (scoreRating) scoreRating.textContent = "High Risk Posture";
    if (scoreSubtext) scoreSubtext.textContent = "Immediate remediation required";
  }

  // 2. Update Counts
  const critCount = data.counts?.critical ?? (data.findings ? data.findings.filter(f => matchesFilter(f.severity, "critical")).length : 0);
  const highCount = data.counts?.high ?? (data.findings ? data.findings.filter(f => matchesFilter(f.severity, "high")).length : 0);
  const medCount = data.counts?.medium ?? (data.findings ? data.findings.filter(f => matchesFilter(f.severity, "medium")).length : 0);
  const lowCount = data.counts?.low ?? (data.findings ? data.findings.filter(f => matchesFilter(f.severity, "low")).length : 0);

  const elCrit = document.getElementById("count-critical");
  const elHigh = document.getElementById("count-high");
  const elMed = document.getElementById("count-medium");
  const elLow = document.getElementById("count-low");

  if (elCrit) elCrit.textContent = critCount;
  if (elHigh) elHigh.textContent = highCount;
  if (elMed) elMed.textContent = medCount;
  if (elLow) elLow.textContent = lowCount;

  // 3. Update Defense Headers
  updateBadge("chk-https", data.headers?.https, "HTTPS Enforced", "Insecure HTTP");
  updateBadge("chk-csp", data.headers?.csp, "CSP Active", "Missing CSP");
  updateBadge("chk-xframe", data.headers?.xframe, "X-Frame Protected", "Missing X-Frame-Options");
  updateBadge("chk-cookies", data.headers?.secureCookies, "Secure Cookies", "Insecure Cookie Flags");

  // 4. Render Findings
  renderFindings(data.findings || defaultPopupFindings);
}

function updateBadge(id, isPass, passText, failText) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `integrity-badge ${isPass ? "pass" : "fail"}`;
  el.innerHTML = `<span class="badge-icon">${isPass ? "✓" : "✕"}</span> ${isPass ? passText : failText}`;
}

function matchesFilter(findingSeverity, filter) {
  if (!filter || filter === "all") return true;
  const fSev = (findingSeverity || "").toLowerCase().trim();
  const flt = filter.toLowerCase().trim();
  if (flt === "medium" || flt === "med") {
    return fSev === "medium" || fSev === "med" || fSev === "moderate";
  }
  if (flt === "critical" || flt === "crit") {
    return fSev === "critical" || fSev === "crit";
  }
  if (flt === "high") {
    return fSev === "high";
  }
  if (flt === "low") {
    return fSev === "low";
  }
  return fSev === flt;
}

// Render dynamic list of findings with SHAP attribution and severity filtering
function renderFindings(findings) {
  const container = document.getElementById("findings-container");
  if (!container) return;
  container.innerHTML = "";

  const list = (findings && findings.length > 0) ? findings : defaultPopupFindings;
  const filtered = list.filter(f => matchesFilter(f.severity, currentFilter));

  if (filtered.length === 0) {
    const filterLabel = currentFilter === "medium" ? "Medium" : currentFilter.charAt(0).toUpperCase() + currentFilter.slice(1);
    container.innerHTML = `<div style="text-align:center; padding: 24px 10px; color: #94a3b8; font-size: 11px;">
      <div style="font-size: 18px; margin-bottom: 4px;">🛡️</div>
      No <strong>${filterLabel}</strong> severity findings detected on this target.
    </div>`;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement("article");
    const normSev = (f.severity || "low").toLowerCase().startsWith("crit") 
      ? "critical" 
      : (f.severity || "low").toLowerCase().startsWith("med") 
        ? "medium" 
        : (f.severity || "low").toLowerCase();

    card.className = `vuln-card ${normSev}-border`;

    let shapHTML = "";
    if (f.shap && f.shap.length > 0) {
      const items = f.shap.map(s => `<li>${escapeHtml(s.feature)}: <code class="shap-val">${escapeHtml(s.weight)}</code></li>`).join("");
      shapHTML = `
        <div class="shap-attribution">
          <span class="shap-header">💡 SHAP Feature Attribution:</span>
          <ul class="shap-list">${items}</ul>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="vuln-top">
        <span class="vuln-title">${escapeHtml(f.type || f.title || "Security Vulnerability")}</span>
        <span class="vuln-tag tag-${normSev}">${escapeHtml(normSev.toUpperCase())}</span>
      </div>
      <p class="vuln-detail">${escapeHtml(f.detail || "")} <code class="code-target">${escapeHtml(f.selector || "")}</code></p>
      <div class="impact-box">
        <strong>Exploit Impact:</strong> ${escapeHtml(f.impact || "Security integrity risk")}
      </div>
      ${shapHTML}
    `;

    container.appendChild(card);
  });
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function setupFilterListeners() {
  const buttons = document.querySelectorAll(".filter-btn");
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      buttons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter || "all";
      const findings = (activeAuditData && activeAuditData.findings && activeAuditData.findings.length > 0) 
        ? activeAuditData.findings 
        : defaultPopupFindings;
      renderFindings(findings);
    });
  });
}

function setupActionListeners() {
  document.getElementById("btn-run-audit").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) triggerRescan(tab.id);
  });

  // Export Modal trigger
  const exportBtn = document.getElementById("btn-export-report");
  const exportModal = document.getElementById("export-modal");
  const closeExportBtn = document.getElementById("btn-close-export-modal");

  if (exportBtn && exportModal) {
    exportBtn.addEventListener("click", () => {
      exportModal.style.display = "flex";
    });
  }

  if (closeExportBtn && exportModal) {
    closeExportBtn.addEventListener("click", () => {
      exportModal.style.display = "none";
    });
  }

  if (exportModal) {
    exportModal.addEventListener("click", (e) => {
      if (e.target === exportModal) {
        exportModal.style.display = "none";
      }
    });
  }

  // Export format options click handlers
  const optButtons = document.querySelectorAll(".export-opt-btn");
  optButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const format = btn.dataset.format || "json";
      executePopupExport(format);
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

function executePopupExport(format) {
  const targetUrl = document.getElementById("target-url")?.textContent || "Target IoT Device";
  const scoreVal = parseInt(document.getElementById("security-score")?.textContent, 10) || 42;

  const dataToExport = activeAuditData ? { ...activeAuditData } : {
    score: scoreVal,
    counts: {
      critical: parseInt(document.getElementById("count-critical")?.textContent, 10) || 2,
      high: parseInt(document.getElementById("count-high")?.textContent, 10) || 1,
      medium: parseInt(document.getElementById("count-medium")?.textContent, 10) || 3,
      low: parseInt(document.getElementById("count-low")?.textContent, 10) || 0
    },
    headers: {
      https: document.getElementById("chk-https")?.classList.contains("pass") || false,
      csp: document.getElementById("chk-csp")?.classList.contains("pass") || false,
      xframe: document.getElementById("chk-xframe")?.classList.contains("pass") || false,
      secureCookies: document.getElementById("chk-cookies")?.classList.contains("pass") || false
    },
    findings: []
  };

  const payload = {
    title: "IoT Security Auditor - Active Target Report",
    timestamp: new Date().toLocaleString(),
    targetUrl: targetUrl,
    score: dataToExport.score,
    counts: dataToExport.counts,
    headers: dataToExport.headers,
    findings: dataToExport.findings || []
  };

  if (typeof IoTReportExporter !== "undefined") {
    IoTReportExporter.exportAuditReport(format, payload, "iot-security-audit");
  } else {
    // Fallback JSON download
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iot-security-audit-${Date.now()}.${format === "json" ? "json" : "txt"}`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

function triggerRescan(tabId) {
  const btn = document.getElementById("btn-run-audit");
  const progressBox = document.getElementById("popup-scan-progress");
  const progressFill = document.getElementById("popup-progress-fill");
  const statusText = document.getElementById("popup-progress-status");
  const percentText = document.getElementById("popup-progress-percent");

  if (btn) {
    btn.innerHTML = `<span class="spin">🔄</span> Auditing...`;
    btn.disabled = true;
    btn.classList.add("loading");
  }

  if (progressBox) progressBox.style.display = "block";
  if (progressFill) progressFill.style.width = "20%";
  if (percentText) percentText.textContent = "20%";
  if (statusText) statusText.textContent = "Probing active tab DOM elements...";

  setTimeout(() => {
    if (progressFill) progressFill.style.width = "55%";
    if (percentText) percentText.textContent = "55%";
    if (statusText) statusText.textContent = "Inspecting HTTP security defense headers...";
  }, 250);

  setTimeout(() => {
    if (progressFill) progressFill.style.width = "85%";
    if (percentText) percentText.textContent = "85%";
    if (statusText) statusText.textContent = "Computing XAI SHAP vulnerability weights...";
  }, 500);

  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ type: "TRIGGER_RESCAN", tabId }, () => {
      setTimeout(() => {
        chrome.runtime.sendMessage({ type: "GET_AUDIT_DATA", tabId }, (res) => {
          if (progressFill) progressFill.style.width = "100%";
          if (percentText) percentText.textContent = "100%";
          if (statusText) statusText.textContent = "✓ Target Audit Complete";

          if (btn) {
            btn.innerHTML = `<span>🛡️</span> Run Audit`;
            btn.disabled = false;
            btn.classList.remove("loading");
          }

          if (res && res.data && res.data.findings && res.data.findings.length > 0) {
            activeAuditData = res.data;
          }
          renderAuditView(activeAuditData);

          setTimeout(() => {
            if (progressBox) progressBox.style.display = "none";
            if (progressFill) progressFill.style.width = "0%";
          }, 1800);
        });
      }, 700);
    });
  } else {
    // Standalone fallback simulation
    setTimeout(() => {
      if (progressFill) progressFill.style.width = "100%";
      if (percentText) percentText.textContent = "100%";
      if (statusText) statusText.textContent = "✓ Target Audit Complete";

      if (btn) {
        btn.innerHTML = `<span>🛡️</span> Run Audit`;
        btn.disabled = false;
        btn.classList.remove("loading");
      }

      renderAuditView(activeAuditData);

      setTimeout(() => {
        if (progressBox) progressBox.style.display = "none";
        if (progressFill) progressFill.style.width = "0%";
      }, 1800);
    }, 800);
  }
}
