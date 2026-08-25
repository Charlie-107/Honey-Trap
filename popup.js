// popup.js

let activeAuditData = null;
let currentFilter = "all";

document.addEventListener("DOMContentLoaded", async () => {
  setupFilterListeners();
  setupActionListeners();
  await loadActiveTabData();
});

// Load audit data for active tab
async function loadActiveTabData() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  document.getElementById("target-url").textContent = tab.url || "Unknown Target";

  chrome.runtime.sendMessage({ type: "GET_AUDIT_DATA", tabId: tab.id }, (response) => {
    if (response && response.data) {
      activeAuditData = response.data;
      renderAuditView(response.data);
    } else {
      // Trigger scan if not yet cached
      triggerRescan(tab.id);
    }
  });
}

// Render score, headers, and findings
function renderAuditView(data) {
  if (!data) return;

  // 1. Update Score & Posture
  const scoreEl = document.getElementById("security-score");
  const scoreCircle = document.querySelector(".score-circle");
  const scoreRating = document.querySelector(".score-rating");
  const scoreSubtext = document.querySelector(".score-subtext");

  scoreEl.textContent = data.score;
  scoreCircle.className = "score-circle";
  if (data.score >= 80) {
    scoreCircle.classList.add("score-safe");
    scoreRating.textContent = "Low Risk Posture";
    scoreSubtext.textContent = "Basic defense baselines met";
  } else if (data.score >= 50) {
    scoreCircle.classList.add("score-medium");
    scoreRating.textContent = "Moderate Risk Posture";
    scoreSubtext.textContent = "Security mitigations advised";
  } else {
    scoreCircle.classList.add("score-critical");
    scoreRating.textContent = "High Risk Posture";
    scoreSubtext.textContent = "Immediate remediation required";
  }

  // 2. Update Counts
  document.getElementById("count-critical").textContent = data.counts?.critical || 0;
  document.getElementById("count-high").textContent = data.counts?.high || 0;
  document.getElementById("count-medium").textContent = data.counts?.medium || 0;
  document.getElementById("count-low").textContent = data.counts?.low || 0;

  // 3. Update Defense Headers
  updateBadge("chk-https", data.headers?.https, "HTTPS Enforced", "Insecure HTTP");
  updateBadge("chk-csp", data.headers?.csp, "CSP Active", "Missing CSP");
  updateBadge("chk-xframe", data.headers?.xframe, "X-Frame Protected", "Missing X-Frame-Options");
  updateBadge("chk-cookies", data.headers?.secureCookies, "Secure Cookies", "Insecure Cookie Flags");

  // 4. Render Findings
  renderFindings(data.findings || []);
}

function updateBadge(id, isPass, passText, failText) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `integrity-badge ${isPass ? "pass" : "fail"}`;
  el.innerHTML = `<span class="badge-icon">${isPass ? "✓" : "✕"}</span> ${isPass ? passText : failText}`;
}

// Render dynamic list of findings with SHAP attribution
function renderFindings(findings) {
  const container = document.getElementById("findings-container");
  container.innerHTML = "";

  const filtered = findings.filter(f => currentFilter === "all" || f.severity === currentFilter);

  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding: 20px; color: #94a3b8;">No ${currentFilter === "all" ? "" : currentFilter + " "}vulnerabilities detected on this target.</div>`;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement("article");
    card.className = `vuln-card ${f.severity}-border`;

    let shapHTML = "";
    if (f.shap && f.shap.length > 0) {
      const items = f.shap.map(s => `<li>${s.feature}: <code class="shap-val">${s.weight}</code></li>`).join("");
      shapHTML = `
        <div class="shap-attribution">
          <span class="shap-header">💡 SHAP Feature Attribution:</span>
          <ul class="shap-list">${items}</ul>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="vuln-top">
        <span class="vuln-title">${f.type}</span>
        <span class="vuln-tag tag-${f.severity}">${f.severity}</span>
      </div>
      <p class="vuln-detail">${f.detail} <code class="code-target">${f.selector || ""}</code></p>
      <div class="impact-box">
        <strong>Exploit Impact:</strong> ${f.impact}
      </div>
      ${shapHTML}
    `;

    container.appendChild(card);
  });
}

function setupFilterListeners() {
  const buttons = document.querySelectorAll(".filter-btn");
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      buttons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      if (activeAuditData) {
        renderFindings(activeAuditData.findings || []);
      }
    });
  });
}

function setupActionListeners() {
  document.getElementById("btn-run-audit").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) triggerRescan(tab.id);
  });

  document.getElementById("btn-export-report").addEventListener("click", () => {
    if (!activeAuditData) return;
    const blob = new Blob([JSON.stringify(activeAuditData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iot-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  const fullDashLink = document.getElementById("link-expanded-view");
  if (fullDashLink) {
    fullDashLink.addEventListener("click", (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
    });
  }
}

function triggerRescan(tabId) {
  const btn = document.getElementById("btn-run-audit");
  btn.textContent = "Scanning...";
  btn.disabled = true;

  chrome.runtime.sendMessage({ type: "TRIGGER_RESCAN", tabId }, () => {
    setTimeout(() => {
      chrome.runtime.sendMessage({ type: "GET_AUDIT_DATA", tabId }, (res) => {
        btn.innerHTML = "<span>↻</span> Run Audit";
        btn.disabled = false;
        if (res && res.data) {
          activeAuditData = res.data;
          renderAuditView(res.data);
        }
      });
    }, 500);
  });
}
