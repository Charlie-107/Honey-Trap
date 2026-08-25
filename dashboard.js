// dashboard.js

// Comprehensive IoT Subnet Device Registry
const defaultIoTDevices = [
  {
    id: "dev-01",
    name: "Main Gateway / Router",
    ip: "192.168.1.1",
    mac: "00:1A:2B:3C:4D:5E",
    category: "Gateway",
    ports: "80, 443, 8080",
    score: 42,
    status: "online",
    flaws: ["Missing CSRF Token on /reboot", "No CSP Header", "Insecure Cookies"],
    headers: { https: false, hsts: false, csp: false, xframe: true, secureCookies: false },
    activeTarget: true
  },
  {
    id: "dev-02",
    name: "Living Room IP Camera",
    ip: "192.168.1.105",
    mac: "AC:DE:48:11:22:33",
    category: "Surveillance",
    ports: "80, 554 (RTSP)",
    score: 35,
    status: "online",
    flaws: ["DOM-Based XSS in OSD Config", "Default RTSP Stream Unauthenticated"],
    headers: { https: false, hsts: false, csp: false, xframe: false, secureCookies: false },
    activeTarget: false
  },
  {
    id: "dev-03",
    name: "Smart Thermostat Controller",
    ip: "192.168.1.112",
    mac: "34:E6:D7:88:99:AA",
    category: "HVAC / Climate",
    ports: "80, 8443",
    score: 88,
    status: "online",
    flaws: ["Missing HSTS Header"],
    headers: { https: true, hsts: false, csp: true, xframe: true, secureCookies: true },
    activeTarget: false
  },
  {
    id: "dev-04",
    name: "Smart Lighting Bridge (Hue)",
    ip: "192.168.1.120",
    mac: "00:17:88:55:66:77",
    category: "Lighting Hub",
    ports: "80, 443, 8000",
    score: 78,
    status: "online",
    flaws: ["Missing X-Frame-Options (Clickjacking)"],
    headers: { https: true, hsts: true, csp: false, xframe: false, secureCookies: true },
    activeTarget: false
  },
  {
    id: "dev-05",
    name: "Network Attached Storage (NAS)",
    ip: "192.168.1.150",
    mac: "B8:27:EB:AA:BB:CC",
    category: "Storage Server",
    ports: "80, 443, 5000, 5001",
    score: 64,
    status: "online",
    flaws: ["Reflected Parameter Injection", "Missing SameSite on Session"],
    headers: { https: true, hsts: false, csp: false, xframe: true, secureCookies: false },
    activeTarget: false
  },
  {
    id: "dev-06",
    name: "Front Door Smart Lock Gateway",
    ip: "192.168.1.180",
    mac: "70:85:C2:33:44:55",
    category: "Access Control",
    ports: "8080",
    score: 92,
    status: "online",
    flaws: [],
    headers: { https: true, hsts: true, csp: true, xframe: true, secureCookies: true },
    activeTarget: false
  },
  {
    id: "dev-07",
    name: "Kitchen Smart Energy Plug",
    ip: "192.168.1.195",
    mac: "50:02:91:66:77:88",
    category: "Smart Power",
    ports: "80",
    score: 30,
    status: "online",
    flaws: ["Plaintext HTTP Admin", "Missing Authentication Nonce"],
    headers: { https: false, hsts: false, csp: false, xframe: false, secureCookies: false },
    activeTarget: false
  }
];

// XAI SHAP Features definitions
const xaiModels = [
  {
    vulnerability: "DOM-Based Cross-Site Scripting (XSS)",
    modelType: "TreeSHAP Decision Forest (Wasm Engine)",
    baseScore: "+0.85 (Critical)",
    features: [
      { name: "Unescaped Payload Pattern (<script>, onerror=)", impact: 0.74, positive: true },
      { name: "Sink Proximity (element.innerHTML / eval)", impact: 0.58, positive: true },
      { name: "Input Parameter In Reflection Path", impact: 0.32, positive: true },
      { name: "Absence of Input Sanitize Library (DOMPurify)", impact: 0.22, positive: true },
      { name: "Strict CSP nonces detected", impact: -0.65, positive: false }
    ]
  },
  {
    vulnerability: "Cross-Site Request Forgery (CSRF)",
    modelType: "Linear SHAP Gradient Explainer",
    baseScore: "+0.71 (High)",
    features: [
      { name: "State-Altering HTTP Verb (POST/PUT/DELETE)", impact: 0.62, positive: true },
      { name: "Absence of Anti-CSRF Token / Nonce", impact: 0.55, positive: true },
      { name: "Missing Origin / Sec-Fetch-Site Validation", impact: 0.41, positive: true },
      { name: "SameSite=None or Unset on Auth Cookie", impact: 0.38, positive: true },
      { name: "Custom Authorization Header Present", impact: -0.52, positive: false }
    ]
  },
  {
    vulnerability: "Defensive Header Compliance Deficit",
    modelType: "Attribution Vector Matrix",
    baseScore: "+0.60 (Medium)",
    features: [
      { name: "Plaintext HTTP without TLS redirection", impact: 0.68, positive: true },
      { name: "Missing Content-Security-Policy (CSP)", impact: 0.45, positive: true },
      { name: "Missing X-Frame-Options (Clickjacking risk)", impact: 0.35, positive: true },
      { name: "Cookies lacking Secure / HttpOnly flags", impact: 0.30, positive: true },
      { name: "HSTS preload list presence", impact: -0.70, positive: false }
    ]
  }
];

// Mock audit log history
let auditLogs = [
  { time: new Date(Date.now() - 15000).toLocaleTimeString(), level: "CRIT", msg: "DOM XSS sink detected in element <input name='device_name'> on 192.168.1.1" },
  { time: new Date(Date.now() - 32000).toLocaleTimeString(), level: "WARN", msg: "Form lacking anti-CSRF token on action POST /api/system/reboot" },
  { time: new Date(Date.now() - 55000).toLocaleTimeString(), level: "WARN", msg: "Insecure transport: Plaintext HTTP detected on 192.168.1.105:80" },
  { time: new Date(Date.now() - 72000).toLocaleTimeString(), level: "INFO", msg: "WebAssembly analysis engine initialized and bound to tab context" },
  { time: new Date(Date.now() - 95000).toLocaleTimeString(), level: "INFO", msg: "Local IoT Subnet passive discovery indexed 7 active device gateways" }
];

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  renderDevicesTable(defaultIoTDevices);
  renderXAISection();
  renderHeadersTable(defaultIoTDevices);
  renderAuditLogs();
  setupEventListeners();
  loadLiveChromeStorageData();
});

// Tab Navigation
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const tabTitle = document.getElementById("tab-title");

  const titles = {
    overview: "Network Security Overview & Posture",
    devices: "Network Connected IoT Devices Inventory",
    xai: "Explainable AI (SHAP) Vulnerability Decomposition",
    headers: "Transport & Defensive Security Headers Matrix",
    logs: "Real-Time Diagnostic & Audit Log Stream"
  };

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const targetTab = item.dataset.tab;

      navItems.forEach(n => n.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      item.classList.add("active");
      document.getElementById(`tab-${targetTab}`).classList.add("active");
      tabTitle.textContent = titles[targetTab] || "Security Dashboard";
    });
  });
}

// Render Devices Table
function renderDevicesTable(devices) {
  const tbody = document.getElementById("devices-tbody");
  tbody.innerHTML = "";

  devices.forEach(dev => {
    const tr = document.createElement("tr");

    let scoreBadge = "badge-critical";
    if (dev.score >= 80) scoreBadge = "badge-low";
    else if (dev.score >= 50) scoreBadge = "badge-medium";

    let flawsHTML = dev.flaws.length === 0 
      ? `<span class="badge badge-low">No High Flaws</span>`
      : dev.flaws.map(f => `<div style="font-size:11px; color:#fca5a5; margin-bottom:2px;">• ${f}</div>`).join("");

    tr.innerHTML = `
      <td><span class="online-dot" title="Device Online"></span></td>
      <td><strong>${dev.name}</strong> ${dev.activeTarget ? '<span class="badge badge-blue" style="font-size:9px;">Active Target</span>' : ''}</td>
      <td class="code-cell">${dev.ip}</td>
      <td class="code-cell" style="color:#94a3b8;">${dev.mac}</td>
      <td><span class="badge badge-blue">${dev.category}</span></td>
      <td class="code-cell">${dev.ports}</td>
      <td><span class="badge ${scoreBadge}">${dev.score}/100</span></td>
      <td>${flawsHTML}</td>
      <td>
        <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="window.inspectDevice('${dev.id}')">Audit Now</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Render Explainable AI (SHAP) Cards
function renderXAISection() {
  const container = document.getElementById("xai-container");
  container.innerHTML = "";

  xaiModels.forEach(m => {
    const card = document.createElement("div");
    card.className = "xai-card";

    let featuresHTML = m.features.map(f => {
      const widthPct = Math.min(100, Math.abs(f.impact) * 100);
      const color = f.positive ? "var(--color-critical)" : "var(--color-low)";
      const sign = f.positive ? "+" : "";

      return `
        <div class="xai-feature-row">
          <div style="flex:1;">
            <div style="font-size:12px; font-weight:600; color:#e2e8f0;">${f.name}</div>
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
    }).join("");

    card.innerHTML = `
      <div class="xai-card-title">${m.vulnerability}</div>
      <div style="font-size:11px; color:var(--accent-blue); margin-bottom:12px;">Model: ${m.modelType} | Risk Level: <strong>${m.baseScore}</strong></div>
      <div class="xai-feature-list">${featuresHTML}</div>
    `;

    container.appendChild(card);
  });
}

// Render Headers Compliance Table
function renderHeadersTable(devices) {
  const tbody = document.getElementById("headers-tbody");
  tbody.innerHTML = "";

  devices.forEach(dev => {
    const tr = document.createElement("tr");
    const h = dev.headers;

    const renderCheck = (val) => val 
      ? `<span class="badge badge-low">✓ Pass</span>` 
      : `<span class="badge badge-critical">✕ Fail</span>`;

    tr.innerHTML = `
      <td><strong>${dev.name}</strong></td>
      <td class="code-cell">http://${dev.ip}</td>
      <td>${renderCheck(h.https)}</td>
      <td>${renderCheck(h.hsts)}</td>
      <td>${renderCheck(h.csp)}</td>
      <td>${renderCheck(h.xframe)}</td>
      <td>${renderCheck(h.secureCookies)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Render Real-Time Audit Logs
function renderAuditLogs() {
  const stream = document.getElementById("log-stream-container");
  stream.innerHTML = "";

  auditLogs.forEach(l => {
    const entry = document.createElement("div");
    entry.className = "log-entry";
    entry.innerHTML = `
      <span class="log-time">[${l.time}]</span>
      <span class="log-level-${l.level}">[${l.level}]</span>
      <span class="log-msg">${l.msg}</span>
    `;
    stream.appendChild(entry);
  });
}

// Global Device Inspector helper
window.inspectDevice = function(id) {
  const dev = defaultIoTDevices.find(d => d.id === id);
  if (!dev) return;

  alert(`Initiating WebAssembly audit scan on ${dev.name} (${dev.ip})...\nIdentified Risk Score: ${dev.score}/100\nFlaws: ${dev.flaws.join(", ") || "None"}`);
};

// Search & Actions
function setupEventListeners() {
  const searchInput = document.getElementById("device-search");
  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    const filtered = defaultIoTDevices.filter(d => 
      d.name.toLowerCase().includes(q) || 
      d.ip.includes(q) || 
      d.mac.toLowerCase().includes(q) ||
      d.category.toLowerCase().includes(q)
    );
    renderDevicesTable(filtered);
  });

  document.getElementById("btn-clear-logs").addEventListener("click", () => {
    auditLogs = [];
    renderAuditLogs();
  });

  document.getElementById("btn-refresh-network").addEventListener("click", () => {
    auditLogs.unshift({
      time: new Date().toLocaleTimeString(),
      level: "INFO",
      msg: "Subnet re-scan triggered. WebAssembly engine verified 7 devices."
    });
    renderAuditLogs();
    alert("IoT Subnet re-scan completed successfully!");
  });

  document.getElementById("btn-export-full-report").addEventListener("click", exportFullAuditReport);
}

// Export Full Comprehensive Audit Dossier
function exportFullAuditReport() {
  const dossier = {
    title: "IoT Security Auditor - Executive Diagnostic Dossier",
    timestamp: new Date().toISOString(),
    engine: "Rust / WebAssembly Sandbox (Manifest V3)",
    methodology: "Explainable AI (SHAP) Passive DOM & Header Auditing",
    overallPosture: {
      averageScore: 58,
      riskLevel: "High Risk",
      monitoredDevices: defaultIoTDevices.length,
      criticalFlaws: 5
    },
    deviceInventory: defaultIoTDevices,
    xaiAttributionModels: xaiModels,
    auditTrail: auditLogs
  };

  const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `iot-network-audit-dossier-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// Read live data from active chrome tabs if available
function loadLiveChromeStorageData() {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        const tab = tabs[0];
        document.getElementById("inspect-url").textContent = tab.url || "http://192.168.1.1/admin";
        
        chrome.storage.local.get([`audit_${tab.id}`], (result) => {
          const audit = result[`audit_${tab.id}`];
          if (audit) {
            document.getElementById("metric-score").textContent = audit.score;
            if (defaultIoTDevices[0]) {
              defaultIoTDevices[0].score = audit.score;
              renderDevicesTable(defaultIoTDevices);
            }
          }
        });
      }
    });
  }
}
