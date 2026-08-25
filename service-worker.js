// service-worker.js

// In-memory or storage-backed audit store indexed by tabId
const auditStore = new Map();

// Initialize or clear tab data
function initTabData(tabId, url) {
  const data = {
    url: url || "",
    score: 100,
    timestamp: Date.now(),
    headers: {
      https: false,
      hsts: false,
      csp: false,
      xframe: false,
      secureCookies: false
    },
    findings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0 }
  };
  auditStore.set(tabId, data);
  return data;
}

// Calculate 0-100 Security Score based on findings and headers
function calculateScore(data) {
  let score = 100;

  // Header deductions
  if (!data.headers.https) score -= 25;
  if (!data.headers.csp) score -= 15;
  if (!data.headers.xframe) score -= 10;
  if (!data.headers.secureCookies) score -= 10;

  // Finding deductions
  score -= (data.counts.critical * 20);
  score -= (data.counts.high * 10);
  score -= (data.counts.medium * 5);
  score -= (data.counts.low * 2);

  data.score = Math.max(0, Math.min(100, score));
}

// Passive Header Check via active tab inspection
async function auditSecurityHeaders(tabId, url) {
  let data = auditStore.get(tabId) || initTabData(tabId, url);
  data.url = url;
  data.headers.https = url.startsWith("https://");

  try {
    const response = await fetch(url, { method: "HEAD", cache: "no-store" });
    
    // Check defense headers
    data.headers.hsts = response.headers.has("strict-transport-security");
    data.headers.csp = response.headers.has("content-security-policy");
    data.headers.xframe = response.headers.has("x-frame-options");

    // Cookie security flags check
    const cookieHeader = response.headers.get("set-cookie") || "";
    data.headers.secureCookies = !cookieHeader || (cookieHeader.includes("Secure") && cookieHeader.includes("HttpOnly"));
  } catch (err) {
    // If HEAD request fails (e.g. CORS/local router constraints), fallback to URL defaults
    data.headers.hsts = false;
    data.headers.csp = false;
  }

  calculateScore(data);
  chrome.storage.local.set({ [`audit_${tabId}`]: data });
}

// Listen for lifecycle events
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
    initTabData(tabId, tab.url);
    auditSecurityHeaders(tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  auditStore.delete(tabId);
  chrome.storage.local.remove(`audit_${tabId}`);
});

// Communication Hub
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : message.tabId;

  if (message.type === "DOM_FINDINGS_REPORTED") {
    let data = auditStore.get(tabId) || initTabData(tabId, sender.tab?.url);
    
    // Merge DOM findings
    data.findings = message.payload.findings;
    data.counts = message.payload.counts;
    
    calculateScore(data);
    auditStore.set(tabId, data);
    chrome.storage.local.set({ [`audit_${tabId}`]: data });

    sendResponse({ status: "ACK", score: data.score });
    return true;
  }

  if (message.type === "GET_AUDIT_DATA") {
    const currentData = auditStore.get(tabId) || null;
    sendResponse({ data: currentData });
    return true;
  }

  if (message.type === "TRIGGER_RESCAN") {
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { type: "EXECUTE_DOM_SCAN" }, (res) => {
        sendResponse(res);
      });
      return true;
    }
  }
});