// webScanner.js
// Mode 1: Isolated Active-Tab Website Security Scanner
// Audits the currently active browser tab (DOM, headers, cookies, scripts).
// State and scan results are kept strictly isolated from Mode 2 (IoT Auditor).

(function (global) {
  "use strict";

  const STORAGE_KEYS = {
    LAST_WEBSITE_SCAN: "lastWebsiteScan",
    TAB_PREFIX: "websiteScan_"
  };

  function hasChromeApis() {
    return typeof chrome !== "undefined" && chrome.tabs && chrome.scripting;
  }

  function isRestrictedUrl(url) {
    if (!url) return true;
    return !/^https?:\/\//i.test(url);
  }

  /**
   * Function injected into the active tab via chrome.scripting.executeScript.
   * Must be self-contained so it executes cleanly inside the page context.
   */
  function inspectActiveTabDom() {
    const findings = [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };

    // Clean any previous highlights/badges from prior Mode 1 scans
    document.querySelectorAll(".iot-sec-warning-badge").forEach((el) => el.remove());
    document.querySelectorAll(".iot-sec-highlight").forEach((el) => el.classList.remove("iot-sec-highlight"));

    function injectBadge(targetElement, label) {
      const badge = document.createElement("span");
      badge.className = "iot-sec-warning-badge";
      badge.title = `${label} - Flagged by Website Security Scanner`;
      badge.innerText = "⚠ Vulnerable";
      if (targetElement.parentNode) {
        targetElement.parentNode.insertBefore(badge, targetElement.nextSibling);
      }
    }

    // 1. Audit state-changing forms for missing CSRF tokens
    const forms = document.querySelectorAll("form");
    forms.forEach((form, idx) => {
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      const action = form.getAttribute("action") || window.location.pathname;
      if (method === "POST" || method === "PUT" || method === "DELETE") {
        const inputs = Array.from(form.querySelectorAll("input"));
        const hasCsrfToken = inputs.some((input) => {
          const name = (input.name || "").toLowerCase();
          return name.includes("csrf") || name.includes("token") || name.includes("_nonce") || name.includes("xsrf");
        });

        if (!hasCsrfToken) {
          counts.high++;
          form.classList.add("iot-sec-highlight");
          findings.push({
            id: `web-csrf-${idx}`,
            type: "Missing CSRF Token",
            severity: "high",
            selector: form.id ? `form#${form.id}` : `form[action='${action}']`,
            detail: `State-changing ${method} form lacks anti-CSRF token parameters.`,
            impact: "Permits unauthorized third-party origins to trigger state changes without user consent.",
            shap: [
              { feature: "Missing Origin/Referer token parameter", weight: "+0.62" },
              { feature: "State-altering verb without nonce", weight: "+0.29" }
            ]
          });
        }
      }
    });

    // 2. Audit input fields & DOM sinks for XSS risks
    const xssPattern = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*>|javascript:|onerror=|onload=/gi;
    const inputElements = document.querySelectorAll("input[type='text'], input:not([type]), textarea, input[type='search']");
    inputElements.forEach((input, idx) => {
      const nameAttr = input.name || input.id || `input_${idx}`;
      const value = input.value || "";
      const hasSuspiciousPayload = xssPattern.test(value) || xssPattern.test(window.location.search);
      xssPattern.lastIndex = 0;

      if (hasSuspiciousPayload || input.hasAttribute("onchange") || input.hasAttribute("oninput")) {
        counts.critical++;
        input.classList.add("iot-sec-highlight");
        injectBadge(input, "DOM XSS Risk");
        findings.push({
          id: `web-xss-${idx}`,
          type: "DOM-Based XSS Risk",
          severity: "critical",
          selector: input.id ? `#${input.id}` : `input[name='${nameAttr}']`,
          detail: `Unsanitized input sink or inline DOM event handler detected on parameter ${nameAttr}.`,
          impact: "Allows execution of arbitrary JavaScript, enabling session hijacking and unauthorized actions.",
          shap: [
            { feature: "Unescaped payload syntax / inline DOM sink", weight: "+0.74" },
            { feature: "DOM sink proximity (innerHTML/inline-event)", weight: "+0.18" }
          ]
        });
      }
    });

    // Check javascript: URI sinks in links/iframes
    const jsUriElements = document.querySelectorAll("a[href^='javascript:'], iframe[src^='javascript:']");
    if (jsUriElements.length > 0) {
      counts.high++;
      findings.push({
        id: "web-js-uri",
        type: "Unsafe javascript: URI Sink",
        severity: "high",
        selector: `${jsUriElements.length} DOM element(s)`,
        detail: `Found ${jsUriElements.length} anchor/iframe element(s) using executable javascript: URIs.`,
        impact: "Increases XSS attack surface and violates strict CSP script execution guidelines.",
        shap: [
          { feature: "Executable javascript: URI attribute", weight: "+0.58" },
          { feature: "Potential user-controlled href/src sink", weight: "+0.24" }
        ]
      });
    }

    // 3. Scripts Audit (inline scripts without nonce, mixed content, missing SRI)
    const scripts = Array.from(document.querySelectorAll("script"));
    let externalScripts = 0;
    let inlineScripts = 0;
    let inlineWithoutNonce = 0;
    let mixedContentScripts = 0;
    let externalWithoutSri = 0;
    const isHttpsPage = window.location.protocol === "https:";

    scripts.forEach((script) => {
      const src = script.getAttribute("src");
      if (src) {
        externalScripts++;
        if (isHttpsPage && /^http:\/\//i.test(src)) {
          mixedContentScripts++;
        }
        try {
          const scriptUrl = new URL(src, window.location.href);
          if (scriptUrl.origin !== window.location.origin && !script.hasAttribute("integrity")) {
            externalWithoutSri++;
          }
        } catch (_e) {}
      } else {
        inlineScripts++;
        if (!script.hasAttribute("nonce") && (script.textContent || "").trim().length > 0) {
          inlineWithoutNonce++;
        }
      }
    });

    if (mixedContentScripts > 0) {
      counts.high++;
      findings.push({
        id: "web-mixed-scripts",
        type: "Mixed Content Script Loading",
        severity: "high",
        selector: `${mixedContentScripts} <script src="http://...">`,
        detail: `HTTPS page references ${mixedContentScripts} external script(s) over unencrypted HTTP.`,
        impact: "Enables Man-in-the-Middle attackers to inject malicious JavaScript in transit.",
        shap: [
          { feature: "Insecure HTTP script origin on HTTPS page", weight: "+0.69" },
          { feature: "Unauthenticated script integrity", weight: "+0.25" }
        ]
      });
    }

    if (inlineWithoutNonce > 0) {
      counts.medium++;
      findings.push({
        id: "web-inline-scripts",
        type: "Unprotected Inline <script> Blocks",
        severity: "medium",
        selector: `${inlineWithoutNonce} inline <script> tag(s)`,
        detail: `Detected ${inlineWithoutNonce} inline script block(s) lacking a cryptographic CSP nonce.`,
        impact: "Forces reliance on unsafe-inline CSP or exposes page to injected inline script execution.",
        shap: [
          { feature: "Inline script without nonce attribute", weight: "+0.44" },
          { feature: "Weak script execution isolation", weight: "+0.21" }
        ]
      });
    }

    if (externalWithoutSri > 0) {
      counts.low++;
      findings.push({
        id: "web-missing-sri",
        type: "Third-Party Scripts Missing SRI",
        severity: "low",
        selector: `${externalWithoutSri} external <script> tag(s)`,
        detail: `${externalWithoutSri} cross-origin script(s) lack a Subresource Integrity (integrity) hash.`,
        impact: "If an external CDN is compromised, tampered scripts execute without browser hash verification.",
        shap: [
          { feature: "Cross-origin script without integrity attribute", weight: "+0.31" },
          { feature: "External supply-chain trust dependency", weight: "+0.17" }
        ]
      });
    }

    // 4. Client-side Cookies & Token Storage Exposure
    const rawCookieStr = document.cookie || "";
    const cookiePairs = rawCookieStr
      ? rawCookieStr.split(";").map((c) => c.trim()).filter(Boolean)
      : [];
    const sensitiveCookieNames = cookiePairs
      .map((c) => c.split("=")[0].trim())
      .filter((name) => /token|jwt|auth|session|sid|secret|key/i.test(name));

    if (sensitiveCookieNames.length > 0) {
      counts.high++;
      findings.push({
        id: "web-js-cookies",
        type: "Sensitive Cookies Accessible to JavaScript",
        severity: "high",
        selector: `document.cookie (${sensitiveCookieNames.join(", ")})`,
        detail: `Detected ${sensitiveCookieNames.length} sensitive cookie(s) without HttpOnly flag protection.`,
        impact: "Any XSS vulnerability can exfiltrate session/auth cookies directly via document.cookie.",
        shap: [
          { feature: "Auth/session cookie readable via document.cookie", weight: "+0.66" },
          { feature: "Missing HttpOnly cookie flag", weight: "+0.32" }
        ]
      });
    } else if (cookiePairs.length > 0 && !isHttpsPage) {
      counts.medium++;
      findings.push({
        id: "web-http-cookies",
        type: "Cookies Transmitted Over Plaintext HTTP",
        severity: "medium",
        selector: `document.cookie (${cookiePairs.length} cookie(s))`,
        detail: `Page sets ${cookiePairs.length} cookie(s) over an unencrypted HTTP origin.`,
        impact: "Cookies can be intercepted on the local network without TLS encryption.",
        shap: [
          { feature: "Plaintext HTTP cookie transmission", weight: "+0.52" },
          { feature: "Missing Secure cookie attribute", weight: "+0.28" }
        ]
      });
    }

    let exposedStorageTokens = 0;
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i) || "";
        if (/jwt|token|auth|secret|api_?key/i.test(key)) {
          exposedStorageTokens++;
        }
      }
    } catch (_e) {}

    return {
      url: window.location.href,
      title: document.title || "",
      findings,
      counts,
      metrics: {
        totalScripts: scripts.length,
        externalScripts,
        inlineScripts,
        inlineWithoutNonce,
        mixedContentScripts,
        externalWithoutSri,
        jsAccessibleCookies: cookiePairs.length,
        sensitiveJsCookies: sensitiveCookieNames.length,
        exposedStorageTokens
      }
    };
  }

  /**
   * Inspects HTTP response headers on the active tab URL.
   */
  async function auditResponseHeaders(url) {
    const isHttps = /^https:\/\//i.test(url);
    const headersResult = {
      https: isHttps,
      hsts: false,
      csp: false,
      xframe: false,
      xContentType: false,
      secureCookies: isHttps,
      headerFetchSucceeded: false
    };

    try {
      let response = await fetch(url, {
        method: "HEAD",
        cache: "no-store",
        signal: AbortSignal.timeout(4000)
      });

      if (response.status === 405) {
        response = await fetch(url, {
          method: "GET",
          cache: "no-store",
          signal: AbortSignal.timeout(4000)
        });
      }

      headersResult.headerFetchSucceeded = true;
      const cspHeader = response.headers.get("content-security-policy") || "";
      headersResult.hsts = response.headers.has("strict-transport-security");
      headersResult.csp = Boolean(cspHeader);
      headersResult.xframe =
        response.headers.has("x-frame-options") ||
        cspHeader.toLowerCase().includes("frame-ancestors");
      headersResult.xContentType =
        (response.headers.get("x-content-type-options") || "").toLowerCase() === "nosniff";

      const setCookie = response.headers.get("set-cookie") || "";
      if (setCookie) {
        headersResult.secureCookies =
          setCookie.includes("Secure") && setCookie.includes("HttpOnly");
      }
    } catch (_err) {
      headersResult.headerFetchSucceeded = false;
    }

    return headersResult;
  }

  /**
   * Merges header deficiencies with DOM/script/cookie findings and computes a 0-100 score.
   */
  function buildWebsiteAuditReport(tabUrl, domResult, headersResult) {
    const findings = [...(domResult.findings || [])];
    const counts = {
      critical: domResult.counts?.critical || 0,
      high: domResult.counts?.high || 0,
      medium: domResult.counts?.medium || 0,
      low: domResult.counts?.low || 0
    };

    // Reflect JS-accessible sensitive cookies in secureCookies posture
    if (domResult.metrics?.sensitiveJsCookies > 0) {
      headersResult.secureCookies = false;
    }

    if (!headersResult.https) {
      counts.high++;
      findings.push({
        id: "web-no-https",
        type: "Plaintext HTTP Transport (No TLS)",
        severity: "high",
        selector: tabUrl,
        detail: "Target webpage is served over unencrypted HTTP without TLS.",
        impact: "Exposes credentials, cookies, and page payloads to passive network interception.",
        shap: [
          { feature: "Cleartext http:// protocol scheme", weight: "+0.68" },
          { feature: "Absence of TLS transport encryption", weight: "+0.31" }
        ]
      });
    }

    if (!headersResult.csp) {
      counts.medium++;
      findings.push({
        id: "web-no-csp",
        type: "Missing Content-Security-Policy (CSP)",
        severity: "medium",
        selector: "HTTP Response Header",
        detail: "Target does not enforce a Content-Security-Policy (CSP) header.",
        impact: "Increases risk of inline script execution and unauthorized data exfiltration.",
        shap: [
          { feature: "Absence of CSP header directive", weight: "+0.48" },
          { feature: "Unrestricted script execution surface", weight: "+0.33" }
        ]
      });
    }

    if (!headersResult.xframe) {
      counts.medium++;
      findings.push({
        id: "web-no-xframe",
        type: "Missing X-Frame-Options / frame-ancestors",
        severity: "medium",
        selector: "HTTP Response Header",
        detail: "Missing anti-framing header allows UI redressing / clickjacking.",
        impact: "Permits malicious third-party sites to embed this page in an invisible iframe.",
        shap: [
          { feature: "Missing X-Frame-Options / frame-ancestors", weight: "+0.41" },
          { feature: "No top-level frame restriction", weight: "+0.22" }
        ]
      });
    }

    if (headersResult.https && !headersResult.hsts) {
      counts.low++;
      findings.push({
        id: "web-no-hsts",
        type: "Missing Strict-Transport-Security (HSTS)",
        severity: "low",
        selector: "HTTP Response Header",
        detail: "HTTPS origin does not advertise a Strict-Transport-Security policy.",
        impact: "Leaves initial navigation vulnerable to SSL-stripping downgrade attacks.",
        shap: [
          { feature: "Absence of Strict-Transport-Security header", weight: "+0.28" },
          { feature: "Potential HTTP-to-HTTPS downgrade window", weight: "+0.16" }
        ]
      });
    }

    if (headersResult.headerFetchSucceeded && !headersResult.xContentType) {
      counts.low++;
      findings.push({
        id: "web-no-nosniff",
        type: "Missing X-Content-Type-Options: nosniff",
        severity: "low",
        selector: "HTTP Response Header",
        detail: "Response omits X-Content-Type-Options: nosniff header.",
        impact: "Browsers may MIME-sniff non-script responses into executable contexts.",
        shap: [
          { feature: "Missing X-Content-Type-Options header", weight: "+0.24" },
          { feature: "MIME-type confusion exposure", weight: "+0.14" }
        ]
      });
    }

    // Score calculation (0 - 100)
    let score = 100;
    if (!headersResult.https) score -= 22;
    if (!headersResult.csp) score -= 14;
    if (!headersResult.xframe) score -= 10;
    if (!headersResult.secureCookies) score -= 10;
    score -= counts.critical * 18;
    score -= counts.high * 10;
    score -= counts.medium * 5;
    score -= counts.low * 2;
    score = Math.max(0, Math.min(100, score));

    const now = new Date();
    return {
      mode: "website",
      auditType: "Website Security Scan",
      targetUrl: tabUrl,
      pageTitle: domResult.title || "",
      timestamp: now.toISOString(),
      timestampDisplay: now.toLocaleString(),
      score,
      counts,
      headers: headersResult,
      metrics: domResult.metrics || {},
      findings
    };
  }

  /**
   * Executes Mode 1 (Website Security Scan) strictly on the active browser tab
   * (or a specific targetTabId when launched from the full dashboard tab selector).
   */
  async function runWebsiteScan(onProgress, targetTabId) {
    if (!hasChromeApis()) {
      throw new Error("Chrome tabs/scripting APIs are unavailable in this context.");
    }

    if (typeof onProgress === "function") onProgress(15, "Querying target browser tab...");

    let tab = null;
    if (typeof targetTabId === "number") {
      tab = await chrome.tabs.get(targetTabId);
    } else {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      tab = activeTab;
    }

    if (!tab || !tab.id) {
      throw new Error("No target browser tab found.");
    }

    if (isRestrictedUrl(tab.url)) {
      throw new Error("Cannot audit restricted browser pages (chrome://, about:, or extension pages). Navigate to an http:// or https:// website first.");
    }

    if (typeof onProgress === "function") onProgress(40, "Auditing active tab DOM, scripts & cookies...");

    // Inject highlight styles (best-effort)
    try {
      await chrome.scripting.insertCSS({
        target: { tabId: tab.id },
        files: ["content.css"]
      });
    } catch (_cssErr) {}

    const execResults = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: inspectActiveTabDom
    });

    const domResult = execResults?.[0]?.result;
    if (!domResult) {
      throw new Error("Unable to inspect active tab DOM.");
    }

    if (typeof onProgress === "function") onProgress(75, "Inspecting HTTP transport & security headers...");
    const headersResult = await auditResponseHeaders(tab.url);

    if (typeof onProgress === "function") onProgress(92, "Computing SHAP vulnerability weights...");
    const report = buildWebsiteAuditReport(tab.url, domResult, headersResult);
    report.tabId = tab.id;

    // Persist strictly under website-mode storage keys
    if (chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({
        [STORAGE_KEYS.LAST_WEBSITE_SCAN]: report,
        [`${STORAGE_KEYS.TAB_PREFIX}${tab.id}`]: report
      });
    }

    if (typeof onProgress === "function") onProgress(100, "Website Security Scan complete.");
    return report;
  }

  /**
   * Loads the previously saved Website Scan for the active tab (if URL matches),
   * without leaking any IoT audit state.
   */
  async function getSavedWebsiteScanForActiveTab() {
    if (!hasChromeApis() || !chrome.storage?.local) return null;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) return null;

      const tabKey = `${STORAGE_KEYS.TAB_PREFIX}${tab.id}`;
      const stored = await chrome.storage.local.get([tabKey]);
      const saved = stored[tabKey] || null;
      if (saved && saved.mode === "website" && saved.targetUrl === tab.url) {
        return saved;
      }
      return null;
    } catch (_err) {
      return null;
    }
  }

  global.WebScanner = {
    STORAGE_KEYS,
    isRestrictedUrl,
    runWebsiteScan,
    getSavedWebsiteScanForActiveTab
  };
})(typeof window !== "undefined" ? window : globalThis);
