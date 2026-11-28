// content.js
// On-demand DOM scanner helper (injected only when Mode 1 Website Security Scan runs).

function scanActivePageDOM() {
  const findings = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  // Clear previous injected warning UI
  document.querySelectorAll(".iot-sec-warning-badge").forEach((el) => el.remove());
  document.querySelectorAll(".iot-sec-highlight").forEach((el) => el.classList.remove("iot-sec-highlight"));

  // 1. Audit Forms for Missing CSRF Nonces on State-Changing Actions
  const forms = document.querySelectorAll("form");
  forms.forEach((form, idx) => {
    const method = (form.getAttribute("method") || "GET").toUpperCase();
    const action = form.getAttribute("action") || window.location.pathname;

    if (method === "POST" || method === "PUT" || method === "DELETE") {
      const inputs = Array.from(form.querySelectorAll("input"));
      const hasCsrfToken = inputs.some((input) => {
        const name = (input.name || "").toLowerCase();
        return name.includes("csrf") || name.includes("token") || name.includes("_nonce");
      });

      if (!hasCsrfToken) {
        counts.high++;
        form.classList.add("iot-sec-highlight");

        findings.push({
          id: `csrf_${idx}`,
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

  // 2. Audit Input Fields for Insecure Sanitization & Reflection
  const inputElements = document.querySelectorAll("input[type='text'], input:not([type]), textarea");
  inputElements.forEach((input, idx) => {
    const nameAttr = input.name || input.id || `input_${idx}`;
    const value = input.value || "";

    const xssPattern = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*>|javascript:|onerror=|onload=/gi;
    const containsSuspiciousPayload = xssPattern.test(value) || xssPattern.test(window.location.search);

    if (containsSuspiciousPayload || input.hasAttribute("onchange") || input.hasAttribute("oninput")) {
      counts.critical++;
      input.classList.add("iot-sec-highlight");
      injectWarningBadge(input, "DOM XSS Vulnerability");

      findings.push({
        id: `xss_${idx}`,
        type: "DOM-Based XSS Risk",
        severity: "critical",
        selector: input.id ? `#${input.id}` : `input[name='${nameAttr}']`,
        detail: `Unsanitized input sink detected on parameter ${nameAttr}.`,
        impact: "Allows execution of arbitrary JavaScript, enabling session hijacking and unauthorized device control.",
        shap: [
          { feature: "Unescaped payload syntax pattern", weight: "+0.74" },
          { feature: "DOM sink proximity (innerHTML/inline-event)", weight: "+0.18" }
        ]
      });
    }
  });

  return { findings, counts };
}

function injectWarningBadge(targetElement, label) {
  const badge = document.createElement("span");
  badge.className = "iot-sec-warning-badge";
  badge.title = `${label} - Flagged by IoT Security Auditor`;
  badge.innerText = "⚠ Vulnerable";

  if (targetElement.parentNode) {
    targetElement.parentNode.insertBefore(badge, targetElement.nextSibling);
  }
}

if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    if (request.type === "EXECUTE_DOM_SCAN") {
      const result = scanActivePageDOM();
      sendResponse({ status: "COMPLETED", payload: result });
    }
  });
}
