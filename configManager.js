// configManager.js
// Dynamic Managing Website Switcher & Runtime Host Permission Manager (Manifest V3)

(function (global) {
  "use strict";

  const STORAGE_KEYS = {
    MANAGING_URL: "managingUrl",
    HEALTH_STATUS: "managingUrlStatus"
  };

  /**
   * Validates and normalizes a user-entered managing server URL.
   * Enforces http:// or https:// and strips trailing slashes.
   */
  function validateAndNormalizeUrl(rawInput) {
    if (typeof rawInput !== "string") {
      return { valid: false, error: "Please enter a valid server URL." };
    }

    const trimmed = rawInput.trim();
    if (!trimmed) {
      return { valid: false, error: "Server URL cannot be empty." };
    }

    if (!/^https?:\/\//i.test(trimmed)) {
      return {
        valid: false,
        error: "URL must start with http:// or https://"
      };
    }

    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch (_err) {
      return { valid: false, error: "Malformed URL. Example: https://iot.example.com:8080" };
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, error: "Only http:// and https:// protocols are supported." };
    }

    if (!parsed.hostname) {
      return { valid: false, error: "URL must include a valid hostname or IP." };
    }

    // Strip trailing slashes from path and remove query/hash for clean base URL
    const cleanPath = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
    const normalizedUrl = `${parsed.origin}${cleanPath}`;
    const originPattern = `${parsed.origin}/*`;

    return {
      valid: true,
      normalizedUrl,
      origin: parsed.origin,
      originPattern
    };
  }

  function hasChromeStorage() {
    return typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
  }

  function hasChromePermissions() {
    return typeof chrome !== "undefined" && chrome.permissions;
  }

  /**
   * Reads the persisted managingUrl from chrome.storage.local.
   */
  async function getManagingUrl() {
    if (!hasChromeStorage()) {
      return localStorage.getItem(STORAGE_KEYS.MANAGING_URL) || null;
    }
    const res = await chrome.storage.local.get([STORAGE_KEYS.MANAGING_URL]);
    return res[STORAGE_KEYS.MANAGING_URL] || null;
  }

  /**
   * Persists the normalized managingUrl to chrome.storage.local.
   */
  async function saveManagingUrl(normalizedUrl) {
    if (!hasChromeStorage()) {
      localStorage.setItem(STORAGE_KEYS.MANAGING_URL, normalizedUrl);
      return;
    }
    await chrome.storage.local.set({ [STORAGE_KEYS.MANAGING_URL]: normalizedUrl });
  }

  /**
   * Clears the persisted managingUrl and cached health status.
   */
  async function clearManagingUrl() {
    if (!hasChromeStorage()) {
      localStorage.removeItem(STORAGE_KEYS.MANAGING_URL);
      localStorage.removeItem(STORAGE_KEYS.HEALTH_STATUS);
      return;
    }
    await chrome.storage.local.remove([
      STORAGE_KEYS.MANAGING_URL,
      STORAGE_KEYS.HEALTH_STATUS
    ]);
  }

  /**
   * Checks whether runtime host permission has already been granted for the URL's origin.
   */
  async function hasHostPermission(url) {
    if (!url || !hasChromePermissions()) return false;
    try {
      const originPattern = `${new URL(url).origin}/*`;
      return await chrome.permissions.contains({ origins: [originPattern] });
    } catch (_err) {
      return false;
    }
  }

  /**
   * Requests runtime host access via chrome.permissions.request({ origins: [newUrl + "/*"] }).
   * Must be invoked directly within a user gesture handler.
   */
  async function requestHostPermission(originPattern) {
    if (!hasChromePermissions()) return true;
    return await chrome.permissions.request({ origins: [originPattern] });
  }

  /**
   * Performs a lightweight fetch() health check against the configured managingUrl.
   */
  async function checkServerHealth(managingUrl) {
    if (!managingUrl) {
      return {
        status: "not_configured",
        reachable: false,
        label: "Not Configured",
        message: "Configure an IoT Managing Website URL to connect."
      };
    }

    const validation = validateAndNormalizeUrl(managingUrl);
    if (!validation.valid) {
      return {
        status: "disconnected",
        reachable: false,
        label: "Disconnected",
        message: validation.error
      };
    }

    const permitted = await hasHostPermission(validation.normalizedUrl);
    if (!permitted) {
      return {
        status: "disconnected",
        reachable: false,
        permissionMissing: true,
        label: "Disconnected",
        message: "Host permission not granted for this server."
      };
    }

    const startTime = performance.now();
    const probeTarget = `${validation.normalizedUrl}/`;

    try {
      let response;
      try {
        response = await fetch(probeTarget, {
          method: "HEAD",
          cache: "no-store",
          signal: AbortSignal.timeout(4000)
        });
      } catch (headErr) {
        // Fallback to lightweight GET if HEAD is blocked or aborted by proxy/server
        response = await fetch(probeTarget, {
          method: "GET",
          cache: "no-store",
          signal: AbortSignal.timeout(4000)
        });
      }

      // Some servers reject HEAD with 405 Method Not Allowed; retry with GET
      if (response && response.status === 405) {
        response = await fetch(probeTarget, {
          method: "GET",
          cache: "no-store",
          signal: AbortSignal.timeout(4000)
        });
      }

      const latencyMs = Math.round(performance.now() - startTime);
      const statusResult = {
        status: "connected",
        reachable: true,
        label: "Connected",
        httpStatus: response.status,
        latencyMs,
        checkedAt: Date.now(),
        message: `Reachable (HTTP ${response.status}, ${latencyMs}ms)`
      };

      if (hasChromeStorage()) {
        await chrome.storage.local.set({ [STORAGE_KEYS.HEALTH_STATUS]: statusResult });
      }
      return statusResult;
    } catch (err) {
      const statusResult = {
        status: "disconnected",
        reachable: false,
        label: "Disconnected",
        checkedAt: Date.now(),
        message: err?.name === "TimeoutError"
          ? "Connection timed out after 4s"
          : `Unreachable (${err?.message || "Network error"})`
      };

      if (hasChromeStorage()) {
        await chrome.storage.local.set({ [STORAGE_KEYS.HEALTH_STATUS]: statusResult });
      }
      return statusResult;
    }
  }

  /**
   * Full user-triggered workflow:
   * 1) Validate & normalize URL
   * 2) Request runtime host permission immediately (preserving user gesture)
   * 3) Persist URL in chrome.storage.local under `managingUrl`
   * 4) Run lightweight health check and return status
   */
  async function setAndConnectManagingUrl(rawInput) {
    const validation = validateAndNormalizeUrl(rawInput);
    if (!validation.valid) {
      return {
        ok: false,
        error: validation.error,
        health: {
          status: "disconnected",
          reachable: false,
          label: "Disconnected",
          message: validation.error
        }
      };
    }

    const granted = await requestHostPermission(validation.originPattern);
    if (!granted) {
      return {
        ok: false,
        error: `Host permission denied for ${validation.origin}. Extension needs access to audit devices on this server.`,
        health: {
          status: "disconnected",
          reachable: false,
          permissionMissing: true,
          label: "Disconnected",
          message: "Host permission denied by user."
        }
      };
    }

    await saveManagingUrl(validation.normalizedUrl);
    const health = await checkServerHealth(validation.normalizedUrl);

    return {
      ok: true,
      managingUrl: validation.normalizedUrl,
      health
    };
  }

  global.ConfigManager = {
    STORAGE_KEYS,
    validateAndNormalizeUrl,
    getManagingUrl,
    saveManagingUrl,
    clearManagingUrl,
    hasHostPermission,
    requestHostPermission,
    checkServerHealth,
    setAndConnectManagingUrl
  };
})(typeof window !== "undefined" ? window : globalThis);
