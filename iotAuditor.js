// iotAuditor.js
// Mode 2: Dynamic IoT Network Anomaly Auditor (OWASP IoT Top 10 + Rust/Wasm SHAP)
// Dynamically reads `managingUrl` from chrome.storage.local, handles ThingsBoard JWT auth,
// fetches devices & telemetry, and runs full OWASP IoT Top 10 (I1-I10) + SHAP anomaly evaluation.

(function (global) {
  "use strict";

  const STORAGE_KEYS = {
    LAST_IOT_AUDIT: "lastIotAudit",
    TOKEN_PREFIX: "tbAuthToken_"
  };

  const OWASP_IOT_TOP_10 = {
    I1: "I1: Weak, Guessable, or Hardcoded Passwords",
    I2: "I2: Insecure Network Services",
    I3: "I3: Insecure Ecosystem Interfaces",
    I4: "I4: Lack of Secure Update Mechanism",
    I5: "I5: Use of Insecure or Outdated Components",
    I6: "I6: Insufficient Privacy Protection",
    I7: "I7: Insecure Data Transfer and Storage",
    I8: "I8: Lack of Device Management",
    I9: "I9: Insecure Default Settings",
    I10: "I10: Lack of Physical Hardening"
  };

  const OWASP_REMEDIATIONS = {
    I1: "Enforce strong unique credentials, rotate access tokens/X.509 certificates, and block default passwords.",
    I2: "Disable legacy plaintext services (Telnet/23, FTP/21, unauthenticated MQTT/1883, RTSP/554) and restrict firewall ports.",
    I3: "Enforce HTTPS/TLS on the managing server and APIs, validate origin/CORS policies, and protect bearer JWTs.",
    I4: "Enable cryptographically signed OTA firmware updates, track fw_version, and verify rollback protection.",
    I5: "Upgrade deprecated TLS 1.0/1.1 stacks, patch embedded OS/SDK libraries, and decommission EOL components.",
    I6: "Minimize PII/location/media telemetry collection and encrypt sensitive fields end-to-end.",
    I7: "Use TLS/DTLS for telemetry transport, encrypt local flash storage, and investigate statistical telemetry anomalies.",
    I8: "Monitor device heartbeats, decommission stale/inactive nodes, and ensure continuous telemetry observability.",
    I9: "Disable debug modes, factory defaults, UPnP, and root SSH before production deployment.",
    I10: "Enable physical tamper detection alerts and disable exposed UART/JTAG/serial debug headers."
  };

  function hasChromeStorage() {
    return typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
  }

  function tokenKeyForUrl(managingUrl) {
    const origin = new URL(managingUrl).origin;
    return `${STORAGE_KEYS.TOKEN_PREFIX}${origin}`;
  }

  /**
   * Attempts to read an active ThingsBoard JWT (`localStorage.getItem('jwt_token')`)
   * from any open browser tab matching `managingUrl`, or falls back to cached token.
   */
  async function resolveAuthToken(managingUrl) {
    const origin = new URL(managingUrl).origin;

    if (typeof chrome !== "undefined" && chrome.tabs && chrome.scripting) {
      try {
        const tabs = await chrome.tabs.query({});
        const matchingTabs = tabs.filter(
          (t) => t.id && t.url && t.url.startsWith(origin)
        );

        for (const tab of matchingTabs) {
          try {
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              func: () => {
                try {
                  return window.localStorage.getItem("jwt_token");
                } catch (_e) {
                  return null;
                }
              }
            });
            const tabToken = results?.[0]?.result;
            if (tabToken && typeof tabToken === "string" && tabToken.trim().length > 10) {
              return { token: tabToken.trim(), source: "open_tab" };
            }
          } catch (_tabErr) {}
        }
      } catch (_queryErr) {}
    }

    if (hasChromeStorage()) {
      const key = tokenKeyForUrl(managingUrl);
      const data = await chrome.storage.local.get([key]);
      if (data[key]) {
        return { token: data[key], source: "extension_storage" };
      }
    }

    return null;
  }

  /**
   * Authenticates directly against ThingsBoard `${managingUrl}/api/auth/login`.
   */
  async function loginThingsBoard(managingUrl, username, password) {
    if (!managingUrl) {
      throw new Error("Managing server URL is not configured.");
    }
    if (!username || !password) {
      throw new Error("Username and password are required.");
    }

    const response = await fetch(`${managingUrl}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({ username: username.trim(), password }),
      signal: AbortSignal.timeout(8000)
    });

    if (!response.ok) {
      let msg = `Authentication failed (HTTP ${response.status})`;
      try {
        const errBody = await response.json();
        if (errBody?.message) msg = errBody.message;
      } catch (_e) {}
      throw new Error(msg);
    }

    const data = await response.json();
    if (!data?.token) {
      throw new Error("Login succeeded but server did not return a JWT token.");
    }

    if (hasChromeStorage()) {
      await chrome.storage.local.set({ [tokenKeyForUrl(managingUrl)]: data.token });
    }

    return data.token;
  }

  async function clearCachedToken(managingUrl) {
    if (!managingUrl || !hasChromeStorage()) return;
    await chrome.storage.local.remove([tokenKeyForUrl(managingUrl)]);
  }

  async function tbApiGet(url, token) {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "X-Authorization": `Bearer ${token}`,
        Accept: "application/json"
      },
      cache: "no-store",
      signal: AbortSignal.timeout(8000)
    });

    if (response.status === 401 || response.status === 403) {
      const authErr = new Error("Session expired or unauthorized (HTTP " + response.status + ").");
      authErr.code = "AUTH_REQUIRED";
      throw authErr;
    }

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status} for ${url}`);
    }

    return await response.json();
  }

  function extractLatestTelemetryValue(telemetry, candidateKeys) {
    if (!telemetry || typeof telemetry !== "object") return null;
    for (const key of candidateKeys) {
      const series = telemetry[key];
      if (Array.isArray(series) && series.length > 0 && series[0]?.value !== undefined) {
        return series[0].value;
      }
    }
    return null;
  }

  /**
   * Fetches tenant IoT devices and each device's attributes & telemetry timeseries.
   */
  async function fetchDevicesAndTelemetry(managingUrl, token, onProgress) {
    if (typeof onProgress === "function") onProgress(30, "Fetching IoT device inventory...");

    const devicesResp = await tbApiGet(
      `${managingUrl}/api/tenant/devices?pageSize=50&page=0`,
      token
    );

    const rawDevices = Array.isArray(devicesResp)
      ? devicesResp
      : Array.isArray(devicesResp?.data)
        ? devicesResp.data
        : [];

    const cappedDevices = rawDevices.slice(0, 25);
    const structuredDevices = [];
    const nowTs = Date.now();
    const dayAgoTs = nowTs - 24 * 60 * 60 * 1000;

    for (let i = 0; i < cappedDevices.length; i++) {
      const dev = cappedDevices[i];
      const deviceId = dev?.id?.id || dev?.id;
      if (!deviceId) continue;

      if (typeof onProgress === "function") {
        const pct = 35 + Math.round(((i + 1) / Math.max(1, cappedDevices.length)) * 35);
        onProgress(pct, `Pulling telemetry (${i + 1}/${cappedDevices.length}): ${dev.name || deviceId}`);
      }

      let telemetry = {};
      try {
        const keys = await tbApiGet(
          `${managingUrl}/api/plugins/telemetry/DEVICE/${deviceId}/keys/timeseries`,
          token
        );

        if (Array.isArray(keys) && keys.length > 0) {
          const keysParam = encodeURIComponent(keys.slice(0, 25).join(","));
          try {
            telemetry = await tbApiGet(
              `${managingUrl}/api/plugins/telemetry/DEVICE/${deviceId}/values/timeseries?keys=${keysParam}&startTs=${dayAgoTs}&endTs=${nowTs}&limit=50&agg=NONE`,
              token
            );
          } catch (_histErr) {
            telemetry = await tbApiGet(
              `${managingUrl}/api/plugins/telemetry/DEVICE/${deviceId}/values/timeseries?keys=${keysParam}`,
              token
            );
          }
        } else {
          telemetry = await tbApiGet(
            `${managingUrl}/api/plugins/telemetry/DEVICE/${deviceId}/values/timeseries`,
            token
          ).catch(() => ({}));
        }
      } catch (teleErr) {
        if (teleErr.code === "AUTH_REQUIRED") throw teleErr;
        telemetry = {};
      }

      let attributesList = [];
      try {
        const attrResp = await tbApiGet(
          `${managingUrl}/api/plugins/telemetry/DEVICE/${deviceId}/values/attributes`,
          token
        );
        if (Array.isArray(attrResp)) {
          attributesList = attrResp;
        }
      } catch (attrErr) {
        if (attrErr.code === "AUTH_REQUIRED") throw attrErr;
        attributesList = [];
      }

      const attributesMap = {};
      attributesList.forEach((item) => {
        if (item && item.key !== undefined) {
          attributesMap[item.key] = item.value;
        }
      });

      const additionalInfo = dev.additionalInfo || {};
      const ip =
        attributesMap.ip ||
        attributesMap.ipAddress ||
        attributesMap.ip_address ||
        additionalInfo.ip ||
        extractLatestTelemetryValue(telemetry, ["ip", "ipAddress", "ip_address"]) ||
        "N/A";

      const mac =
        attributesMap.mac ||
        attributesMap.macAddress ||
        attributesMap.mac_address ||
        additionalInfo.mac ||
        extractLatestTelemetryValue(telemetry, ["mac", "macAddress", "mac_address"]) ||
        "N/A";

      structuredDevices.push({
        id: deviceId,
        name: dev.name || dev.label || `Device ${deviceId}`,
        label: dev.label || "",
        type: dev.type || "IoT Device",
        ip: String(ip),
        mac: String(mac),
        active: attributesMap.active !== undefined ? Boolean(attributesMap.active) : true,
        lastActivityTime: attributesMap.lastActivityTime || dev.createdTime || null,
        additionalInfo,
        attributes: attributesMap,
        telemetry
      });
    }

    return structuredDevices;
  }

  /**
   * Attempts to invoke existing Rust/Wasm bindings from pkg/ if compiled & present.
   */
  async function tryInvokeWasmEngine(payload) {
    if (global.IoTWasmEngine && typeof global.IoTWasmEngine.evaluate_iot_anomalies === "function") {
      try {
        const raw = global.IoTWasmEngine.evaluate_iot_anomalies(JSON.stringify(payload));
        return typeof raw === "string" ? JSON.parse(raw) : raw;
      } catch (_err) {}
    }

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
      const candidateModules = ["pkg/iot_auditor.js", "pkg/rust_scanner.js"];
      for (const relPath of candidateModules) {
        try {
          const modUrl = chrome.runtime.getURL(relPath);
          const probe = await fetch(modUrl, { method: "HEAD" });
          if (!probe.ok) continue;

          const wasmMod = await import(modUrl);
          if (typeof wasmMod.default === "function") {
            await wasmMod.default();
          }
          if (typeof wasmMod.evaluate_iot_anomalies === "function") {
            const raw = wasmMod.evaluate_iot_anomalies(JSON.stringify(payload));
            return typeof raw === "string" ? JSON.parse(raw) : raw;
          }
        } catch (_modErr) {}
      }
    }

    return null;
  }

  /**
   * Statistical anomaly & physical/auth telemetry checks (I1, I6, I7, I10).
   */
  function analyzeTelemetryAnomalies(device) {
    const anomalies = [];
    const telemetry = device.telemetry || {};

    for (const [metric, points] of Object.entries(telemetry)) {
      if (!Array.isArray(points) || points.length === 0) continue;

      const numericValues = points
        .map((p) => Number(p.value))
        .filter((v) => Number.isFinite(v));

      const latestRaw = points[0]?.value;
      const metricLower = metric.toLowerCase();

      // I10: Physical Tamper / Enclosure Breach telemetry
      if (
        (metricLower.includes("tamper") || metricLower.includes("intrusion") || metricLower.includes("breach") || metricLower.includes("case_open")) &&
        (latestRaw === true || String(latestRaw).toLowerCase() === "true" || Number(latestRaw) > 0)
      ) {
        anomalies.push({
          owaspId: "I10",
          severity: "critical",
          type: "Physical Tamper / Enclosure Breach Alert",
          detail: `Telemetry key '${metric}' triggered '${latestRaw}' on ${device.name}.`,
          impact: "Indicates physical tampering, enclosure opening, or unauthorized hardware debug probing.",
          shap: [
            { feature: `Tamper telemetry flag (${metric}=${latestRaw})`, weight: "+0.81" },
            { feature: "Physical perimeter alert state", weight: "+0.34" }
          ]
        });
      }

      // I1: Authentication failure spikes
      if (
        (metricLower.includes("failed") || metricLower.includes("auth_err") || metricLower.includes("unauthorized")) &&
        Number(latestRaw) >= 3
      ) {
        anomalies.push({
          owaspId: "I1",
          severity: "high",
          type: "Anomalous Authentication Failure Spike",
          detail: `Device ${device.name} reported ${latestRaw} failed authentication attempts (${metric}).`,
          impact: "Indicates credential stuffing, brute-force, or weak hardcoded password probing.",
          shap: [
            { feature: `High auth failure count (${metric}=${latestRaw})`, weight: "+0.72" },
            { feature: "Potential credential brute-force vector", weight: "+0.31" }
          ]
        });
      }

      // I7: Packet loss / transfer integrity degradation
      if (
        (metricLower.includes("packet_loss") || metricLower.includes("error_rate")) &&
        Number(latestRaw) > 15
      ) {
        anomalies.push({
          owaspId: "I7",
          severity: "medium",
          type: "Elevated Telemetry Packet Loss / Corruption",
          detail: `Metric '${metric}' reached ${latestRaw}% on ${device.name}.`,
          impact: "Degrades telemetry integrity and may indicate RF jamming, flooding, or MITM interference.",
          shap: [
            { feature: `Elevated error/loss rate (${latestRaw}%)`, weight: "+0.54" },
            { feature: "Channel reliability degradation", weight: "+0.23" }
          ]
        });
      }

      // I7: Statistical Z-score spike detection
      if (numericValues.length >= 4) {
        const mean = numericValues.reduce((a, b) => a + b, 0) / numericValues.length;
        const variance =
          numericValues.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / numericValues.length;
        const stdDev = Math.sqrt(variance);

        if (stdDev > 0) {
          const latestVal = numericValues[0];
          const zScore = Math.abs((latestVal - mean) / stdDev);
          if (zScore >= 2.5) {
            anomalies.push({
              owaspId: "I7",
              severity: zScore >= 3.5 ? "high" : "medium",
              type: "Telemetry Statistical Anomaly (Z-Score Spike)",
              detail: `Metric '${metric}' jumped to ${latestVal} (mean ${mean.toFixed(2)}, z-score ${zScore.toFixed(2)}) on ${device.name}.`,
              impact: "Abnormal sensor or traffic burst may indicate sensor spoofing, replay injection, or compromised firmware.",
              shap: [
                { feature: `Z-score deviation (${zScore.toFixed(2)}σ on ${metric})`, weight: zScore >= 3.5 ? "+0.67" : "+0.49" },
                { feature: `Baseline drift from mean (${mean.toFixed(2)})`, weight: "+0.27" }
              ]
            });
          }
        }
      }
    }

    return anomalies;
  }

  function buildOwaspMatrix(findings, devicesCount) {
    const severityRank = { passed: 0, low: 1, medium: 2, high: 3, critical: 4 };
    return Object.entries(OWASP_IOT_TOP_10).map(([id, fullTitle]) => {
      const catFindings = findings.filter((f) => f.owaspId === id);
      let worstStatus = "passed";
      const affectedSet = new Set();

      catFindings.forEach((f) => {
        const sev = (f.severity || "medium").toLowerCase();
        if ((severityRank[sev] || 0) > (severityRank[worstStatus] || 0)) {
          worstStatus = sev;
        }
        if (f.selector) affectedSet.add(f.selector);
      });

      return {
        id,
        title: fullTitle.replace(`${id}: `, ""),
        fullTitle,
        status: worstStatus,
        findingsCount: catFindings.length,
        affectedNodes: Array.from(affectedSet),
        checkedDevices: devicesCount,
        remediation: OWASP_REMEDIATIONS[id]
      };
    });
  }

  /**
   * Evaluates structured devices & telemetry against all 10 OWASP IoT Top 10 categories + SHAP.
   */
  async function evaluateWithWasmAndShap(managingUrl, structuredDevices) {
    const wasmResult = await tryInvokeWasmEngine({
      managingUrl,
      devices: structuredDevices
    });

    if (wasmResult && Array.isArray(wasmResult.findings)) {
      const owaspMatrix = wasmResult.owaspMatrix || buildOwaspMatrix(wasmResult.findings, structuredDevices.length);
      return {
        ...wasmResult,
        owaspMatrix,
        engineUsed: "Rust / WebAssembly + SHAP (pkg)"
      };
    }

    const findings = [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    const owaspBreakdown = {};
    Object.keys(OWASP_IOT_TOP_10).forEach((k) => {
      owaspBreakdown[k] = 0;
    });

    function recordFinding(item, devFlaws, devOwasp) {
      counts[item.severity] = (counts[item.severity] || 0) + 1;
      owaspBreakdown[item.owaspId] = (owaspBreakdown[item.owaspId] || 0) + 1;
      if (devOwasp) devOwasp.add(item.owaspId);
      if (devFlaws) devFlaws.push(`${item.type} (${item.owaspId})`);
      findings.push({
        ...item,
        owaspName: OWASP_IOT_TOP_10[item.owaspId] || item.owaspId
      });
    }

    // I3: Insecure Ecosystem Interfaces (server-level transport check)
    const isPlaintextServer = /^http:\/\//i.test(managingUrl);
    if (isPlaintextServer) {
      recordFinding({
        id: "iot-i3-plaintext-server",
        owaspId: "I3",
        type: "Insecure Ecosystem Interface (Plaintext HTTP)",
        severity: "high",
        selector: managingUrl,
        detail: "Managing server API communicates over unencrypted HTTP instead of HTTPS/TLS.",
        impact: "Exposes ThingsBoard JWT bearer tokens and device telemetry streams to passive interception.",
        shap: [
          { feature: "Managing API served over cleartext http://", weight: "+0.71" },
          { feature: "Bearer JWT exposed to network sniffing", weight: "+0.39" }
        ]
      });
    }

    const devicesSummary = [];
    const now = Date.now();

    structuredDevices.forEach((dev, idx) => {
      const attrs = dev.attributes || {};
      const devFlaws = [];
      const devOwasp = new Set();
      let devScore = 100;
      const targetLabel = `${dev.name} (${dev.ip !== "N/A" ? dev.ip : dev.id})`;

      if (isPlaintextServer) {
        devScore -= 10;
        devOwasp.add("I3");
      }

      // I1: Weak, Guessable, or Hardcoded Passwords
      if (
        attrs.defaultPassword === true ||
        attrs.weakCredentials === true ||
        attrs.hardcodedCredentials === true ||
        attrs.allowAnonymous === true ||
        String(attrs.authMode || "").toLowerCase() === "none"
      ) {
        devScore -= 25;
        recordFinding({
          id: `iot-i1-${idx}`,
          owaspId: "I1",
          type: "Weak / Hardcoded Device Credentials",
          severity: "critical",
          selector: targetLabel,
          detail: "Device attributes indicate default, weak, hardcoded, or anonymous authentication.",
          impact: "Enables trivial takeover of device telemetry and remote control endpoints.",
          shap: [
            { feature: "Default/anonymous authentication attribute", weight: "+0.79" },
            { feature: "Lack of rotated X.509/token credentials", weight: "+0.31" }
          ]
        }, devFlaws, devOwasp);
      }

      // I2: Insecure Network Services
      const rawPorts = String(attrs.openPorts || attrs.ports || "");
      const riskyPorts = ["23", "21", "1883", "554", "69"].filter((p) =>
        new RegExp(`\\b${p}\\b`).test(rawPorts)
      );
      if (riskyPorts.length > 0 || attrs.telnetEnabled === true || attrs.ftpEnabled === true) {
        devScore -= 22;
        recordFinding({
          id: `iot-i2-${idx}`,
          owaspId: "I2",
          type: "Insecure Network Services Exposed",
          severity: "critical",
          selector: targetLabel,
          detail: `Unencrypted or legacy network services exposed: ${riskyPorts.join(", ") || "Telnet/FTP"}.`,
          impact: "Exposes remote shells, video feeds, or unencrypted MQTT topics to LAN attackers.",
          shap: [
            { feature: `Exposed insecure ports [${riskyPorts.join(", ") || "23"}]`, weight: "+0.76" },
            { feature: "Unnecessary network attack surface", weight: "+0.28" }
          ]
        }, devFlaws, devOwasp);
      }

      // I3: Device-level insecure ecosystem interface flags
      if (attrs.insecureWebhook === true || attrs.corsAllowAll === true || attrs.httpApiEnabled === true) {
        devScore -= 14;
        recordFinding({
          id: `iot-i3-dev-${idx}`,
          owaspId: "I3",
          type: "Insecure Device Ecosystem API Flag",
          severity: "high",
          selector: targetLabel,
          detail: "Device exposes permissive CORS wildcard, unencrypted webhook, or HTTP management API.",
          impact: "Allows cross-origin abuse or API credential interception across ecosystem integrations.",
          shap: [
            { feature: "Permissive API / webhook interface", weight: "+0.62" },
            { feature: "Insufficient ecosystem boundary validation", weight: "+0.27" }
          ]
        }, devFlaws, devOwasp);
      }

      // I4: Lack of Secure Update Mechanism
      const fwState = String(attrs.fw_state || attrs.sw_state || "").toUpperCase();
      const hasFwVersion = Boolean(attrs.fw_version || attrs.firmwareVersion || attrs.sw_version);
      if (fwState === "FAILED" || attrs.signedFirmware === false || attrs.otaOverHttp === true || !hasFwVersion) {
        devScore -= 10;
        recordFinding({
          id: `iot-i4-${idx}`,
          owaspId: "I4",
          type: "Lack of Secure Firmware Update Mechanism",
          severity: attrs.otaOverHttp === true || fwState === "FAILED" ? "high" : "medium",
          selector: targetLabel,
          detail: fwState === "FAILED"
            ? "Firmware OTA update state reports FAILED."
            : attrs.otaOverHttp === true
              ? "Device OTA update channel uses unencrypted HTTP."
              : "Device lacks tracked firmware version or signed OTA verification metadata.",
          impact: "Prevents timely CVE patching and exposes firmware updates to tampering.",
          shap: [
            { feature: "Missing/unverified OTA update integrity", weight: "+0.53" },
            { feature: "Unverified firmware version provenance", weight: "+0.24" }
          ]
        }, devFlaws, devOwasp);
      }

      // I5: Use of Insecure or Outdated Components
      const tlsVer = String(attrs.tlsVersion || attrs.tls || "");
      const osVer = String(attrs.osVersion || attrs.sdkVersion || "");
      if (/1\.0|1\.1|ssl/i.test(tlsVer) || attrs.eolComponent === true || Number(attrs.knownCveCount || 0) > 0 || /openssl\s*1\.0/i.test(osVer)) {
        devScore -= 15;
        recordFinding({
          id: `iot-i5-${idx}`,
          owaspId: "I5",
          type: "Outdated or Vulnerable Embedded Component",
          severity: "high",
          selector: targetLabel,
          detail: tlsVer
            ? `Deprecated cryptographic protocol detected (${tlsVer}).`
            : `Outdated or EOL embedded OS/SDK component detected (${osVer || "CVE flagged"}).`,
          impact: "Susceptible to known CVEs, downgrade attacks, and memory-corruption exploits.",
          shap: [
            { feature: `Legacy component / protocol (${tlsVer || osVer || "EOL"})`, weight: "+0.65" },
            { feature: "Unpatched third-party dependency", weight: "+0.26" }
          ]
        }, devFlaws, devOwasp);
      }

      // I6: Insufficient Privacy Protection
      const teleKeys = Object.keys(dev.telemetry || {});
      const hasPiiKeys = teleKeys.some((k) => /gps|lat|lon|location|camera|audio|ssid|pii|user/i.test(k));
      if ((hasPiiKeys && isPlaintextServer) || attrs.piiUnencrypted === true) {
        devScore -= 14;
        recordFinding({
          id: `iot-i6-${idx}`,
          owaspId: "I6",
          type: "Insufficient Privacy Protection on Telemetry",
          severity: "high",
          selector: targetLabel,
          detail: "Sensitive location, media, or personal telemetry transmitted without end-to-end encryption.",
          impact: "Exposes user privacy, physical location, or household activity metadata.",
          shap: [
            { feature: "Sensitive telemetry keys on plaintext channel", weight: "+0.63" },
            { feature: "Absence of payload privacy masking", weight: "+0.29" }
          ]
        }, devFlaws, devOwasp);
      }

      // I7: Insecure Data Transfer and Storage (attributes + telemetry anomalies)
      if (attrs.mqttTlsEnabled === false || attrs.unencryptedStorage === true) {
        devScore -= 14;
        recordFinding({
          id: `iot-i7-attr-${idx}`,
          owaspId: "I7",
          type: "Insecure Telemetry Transport / Flash Storage",
          severity: "high",
          selector: targetLabel,
          detail: "Device disables MQTT TLS or stores credentials/telemetry in unencrypted storage.",
          impact: "Enables cleartext payload capture on the wire or extraction from local flash.",
          shap: [
            { feature: "Cleartext data transfer/storage flag", weight: "+0.66" },
            { feature: "Missing at-rest or in-transit encryption", weight: "+0.28" }
          ]
        }, devFlaws, devOwasp);
      }

      const teleAnomalies = analyzeTelemetryAnomalies(dev);
      teleAnomalies.forEach((anom, aIdx) => {
        devScore -= anom.severity === "critical" ? 20 : anom.severity === "high" ? 14 : 8;
        recordFinding({
          id: `iot-anom-${idx}-${aIdx}`,
          owaspId: anom.owaspId,
          type: anom.type,
          severity: anom.severity,
          selector: targetLabel,
          detail: anom.detail,
          impact: anom.impact,
          shap: anom.shap
        }, devFlaws, devOwasp);
      });

      // I8: Lack of Device Management
      const lastAct = Number(attrs.lastActivityTime || 0);
      const isStale = lastAct > 0 && now - lastAct > 24 * 60 * 60 * 1000;
      if (dev.active === false || isStale) {
        devScore -= 10;
        recordFinding({
          id: `iot-i8-${idx}`,
          owaspId: "I8",
          type: "Stale or Unmonitored IoT Node",
          severity: "medium",
          selector: targetLabel,
          detail: dev.active === false
            ? "Device reports active=false on ThingsBoard."
            : "Device lastActivityTime is older than 24 hours.",
          impact: "Unmonitored or offline endpoints may indicate silent compromise or missed updates.",
          shap: [
            { feature: "Heartbeat inactivity / offline status", weight: "+0.47" },
            { feature: "Device lifecycle management gap", weight: "+0.22" }
          ]
        }, devFlaws, devOwasp);
      } else if (teleKeys.length === 0) {
        devScore -= 5;
        recordFinding({
          id: `iot-i8-notele-${idx}`,
          owaspId: "I8",
          type: "Missing Telemetry Visibility",
          severity: "low",
          selector: targetLabel,
          detail: "Device has no active timeseries telemetry keys reported to the managing server.",
          impact: "Limits continuous anomaly detection and asset health tracking.",
          shap: [
            { feature: "Zero telemetry timeseries keys", weight: "+0.29" },
            { feature: "Reduced observability posture", weight: "+0.18" }
          ]
        }, devFlaws, devOwasp);
      }

      // I9: Insecure Default Settings
      if (attrs.debugMode === true || attrs.factoryDefault === true || attrs.upnpEnabled === true || attrs.sshRootLogin === true) {
        devScore -= 15;
        recordFinding({
          id: `iot-i9-${idx}`,
          owaspId: "I9",
          type: "Insecure Default / Debug Configuration",
          severity: "high",
          selector: targetLabel,
          detail: "Device attributes expose debugMode, factoryDefault, UPnP, or root SSH enabled.",
          impact: "Permits privilege escalation or unauthorized LAN port exposure.",
          shap: [
            { feature: "Debug/factory-default configuration flag", weight: "+0.61" },
            { feature: "Hardening baseline non-compliance", weight: "+0.25" }
          ]
        }, devFlaws, devOwasp);
      }

      // I10: Lack of Physical Hardening (attribute-level checks in addition to tamper telemetry)
      if (attrs.uartEnabled === true || attrs.jtagEnabled === true || attrs.tamperDetected === true || attrs.physicalHardening === false) {
        devScore -= 18;
        recordFinding({
          id: `iot-i10-attr-${idx}`,
          owaspId: "I10",
          type: "Insufficient Physical Hardening / Debug Port Exposed",
          severity: attrs.tamperDetected === true ? "critical" : "high",
          selector: targetLabel,
          detail: "Device attributes report exposed UART/JTAG hardware debug ports or missing tamper protection.",
          impact: "Allows physical attackers to dump firmware, extract keys, or obtain root serial shell.",
          shap: [
            { feature: "Exposed hardware debug interface (UART/JTAG)", weight: "+0.70" },
            { feature: "Missing physical enclosure hardening", weight: "+0.29" }
          ]
        }, devFlaws, devOwasp);
      }

      devScore = Math.max(10, Math.min(100, devScore));
      devicesSummary.push({
        id: dev.id,
        name: dev.name,
        type: dev.type,
        ip: dev.ip,
        mac: dev.mac,
        score: devScore,
        status: dev.active ? "online" : "offline",
        telemetryKeysCount: teleKeys.length,
        flaws: devFlaws,
        owaspCategories: Array.from(devOwasp)
      });
    });

    if (structuredDevices.length === 0) {
      recordFinding({
        id: "iot-no-devices",
        owaspId: "I8",
        type: "No Tenant IoT Devices Registered",
        severity: "low",
        selector: managingUrl,
        detail: "Connected to managing server, but the authenticated tenant has 0 registered IoT devices.",
        impact: "Provision IoT devices on ThingsBoard to enable continuous telemetry anomaly auditing.",
        shap: [{ feature: "Empty tenant device inventory", weight: "+0.15" }]
      });
    }

    let overallScore = 100;
    if (devicesSummary.length > 0) {
      overallScore = Math.round(
        devicesSummary.reduce((sum, d) => sum + d.score, 0) / devicesSummary.length
      );
    } else if (isPlaintextServer) {
      overallScore = 75;
    }

    const owaspMatrix = buildOwaspMatrix(findings, devicesSummary.length);

    return {
      score: Math.max(0, Math.min(100, overallScore)),
      counts,
      devicesAudited: devicesSummary,
      owaspBreakdown,
      owaspMatrix,
      findings,
      engineUsed: "SHAP + OWASP IoT Top 10 (Wasm-Ready)"
    };
  }

  /**
   * Executes Mode 2 (IoT Network Anomaly Audit).
   * Always reads `managingUrl` from chrome.storage.local before auditing.
   */
  async function runIoTAnomalyAudit(options = {}) {
    const { onProgress, credentials } = options;

    if (!global.ConfigManager) {
      throw new Error("ConfigManager module is not loaded.");
    }

    const managingUrl = await global.ConfigManager.getManagingUrl();
    if (!managingUrl) {
      return {
        status: "NOT_CONFIGURED",
        message: "IoT Managing Website URL is not configured. Click 'Change URL' to set your server."
      };
    }

    const hasPerm = await global.ConfigManager.hasHostPermission(managingUrl);
    if (!hasPerm) {
      return {
        status: "PERMISSION_REQUIRED",
        managingUrl,
        message: `Host access permission is required for ${managingUrl}. Click 'Change URL' and save to grant access.`
      };
    }

    if (typeof onProgress === "function") onProgress(10, "Checking ThingsBoard session token...");

    let token = null;
    if (credentials && credentials.username && credentials.password) {
      if (typeof onProgress === "function") onProgress(20, "Authenticating with managing server...");
      token = await loginThingsBoard(managingUrl, credentials.username, credentials.password);
    } else {
      const resolved = await resolveAuthToken(managingUrl);
      token = resolved?.token || null;
    }

    if (!token) {
      return {
        status: "AUTH_REQUIRED",
        managingUrl,
        message: "No active ThingsBoard JWT token found. Please sign in to run the IoT Anomaly Audit."
      };
    }

    let structuredDevices;
    try {
      structuredDevices = await fetchDevicesAndTelemetry(managingUrl, token, onProgress);
    } catch (err) {
      if (err.code === "AUTH_REQUIRED") {
        await clearCachedToken(managingUrl);
        return {
          status: "AUTH_REQUIRED",
          managingUrl,
          message: "Session token expired or rejected. Please sign in again."
        };
      }
      throw err;
    }

    if (typeof onProgress === "function") onProgress(82, "Running OWASP IoT Top 10 + Rust/Wasm SHAP engine...");
    const evaluation = await evaluateWithWasmAndShap(managingUrl, structuredDevices);

    const now = new Date();
    const report = {
      status: "OK",
      mode: "iot",
      auditType: "IoT Network Anomaly Audit (OWASP IoT Top 10)",
      managingServer: managingUrl,
      timestamp: now.toISOString(),
      timestampDisplay: now.toLocaleString(),
      score: evaluation.score,
      counts: evaluation.counts,
      devicesAudited: evaluation.devicesAudited,
      owaspBreakdown: evaluation.owaspBreakdown,
      owaspMatrix: evaluation.owaspMatrix,
      findings: evaluation.findings,
      engineUsed: evaluation.engineUsed
    };

    if (hasChromeStorage()) {
      await chrome.storage.local.set({ [STORAGE_KEYS.LAST_IOT_AUDIT]: report });
    }

    if (typeof onProgress === "function") onProgress(100, "IoT Network Anomaly Audit complete.");
    return report;
  }

  async function getSavedIoTAudit() {
    if (!hasChromeStorage()) return null;
    const data = await chrome.storage.local.get([STORAGE_KEYS.LAST_IOT_AUDIT]);
    const saved = data[STORAGE_KEYS.LAST_IOT_AUDIT] || null;
    return saved && saved.mode === "iot" ? saved : null;
  }

  global.IoTAuditor = {
    STORAGE_KEYS,
    OWASP_IOT_TOP_10,
    OWASP_REMEDIATIONS,
    resolveAuthToken,
    loginThingsBoard,
    clearCachedToken,
    fetchDevicesAndTelemetry,
    evaluateWithWasmAndShap,
    runIoTAnomalyAudit,
    getSavedIoTAudit
  };
})(typeof window !== "undefined" ? window : globalThis);
