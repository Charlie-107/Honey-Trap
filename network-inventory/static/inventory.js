const state = { devices: [], filter: "all", query: "", pollTimer: null, liveTimer: null, scanning: false, awaitingScan: false, hasCurrentResult: false };

const elements = {
  networkSelect: document.querySelector("#networkSelect"),
  scanButton: document.querySelector("#scanButton"),
  scanButtonText: document.querySelector("#scanButtonText"),
  liveToggle: document.querySelector("#liveToggle"),
  statusPulse: document.querySelector("#statusPulse"),
  statusTitle: document.querySelector("#statusTitle"),
  statusDetail: document.querySelector("#statusDetail"),
  lastScan: document.querySelector("#lastScan"),
  totalCount: document.querySelector("#totalCount"),
  iotCount: document.querySelector("#iotCount"),
  otherCount: document.querySelector("#otherCount"),
  serviceCount: document.querySelector("#serviceCount"),
  allBadge: document.querySelector("#allBadge"),
  iotBadge: document.querySelector("#iotBadge"),
  otherBadge: document.querySelector("#otherBadge"),
  searchInput: document.querySelector("#searchInput"),
  resultCount: document.querySelector("#resultCount"),
  deviceRows: document.querySelector("#deviceRows"),
  emptyState: document.querySelector("#emptyState"),
  drawerBackdrop: document.querySelector("#drawerBackdrop"),
  deviceDrawer: document.querySelector("#deviceDrawer"),
  drawerClose: document.querySelector("#drawerClose"),
  drawerTitle: document.querySelector("#drawerTitle"),
  drawerSubtitle: document.querySelector("#drawerSubtitle"),
  drawerFacts: document.querySelector("#drawerFacts"),
  drawerInsights: document.querySelector("#drawerInsights"),
  drawerServiceCount: document.querySelector("#drawerServiceCount"),
  drawerServices: document.querySelector("#drawerServices"),
  toast: document.querySelector("#toast"),
};

function text(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.className = `toast show${isError ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { elements.toast.className = "toast"; }, 3500);
}

async function request(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function setScanning(scanning, phase) {
  state.scanning = scanning;
  elements.scanButton.disabled = scanning || !elements.networkSelect.value;
  elements.scanButton.classList.toggle("scanning", scanning);
  elements.scanButtonText.textContent = scanning ? "Scanning..." : "Run scan";
  elements.statusPulse.className = `pulse ${scanning ? "active" : "idle"}`;
  if (scanning) {
    elements.statusTitle.textContent = phase || "Scan in progress";
    elements.statusDetail.textContent = `Inspecting authorized hosts on ${elements.networkSelect.value}.`;
  }
}

function formatDate(value) {
  if (!value) return "No scans yet";
  return `Last scan ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value))}`;
}

function deviceGlyph(type) {
  const glyphs = { iot: "\u2302", network: "\u2318", computer: "\u25b1", mobile: "\u25af", printer: "\u25a4", unknown: "?" };
  return glyphs[type] || "?";
}

function createServiceBadge(service) {
  const badge = document.createElement("div");
  badge.className = "service-badge";
  badge.append(text("strong", "", service.name.toUpperCase()));
  badge.append(text("span", "mono", `${service.port}/${service.protocol}`));
  return badge;
}

function openDrawer(device) {
  elements.drawerTitle.textContent = device.name;
  elements.drawerSubtitle.textContent = `${device.group} / ${device.typeLabel}`;
  elements.drawerFacts.replaceChildren();
  [["Device group", device.group], ["Device type", device.typeLabel], ["Hostname", device.hostname || "Not resolved"], ["Manufacturer", device.vendor], ["Response time", device.latencyMs === null ? "Not measured" : `${device.latencyMs} ms`], ["Last confirmed", new Date(device.lastSeen).toLocaleString()]].forEach(([label, value]) => {
    const fact = document.createElement("div");
    fact.append(text("span", "", label), text("strong", label.includes("address") ? "mono" : "", value));
    elements.drawerFacts.append(fact);
  });
  const services = device.services || [];
  const serviceNames = services.map((service) => service.name.toLowerCase());
  const roles = [];
  if (serviceNames.some((name) => ["http", "https", "http-proxy"].includes(name))) roles.push("Web interface");
  if (serviceNames.some((name) => ["ssh", "telnet"].includes(name))) roles.push("Remote administration");
  if (serviceNames.includes("domain")) roles.push("DNS service");
  if (serviceNames.some((name) => ["rtsp", "mqtt", "coap"].includes(name))) roles.push("IoT communications");
  if (serviceNames.some((name) => ["ipp", "printer", "jetdirect"].includes(name))) roles.push("Printing");
  const encrypted = services.filter((service) => service.secure || ["https", "ssh", "mqtts"].includes(service.name.toLowerCase())).length;
  const identitySignals = [device.hostname, device.vendor !== "Unknown vendor" ? device.vendor : null].filter(Boolean).length;
  const insights = [
    ["Likely role", roles.length ? roles.join(", ") : "No role inferred from exposed services"],
    ["Identity confidence", identitySignals === 2 ? "Hostname and manufacturer identified" : (identitySignals === 1 ? "Partially identified" : "Limited identity evidence")],
    ["Service exposure", services.length ? `${services.length} open service${services.length === 1 ? "" : "s"} in the bounded scan` : "No open service found in the top 50 TCP ports"],
    ["Protected services", services.length ? `${encrypted} of ${services.length} identified as encrypted` : "No transport assessment available"],
  ];
  elements.drawerInsights.replaceChildren(...insights.map(([label, value]) => {
    const item = document.createElement("div");
    item.append(text("span", "", label), text("strong", "", value));
    return item;
  }));
  elements.drawerServiceCount.textContent = `${services.length} found`;
  if (!services.length) {
    elements.drawerServices.replaceChildren(text("div", "quiet-state", "No open service was identified in the top 50 TCP ports."));
  } else {
    elements.drawerServices.replaceChildren(...services.map((service) => {
      const card = document.createElement("div");
      card.className = "drawer-service";
      const heading = document.createElement("div");
      heading.append(createServiceBadge(service));
      if (service.secure) heading.append(text("span", "tls-pill", "TLS"));
      card.append(heading, text("p", service.detail ? "" : "muted-value", service.detail || "No product or version fingerprint available."));
      return card;
    }));
  }
  elements.drawerBackdrop.hidden = false;
  elements.deviceDrawer.classList.add("open");
  elements.deviceDrawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
}

function closeDrawer() {
  elements.deviceDrawer.classList.remove("open");
  elements.deviceDrawer.setAttribute("aria-hidden", "true");
  elements.drawerBackdrop.hidden = true;
  document.body.classList.remove("drawer-open");
}

function createDeviceRow(device) {
  const row = document.createElement("tr");
  row.className = "clickable-row";
  row.tabIndex = 0;
  row.setAttribute("aria-label", `Open details for ${device.name}`);
  row.addEventListener("click", () => openDrawer(device));
  row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") openDrawer(device); });
  const identityCell = document.createElement("td");
  const identity = document.createElement("div");
  identity.className = "device-cell";
  identity.append(text("span", `device-avatar${device.group === "IoT" ? " iot" : ""}`, deviceGlyph(device.type)));
  const identityCopy = document.createElement("div");
  identityCopy.append(text("span", "device-name", device.name));
  identityCopy.append(text("span", "device-meta", device.hostname ? "Resolved hostname" : "Generated identity"));
  identity.append(identityCopy);
  identityCell.append(identity);
  const groupCell = document.createElement("td");
  groupCell.append(text("span", `group-pill${device.group === "IoT" ? " iot" : ""}`, device.group));
  groupCell.append(text("span", "type-label", device.typeLabel));
  const servicesCell = document.createElement("td");
  const serviceButton = text("button", `service-button${device.services?.length ? " found" : ""}`, device.services?.length ? `${device.services.length} open` : "None found");
  serviceButton.type = "button";
  serviceButton.addEventListener("click", () => openDrawer(device));
  servicesCell.append(serviceButton);
  const statusCell = document.createElement("td");
  statusCell.append(text("span", "online", device.latencyMs === null ? "Online" : `Online / ${device.latencyMs} ms`));
  row.append(
    identityCell,
    groupCell,
    text("td", "mono", device.ip),
    text("td", `mono${device.mac ? "" : " muted-value"}`, device.mac || "Not available"),
    text("td", device.vendor === "Unknown vendor" ? "muted-value" : "", device.vendor),
    servicesCell,
    statusCell,
  );
  return row;
}

function render() {
  const iot = state.devices.filter((device) => device.group === "IoT").length;
  const serviceTotal = state.devices.reduce((total, device) => total + (device.services?.length || 0), 0);
  elements.totalCount.textContent = state.devices.length;
  elements.iotCount.textContent = iot;
  elements.otherCount.textContent = state.devices.length - iot;
  elements.serviceCount.textContent = serviceTotal;
  elements.allBadge.textContent = state.devices.length;
  elements.iotBadge.textContent = iot;
  elements.otherBadge.textContent = state.devices.length - iot;
  const query = state.query.toLowerCase();
  const visible = state.devices.filter((device) => {
    const serviceText = (device.services || []).map((service) => `${service.name} ${service.port} ${service.detail || ""}`).join(" ");
    const haystack = [device.name, device.ip, device.mac, device.vendor, device.typeLabel, serviceText].filter(Boolean).join(" ").toLowerCase();
    return (state.filter === "all" || device.group === state.filter) && haystack.includes(query);
  });
  elements.deviceRows.replaceChildren(...visible.map(createDeviceRow));
  elements.emptyState.hidden = visible.length > 0;
  elements.resultCount.textContent = `${visible.length} device${visible.length === 1 ? "" : "s"}`;
}

async function loadNetworks() {
  try {
    const data = await request("/api/interfaces");
    elements.networkSelect.replaceChildren();
    const available = data.networks.filter((network) => network.scannable).sort((left, right) => {
      const rank = (network) => network.interface.startsWith("wl") ? 0 : (network.interface.startsWith("vm") ? 2 : 1);
      return rank(left) - rank(right);
    });
    if (!available.length) {
      elements.networkSelect.add(new Option("No scannable local network", ""));
      elements.networkSelect.disabled = true;
      elements.scanButton.disabled = true;
      return;
    }
    available.forEach((network) => {
      const medium = network.interface.startsWith("wl") ? "Wi-Fi" : (network.interface.startsWith("vm") ? "Virtual" : "Wired");
      elements.networkSelect.add(new Option(`${network.cidr} / ${network.interface} / ${medium}`, network.cidr));
    });
    elements.scanButton.disabled = false;
  } catch (error) {
    showToast(error.message, true);
  }
}

async function refreshStatus() {
  try {
    const data = await request("/api/status");
    if (!data.scanning && state.awaitingScan && data.lastScanAt) {
      state.awaitingScan = false;
      state.hasCurrentResult = true;
    }
    state.devices = state.hasCurrentResult ? (data.devices || []) : [];
    setScanning(data.scanning, data.phase);
    elements.lastScan.textContent = state.hasCurrentResult ? formatDate(data.lastScanAt) : "No current scan";
    if (data.error) {
      elements.statusPulse.className = "pulse error";
      elements.statusTitle.textContent = "Scan failed";
      elements.statusDetail.textContent = data.error;
    } else if (!data.scanning && state.hasCurrentResult && data.lastScanAt) {
      elements.statusPulse.className = "pulse";
      elements.statusPulse.style.background = "#32a879";
      elements.statusTitle.textContent = "Inventory current";
      elements.statusDetail.textContent = `${state.devices.length} online devices found on ${data.network} in ${data.durationSeconds} seconds.`;
    } else if (!data.scanning) {
      elements.statusTitle.textContent = "Ready for a real scan";
      elements.statusDetail.textContent = "No retained or demonstration devices are displayed in this browser session.";
    }
    render();
    if (!data.scanning && state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
      scheduleLiveScan();
    }
  } catch (error) {
    showToast(error.message, true);
  }
}

async function runScan() {
  if (state.scanning || !elements.networkSelect.value) return;
  window.clearTimeout(state.liveTimer);
  try {
    state.awaitingScan = true;
    setScanning(true);
    await request("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ network: elements.networkSelect.value }) });
    state.pollTimer = window.setInterval(refreshStatus, 1200);
    await refreshStatus();
  } catch (error) {
    state.awaitingScan = false;
    setScanning(false);
    showToast(error.message, true);
    scheduleLiveScan();
  }
}

function scheduleLiveScan() {
  window.clearTimeout(state.liveTimer);
  if (!elements.liveToggle.checked || state.scanning) return;
  state.liveTimer = window.setTimeout(runScan, 60_000);
}

elements.scanButton.addEventListener("click", runScan);
elements.liveToggle.addEventListener("change", () => {
  localStorage.setItem("netscope-live-monitor", String(elements.liveToggle.checked));
  window.clearTimeout(state.liveTimer);
  if (elements.liveToggle.checked) runScan();
});
elements.drawerClose.addEventListener("click", closeDrawer);
elements.drawerBackdrop.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); });
elements.searchInput.addEventListener("input", (event) => { state.query = event.target.value.trim(); render(); });
document.querySelectorAll(".filter").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".filter").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    state.filter = button.dataset.filter;
    render();
  });
});

async function initialize() {
  elements.liveToggle.checked = localStorage.getItem("netscope-live-monitor") === "true";
  await loadNetworks();
  await refreshStatus();
  if (elements.liveToggle.checked) runScan();
}

initialize();
