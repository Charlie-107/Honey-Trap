const state = { devices: [], filter: "all", query: "", pollTimer: null };

const elements = {
  networkSelect: document.querySelector("#networkSelect"),
  scanButton: document.querySelector("#scanButton"),
  scanButtonText: document.querySelector("#scanButtonText"),
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
  [["IP address", device.ip], ["MAC address", device.mac || "Not available"], ["Manufacturer", device.vendor]].forEach(([label, value]) => {
    const fact = document.createElement("div");
    fact.append(text("span", "", label), text("strong", label.includes("address") ? "mono" : "", value));
    elements.drawerFacts.append(fact);
  });
  const services = device.services || [];
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
    const available = data.networks.filter((network) => network.scannable);
    if (!available.length) {
      elements.networkSelect.add(new Option("No scannable local network", ""));
      elements.networkSelect.disabled = true;
      elements.scanButton.disabled = true;
      return;
    }
    available.forEach((network) => elements.networkSelect.add(new Option(`${network.cidr} / ${network.interface}`, network.cidr)));
    elements.scanButton.disabled = false;
  } catch (error) {
    showToast(error.message, true);
  }
}

async function refreshStatus() {
  try {
    const data = await request("/api/status");
    state.devices = data.devices || [];
    setScanning(data.scanning, data.phase);
    elements.lastScan.textContent = formatDate(data.lastScanAt);
    if (data.error) {
      elements.statusPulse.className = "pulse error";
      elements.statusTitle.textContent = "Scan failed";
      elements.statusDetail.textContent = data.error;
    } else if (!data.scanning && data.lastScanAt) {
      elements.statusPulse.className = "pulse";
      elements.statusPulse.style.background = "#32a879";
      elements.statusTitle.textContent = "Inventory current";
      elements.statusDetail.textContent = `${state.devices.length} online devices found on ${data.network} in ${data.durationSeconds} seconds.`;
    }
    render();
    if (!data.scanning && state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  } catch (error) {
    showToast(error.message, true);
  }
}

async function runScan() {
  try {
    setScanning(true);
    await request("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ network: elements.networkSelect.value }) });
    state.pollTimer = window.setInterval(refreshStatus, 1200);
    await refreshStatus();
  } catch (error) {
    setScanning(false);
    showToast(error.message, true);
  }
}

elements.scanButton.addEventListener("click", runScan);
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

Promise.all([loadNetworks(), refreshStatus()]);
