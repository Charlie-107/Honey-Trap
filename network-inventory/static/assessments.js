const state = { devices: [], filter: "all", plan: new Set() };

const TESTS = [
  { id: "exposure", category: "general", title: "Service exposure review", mode: "Passive", risk: "Low impact", objective: "Confirm each exposed port and service is required for the device's business purpose.", evidence: "Approved service list and unexpected exposure notes." },
  { id: "tls", category: "general", title: "TLS configuration review", mode: "Passive", risk: "Low impact", objective: "Review certificates, protocol versions, and encryption on web or management services.", evidence: "Certificate chain, protocol, and cipher observations.", services: ["https", "ssl"] },
  { id: "web", category: "general", title: "Web interface baseline", mode: "Manual", risk: "Controlled", objective: "Review security headers, session handling, access control, and exposed administrative pages.", evidence: "Screenshots and redacted request/response evidence.", services: ["http", "https", "http-proxy"] },
  { id: "credentials", category: "general", title: "Default credential policy", mode: "Manual", risk: "Controlled", objective: "Confirm vendor defaults were removed using approved test credentials; do not brute-force accounts.", evidence: "Credential policy result without storing passwords." },
  { id: "mqtt", category: "iot", title: "MQTT access-control review", mode: "Manual", risk: "Controlled", objective: "Verify broker authentication, topic authorization, transport encryption, and retained-message policy.", evidence: "Broker settings and authorized publish/subscribe results.", services: ["mqtt", "mqtts"] },
  { id: "rtsp", category: "iot", title: "Camera and RTSP review", mode: "Manual", risk: "Controlled", objective: "Confirm media streams require authentication and are isolated from untrusted network segments.", evidence: "Authentication requirement and segmentation result.", services: ["rtsp"] },
  { id: "upnp", category: "iot", title: "UPnP exposure review", mode: "Passive", risk: "Low impact", objective: "Identify unnecessary discovery and control endpoints exposed beyond the intended local segment.", evidence: "Discovery endpoint and network-boundary observations.", services: ["upnp"] },
  { id: "firmware", category: "iot", title: "Firmware posture review", mode: "Manual", risk: "Controlled", objective: "Record firmware version, update support, signed-update status, and vendor end-of-life information.", evidence: "Version, release date, and update-policy references." },
  { id: "snmp", category: "network", title: "SNMP configuration review", mode: "Passive", risk: "Low impact", objective: "Confirm SNMP is required, restricted to management networks, and uses approved authentication.", evidence: "Version and access-control configuration summary.", services: ["snmp"] },
  { id: "management", category: "network", title: "Management-plane exposure", mode: "Passive", risk: "Low impact", objective: "Review SSH, Telnet, web administration, and remote-management reachability by network segment.", evidence: "Reachability matrix and approved management sources.", services: ["ssh", "telnet", "http", "https"] },
  { id: "segmentation", category: "network", title: "Network segmentation review", mode: "Manual", risk: "Controlled", objective: "Verify IoT and user devices cannot reach unauthorized management or sensitive network zones.", evidence: "Approved source-to-destination connectivity matrix." },
  { id: "printer", category: "network", title: "Printer service review", mode: "Passive", risk: "Low impact", objective: "Review printing, web administration, and file-transfer services for unnecessary exposure.", evidence: "Enabled protocols and administration access summary.", services: ["ipp", "printer", "jetdirect"] },
];

const elements = {
  device: document.querySelector("#assessmentDevice"),
  authorization: document.querySelector("#authorizationCheck"),
  catalog: document.querySelector("#assessmentCatalog"),
  planCount: document.querySelector("#planCount"),
  planTarget: document.querySelector("#planTarget"),
  planItems: document.querySelector("#planItems"),
  clearPlan: document.querySelector("#clearPlan"),
  exportPlan: document.querySelector("#exportPlan"),
  notice: document.querySelector("#inventoryNotice"),
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

async function request(url) {
  const response = await fetch(url);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function selectedDevice() {
  return state.devices.find((device) => device.id === elements.device.value) || null;
}

function updateTargets() {
  const signature = state.devices.map((device) => device.id).join("|");
  if (elements.device.dataset.signature === signature) return;
  const previous = elements.device.value;
  const options = [new Option(state.devices.length ? "Choose a discovered device" : "No devices available - run an inventory scan", "")];
  state.devices.forEach((device) => options.push(new Option(`${device.name} / ${device.ip} / ${device.group}`, device.id)));
  elements.device.replaceChildren(...options);
  elements.device.dataset.signature = signature;
  if (state.devices.some((device) => device.id === previous)) elements.device.value = previous;
}

function recommended(test, device) {
  if (!device) return false;
  const names = (device.services || []).map((service) => service.name.toLowerCase());
  return (test.services || []).some((service) => names.includes(service))
    || (test.category === "iot" && device.group === "IoT")
    || (test.category === "network" && ["network", "printer"].includes(device.type));
}

function renderCatalog() {
  const device = selectedDevice();
  const authorized = elements.authorization.checked;
  const visible = TESTS.filter((test) => state.filter === "all" || test.category === state.filter);
  elements.catalog.replaceChildren(...visible.map((test) => {
    const card = document.createElement("article");
    card.className = `assessment-card${recommended(test, device) ? " recommended" : ""}`;
    const top = document.createElement("div");
    const labels = document.createElement("div");
    labels.className = "test-labels";
    labels.append(text("span", `category-tag ${test.category}`, test.category), text("span", "mode-tag", test.mode));
    if (recommended(test, device)) labels.append(text("span", "recommended-tag", "Recommended"));
    top.append(labels, text("span", "risk-label", test.risk));
    const evidence = document.createElement("div");
    evidence.className = "evidence-line";
    evidence.append(text("strong", "", "Evidence"), text("span", "", test.evidence));
    const button = text("button", `add-check${state.plan.has(test.id) ? " added" : ""}`, state.plan.has(test.id) ? "Added to plan" : "Add to plan");
    button.type = "button";
    button.disabled = !device || !authorized || state.plan.has(test.id);
    button.addEventListener("click", () => { state.plan.add(test.id); render(); });
    const footer = document.createElement("div");
    footer.className = "assessment-card-footer";
    footer.append(evidence, button);
    card.append(top, text("h4", "", test.title), text("p", "", test.objective), footer);
    return card;
  }));
}

function renderPlan() {
  const device = selectedDevice();
  const selected = TESTS.filter((test) => state.plan.has(test.id));
  elements.planCount.textContent = `${selected.length} check${selected.length === 1 ? "" : "s"}`;
  elements.planTarget.textContent = device ? `${device.name} / ${device.ip}` : "Select a discovered device.";
  elements.clearPlan.disabled = selected.length === 0;
  elements.exportPlan.disabled = !device || !selected.length || !elements.authorization.checked;
  if (!selected.length) {
    elements.planItems.replaceChildren(text("div", "quiet-state", "Choose checks from the catalog to create a plan."));
    return;
  }
  elements.planItems.replaceChildren(...selected.map((test, index) => {
    const item = document.createElement("div");
    item.className = "plan-item";
    const copy = document.createElement("div");
    copy.append(text("strong", "", test.title), text("small", "", `${test.mode} / ${test.category}`));
    const remove = text("button", "remove-check", "Remove");
    remove.type = "button";
    remove.addEventListener("click", () => { state.plan.delete(test.id); render(); });
    item.append(text("span", "plan-number", String(index + 1).padStart(2, "0")), copy, remove);
    return item;
  }));
}

function render() {
  updateTargets();
  renderCatalog();
  renderPlan();
}

function exportPlan() {
  const device = selectedDevice();
  if (!device || !elements.authorization.checked || !state.plan.size) return;
  const checks = TESTS.filter((test) => state.plan.has(test.id)).map(({ services, ...test }) => test);
  const plan = {
    title: "Authorized non-destructive security assessment",
    generatedAt: new Date().toISOString(),
    target: { name: device.name, ip: device.ip, mac: device.mac, vendor: device.vendor, group: device.group, type: device.typeLabel },
    authorizationConfirmed: true,
    guardrails: ["No exploitation", "No password attacks", "No denial of service", "No persistence", "Stop if device stability changes"],
    checks,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `netscope-assessment-${device.ip}.json`;
  link.click();
  URL.revokeObjectURL(url);
  showToast("Assessment plan exported.");
}

async function refreshInventory() {
  try {
    const data = await request("/api/status");
    state.devices = data.devices || [];
    elements.notice.textContent = data.scanning
      ? `${data.phase || "Scan in progress"}. Targets update automatically when complete.`
      : `${state.devices.length} discovered device${state.devices.length === 1 ? "" : "s"} available from the shared inventory.`;
    render();
  } catch (error) {
    elements.notice.textContent = "Could not load the shared inventory.";
    showToast(error.message, true);
  }
}

document.querySelectorAll(".assessment-filter").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".assessment-filter").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    state.filter = button.dataset.assessmentFilter;
    renderCatalog();
  });
});
elements.device.addEventListener("change", () => { state.plan.clear(); elements.authorization.checked = false; render(); });
elements.authorization.addEventListener("change", render);
elements.clearPlan.addEventListener("click", () => { state.plan.clear(); render(); });
elements.exportPlan.addEventListener("click", exportPlan);

refreshInventory();
window.setInterval(refreshInventory, 4000);
