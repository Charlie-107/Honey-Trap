const elements = {
  statusPulse: document.querySelector("#statusPulse"),
  statusTitle: document.querySelector("#statusTitle"),
  statusDetail: document.querySelector("#statusDetail"),
  lastScan: document.querySelector("#lastScan"),
  deviceCount: document.querySelector("#deviceCount"),
  openServiceCount: document.querySelector("#openServiceCount"),
  eventCount: document.querySelector("#eventCount"),
  activityCount: document.querySelector("#activityCount"),
  activityList: document.querySelector("#activityList"),
  serviceCatalog: document.querySelector("#serviceCatalog"),
  drawerBackdrop: document.querySelector("#drawerBackdrop"),
  drawer: document.querySelector("#deviceDrawer"),
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

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.className = "toast show error";
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { elements.toast.className = "toast"; }, 3500);
}

function createServiceBadge(service) {
  const badge = document.createElement("div");
  badge.className = "service-badge";
  badge.append(text("strong", "", service.name.toUpperCase()), text("span", "mono", `${service.port}/${service.protocol}`));
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
  elements.drawerServices.replaceChildren(...(services.length ? services.map((service) => {
    const card = document.createElement("div");
    card.className = "drawer-service";
    const heading = document.createElement("div");
    heading.append(createServiceBadge(service));
    if (service.secure) heading.append(text("span", "tls-pill", "TLS"));
    card.append(heading, text("p", service.detail ? "" : "muted-value", service.detail || "No product or version fingerprint available."));
    return card;
  }) : [text("div", "quiet-state", "No open service was identified in the top 50 TCP ports.")]));
  elements.drawerBackdrop.hidden = false;
  elements.drawer.classList.add("open");
  elements.drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
}

function closeDrawer() {
  elements.drawer.classList.remove("open");
  elements.drawer.setAttribute("aria-hidden", "true");
  elements.drawerBackdrop.hidden = true;
  document.body.classList.remove("drawer-open");
}

function render(data) {
  const devices = data.devices || [];
  const activity = data.activity || [];
  const serviceTotal = devices.reduce((total, device) => total + (device.services?.length || 0), 0);
  elements.deviceCount.textContent = devices.length;
  elements.openServiceCount.textContent = serviceTotal;
  elements.eventCount.textContent = activity.length;
  elements.activityCount.textContent = `${activity.length} event${activity.length === 1 ? "" : "s"}`;
  elements.lastScan.textContent = data.lastScanAt ? `Last scan ${new Date(data.lastScanAt).toLocaleString()}` : "No scans yet";
  elements.statusPulse.className = `pulse ${data.error ? "error" : (data.scanning ? "active" : "idle")}`;
  if (data.error) {
    elements.statusTitle.textContent = "Scan failed";
    elements.statusDetail.textContent = data.error;
  } else if (data.scanning) {
    elements.statusTitle.textContent = data.phase || "Scan in progress";
    elements.statusDetail.textContent = `Current scope: ${data.network}`;
  } else if (data.lastScanAt) {
    elements.statusTitle.textContent = "Activity current";
    elements.statusDetail.textContent = `${devices.length} devices and ${serviceTotal} exposed services in the latest result.`;
  } else {
    elements.statusTitle.textContent = "No activity yet";
    elements.statusDetail.textContent = "Run a scan from the Inventory page.";
  }
  elements.activityList.replaceChildren(...(activity.length ? activity.map((event) => {
    const item = document.createElement("div");
    item.className = `activity-item ${event.kind}`;
    const copy = document.createElement("div");
    const top = document.createElement("div");
    top.append(text("strong", "", event.title), text("time", "", new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })));
    copy.append(top, text("p", "", event.detail));
    item.append(text("span", "activity-marker", ""), copy);
    return item;
  }) : [text("div", "quiet-state", "Run a scan to begin the activity timeline.")]));
  const withServices = devices.filter((device) => device.services?.length);
  elements.serviceCatalog.replaceChildren(...(withServices.length ? withServices.map((device) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "service-device";
    const heading = document.createElement("div");
    heading.append(text("strong", "", device.name), text("span", "mono", device.ip));
    const badges = document.createElement("div");
    badges.className = "service-badges";
    device.services.slice(0, 4).forEach((service) => badges.append(createServiceBadge(service)));
    if (device.services.length > 4) badges.append(text("span", "more-services", `+${device.services.length - 4}`));
    item.append(heading, badges);
    item.addEventListener("click", () => openDrawer(device));
    return item;
  }) : [text("div", "quiet-state", "Detected services will appear here.")]));
}

async function refresh() {
  try {
    const response = await fetch("/api/status");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load activity.");
    render(data);
  } catch (error) {
    showToast(error.message);
  }
}

elements.drawerClose.addEventListener("click", closeDrawer);
elements.drawerBackdrop.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); });
refresh();
window.setInterval(refresh, 2000);
