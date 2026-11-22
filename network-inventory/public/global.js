const fragmentToken = new URLSearchParams(location.hash.slice(1)).get("workspace");
if (fragmentToken) {
  localStorage.setItem("netscope-workspace-token", fragmentToken);
  history.replaceState(null, "", location.pathname);
}
const state = { token: fragmentToken || localStorage.getItem("netscope-workspace-token"), data: null, query: "", timer: null };
document.documentElement.dataset.globalTheme = localStorage.getItem("netscope-global-theme") || "light";
const $ = (selector) => document.querySelector(selector);
const elements = {
  welcome: $("#welcomeView"), workspace: $("#workspaceView"), create: $("#createWorkspace"), forget: $("#forgetWorkspace"),
  pairPanel: $("#pairPanel"), pairCode: $("#pairCode"), newPairCode: $("#newPairCode"), installCommand: $("#installCommand"), copy: $("#copyCommand"),
  agentCount: $("#agentCount"), deviceCount: $("#deviceCount"), serviceCount: $("#serviceCount"), statusCount: $("#statusCount"),
  agentList: $("#agentList"), deviceRows: $("#deviceRows"), deviceEmpty: $("#deviceEmpty"), eventList: $("#eventList"),
  search: $("#deviceSearch"), refreshTime: $("#refreshTime"), toast: $("#toast"),
  statusText: $("#workspaceStatusText"), themeToggle: $("#globalThemeToggle"),
  drawerBackdrop: $("#globalDrawerBackdrop"), drawer: $("#globalDeviceDrawer"), drawerClose: $("#globalDrawerClose"),
  drawerTitle: $("#globalDrawerTitle"), drawerSubtitle: $("#globalDrawerSubtitle"), drawerFacts: $("#globalDrawerFacts"),
  drawerInsights: $("#globalDrawerInsights"), drawerServices: $("#globalDrawerServices"),
};

function text(tag, className, value) { const node = document.createElement(tag); if (className) node.className = className; node.textContent = value; return node; }
function toast(message, error = false) { elements.toast.textContent = message; elements.toast.className = `toast show${error ? " error" : ""}`; clearTimeout(toast.timer); toast.timer = setTimeout(() => { elements.toast.className = "toast"; }, 3500); }

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function commandFor(code) {
  return `git clone https://github.com/Charlie-107/Honey-Trap.git && cd Honey-Trap/network-inventory && python3 agent.py --server ${location.origin} --pair ${code} && python3 agent.py`;
}

function showWorkspace(updatePath = false) {
  document.body.classList.add("workspace-active");
  elements.welcome.hidden = true;
  document.querySelector(".principles").hidden = true;
  elements.workspace.hidden = false;
  if (updatePath && location.pathname !== "/inventory") history.pushState(null, "", "/inventory");
}

function openWorkspaceView(view, updatePath = true) {
  const selected = ["inventory", "agents", "activity"].includes(view) ? view : "inventory";
  document.querySelectorAll(".workspace-pane").forEach((pane) => { pane.hidden = pane.id !== `${selected}Pane`; });
  document.querySelectorAll(".dash-nav-item").forEach((button) => button.classList.toggle("active", button.dataset.workspaceView === selected));
  if (updatePath && location.pathname !== `/${selected}`) history.pushState(null, "", `/${selected}`);
}

async function createWorkspace() {
  try {
    elements.create.disabled = true;
    const data = await request("/api/global/workspaces", { method: "POST", body: "{}" });
    state.token = data.workspaceToken;
    localStorage.setItem("netscope-workspace-token", state.token);
    showWorkspace(true);
    setPairCode(data.pairCode);
    await refresh();
  } catch (error) { toast(error.message, true); } finally { elements.create.disabled = false; }
}

function setPairCode(code) { elements.pairCode.textContent = `${code.slice(0, 4)}-${code.slice(4)}`; elements.installCommand.textContent = commandFor(code); }

async function newPairCode() { try { const data = await request("/api/global/pair-code", { method: "POST", body: "{}" }); setPairCode(data.pairCode); toast("New pairing code created."); } catch (error) { toast(error.message, true); } }

function renderAgents(data) {
  if (!data.agents.length) { elements.agentList.replaceChildren(text("div", "empty", "No agent paired yet.")); return; }
  elements.agentList.replaceChildren(...data.agents.map((agent) => {
    const card = document.createElement("article"); card.className = "agent-card";
    const top = document.createElement("div");
    const title = document.createElement("div"); title.append(text("strong", "", agent.name), text("small", "", `Last seen ${agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "never"}`));
    top.append(title, text("span", "online-pill", "Connected")); card.append(top);
    const networks = document.createElement("div"); networks.className = "network-list";
    if (!agent.networks.length) networks.append(text("p", "empty-inline", "Waiting for private network report..."));
    agent.networks.forEach((network) => {
      const row = document.createElement("div");
      const copy = document.createElement("div"); copy.append(text("span", "mono", network.cidr), text("small", "", network.interface));
      const button = text("button", "scan-network", "Run authorized scan"); button.type = "button";
      button.addEventListener("click", () => startScan(agent.id, network.cidr, button)); row.append(copy, button); networks.append(row);
    });
    card.append(networks); return card;
  }));
}

function openDeviceProfile(device, agentName) {
  const services = device.services || [];
  const names = services.map((service) => service.name.toLowerCase());
  const roles = [];
  if (names.some((name) => ["http", "https", "http-proxy"].includes(name))) roles.push("Web interface");
  if (names.some((name) => ["ssh", "telnet"].includes(name))) roles.push("Remote administration");
  if (names.includes("domain")) roles.push("DNS service");
  if (names.some((name) => ["rtsp", "mqtt", "coap"].includes(name))) roles.push("IoT communications");
  if (names.some((name) => ["ipp", "printer", "jetdirect"].includes(name))) roles.push("Printing");
  const encrypted = services.filter((service) => service.secure || ["https", "ssh", "mqtts"].includes(service.name.toLowerCase())).length;
  const identified = [device.hostname, device.vendor && device.vendor !== "Unknown vendor" ? device.vendor : null].filter(Boolean).length;
  elements.drawerTitle.textContent = device.name || "Unknown device";
  elements.drawerSubtitle.textContent = `${device.group || "Other"} / ${device.typeLabel || "Unknown"}`;
  const facts = [["Observed by", agentName], ["Hostname", device.hostname || "Not resolved"], ["Manufacturer", device.vendor || "Unknown vendor"], ["Response time", device.latencyMs === null || device.latencyMs === undefined ? "Not measured" : `${device.latencyMs} ms`], ["Last confirmed", device.lastSeen ? new Date(device.lastSeen).toLocaleString() : "Unknown"]];
  elements.drawerFacts.replaceChildren(...facts.map(([label, value]) => { const item = document.createElement("div"); item.append(text("span", "", label), text("strong", "", value)); return item; }));
  const insights = [["Likely role", roles.length ? roles.join(", ") : "No role inferred from exposed services"], ["Identity confidence", identified === 2 ? "Hostname and manufacturer identified" : (identified === 1 ? "Partially identified" : "Limited identity evidence")], ["Service exposure", services.length ? `${services.length} open service${services.length === 1 ? "" : "s"} observed` : "No open service found in the top 50 TCP ports"], ["Protected services", services.length ? `${encrypted} of ${services.length} identified as encrypted` : "No transport assessment available"]];
  elements.drawerInsights.replaceChildren(...insights.map(([label, value]) => { const item = document.createElement("div"); item.append(text("span", "", label), text("strong", "", value)); return item; }));
  elements.drawerServices.replaceChildren(...(services.length ? services.map((service) => { const item = document.createElement("div"); item.append(text("strong", "", service.name.toUpperCase()), text("span", "mono", `${service.port}/${service.protocol}`), text("p", "", service.detail || "No product or version fingerprint available.")); return item; }) : [text("div", "empty", "No exposed service was identified in the bounded scan.")]));
  elements.drawerBackdrop.hidden = false;
  elements.drawer.classList.add("open");
  elements.drawer.setAttribute("aria-hidden", "false");
}

function closeDeviceProfile() {
  elements.drawer.classList.remove("open");
  elements.drawer.setAttribute("aria-hidden", "true");
  elements.drawerBackdrop.hidden = true;
}

async function startScan(agentId, network, button) {
  try { button.disabled = true; await request("/api/global/scans", { method: "POST", body: JSON.stringify({ agentId, network }) }); toast(`Scan queued for ${network}.`); await refresh(); }
  catch (error) { toast(error.message, true); button.disabled = false; }
}

function renderDevices(data) {
  const agents = Object.fromEntries(data.agents.map((agent) => [agent.id, agent.name]));
  const query = state.query.toLowerCase();
  const devices = data.devices.filter((device) => [device.name, device.ip, device.mac, device.vendor, ...(device.services || []).map((service) => `${service.name} ${service.port}`)].filter(Boolean).join(" ").toLowerCase().includes(query));
  elements.deviceRows.replaceChildren(...devices.map((device) => {
    const row = document.createElement("tr"); row.className = "global-device-row"; row.tabIndex = 0;
    const identity = document.createElement("td"); identity.append(text("strong", "device-name", device.name || "Unknown device"), text("small", "", device.vendor || "Unknown vendor"));
    const services = (device.services || []).map((service) => `${service.name}:${service.port}`).join(", ") || "None found";
    const agentName = agents[device.agentId] || "Unknown";
    row.append(identity, text("td", "", agentName), text("td", "", device.typeLabel || "Unknown"), text("td", "mono", device.ip), text("td", "mono", device.mac || "Not available"), text("td", "service-copy", services));
    row.addEventListener("click", () => openDeviceProfile(device, agentName));
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") openDeviceProfile(device, agentName); });
    return row;
  }));
  elements.deviceEmpty.hidden = devices.length > 0;
}

function renderEvents(data) {
  elements.eventList.replaceChildren(...(data.events.length ? data.events.map((event) => {
    const item = document.createElement("div"); item.className = `event ${event.kind}`;
    const copy = document.createElement("div"); copy.append(text("strong", "", event.title), text("p", "", event.detail));
    item.append(text("span", "event-dot", ""), copy, text("time", "", new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))); return item;
  }) : [text("div", "empty", "No activity yet.")]));
}

function render(data) {
  state.data = data; const services = data.devices.reduce((sum, device) => sum + (device.services || []).length, 0); const active = data.tasks.some((task) => ["pending", "running"].includes(task.status));
  elements.agentCount.textContent = data.agents.length; elements.deviceCount.textContent = data.devices.length; elements.serviceCount.textContent = services; elements.statusCount.textContent = active ? "Scanning" : "Idle";
  elements.statusText.textContent = active ? "Agent scan in progress" : (data.agents.length ? "Workspace synchronized" : "Connect your first agent");
  if (data.pairCode) setPairCode(data.pairCode);
  elements.pairPanel.classList.toggle("compact", data.agents.length > 0); elements.refreshTime.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  renderAgents(data); renderDevices(data); renderEvents(data);
}

async function refresh() {
  if (!state.token) return;
  try { render(await request("/api/global/workspace")); }
  catch (error) { if (error.message === "Unauthorized.") { localStorage.removeItem("netscope-workspace-token"); state.token = null; location.reload(); } else toast(error.message, true); }
}

elements.create.addEventListener("click", createWorkspace); elements.newPairCode.addEventListener("click", newPairCode);
elements.copy.addEventListener("click", async () => { await navigator.clipboard.writeText(elements.installCommand.textContent); toast("Install command copied."); });
elements.search.addEventListener("input", (event) => { state.query = event.target.value.trim(); if (state.data) renderDevices(state.data); });
elements.forget.addEventListener("click", () => { if (confirm("Forget this workspace token in this browser?")) { localStorage.removeItem("netscope-workspace-token"); location.href = "/global"; } });
document.querySelectorAll(".dash-nav-item").forEach((button) => button.addEventListener("click", () => openWorkspaceView(button.dataset.workspaceView)));
document.querySelectorAll("[data-open-view]").forEach((button) => button.addEventListener("click", () => openWorkspaceView(button.dataset.openView)));
elements.themeToggle.addEventListener("click", () => {
  const next = document.documentElement.dataset.globalTheme === "dark" ? "light" : "dark";
  document.documentElement.dataset.globalTheme = next;
  localStorage.setItem("netscope-global-theme", next);
});
elements.drawerClose.addEventListener("click", closeDeviceProfile);
elements.drawerBackdrop.addEventListener("click", closeDeviceProfile);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDeviceProfile(); });
window.addEventListener("popstate", () => openWorkspaceView(location.pathname.slice(1), false));

if (state.token) {
  const requestedView = ["inventory", "agents", "activity"].includes(location.pathname.slice(1)) ? location.pathname.slice(1) : "inventory";
  showWorkspace(location.pathname === "/global" || location.pathname === "/");
  openWorkspaceView(requestedView, false);
  refresh();
  state.timer = setInterval(refresh, 3000);
}
