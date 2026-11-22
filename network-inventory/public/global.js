const state = { token: localStorage.getItem("netscope-workspace-token"), data: null, query: "", timer: null };
const $ = (selector) => document.querySelector(selector);
const elements = {
  welcome: $("#welcomeView"), workspace: $("#workspaceView"), create: $("#createWorkspace"), forget: $("#forgetWorkspace"),
  pairPanel: $("#pairPanel"), pairCode: $("#pairCode"), newPairCode: $("#newPairCode"), installCommand: $("#installCommand"), copy: $("#copyCommand"),
  agentCount: $("#agentCount"), deviceCount: $("#deviceCount"), serviceCount: $("#serviceCount"), statusCount: $("#statusCount"),
  agentList: $("#agentList"), deviceRows: $("#deviceRows"), deviceEmpty: $("#deviceEmpty"), eventList: $("#eventList"),
  search: $("#deviceSearch"), refreshTime: $("#refreshTime"), toast: $("#toast"),
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

function showWorkspace() { elements.welcome.hidden = true; document.querySelector(".principles").hidden = true; elements.workspace.hidden = false; }

async function createWorkspace() {
  try {
    elements.create.disabled = true;
    const data = await request("/api/global/workspaces", { method: "POST", body: "{}" });
    state.token = data.workspaceToken;
    localStorage.setItem("netscope-workspace-token", state.token);
    showWorkspace();
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

async function startScan(agentId, network, button) {
  try { button.disabled = true; await request("/api/global/scans", { method: "POST", body: JSON.stringify({ agentId, network }) }); toast(`Scan queued for ${network}.`); await refresh(); }
  catch (error) { toast(error.message, true); button.disabled = false; }
}

function renderDevices(data) {
  const agents = Object.fromEntries(data.agents.map((agent) => [agent.id, agent.name]));
  const query = state.query.toLowerCase();
  const devices = data.devices.filter((device) => [device.name, device.ip, device.mac, device.vendor, ...(device.services || []).map((service) => `${service.name} ${service.port}`)].filter(Boolean).join(" ").toLowerCase().includes(query));
  elements.deviceRows.replaceChildren(...devices.map((device) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td"); identity.append(text("strong", "device-name", device.name || "Unknown device"), text("small", "", device.vendor || "Unknown vendor"));
    const services = (device.services || []).map((service) => `${service.name}:${service.port}`).join(", ") || "None found";
    row.append(identity, text("td", "", agents[device.agentId] || "Unknown"), text("td", "", device.typeLabel || "Unknown"), text("td", "mono", device.ip), text("td", "mono", device.mac || "Not available"), text("td", "service-copy", services)); return row;
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
elements.forget.addEventListener("click", () => { if (confirm("Forget this workspace token in this browser?")) { localStorage.removeItem("netscope-workspace-token"); location.reload(); } });

if (state.token) { showWorkspace(); refresh(); state.timer = setInterval(refresh, 3000); }
