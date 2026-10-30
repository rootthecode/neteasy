"use strict";
// Toolbox view: ping, telnet/port check, traceroute, DNS, port scan, Wake-on-LAN, speed test.
// Backend: run_tool / poll_tool / stop_tool (neteasy/tools.py). Shares helpers from app.js.

const HOST = { k: "host", label: "Host or IP", ph: "e.g. 8.8.8.8 or google.com", wide: true, hosts: true };
const TOOL_DEFS = [
  { id: "ping", name: "Ping", icon: "pulse", desc: "ICMP echo with live latency, packet loss and jitter. Count 0 = continuous, like ping -t.",
    fields: [HOST, { k: "count", label: "Count", type: "number", def: 4 }, { k: "size", label: "Bytes", type: "number", def: 32 },
      { k: "interval", label: "Interval (s)", type: "number", def: 1, step: 0.1 }, { k: "df", label: "Don't fragment (MTU test)", type: "checkbox" }] },
  { id: "tcp", name: "Telnet / port check", icon: "plug", desc: "Like telnet host port: shows OPEN / CLOSED / FILTERED, connect time and the service banner.",
    fields: [HOST, { k: "port", label: "Port", type: "number", def: 23, ports: [23, 22, 80, 443, 3389, 445, 25, 21, 8080, 554] },
      { k: "count", label: "Attempts", type: "number", def: 3 }] },
  { id: "trace", name: "Traceroute", icon: "route", desc: "Hop-by-hop path to a host (tracert): find where latency or loss starts.",
    fields: [HOST, { k: "max_hops", label: "Max hops", type: "number", def: 30 }] },
  { id: "dns", name: "DNS lookup", icon: "dns", desc: "Ask several DNS servers at once and compare answers and speed. \"system\" = this PC's DNS.",
    fields: [{ k: "name", label: "Name (or IP for PTR)", ph: "e.g. google.com", wide: true },
      { k: "type", label: "Type", type: "select", options: ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR", "SOA", "SRV"], def: "A" },
      { k: "servers", label: "DNS servers", def: "system, 8.8.8.8, 1.1.1.1", wide: true }] },
  { id: "portscan", name: "Port scan", icon: "radar", desc: "TCP connect scan. Ports: common · 1-1024 · 22,80,443 · all.",
    fields: [HOST, { k: "ports", label: "Ports", def: "common" }] },
  { id: "wol", name: "Wake-on-LAN", icon: "power", desc: "Send a magic packet to wake a sleeping PC on this LAN.",
    fields: [{ k: "mac", label: "MAC address", ph: "AA:BB:CC:DD:EE:FF", wide: true, macs: true }] },
  { id: "speed", name: "Speed test", icon: "gauge", desc: "Download and upload throughput via Cloudflare (about 20 s, uses ~100–300 MB).", fields: [] },
];

const tools = { current: "ping", job: null, since: 0, timer: null, values: {} };

function setView(view) {
  document.querySelectorAll("#viewSwitch button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $("#devicesView").classList.toggle("hidden", view !== "devices");
  $("#toolsView").classList.toggle("hidden", view !== "tools");
  $("#cards").classList.toggle("hidden", view === "tools"); // give the console the full height
  if (view === "tools") {
    closeDrawer();
    renderToolList();
  }
}

function renderToolList() {
  $("#toolList").innerHTML = TOOL_DEFS.map((t) =>
    `<button class="tool-item ${t.id === tools.current ? "active" : ""}" data-tool="${t.id}">${icon(t.icon)}<span>${t.name}</span></button>`).join("");
}

function quickHosts() {
  const n = state.net || {};
  const list = [];
  if (state.selected) list.push([state.selected, "selected"]);
  if (n.gateway) list.push([n.gateway, "router"]);
  list.push(["8.8.8.8", "Google DNS"], ["1.1.1.1", "Cloudflare"], ["google.com", ""]);
  return list.filter((v, i, a) => a.findIndex((x) => x[0] === v[0]) === i);
}

function fieldHtml(f) {
  const v = tools.values[f.k] ?? f.def ?? "";
  const id = `tf-${f.k}`;
  let input;
  if (f.type === "select") input = `<select id="${id}" name="${f.k}">${f.options.map((o) => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select>`;
  else if (f.type === "checkbox") return `<label class="tf check"><input type="checkbox" name="${f.k}" ${v ? "checked" : ""}><span>${f.label}</span></label>`;
  else input = `<input id="${id}" name="${f.k}" type="${f.type === "number" ? "number" : "text"}" value="${esc(v)}" placeholder="${esc(f.ph || "")}"${f.step ? ` step="${f.step}"` : ""} autocomplete="off" spellcheck="false">`;
  let chips = "";
  if (f.hosts) chips = quickHosts().map(([h, l]) => `<button type="button" class="qchip" data-set="${f.k}" data-val="${esc(h)}">${esc(h)}${l ? `<i>${esc(l)}</i>` : ""}</button>`).join("");
  if (f.ports) chips = f.ports.map((p) => `<button type="button" class="qchip" data-set="${f.k}" data-val="${p}">${p}</button>`).join("");
  if (f.macs) {
    chips = (state.scan?.devices || []).filter((d) => d.mac && !d.is_self && !d.is_gateway)
      .map((d) => `<button type="button" class="qchip" data-set="${f.k}" data-val="${esc(d.mac)}">${esc(d.name || d.ip)}<i>${esc(d.mac)}</i></button>`).join("");
  }
  return `<label class="tf ${f.wide ? "wide" : ""}" for="${id}"><span>${f.label}</span>${input}${chips ? `<div class="qchips">${chips}</div>` : ""}</label>`;
}

function renderTool() {
  const t = TOOL_DEFS.find((x) => x.id === tools.current);
  $("#toolTitle").innerHTML = `${icon(t.icon)}${t.name}`;
  $("#toolDesc").textContent = t.desc;
  const running = !!tools.job;
  $("#toolForm").innerHTML = `<div class="tf-grid">${t.fields.map(fieldHtml).join("")}</div>
    <div class="tf-actions">
      <button type="submit" class="btn primary ${running ? "scanning" : ""}" id="toolRun">${running ? `${icon("stop")}Stop` : `${icon("play")}Run`}</button>
      <button type="button" class="btn ghost small" id="toolCopy">${icon("copy")}Copy output</button>
      <button type="button" class="btn ghost small" id="toolClear">${icon("close")}Clear</button>
    </div>`;
}

function readForm() {
  const form = $("#toolForm");
  const out = {};
  form.querySelectorAll("input, select").forEach((el) => {
    out[el.name] = el.type === "checkbox" ? el.checked : el.type === "number" ? (el.value === "" ? null : Number(el.value)) : el.value;
  });
  return out;
}

function selectTool(id, values = {}) {
  if (tools.job) stopTool();
  tools.current = id;
  tools.values = { ...values };
  renderToolList();
  renderTool();
  clearOutput();
}

function clearOutput() {
  $("#toolOut").innerHTML = "";
  $("#toolStats").innerHTML = "";
}

function appendLines(events) {
  const out = $("#toolOut");
  const stick = out.scrollHeight - out.scrollTop - out.clientHeight < 40;
  const frag = document.createDocumentFragment();
  for (const e of events) {
    const div = document.createElement("div");
    div.className = `ln ${e.level}`;
    div.textContent = e.text; // textContent: banners and DNS answers are untrusted
    frag.append(div);
  }
  out.append(frag);
  while (out.childElementCount > 3000) out.firstChild.remove();
  if (stick) out.scrollTop = out.scrollHeight;
}

function renderStats(stats) {
  $("#toolStats").innerHTML = Object.entries(stats || {}).map(([k, v]) => `<div class="stat"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("");
}

async function runTool() {
  const params = readForm();
  tools.values = params;
  clearOutput();
  const res = await call("run_tool", tools.current, params);
  if (!res || res.error) return;
  tools.job = res.job;
  tools.since = 0;
  renderTool();
  clearInterval(tools.timer);
  tools.timer = setInterval(pollTool, 250);
}

async function pollTool() {
  if (!tools.job) return;
  const job = tools.job;
  const r = await api.poll_tool(job, tools.since);
  if (!r || r.error || job !== tools.job) return;
  tools.since = r.next;
  if (r.events.length) appendLines(r.events);
  renderStats(r.stats);
  if (r.done) {
    clearInterval(tools.timer);
    tools.job = null;
    tools.values = readForm();
    renderTool();
  }
}

async function stopTool() {
  if (tools.job) await call("stop_tool", tools.job);
}

// Entry point used by the device drawer: jump to a tool with fields pre-filled.
function openTool(id, values, autorun = true) {
  setView("tools");
  selectTool(id, values);
  if (autorun) runTool();
}

function bindTools() {
  $("#viewSwitch").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-view]");
    if (b) setView(b.dataset.view);
  });
  $("#toolList").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tool]");
    if (b && b.dataset.tool !== tools.current) selectTool(b.dataset.tool, {});
  });
  $("#toolForm").addEventListener("submit", (e) => {
    e.preventDefault();
    tools.job ? stopTool() : runTool();
  });
  $("#toolForm").addEventListener("click", (e) => {
    const q = e.target.closest(".qchip");
    if (q) {
      const input = $("#toolForm").querySelector(`[name="${q.dataset.set}"]`);
      input.value = q.dataset.val;
      input.focus();
    } else if (e.target.closest("#toolCopy")) {
      copy([...$("#toolOut").children].map((d) => d.textContent).join("\n") || "(empty)");
    } else if (e.target.closest("#toolClear")) {
      clearOutput();
    }
  });
  renderToolList();
  renderTool();
}
