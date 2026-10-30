"use strict";
// NetEasy UI. All data comes from window.pywebview.api (see neteasy/app.py).
// Every value from the network (hostnames, vendors…) is untrusted: always render through esc().

const $ = (sel) => document.querySelector(sel);
const state = { net: null, pub: null, health: null, scan: null, filter: "all", query: "", selected: null, seen: new Set(),
  live: loadPref("live", true), liveTimer: null, known: null, background: false };
let api = null;
let pollTimer = null;
const LIVE_INTERVAL_MS = 45000;

function loadPref(key, fallback) {
  try {
    const v = localStorage.getItem(`neteasy.${key}`);
    return v === null ? fallback : JSON.parse(v);
  } catch {
    return fallback;
  }
}

function savePref(key, value) {
  try {
    localStorage.setItem(`neteasy.${key}`, JSON.stringify(value));
  } catch { /* storage unavailable: preference just isn't remembered */ }
}

function ago(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
}

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const dash = '<span class="muted">—</span>';
const val = (v) => (v === null || v === undefined || v === "" ? dash : esc(v));
const copyable = (v, cls = "") => (v ? `<span class="copy ${cls}" data-copy="${esc(v)}" title="Click to copy">${esc(v)}</span>` : dash);

const ICONS = {
  router: '<path d="M4 15h16v5H4z"/><path d="M8 17.5h.01M12 17.5h.01"/><path d="M8 11a5.5 5.5 0 0 1 8 0"/><path d="M5.5 8.5a9 9 0 0 1 13 0"/>',
  computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  printer: '<path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
  camera: '<path d="M3 7h12l3 3v4l-3 3H3z"/><circle cx="9" cy="12" r="2.5"/><path d="m18 10 3-2v8l-3-2"/>',
  tv: '<rect x="2.5" y="5" width="19" height="13" rx="2"/><path d="M8 21h8M9 2l3 3 3-3"/>',
  network: '<rect x="2.5" y="13" width="19" height="7" rx="2"/><path d="M6 16.5h.01M9.5 16.5h.01M13 16.5h.01"/><path d="M12 13V8M8 8h8"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  device: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/>',
  unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01"/>',
  pc: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  wifi: '<path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><path d="M12 19h.01"/>',
  ethernet: '<path d="M5 4h14v11H5z"/><path d="M8 15v5h8v-5M9 7v3M12 7v3M15 7v3"/>',
  dns: '<path d="M4 6h16M4 12h16M4 18h10"/><circle cx="18" cy="18" r="2"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
  web: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18"/>',
  rdp: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="m10 8 3 2-3 2M8 20h8"/>',
  folder: '<path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  play: '<path d="M7 4.5v15l12-7.5z"/>',
  plug: '<path d="M9 3v5M15 3v5"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v4"/>',
  route: '<circle cx="5" cy="18" r="2"/><circle cx="19" cy="6" r="2"/><path d="M7 18h8a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h8"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 19 5"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 7.5a8 8 0 1 0 11.4 0"/>',
  gauge: '<path d="M4 18a9 9 0 1 1 16 0"/><path d="m12 14 4-5"/>',
  warn: '<path d="M12 4 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24">${ICONS[name] || ICONS.unknown}</svg>`;

const KIND_LABEL = {
  router: "Router", computer: "Computer", phone: "Mobile device", printer: "Printer", camera: "IP camera",
  tv: "TV / media device", network: "Network device", server: "Server", device: "Device", unknown: "Unknown device",
};

const FILTERS = [
  { id: "all", label: "All", match: () => true },
  { id: "computer", label: "Computers", match: (d) => d.kind === "computer" || d.kind === "server" },
  { id: "phone", label: "Phones", match: (d) => d.kind === "phone" },
  { id: "network", label: "Network", match: (d) => d.kind === "router" || d.kind === "network" },
  { id: "media", label: "Printers & cams", match: (d) => ["printer", "camera", "tv"].includes(d.kind) },
  { id: "other", label: "Other", match: (d) => d.kind === "device" || d.kind === "unknown" },
];

// ---------- helpers ----------
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2200);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(`Copied ${text}`);
}

async function call(method, ...args) {
  try {
    const res = await api[method](...args);
    if (res && res.error) toast(res.error);
    return res;
  } catch (err) {
    toast(`Error: ${err.message || err}`);
    return { error: String(err) };
  }
}

const latClass = (ms) => (ms == null ? "bad" : ms < 20 ? "ok" : ms < 80 ? "warn" : "bad");
const fmtMs = (ms) => (ms == null ? "—" : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`);

function signalBars(pct) {
  const n = Math.max(0, Math.min(4, Math.ceil((parseInt(pct, 10) || 0) / 25)));
  return `<span class="signal">${[1, 2, 3, 4].map((i) => `<i class="${i <= n ? "on" : ""}"></i>`).join("")}</span>`;
}

function card(ico, title, body, extra = "") {
  return `<article class="card glass"><div class="card-head"><span class="ico">${icon(ico)}</span><h3>${title}</h3><span class="spacer"></span>${extra}</div>${body}</article>`;
}
const kv = (rows) => `<dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
const skel = '<span class="skeleton"></span>';

// ---------- info cards ----------
function renderCards() {
  const n = state.net;
  const p = state.pub;
  const h = state.health;
  if (!n) {
    $("#cards").innerHTML = ["pc", "router", "globe", "wifi", "pulse"].map((i) => card(i, "Loading", `<div class="big">${skel}</div>${skel}`)).join("");
    return;
  }

  const thisPc = card("pc", "This computer",
    `<div class="big">${copyable(n.ip, "mono")}</div>` +
    kv([["Name", val(n.hostname)], ["MAC", copyable(n.mac, "mono")], ["Subnet", copyable(n.cidr, "mono")], ["Adapter", val(n.adapter)]]));

  const gwBtn = n.gateway ? `<button class="btn small" data-web="${esc(n.gateway)}">${icon("web")}Admin</button>` : "";
  const routerVendor = state.scan?.devices?.find((d) => d.is_gateway)?.vendor;
  const router = card("router", "Router",
    `<div class="big">${copyable(n.gateway || "No gateway", "mono")}</div>` +
    kv([["MAC", copyable(n.gateway_mac, "mono")], ["Vendor", val(routerVendor)], ["DHCP server", copyable(n.dhcp_server, "mono")],
        ["Lease ends", n.lease_expires ? esc(new Date(n.lease_expires * 1000).toLocaleString()) : dash]]), gwBtn);

  const internet = card("globe", "Internet / ISP",
    p ? (p.error ? `<div class="big" style="color:var(--bad)">Offline</div><p class="muted">${esc(p.error)}</p>`
      : `<div class="big">${copyable(p.ip, "mono")}</div>` +
        kv([["ISP", val(p.isp)], ["ASN", val(p.asn)], ["Location", val([p.city, p.country].filter(Boolean).join(", "))], ["DNS", copyable((n.dns || []).join(", "), "mono")]]))
      : `<div class="big">${skel}</div>${skel}<br>${skel}`);

  const w = n.wifi || {};
  const link = w.ssid
    ? card("wifi", "Wi-Fi",
        `<div class="big">${copyable(w.ssid)}</div>` +
        kv([["Signal", `${signalBars(w.signal)}${val(w.signal)}`], ["Channel", val([w.channel, w.band].filter(Boolean).join(" · "))],
            ["Standard", val(w.radio)], ["Link rate", w.rx_mbps ? `${esc(w.rx_mbps)} / ${esc(w.tx_mbps)} Mbps` : dash], ["Security", val(w.auth)]]))
    : card("ethernet", "Connection",
        `<div class="big">${val(n.adapter || "Unknown")}</div>` +
        kv([["Type", n.adapter ? "Wired / other" : dash], ["Link speed", n.speed_mbps ? `${esc(n.speed_mbps)} Mbps` : dash], ["Domain", val(n.domain)]]));

  const row = (label, r) => [label, r ? `<span class="pill"><span class="dot ${r.loss_pct === 100 ? "bad" : latClass(r.avg_ms)}"></span>${fmtMs(r.avg_ms)}${r.loss_pct ? ` · ${r.loss_pct}% loss` : ""}</span>` : dash];
  const health = card("pulse", "Connection health",
    h ? `<div class="big">${h.gateway && h.gateway.loss_pct < 100 && h.internet.some((x) => x.loss_pct < 100) ? "Online" : "Problem"}</div>` +
        kv([row("Router", h.gateway), row("1.1.1.1", h.internet[0]), row("8.8.8.8", h.internet[1]),
            ["DNS lookup", h.dns_ms == null ? '<span class="pill"><span class="dot bad"></span>failed</span>' : `<span class="pill"><span class="dot ${latClass(h.dns_ms / 3)}"></span>${fmtMs(h.dns_ms)}</span>`]])
      : `<div class="big">${skel}</div><p class="muted">Pinging router &amp; internet…</p>`);

  $("#cards").innerHTML = thisPc + router + internet + link + health;
}

function renderHeader() {
  const n = state.net;
  if (!n) return;
  const where = n.wifi?.ssid ? `Wi-Fi “${esc(n.wifi.ssid)}”` : esc(n.adapter || "network");
  $("#netLabel").innerHTML = `${where} · <span class="mono">${esc(n.cidr || n.ip)}</span>`;
}

// ---------- device table ----------
function deviceMatches(d) {
  const f = FILTERS.find((x) => x.id === state.filter) || FILTERS[0];
  if (!f.match(d)) return false;
  const q = state.query.trim().toLowerCase();
  if (!q) return true;
  return [d.ip, d.name, d.mac, d.vendor, d.os, d.hostname, d.netbios, d.mdns_name, d.model, d.upnp_model,
    ...d.services.map((s) => s.name)]
    .some((v) => v && String(v).toLowerCase().includes(q));
}

function renderFilters(devices) {
  $("#filters").innerHTML = FILTERS.map((f) => {
    const c = devices.filter(f.match).length;
    return `<button class="chip ${state.filter === f.id ? "active" : ""}" data-filter="${f.id}">${f.label}<b>${c}</b></button>`;
  }).join("");
}

function deviceRow(d) {
  const tags = (d.is_self ? '<span class="tag you">You</span>' : "") + (d.is_gateway ? '<span class="tag gw">Router</span>' : "") +
    (d.randomized_mac ? '<span class="tag rnd" title="Private / randomized MAC">Private</span>' : "");
  const title = d.name || KIND_LABEL[d.kind] || "Unknown device";
  const isNew = !state.seen.has(d.ip);
  state.seen.add(d.ip);
  const latency = !d.online ? `offline · ${ago(d.last_seen)}` : d.rtt_ms == null ? (d.is_self ? "local" : "no ping") : fmtMs(d.rtt_ms);
  const latColor = !d.online || d.rtt_ms == null ? "faint" : latClass(d.rtt_ms);
  return `<tr data-ip="${esc(d.ip)}" class="${state.selected === d.ip ? "selected" : ""} ${isNew ? "new" : ""} ${d.online ? "" : "offline"}">
    <td><div class="dev"><span class="dev-ico k-${esc(d.kind)}">${icon(d.kind)}</span>
      <div style="min-width:0"><div class="dev-name">${esc(title)}${tags}</div><div class="dev-os">${esc([d.os, d.model || d.upnp_model].filter(Boolean).join(" · "))}</div></div></div></td>
    <td class="mono">${esc(d.ip)}</td>
    <td><div class="mono">${val(d.mac)}</div><div class="vendor">${d.vendor ? esc(d.vendor) : d.randomized_mac ? "Randomized (privacy) MAC" : ""}</div></td>
    <td>${d.services.length ? d.services.map((s) => `<span class="svc" title="TCP ${s.port}">${esc(s.name)}</span>`).join("") : dash}</td>
    <td class="num"><span class="lat" style="color:var(--${latColor})">${latency}</span></td>
  </tr>`;
}

function renderDevices() {
  const scan = state.scan;
  const devices = scan?.devices || [];
  renderFilters(devices);
  const shown = devices.filter(deviceMatches);
  $("#devBody").innerHTML = shown.map(deviceRow).join("");
  $("#devCount").textContent = devices.filter((d) => d.online).length;
  $("#empty").classList.toggle("hidden", shown.length > 0);
  $("#empty p").textContent = scan?.status === "scanning" ? "Listening for devices…" : devices.length ? "No devices match this filter" : "No devices yet";
  renderStatus();
  if (state.selected) renderDrawer();
}

// Cheap per-tick update: progress, button, status line. Never touches rows, so clicks aren't lost.
function renderStatus() {
  const scan = state.scan;
  const devices = scan?.devices || [];
  const scanning = scan?.status === "scanning";
  const pct = scan && scan.total ? (scan.done / scan.total) * 100 : 0;
  $("#progress").classList.toggle("on", scanning);
  $("#progressBar").style.width = `${scanning ? pct : 100}%`;
  const btn = $("#btnScan");
  btn.classList.toggle("scanning", scanning);
  btn.innerHTML = scanning ? `${icon("stop")}<span>Stop</span>` : `${icon("search")}<span>${devices.length ? "Rescan" : "Scan network"}</span>`;

  const status = $("#scanStatus");
  if (!scan || scan.status === "idle") status.innerHTML = "Press <b>Scan network</b> to discover everything on this LAN.";
  else if (scanning) status.textContent = `${scan.phase}… ${scan.done}/${scan.total} · ${scan.elapsed}s`;
  else if (scan.status === "error") status.textContent = `Scan failed: ${scan.error}`;
  else {
    const online = devices.filter((d) => d.online).length;
    const offline = devices.length - online;
    const when = state.lastScanAt ? new Date(state.lastScanAt).toLocaleTimeString() : "";
    status.textContent = `${scan.status === "cancelled" ? "Stopped" : `${state.live ? "Live · " : ""}Scanned ${when}`} in ${scan.elapsed}s · ` +
      `${online} online${offline ? ` · ${offline} offline (kept)` : ""}`;
  }
  const live = $("#btnLive");
  live.classList.toggle("on", state.live);
  live.title = state.live ? "Live: rescans every 45 s. Click to pause." : "Paused. Click to rescan automatically every 45 s.";

  const note = $("#scanNote");
  const showNote = !!scan?.note && !scanning;
  note.classList.toggle("hidden", !showNote);
  if (showNote) {
    const gw = state.net?.gateway;
    note.innerHTML = `${icon("warn")}<span>${esc(scan.note)}</span>` +
      (gw ? `<button class="btn small" data-web="${esc(gw)}">${icon("web")}Router admin</button>` : "");
  }
}

// ---------- detail drawer ----------
function renderDrawer() {
  const d = state.scan?.devices.find((x) => x.ip === state.selected);
  const el = $("#drawer");
  if (!d) return closeDrawer();
  const has = (p) => d.ports.includes(p);
  const webPort = [80, 443, 8080, 8443].find(has) ?? (d.is_gateway ? 80 : null);
  const actions = [
    `<button class="btn small" data-copy="${esc(d.ip)}">${icon("copy")}Copy IP</button>`,
    d.mac ? `<button class="btn small" data-copy="${esc(d.mac)}">${icon("copy")}Copy MAC</button>` : "",
    webPort ? `<button class="btn small" data-web="${esc(d.ip)}" data-port="${webPort}">${icon("web")}Open web UI</button>` : "",
    has(3389) ? `<button class="btn small" data-rdp="${esc(d.ip)}">${icon("rdp")}Remote Desktop</button>` : "",
    has(445) || has(139) ? `<button class="btn small" data-share="${esc(d.ip)}">${icon("folder")}Browse shares</button>` : "",
  ].join("");
  const ip = esc(d.ip);
  const firstPort = d.ports[0] ?? 23;
  const toolBtns = [
    `<button class="btn small" data-run="ping" data-host="${ip}">${icon("pulse")}Ping</button>`,
    `<button class="btn small" data-run="tcp" data-host="${ip}" data-port="${firstPort}">${icon("plug")}Telnet / port</button>`,
    `<button class="btn small" data-run="trace" data-host="${ip}">${icon("route")}Traceroute</button>`,
    `<button class="btn small" data-run="portscan" data-host="${ip}">${icon("radar")}Port scan</button>`,
    d.mac && !d.is_self ? `<button class="btn small" data-run="wol" data-mac="${esc(d.mac)}">${icon("power")}Wake-on-LAN</button>` : "",
  ].join("");
  const upnp = [d.upnp_maker, d.upnp_model].filter(Boolean).join(" ");
  el.innerHTML = `
    <button class="btn small close" data-close>${icon("close")}</button>
    <span class="dev-ico hero k-${esc(d.kind)}">${icon(d.kind)}</span>
    <h2>${esc(d.name || KIND_LABEL[d.kind] || d.ip)}</h2>
    <p class="muted">${esc(d.os)} · ${esc(d.confidence)} confidence</p>
    <div class="act">${actions}</div>
    <div class="section">Troubleshoot</div>
    <div class="act">${toolBtns}</div>
    <div class="section">Identity</div>
    ${kv([["IP", copyable(d.ip, "mono")], ["MAC", copyable(d.mac, "mono")], ["Vendor", val(d.vendor || (d.randomized_mac ? "Randomized (privacy) MAC" : ""))],
          ["Hostname", val(d.hostname)], ["NetBIOS", val(d.netbios)], ["Workgroup", val(d.workgroup)],
          ["mDNS name", val(d.mdns_name)], ["Model", val(d.model)], ["UPnP", val(upnp || d.upnp_server)]])}
    <div class="section">Fingerprint</div>
    ${kv([["Status", d.online ? '<span class="pill"><span class="dot ok"></span>online</span>' : `<span class="pill"><span class="dot bad"></span>offline · seen ${ago(d.last_seen)}</span>`],
          ["First seen", d.first_seen ? esc(new Date(d.first_seen * 1000).toLocaleTimeString()) : dash],
          ["Type", val(d.kind)], ["TTL", val(d.ttl)], ["Latency", d.rtt_ms == null ? dash : fmtMs(d.rtt_ms)],
          ["Found by", val(d.found_by.join(", "))], ["Bonjour", val(d.bonjour.join(" "))]])}
    <div class="section">Open TCP ports</div>
    <div style="margin-top:8px">${d.services.length ? d.services.map((s) => `<span class="svc">${s.port} · ${esc(s.name)}</span>`).join("") : '<span class="muted">None of the common ports answered</span>'}</div>`;
  el.classList.add("open");
  el.setAttribute("aria-hidden", "false");
}

function closeDrawer() {
  state.selected = null;
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  document.querySelectorAll("tr.selected").forEach((r) => r.classList.remove("selected"));
}

// ---------- data loading ----------
async function loadNetwork() {
  state.net = null;
  state.pub = null;
  state.health = null;
  renderCards();
  const net = await call("get_network");
  if (net && !net.error) {
    const siteKey = `${net.cidr}|${net.gateway_mac || net.gateway}`;
    if (state.siteKey && siteKey !== state.siteKey) { // moved to another client's network
      state.known = null;
      state.seen.clear();
    }
    state.siteKey = siteKey;
    state.net = net;
  }
  renderHeader();
  renderCards();
  call("get_public").then((p) => { state.pub = p; renderCards(); });
  runHealth();
}

async function runHealth() {
  state.health = null;
  renderCards();
  const h = await call("connectivity");
  state.health = h && !h.error ? h : null;
  renderCards();
}

async function poll() {
  const snap = await call("get_scan");
  if (!snap || snap.error) return;
  const key = JSON.stringify(snap.devices);
  const changed = key !== state.devKey;
  state.devKey = key;
  state.scan = snap;
  if (state.known) announceNewDevices(snap.devices);
  if (changed) renderDevices();
  else renderStatus();
  if (snap.status !== "scanning") {
    clearInterval(pollTimer);
    pollTimer = null;
    state.lastScanAt = Date.now();
    renderStatus();
    renderCards(); // router vendor becomes known after a scan
    if (!state.known) state.known = new Set(snap.devices.map((d) => `${d.ip}|${d.mac}`));
    if (snap.status === "done" && !state.background) toast(`Scan complete: ${snap.devices.filter((d) => d.online).length} devices online`);
    scheduleLive();
  }
}

// Toast once for every device that was not on the network in an earlier scan.
function announceNewDevices(devices) {
  for (const d of devices) {
    const key = `${d.ip}|${d.mac}`;
    if (d.online && !state.known.has(key)) {
      state.known.add(key);
      toast(`New device: ${d.name || KIND_LABEL[d.kind] || "device"} (${d.ip})`);
    }
  }
}

function scheduleLive() {
  clearTimeout(state.liveTimer);
  state.liveTimer = state.live ? setTimeout(() => startScan(true), LIVE_INTERVAL_MS) : null;
}

async function startScan(background) {
  clearTimeout(state.liveTimer);
  if (state.scan?.status === "scanning") return;
  state.background = background;
  const res = await call("start_scan");
  if (res && res.error) return scheduleLive();
  clearInterval(pollTimer);
  pollTimer = setInterval(poll, 400);
  poll();
}

async function toggleScan() {
  if (state.scan?.status === "scanning") {
    await call("cancel_scan");
    return;
  }
  startScan(false);
}

function toggleLive() {
  state.live = !state.live;
  savePref("live", state.live);
  if (state.live && state.scan?.status !== "scanning") startScan(true);
  else scheduleLive();
  renderStatus();
}

// ---------- events ----------
function bindEvents() {
  $("#btnScan").addEventListener("click", toggleScan);
  $("#btnLive").addEventListener("click", toggleLive);
  $("#btnRefresh").addEventListener("click", loadNetwork);
  $("#btnHealth").addEventListener("click", runHealth);
  $("#btnExport").addEventListener("click", async () => {
    const r = await call("export_csv");
    if (r?.path) toast(`Saved ${r.path}`);
  });
  $("#search").addEventListener("input", (e) => { state.query = e.target.value; renderDevices(); });

  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-copy],[data-filter],[data-web],[data-rdp],[data-share],[data-run],[data-close],tbody tr");
    if (!t) return;
    if (t.dataset.run) {
      const { host, port, mac } = t.dataset;
      openTool(t.dataset.run, { host, port: port ? Number(port) : undefined, mac });
    } else if (t.dataset.copy) copy(t.dataset.copy);
    else if (t.dataset.filter) { state.filter = t.dataset.filter; renderDevices(); }
    else if (t.dataset.web) call("open_web", t.dataset.web, Number(t.dataset.port || 80));
    else if (t.dataset.rdp) call("open_rdp", t.dataset.rdp);
    else if (t.dataset.share) call("open_share", t.dataset.share);
    else if (t.hasAttribute("data-close")) closeDrawer();
    else if (t.dataset.ip) {
      state.selected = t.dataset.ip;
      document.querySelectorAll("tr.selected").forEach((r) => r.classList.remove("selected"));
      t.classList.add("selected");
      renderDrawer();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
    if ((e.ctrlKey && e.key.toLowerCase() === "f") || (e.key === "/" && document.activeElement.tagName !== "INPUT")) {
      e.preventDefault();
      $("#search").focus();
    }
    if (e.key === "F5") { e.preventDefault(); toggleScan(); }
  });
}

async function init() {
  if (api) return;
  api = window.pywebview.api;
  bindEvents();
  bindTools();
  renderDevices();
  await loadNetwork();
  toggleScan(); // auto-scan on launch: that is why the app was opened
}

renderCards();
window.addEventListener("pywebviewready", init);
if (window.pywebview?.api) init();
