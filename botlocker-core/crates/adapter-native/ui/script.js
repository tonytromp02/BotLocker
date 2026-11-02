(() => {
  "use strict";

  const API = window.BOTLOCKER_API || "";

  // The UI calls /api on its own origin. The server adds the API key when it forwards the call,
  // so this page never holds the key.
  function apiFetch(path, opts = {}) {
    return fetch(API + path, { cache: "no-store", ...opts });
  }

  const $ = (id) => document.getElementById(id);
  const NS = "http://www.w3.org/2000/svg";
  const W = 1000, H = 600, CX = W / 2, CY = H / 2;
  const KIND_COLOR = {
    origin: "#e8e8f0", challenge: "#fbbf24", maze: "#d946ef",
    captured: "#a78bfa", challenged: "#fbbf24", passing: "#5eead4",
  };
  const EDGE_COLOR = { proxy: "#5eead4", challenge: "#fbbf24", trap: "#a78bfa" };
  // Plain-language reasons for a capture. Keys match the reason labels from the core.
  const WHY_LABEL = {
    honeypot: "Requested a maze path (honeypot)",
    automated: "Browser report flagged automation",
    scored: "Signal score crossed the trap threshold",
  };

  const SYSTEM_INFO = {
    origin: "Your origin site. Proxied requests land here.",
    challenge: "Browser challenge page. Passing it sets a signed cookie, and the browser continues to the page.",
    maze: "Trap pages. Scrapers that reach them are captured and fed endless generated pages.",
  };

  const state = { clients: [], events: [], selected: null, tab: "graph" };
  const sim = {
    nodes: new Map(), links: [], alpha: 0,
    nodeEls: new Map(), linkEls: new Map(), drag: null,
  };

  // ---------- helpers (no innerHTML: visitor data is untrusted) ----------
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (typeof v === "function") node.addEventListener(k.replace(/^on/, ""), v);
      else if (k === "class") node.className = v;
      else node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }
  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }
  function pill(status) {
    const label = { captured: "captured", challenged: "challenged", passing: "passing",
                    proxied: "proxied", trapped: "trapped" }[status] || status;
    return el("span", { class: `pill ${label}` }, label);
  }
  const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString();
  const fmtScore = (n) => Number(n).toFixed(1);
  const kv = (k, v) => el("div", { class: "kv" }, el("span", {}, k), el("span", {}, String(v)));

  async function getJSON(path) {
    const r = await apiFetch(path);
    if (!r.ok) throw new Error(`${path} → ${r.status}`);
    return r.json();
  }

  // ---------- polling ----------
  async function poll() {
    try {
      const [summary, clients, graph, events] = await Promise.all([
        getJSON("/api/summary"), getJSON("/api/clients"),
        getJSON("/api/graph"), getJSON("/api/events?limit=150"),
      ]);
      setOnline(true);
      renderSummary(summary);
      state.clients = clients;
      state.events = events;
      syncGraph(graph);
      renderCaptured();
      renderFeed();
      renderDetail();
      $("updated").textContent = "updated " + new Date().toLocaleTimeString();
    } catch (err) {
      setOnline(false);
    }
  }

  function setOnline(ok) {
    $("dot").classList.toggle("off", !ok);
    $("status-text").textContent = ok ? "live · polling every 2s" : "offline · retrying";
  }

  function renderSummary(s) {
    for (const key of ["requests", "proxied", "challenged", "trapped", "captured"]) {
      $(`s-${key}`).textContent = Number(s[key] ?? 0).toLocaleString();
    }
  }

  // ---------- graph ----------
  function radius(n) {
    if (n.kind === "origin") return 26;
    if (n.kind === "maze") return 24;
    if (n.kind === "challenge") return 20;
    return 6 + Math.min(12, Math.log2((n.requests || 1) + 1) * 2.2);
  }

  // System nodes sit at fixed anchors so the client nodes orbit around them.
  const ANCHORS = {
    origin: { x: 270, y: 300 },
    challenge: { x: 730, y: 150 },
    maze: { x: 730, y: 450 },
  };
  const isSystem = (kind) => kind in ANCHORS;

  function syncGraph(g) {
    const seen = new Set();
    for (const n of g.nodes) {
      seen.add(n.id);
      let s = sim.nodes.get(n.id);
      if (!s) {
        const anchor = ANCHORS[n.kind];
        s = {
          id: n.id,
          x: anchor ? anchor.x : CX + (Math.random() - 0.5) * 260,
          y: anchor ? anchor.y : CY + (Math.random() - 0.5) * 260,
          vx: 0, vy: 0, fixed: isSystem(n.kind),
        };
        sim.nodes.set(n.id, s);
      }
      Object.assign(s, n);
    }
    for (const id of [...sim.nodes.keys()]) if (!seen.has(id)) sim.nodes.delete(id);

    sim.links = g.edges
      .filter((e) => sim.nodes.has(e.source) && sim.nodes.has(e.target))
      .map((e) => ({ ...e, key: `${e.source}|${e.target}|${e.action}` }));

    $("empty").style.display = sim.nodes.size > 3 ? "none" : "grid";
    sim.alpha = Math.max(sim.alpha, 0.6);
    buildElements();
  }

  function buildElements() {
    const linkLayer = $("links");
    const nodeLayer = $("nodes");

    const wantedLinks = new Set(sim.links.map((l) => l.key));
    for (const [key, line] of sim.linkEls) {
      if (!wantedLinks.has(key)) { line.remove(); sim.linkEls.delete(key); }
    }
    for (const l of sim.links) {
      let line = sim.linkEls.get(l.key);
      if (!line) {
        line = svgEl("line", { class: "edge" });
        linkLayer.append(line);
        sim.linkEls.set(l.key, line);
      }
      line.setAttribute("class", `edge ${l.action}`);
      line.setAttribute("stroke", EDGE_COLOR[l.action] || "#888");
      line.setAttribute("stroke-width", (1 + Math.min(4, Math.log2(l.count + 1))).toFixed(2));
    }

    const wantedNodes = new Set(sim.nodes.keys());
    for (const [id, g] of sim.nodeEls) {
      if (!wantedNodes.has(id)) { g.remove(); sim.nodeEls.delete(id); }
    }
    for (const n of sim.nodes.values()) {
      let g = sim.nodeEls.get(n.id);
      if (!g) {
        g = svgEl("g", { class: "node" });
        g.append(svgEl("circle"), svgEl("text", { dy: "0.35em" }));
        g.addEventListener("pointerdown", (ev) => startDrag(ev, n.id));
        g.addEventListener("click", () => select(n.id));
        nodeLayer.append(g);
        sim.nodeEls.set(n.id, g);
      }
      const system = ["origin", "challenge", "maze"].includes(n.kind);
      const captured = n.kind === "captured" || n.kind === "maze";
      g.setAttribute("class", `node${system ? " system" : ""}${state.selected === n.id ? " selected" : ""}`);
      const circle = g.querySelector("circle");
      circle.setAttribute("r", radius(n).toFixed(1));
      circle.setAttribute("fill", KIND_COLOR[n.kind] || "#888");
      circle.setAttribute("stroke", "rgba(255,255,255,.35)");
      circle.setAttribute("opacity", n.kind === "passing" ? "0.85" : "1");
      circle.setAttribute("filter", captured ? "url(#glow)" : "");
      const label = g.querySelector("text");
      label.textContent = system ? n.label : n.id;
      label.setAttribute("dy", "0");
      label.setAttribute("y", (radius(n) + 15).toFixed(1));
    }
  }

  function linkForce(a, b, rest, strength) {
    let dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
    const f = (d - rest) * strength;
    dx = (dx / d) * f; dy = (dy / d) * f;
    if (!a.fixed) { a.vx += dx; a.vy += dy; }
    if (!b.fixed) { b.vx -= dx; b.vy -= dy; }
  }

  function tick() {
    const nodes = [...sim.nodes.values()];
    const k = sim.alpha;

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        const d2 = Math.max(dx * dx + dy * dy, 100);
        const d = Math.sqrt(d2);
        const f = (3400 * k) / d2;
        dx = (dx / d) * f; dy = (dy / d) * f;
        if (!a.fixed) { a.vx += dx; a.vy += dy; }
        if (!b.fixed) { b.vx -= dx; b.vy -= dy; }
      }
    }
    for (const l of sim.links) {
      const a = sim.nodes.get(l.source), b = sim.nodes.get(l.target);
      if (a && b) linkForce(a, b, 190, 0.03 * k);
    }
    for (const n of nodes) {
      if (n.fixed) continue;
      n.vx += (CX - n.x) * 0.004 * k;
      n.vy += (CY - n.y) * 0.004 * k;
      n.vx *= 0.8; n.vy *= 0.8;
      n.x = Math.min(W - 40, Math.max(40, n.x + n.vx));
      n.y = Math.min(H - 40, Math.max(40, n.y + n.vy));
    }
    sim.alpha *= 0.972;
  }

  function draw() {
    for (const l of sim.links) {
      const line = sim.linkEls.get(l.key);
      const a = sim.nodes.get(l.source), b = sim.nodes.get(l.target);
      if (!line || !a || !b) continue;
      line.setAttribute("x1", a.x.toFixed(1)); line.setAttribute("y1", a.y.toFixed(1));
      line.setAttribute("x2", b.x.toFixed(1)); line.setAttribute("y2", b.y.toFixed(1));
    }
    for (const n of sim.nodes.values()) {
      const g = sim.nodeEls.get(n.id);
      if (g) g.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
    }
  }

  function loop() {
    if (sim.alpha > 0.005 || sim.drag) {
      tick();
      draw();
    }
    requestAnimationFrame(loop);
  }

  function toSvg(evt) {
    const svg = $("graph");
    const pt = svg.createSVGPoint();
    pt.x = evt.clientX; pt.y = evt.clientY;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  }

  function startDrag(evt, id) {
    evt.preventDefault();
    const n = sim.nodes.get(id);
    if (!n) return;
    sim.drag = { id, moved: false };
    n.fixed = true;
    const move = (e) => {
      const p = toSvg(e);
      n.x = Math.min(W - 30, Math.max(30, p.x));
      n.y = Math.min(H - 30, Math.max(30, p.y));
      sim.drag.moved = true;
      sim.alpha = Math.max(sim.alpha, 0.2);
      draw();
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      const moved = sim.drag && sim.drag.moved;
      n.fixed = isSystem(n.kind);
      sim.drag = null;
      if (!moved) select(id);
      else sim.alpha = Math.max(sim.alpha, 0.4);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  function select(id) {
    state.selected = id;
    for (const [nid, g] of sim.nodeEls) g.classList.toggle("selected", nid === id);
    renderDetail();
  }

  // ---------- captured / feed ----------
  function renderCaptured() {
    const list = $("captured");
    const captured = state.clients.filter((c) => c.status === "captured");
    if (captured.length === 0) {
      list.replaceChildren(el("div", { class: "empty-state" }, "No captured bots yet. Trapped clients appear here."));
      return;
    }
    list.replaceChildren(...captured.map((c) =>
      el("div", { class: "item", onclick: () => { select(c.ip); switchTab("graph"); } },
        el("div", { class: "item-top" }, el("span", { class: "mono" }, c.ip), pill(c.status)),
        el("div", { class: "item-ua mono" }, c.user_agent || "(no user agent)"),
        el("div", { class: "item-stats" },
          el("span", {}, "requests ", el("b", {}, c.requests)),
          el("span", {}, "trapped ", el("b", {}, c.trapped)),
          el("span", {}, "max score ", el("b", {}, fmtScore(c.max_score))),
          el("span", {}, "last ", el("b", {}, fmtTime(c.last_seen)))),
        el("div", { class: "why" },
          el("div", { class: "why-title" }, WHY_LABEL[c.captured_because] || c.captured_because || "reason not recorded"),
          c.captured_evidence.length
            ? el("div", { class: "chips" }, ...c.captured_evidence.slice(0, 6).map((e) => el("span", { class: "chip", title: e }, e)))
            : el("div", { class: "muted" }, "no evidence recorded")),
      )));
  }

  function renderFeed() {
    const head = el("div", { class: "feed-row feed-head" },
      el("span", {}, "time"), el("span", {}, "action"), el("span", {}, "client"),
      el("span", {}, "request"), el("span", { class: "score" }, "score"));
    const rows = state.events.map((e) =>
      el("div", { class: "feed-row" },
        el("span", { class: "muted mono" }, fmtTime(e.ts)),
        pill(e.action),
        el("span", { class: "mono" }, e.ip),
        el("span", { class: "path mono", title: `${e.method} ${e.path} · ${e.reason}` }, `${e.method} ${e.path}`),
        el("span", { class: "score mono" }, fmtScore(e.score))));
    $("feed").replaceChildren(head, ...rows);
  }

  // ---------- inspector ----------
  function renderDetail() {
    const box = $("detail");
    const id = state.selected;
    if (!id) {
      box.replaceChildren(el("div", { class: "muted" }, "Click a node in the graph to inspect it."));
      return;
    }
    if (SYSTEM_INFO[id]) {
      const n = sim.nodes.get(id);
      box.replaceChildren(
        el("span", { class: "pill passing" }, "system"),
        el("h3", {}, n ? n.label : id),
        el("p", { class: "muted" }, SYSTEM_INFO[id]),
      );
      return;
    }
    const c = state.clients.find((x) => x.ip === id);
    if (!c) {
      box.replaceChildren(el("div", { class: "muted" }, "This client is no longer in the window."));
      return;
    }
    const recent = state.events.filter((e) => e.ip === c.ip).slice(0, 6);
    box.replaceChildren(
      pill(c.status),
      el("h3", { class: "mono" }, c.ip),
      c.captured_because
        ? el("div", { class: "why" },
            el("div", { class: "why-title" }, "Captured because: " + (WHY_LABEL[c.captured_because] || c.captured_because)),
            c.captured_evidence.length
              ? el("ul", { class: "ev" }, ...c.captured_evidence.map((e) => el("li", {}, e)))
              : el("div", { class: "muted" }, "no evidence recorded"))
        : null,
      kv("requests", c.requests),
      kv("proxied", c.proxied),
      kv("challenged", c.challenged),
      kv("trapped", c.trapped),
      kv("max score", fmtScore(c.max_score)),
      kv("first seen", fmtTime(c.first_seen)),
      kv("last seen", fmtTime(c.last_seen)),
      el("div", { class: "block mono" }, c.user_agent || "(no user agent)"),
      c.evidence.length
        ? el("ul", { class: "ev" }, ...c.evidence.map((e) => el("li", {}, e)))
        : el("p", { class: "muted" }, "No scoring evidence."),
      recent.length
        ? el("div", { class: "recent" },
            el("div", { class: "muted", style: "text-transform:uppercase;letter-spacing:.08em;font-size:11px" }, "recent"),
            ...recent.map((e) => el("div", {}, el("span", { class: "mono" }, fmtTime(e.ts)), el("span", {}, `${e.action} ${e.method} ${e.path}`))))
        : null,
    );
  }

  // ---------- settings ----------
  const SETTINGS_SECTIONS = [
    { title: "Detection", fields: [
      { key: "challenge_at", label: "Challenge at score", type: "number", step: "0.5",
        help: "Visitors at or above this score get the challenge page." },
      { key: "trap_at", label: "Trap at score", type: "number", step: "0.5",
        help: "Trapped at this score, when at least two signal families fired." },
      { key: "kill_switch", label: "Kill switch", type: "bool",
        help: "Pass all traffic through untouched. Turn on to stop trapping at once." },
      { key: "inject_honeypot", label: "Honeypot link", type: "bool",
        help: "Add the hidden maze link to HTML pages." },
    ]},
    { title: "Maze", fields: [
      { key: "slow_drip_ms", label: "Slow drip (ms)", type: "int",
        help: "Delay between maze chunks. 0 turns it off." },
      { key: "max_trap_bytes", label: "Max trap page bytes", type: "int" },
      { key: "pass_ttl_secs", label: "Pass lifetime (s)", type: "int",
        help: "How long a pass, and an automation flag, last." },
      { key: "reload_poll_secs", label: "Check file every (s)", type: "int",
        help: "How often the proxy checks for hand edits to the file (5–300, with random jitter). Saves from this page apply at once." },
    ]},
    { title: "Behaviour", fields: [
      { key: "behavior.window_secs", label: "Window (s)", type: "int" },
      { key: "behavior.max_requests", label: "Max requests per window", type: "int" },
      { key: "behavior.min_html_for_asset_check", label: "Page views before asset check", type: "int",
        help: "After this many page views with no asset loads, the client gets the no-assets signal." },
    ]},
    { title: "Lists", fields: [
      { key: "bad_user_agents", label: "Scraper user agents", type: "lines",
        help: "One per line. Matched case-insensitively." },
      { key: "hosting_asns", label: "Hosting ASNs", type: "csv",
        help: "Comma-separated numbers. Needs an ASN source to take effect." },
    ]},
  ];
  let settingsState = null;

  function getPath(obj, key) {
    return key.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
  }
  function setPath(obj, key, value) {
    const parts = key.split(".");
    let o = obj;
    for (const p of parts.slice(0, -1)) { o[p] = o[p] || {}; o = o[p]; }
    o[parts[parts.length - 1]] = value;
  }
  function settingRow(f) {
    const value = getPath(settingsState, f.key);
    let input;
    if (f.type === "bool") {
      input = el("input", { type: "checkbox", "data-key": f.key, ...(value ? { checked: "" } : {}) });
    } else if (f.type === "lines") {
      input = el("textarea", { "data-key": f.key, rows: "5" }, (value || []).join("\n"));
    } else if (f.type === "csv") {
      input = el("input", { type: "text", "data-key": f.key, value: (value || []).join(", ") });
    } else {
      input = el("input", { type: "number", "data-key": f.key, step: f.step || "1", value: String(value ?? "") });
    }
    return el("label", { class: "set-row" },
      el("span", { class: "set-label" }, f.label), input,
      f.help ? el("span", { class: "set-help" }, f.help) : null);
  }
  function renderSettingsForm() {
    const sections = SETTINGS_SECTIONS.map((s) =>
      el("section", { class: "set-section" }, el("h4", {}, s.title), ...s.fields.map(settingRow)));
    sections.push(el("section", { class: "set-section" },
      el("h4", {}, "Edit in botlocker.toml"),
      el("p", { class: "muted", style: "font-size:12px;margin:0 0 8px" },
        "These are not in the form: maze_prefix (the robots.txt rule depends on it), verified crawlers, and signal weights. The origin comes from ORIGIN_URL in nginx/docker-compose-nginx.yaml for the nginx stack, or from this file for the standalone binary."),
      el("div", { class: "block mono" }, JSON.stringify({
        origin: settingsState.origin ?? null,
        maze_prefix: settingsState.maze_prefix,
        verified_crawlers: settingsState.verified_crawlers,
        weights: settingsState.weights,
      }, null, 2))));
    $("settings-form").replaceChildren(...sections);
  }
  function collectSettings() {
    const cfg = JSON.parse(JSON.stringify(settingsState));
    for (const section of SETTINGS_SECTIONS) {
      for (const f of section.fields) {
        const input = document.querySelector(`[data-key="${f.key}"]`);
        if (!input) continue;
        let v;
        if (f.type === "bool") v = input.checked;
        else if (f.type === "int") v = parseInt(input.value, 10);
        else if (f.type === "number") v = parseFloat(input.value);
        else if (f.type === "lines") v = input.value.split("\n").map((s) => s.trim()).filter(Boolean);
        else if (f.type === "csv") v = input.value.split(",").map((s) => s.trim()).filter(Boolean).map((s) => parseInt(s, 10));
        if (typeof v === "number" && Number.isNaN(v)) throw new Error(`${f.label} must be a number`);
        if (Array.isArray(v) && v.some((x) => typeof x === "number" && Number.isNaN(x))) {
          throw new Error(`${f.label} must be numbers`);
        }
        setPath(cfg, f.key, v);
      }
    }
    return cfg;
  }
  function setSettingsMessage(text, kind) {
    const msg = $("settings-msg");
    msg.className = "msg" + (kind ? " " + kind : "");
    msg.textContent = text;
  }
  async function loadSettings() {
    try {
      const r = await apiFetch("/api/settings");
      const body = await r.json();
      if (!r.ok) throw new Error(body.error || String(r.status));
      settingsState = body.config;
      $("settings-path").textContent = body.path;
      renderSettingsForm();
    } catch (e) {
      setSettingsMessage("Could not load settings: " + e.message, "bad");
    }
    loadAudit();
  }
  async function saveSettings() {
    setSettingsMessage("Saving…", "");
    try {
      const body = collectSettings();
      const r = await apiFetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const res = await r.json();
      if (!r.ok) throw new Error(res.error || String(r.status));
      setSettingsMessage(res.changes.length
        ? "Saved and applied: " + res.changes.map((c) => c.key).join(", ")
        : "No changes to save.", "ok");
      await loadSettings();
    } catch (e) {
      setSettingsMessage("Not saved: " + e.message, "bad");
    }
  }
  async function loadAudit() {
    try {
      const entries = await getJSON("/api/audit");
      if (!entries.length) {
        $("audit").replaceChildren(el("div", { class: "muted" }, "No changes yet since the dashboard started."));
        return;
      }
      $("audit").replaceChildren(...entries.slice(0, 30).map((e) =>
        el("div", { class: "audit-row" },
          el("div", { class: "mono muted" }, fmtTime(e.ts)),
          ...e.changes.map((c) => el("div", { class: "mono" },
            `${c.key}: ${JSON.stringify(c.from)} → ${JSON.stringify(c.to)}`)))));
    } catch (e) {
      $("audit").replaceChildren(el("div", { class: "muted" }, "Could not load changes."));
    }
  }

  // ---------- tabs ----------
  function switchTab(name) {
    state.tab = name;
    if (name === "settings") loadSettings();
    document.querySelectorAll(".tab").forEach((t) =>
      t.setAttribute("aria-selected", String(t.dataset.tab === name)));
    document.querySelectorAll(".panel").forEach((p) =>
      p.classList.toggle("active", p.id === `panel-${name}`));
  }
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => switchTab(t.dataset.tab)));

  // ---------- boot ----------
  $("settings-save").addEventListener("click", saveSettings);
  requestAnimationFrame(loop);
  poll();
  setInterval(poll, 2000);
})();