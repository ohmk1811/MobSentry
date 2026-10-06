(function () {
  const root = document.getElementById("app");
  const rid = root.dataset.rid;
  let DATA = null;

  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const sevClass = (s) => (s || "info").toLowerCase();
  const el = (html) => { const d = document.createElement("div"); d.innerHTML = html; return d.firstElementChild; };

  // 202 = analysis still running in the background; poll until the report
  // is ready. A transient fetch failure just retries rather than giving up.
  let misses = 0;
  function load() {
    fetch(`/api/report/${rid}`).then(r => {
      if (r.status === 404) throw new Error("report not found (server restarted?)");
      return r.json().then(d => ({ running: r.status === 202, d }));
    }).then(({ running, d }) => {
      misses = 0;
      if (running) { showProgress(d); setTimeout(load, 1500); return; }
      DATA = d; render();
    }).catch(e => {
      if (/not found/.test(e.message) || ++misses > 20) {
        root.innerHTML = `<div class="loading">Failed to load: ${esc(e.message || e)}</div>`;
      } else { setTimeout(load, 3000); }
    });
  }
  load();

  function showProgress(j) {
    const total = Math.max(j.total || 1, 1), step = j.step || 0;
    // parse dominates on large apps, so give it ~half the bar and advance it
    // on a rough size-based estimate (~3s per MB) so it never looks frozen
    const est = Math.max(10, ((j.size || 0) / 1048576) * 3);
    const pct = j.stage === "queued" ? 2
      : j.stage === "parse" ? Math.round(5 + 43 * Math.min(1, (j.elapsed || 0) / est))
      : Math.round(50 + 48 * step / total);
    const mins = Math.floor((j.elapsed || 0) / 60), secs = (j.elapsed || 0) % 60;
    const size = j.size ? ` · ${(j.size / 1048576).toFixed(1)} MB` : "";
    root.innerHTML = `<div class="progress-wrap">
      <div class="progress-title">Analyzing ${esc(j.filename || "app")}${esc(size)}</div>
      <div class="progress-bar"><div style="width:${pct}%"></div></div>
      <div class="progress-stage">${esc(j.label || "Working…")}
        ${j.stage !== "queued" && j.stage !== "parse" ? `(${step}/${total - 1})` : ""}</div>
      <div class="progress-time">${mins ? mins + "m " : ""}${secs}s elapsed —
        large apps can take a few minutes. You can leave this tab open.</div>
    </div>`;
  }

  function render() {
    const m = DATA.meta || {}, c = DATA.counts || {};
    root.innerHTML = "";
    if (m.parse_failed) {
      root.appendChild(el(`<div class="topbar"><a class="back" href="/">← new</a>
        <span class="name">Could not analyze ${esc(DATA.filename || "APK")}</span></div>`));
      const err = (DATA.errors && DATA.errors[0]) || "unknown error";
      const needsAndro = /androguard/i.test(err);
      root.appendChild(el(`<div class="content" style="max-width:760px;margin:0 auto">
        <div class="card finding high"><h4><span class="sev high">error</span>${esc(m.failure || "APK could not be parsed")}</h4>
        <div class="desc mono">${esc(err)}</div>
        ${needsAndro ? `<div class="rec"><b>Fix:</b> install the parser dependency:
          <pre>pip install -r requirements.txt</pre>then restart and re-upload.</div>`
          : m.failure ? "" : `<div class="rec">The file may not be a valid APK, or may be corrupt.</div>`}
        </div></div>`));
      return;
    }
    const grade = (m.security_grade || "").toLowerCase();
    root.appendChild(el(`
      <div class="topbar">
        <a class="back" href="/">← new</a>
        <span class="name">${esc(m.app_name || DATA.filename || "APK")}</span>
        <span class="pkg">${esc(m.package || "")} ${m.version_name ? "· v" + esc(m.version_name) : ""}</span>
        <div class="pills">
          ${m.security_score != null ? `<span class="score ${grade}" title="Lower = more issues found">Score ${esc(m.security_score)}/100 · ${esc(m.security_grade)}</span>` : ""}
          <span class="pill high">🔴 ${c.high || 0} High</span>
          <span class="pill med">🟠 ${c.medium || 0} Medium</span>
          <span class="pill low">🟡 ${c.low || 0} Low</span>
          <span class="pill info">ℹ️ ${c.info || 0} Info</span>
          <a class="pdfbtn" style="background:var(--acc);color:#fff;border-radius:8px;padding:7px 14px;font-weight:600" href="/report/${rid}/pdf">⬇ PDF report</a>
          <a class="logout" href="/logout">Sign out</a>
        </div>
      </div>`));

    const layout = el(`<div class="layout"><nav class="tabs"></nav><main class="content"></main></div>`);
    root.appendChild(layout);
    const tabsEl = layout.querySelector(".tabs");
    const content = layout.querySelector(".content");

    const S = DATA.sections || {};
    const isIOS = (m.platform === "ios");
    const TABS = isIOS ? [
      ["overview", "Overview", ""],
      ["findings", "Findings", DATA.findings.length],
      ["fingerprint", "Fingerprint", ""],
      ["plist", "Info.plist / ATS", ""],
      ["binary", "Binary Protections", ""],
      ["jailbreak", "Jailbreak", ""],
      ["antidebug", "Anti-Debug / Frida", ""],
      ["sslpinning", "SSL Pinning", ""],
      ["trackers", "Trackers", (S.trackers && S.trackers.count) || ""],
      ["firebase", "Firebase", (S.firebase && S.firebase.realtime_db && S.firebase.realtime_db.length) || ""],
      ["secrets", "Secrets & URLs", (S.secrets && S.secrets.endpoint_count) || ""],
      ["storage", "Storage", ""],
      ["errors", "Analyzer Log", (DATA.errors && DATA.errors.length) || ""],
    ] : [
      ["overview", "Overview", ""],
      ["findings", "Findings", DATA.findings.length],
      ["fingerprint", "Fingerprint", ""],
      ["signing", "Signing", ""],
      ["obfuscation", "Obfuscation", ""],
      ["manifest", "Manifest", ""],
      ["components", "Components", (S.components && S.components.exported_count) || ""],
      ["deeplinks", "Deep Links", (S.deeplinks && S.deeplinks.count) || ""],
      ["permissions", "Permissions", (S.permissions && S.permissions.all && S.permissions.all.length) || ""],
      ["netsec", "Network Config", ""],
      ["trackers", "Trackers", (S.trackers && S.trackers.count) || ""],
      ["firebase", "Firebase", (S.firebase && S.firebase.realtime_db && S.firebase.realtime_db.length) || ""],
      ["secrets", "Secrets & URLs", (S.secrets && S.secrets.endpoint_count) || ""],
      ["insecure", "Insecure Config", ""],
      ["antidebug", "Anti-Debug / Frida", ""],
      ["rootdetect", "Root Detection", ""],
      ["sslpinning", "SSL Pinning", ""],
      ["correlations", "Correlations", (S.correlations && S.correlations.length) || ""],
      ["errors", "Analyzer Log", (DATA.errors && DATA.errors.length) || ""],
    ];
    if (S.ai_summary) TABS.splice(1, 0, ["ai_summary", "AI Summary", ""]);

    let active = "overview";
    TABS.forEach(([k, label, cnt]) => {
      const b = el(`<button data-k="${k}">${esc(label)}${cnt !== "" ? `<span class="count">${cnt}</span>` : ""}</button>`);
      b.addEventListener("click", () => { active = k; draw(); });
      tabsEl.appendChild(b);
    });

    function draw() {
      [...tabsEl.children].forEach(b => b.classList.toggle("active", b.dataset.k === active));
      content.innerHTML = VIEWS[active] ? VIEWS[active]() : `<div class="empty">—</div>`;
      content.scrollIntoView({ block: "start" });
    }

    const VIEWS = {
      overview: overview, findings: () => findings(DATA.findings),
      ai_summary: () => `<h2 class="sec">AI Summary</h2><div class="card"><pre style="white-space:pre-wrap">${esc(S.ai_summary)}</pre></div>`,
      fingerprint: fingerprint, signing: signing, obfuscation: obfuscation,
      manifest: manifest, components: components,
      deeplinks: deeplinks, permissions: permissions, netsec: netsec,
      trackers: trackers, firebase: firebase, secrets: secrets, insecure: insecure,
      rootdetect: rootdetect, sslpinning: sslpinning,
      correlations: correlations, errors: errors,
      antidebug: antidebug, plist: iosPlist, binary: iosBinary,
      jailbreak: iosJailbreak, storage: iosStorage,
    };
    draw();
  }

  // ---------- helpers ----------
  function findingCard(f) {
    const ev = (f.evidence || []).map(e =>
      `<div><span class="loc">${esc(e.location)}</span>${e.detail ? ` <span class="cf">— ${esc(e.detail)}</span>` : ""}<pre>${esc(e.snippet)}</pre></div>`).join("");
    const surfaces = f.extra && f.extra.surfaces
      ? `<div class="rec"><b>Bypass / validation surfaces:</b><br>` +
        Object.entries(f.extra.surfaces).map(([k, v]) => `• <code class="inline">${esc(k)}</code> → <span class="surface">${esc(v)}</span>`).join("<br>") + `</div>` : "";
    return `<div class="card finding ${sevClass(f.severity)}">
      <h4><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span>${esc(f.title)}
        <span class="conf">· confidence ${esc(f.confidence)} · ${esc(f.category)}</span></h4>
      <div class="desc">${esc(f.description)}</div>
      ${f.affected_component ? `<div class="rec"><b>Component:</b> <span class="mono">${esc(f.affected_component)}</span></div>` : ""}
      ${f.recommendation ? `<div class="rec"><b>Validate:</b> ${esc(f.recommendation)}</div>` : ""}
      ${surfaces}
      ${ev ? `<details class="evi"><summary>Evidence (${f.evidence.length})</summary>${ev}</details>` : ""}
    </div>`;
  }
  function findings(list) {
    if (!list.length) return `<h2 class="sec">Findings</h2><div class="empty">No findings.</div>`;
    return `<h2 class="sec">Findings (${list.length})</h2>` + list.map(findingCard).join("");
  }
  const S = () => DATA.sections || {};
  const yn = (v) => v ? `<span class="yes">✓</span>` : `<span class="no">✗</span>`;

  function scoreGauge(score, grade, size) {
    score = Math.max(0, Math.min(100, Number(score) || 0));
    size = size || 132;
    const g = (grade || "").toUpperCase();
    const color = g === "A" ? "#16a34a" : g === "B" ? "#2563eb"
      : g === "C" ? "#d97706" : "#dc2626";
    const r = 54, c = 2 * Math.PI * r, off = c * (1 - score / 100);
    const cx = 60;
    return `<svg width="${size}" height="${size}" viewBox="0 0 120 120" aria-label="security score">
      <circle cx="${cx}" cy="60" r="${r}" fill="none" stroke="#eef2f3" stroke-width="12"/>
      <circle cx="${cx}" cy="60" r="${r}" fill="none" stroke="${color}" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}"
        stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 60 60)"/>
      <text x="${cx}" y="56" text-anchor="middle" font-size="30" font-weight="800"
        fill="${color}" font-family="system-ui,sans-serif">${score}</text>
      <text x="${cx}" y="78" text-anchor="middle" font-size="12" fill="#64748b"
        font-family="system-ui,sans-serif">/ 100 · ${esc(g)}</text>
    </svg>`;
  }

  // ---------- views ----------
  function overview() {
    const m = DATA.meta || {}, as = m.attack_surface || {}, c = DATA.counts || {};
    const h = m.hashes || {};
    const sizeMB = m.file_size ? (m.file_size / 1048576).toFixed(2) + " MB" : "—";
    const asRows = Object.entries(as).map(([k, v]) =>
      `<div class="flagrow"><span>${esc(k.replace(/_/g, " "))}</span><b>${esc(v)}</b></div>`).join("");
    return `<h2 class="sec">Overview</h2>
      <div class="grid2">
        <div class="card"><h3>File information</h3>
          <div class="kv">
            <div>File name</div><div class="mono">${esc(DATA.filename || "")}</div>
            <div>Size</div><div>${esc(sizeMB)}</div>
            <div>MD5</div><div class="mono">${esc(h.md5 || "—")}</div>
            <div>SHA1</div><div class="mono">${esc(h.sha1 || "—")}</div>
            <div>SHA256</div><div class="mono">${esc(h.sha256 || "—")}</div>
          </div></div>
        <div class="card"><h3>Application information</h3>
          <div class="kv">
            <div>App name</div><div>${esc(m.app_name)}</div>
            <div>Package</div><div class="mono">${esc(m.package)}</div>
            <div>Main activity</div><div class="mono">${esc(m.main_activity || "—")}</div>
            <div>Version</div><div>${esc(m.version_name)} (${esc(m.version_code)})</div>
            <div>Min / Target / Max SDK</div><div>${esc(m.min_sdk)} / ${esc(m.target_sdk)} / ${esc(m.max_sdk || "—")}</div>
          </div></div>
      </div>
      <div class="grid2">
        <div class="card"><h3>Security score (vulnerability-driven)</h3>
          <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
            <div style="flex:none">${scoreGauge(m.security_score, m.security_grade)}</div>
            <div style="flex:1;min-width:220px">
              <div class="cf" style="margin-bottom:4px">Hardening controls</div>
              ${(m.hardening_checks || []).map(ck =>
                `<div class="flagrow"><span>${ck.ok ? '✅' : '❌'} ${esc(ck.label)}</span></div>`).join("")
                || '<div class="empty">—</div>'}
            </div>
          </div>
          <div class="cf" style="margin-top:8px">Score drops with each finding (High −15 · Medium −8 · Low −3). Static analysis only — runtime / logic bugs are out of scope.</div>
        </div>
      </div>
      <div class="grid2">
        <div class="card"><h3>Findings & trackers</h3>
          <div class="kv">
            <div>🔴 High</div><div>${c.high || 0}</div>
            <div>🟠 Medium</div><div>${c.medium || 0}</div>
            <div>🟡 Low</div><div>${c.low || 0}</div>
            <div>ℹ️ Info</div><div>${c.info || 0}</div>
            <div>Trackers</div><div>${esc(m.tracker_count || 0)}</div>
            <div>Analysis time</div><div>${esc(m.analysis_seconds)}s</div>
          </div></div>
        <div class="card"><h3>Attack surface</h3>${asRows || '<div class="empty">—</div>'}</div>
      </div>`;
  }

  function trackers() {
    const t = S().trackers; if (!t) return empty("trackers");
    if (!t.count) return `<h2 class="sec">📡 Trackers</h2><div class="card">No third-party trackers detected.</div>`;
    const rows = (t.trackers || []).map(x =>
      `<tr><td>${esc(x.name)}</td><td class="mono cf">${esc(x.prefix)}</td></tr>`).join("");
    return `<h2 class="sec">📡 Trackers & SDKs (${t.count})</h2>
      <div class="card"><table><thead><tr><th>Tracker / SDK</th><th>Signature</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${findings(DATA.findings.filter(f => f.category === "trackers"))}`;
  }

  function fingerprint() {
    const f = S().fingerprint; if (!f) return empty("fingerprint");
    const m = DATA.meta || {}, h = m.hashes || {};
    const sizeMB = m.file_size ? (m.file_size / 1048576).toFixed(2) + " MB" : "—";
    const fw = Object.entries(f.frameworks || {}).map(([k, v]) =>
      `<div>├── ${esc(k).padEnd ? esc(k) : esc(k)} ${yn(v)}</div>`).join("");
    const libs = (f.libraries || []).map(l => `<span class="tag">${esc(l)}</span>`).join(" ") || '<span class="empty">none detected</span>';
    const nat = (f.native_libraries || []).map(l => `<span class="tag">${esc(l)}</span>`).join(" ") || '<span class="empty">none</span>';
    return `<h2 class="sec">🧬 Application fingerprint</h2>
      <div class="grid2">
        <div class="card"><h3>File information</h3>
          <div class="kv">
            <div>File name</div><div class="mono">${esc(DATA.filename || "")}</div>
            <div>Size</div><div>${esc(sizeMB)}</div>
            <div>MD5</div><div class="mono">${esc(h.md5 || "—")}</div>
            <div>SHA1</div><div class="mono">${esc(h.sha1 || "—")}</div>
            <div>SHA256</div><div class="mono">${esc(h.sha256 || "—")}</div>
          </div></div>
        <div class="card"><h3>Application information</h3>
          <div class="kv">
            <div>App name</div><div>${esc(m.app_name)}</div>
            <div>Package</div><div class="mono">${esc(m.package)}</div>
            <div>Main activity</div><div class="mono">${esc(m.main_activity || "—")}</div>
            <div>Version</div><div>${esc(m.version_name)} (${esc(m.version_code)})</div>
            <div>Min / Target / Max SDK</div><div>${esc(m.min_sdk)} / ${esc(m.target_sdk)} / ${esc(m.max_sdk || "—")}</div>
          </div></div>
      </div>
      <div class="card"><h3>Framework</h3><div class="tree">${fw}</div></div>
      <div class="card"><h3>ABIs</h3>${(f.abis || []).map(a => `<span class="tag">${esc(a)}</span>`).join(" ") || '<span class="empty">none</span>'}</div>
      <div class="card"><h3>Libraries (${(f.libraries || []).length})</h3>${libs}</div>
      <div class="card"><h3>Native libraries (${(f.native_libraries || []).length})</h3>${nat}</div>
      <div class="card"><h3>Crypto libraries</h3>${(f.crypto_libs_present || []).map(x => `<span class="tag">${esc(x)}</span>`).join(" ") || '<span class="empty">none</span>'}</div>`;
  }

  function manifest() {
    const flags = S().manifest_flags || {};
    const rows = Object.entries(flags).map(([k, v]) => {
      let cls = "no"; const val = v == null ? "(not set)" : String(v);
      if (v === "true") cls = (k === "debuggable" || k === "usesCleartextTraffic") ? "bad" : "warn";
      return `<div class="flagrow"><span class="mono">${esc(k)}</span><span class="${cls}">${esc(val)}</span></div>`;
    }).join("");
    return `<h2 class="sec">📋 Manifest security flags</h2>
      <div class="card">${rows || empty("manifest")}</div>
      ${findings(DATA.findings.filter(f => f.category === "manifest"))}`;
  }

  function components() {
    const cs = S().components; if (!cs) return empty("components");
    const counts = Object.entries(cs.counts || {}).map(([k, v]) =>
      `<span class="tag">${esc(k)}: ${esc(v)}</span>`).join(" ");
    const rows = (cs.all || []).map(c => `<tr>
      <td>${esc(c.type)}</td>
      <td class="mono">${esc(c.name)}</td>
      <td>${c.exported ? `<span class="bad">exported</span>` : `<span class="no">no</span>`}
          <span class="cf">(${esc(c.exported_source)})</span></td>
      <td>${c.permission ? `<span class="mono">${esc(c.permission.split('.').pop())}</span>` : `<span class="warn">none</span>`}</td>
      <td>${c.intent_filters.length}${c.sensitive ? ` <span class="tag">sensitive</span>` : ""}</td>
    </tr>`).join("");
    return `<h2 class="sec">🚪 Components (${cs.exported_count} exported)</h2>
      <div class="card">${counts}</div>
      <div class="card"><table><thead><tr><th>Type</th><th>Name</th><th>Exported</th><th>Permission</th><th>Filters</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${findings(DATA.findings.filter(f => f.category === "components"))}`;
  }

  function deeplinks() {
    const d = S().deeplinks; if (!d) return empty("deeplinks");
    if (!d.links.length) return `<h2 class="sec">🔗 Deep links</h2><div class="empty">None found.</div>`;
    const rows = d.links.map(l => `<tr>
      <td class="mono">${esc(l.uri)}</td>
      <td class="mono">${esc((l.component || '').split('.').pop())}</td>
      <td>${l.exported ? `<span class="bad">yes</span>` : `<span class="no">no</span>`}</td>
      <td>${l.browsable ? "✓" : ""}</td>
      <td>${l.sensitive ? `<span class="warn">sensitive</span>` : ""}</td>
    </tr>`).join("");
    return `<h2 class="sec">🔗 Deep-link map (${d.count})</h2>
      <div class="card"><table><thead><tr><th>URI</th><th>Component</th><th>Exported</th><th>Browsable</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      ${findings(DATA.findings.filter(f => f.category === "deeplinks"))}`;
  }

  function permissions() {
    const p = S().permissions; if (!p) return empty("permissions");
    const cat = p.categorized || {};
    const block = (name, arr, cls) => `<div class="card"><h3>${name} (${arr.length})</h3>${arr.map(x => `<span class="tag ${cls}">${esc(x.split('.').pop())}</span>`).join(" ") || '<span class="empty">none</span>'}</div>`;
    return `<h2 class="sec">🔐 Permissions (${(p.all || []).length})</h2>
      ${block("Dangerous", cat.dangerous || [], "bad")}
      ${block("Special", cat.special || [], "warn")}
      ${block("Custom", cat.custom || [], "")}
      ${block("Normal", cat.normal || [], "")}
      ${findings(DATA.findings.filter(f => f.category === "permissions"))}`;
  }

  function netsec() {
    const n = S().netsec; if (!n) return empty("netsec");
    if (!n.present) return `<h2 class="sec">🌐 Network Security Config</h2><div class="card">No custom Network Security Config found.</div>`;
    const row = (lbl, v, bad) => `<div class="flagrow"><span>${lbl}</span><span class="${v ? (bad ? 'bad' : 'warn') : 'yes'}">${v ? "⚠ yes" : "✓ no"}</span></div>`;
    const dom = (n.domains || []).map(d => `<tr><td class="mono">${esc((d.domains || []).join(", "))}</td><td>${d.cleartext ? '<span class="bad">yes</span>' : 'no'}</td><td>${d.pinned ? '✓' : ''}</td></tr>`).join("");
    return `<h2 class="sec">🌐 Network Security Config</h2>
      <div class="card"><div class="cf mono">${esc(n.file)}</div>
        ${row("Cleartext permitted", n.cleartext_permitted, true)}
        ${row("User certificates trusted", n.user_certs_trusted, true)}
        ${row("Debug overrides", n.debug_overrides, false)}
        ${row("Custom trust anchors", n.custom_trust_anchors, false)}
        <div class="flagrow"><span>Certificate pins</span><span class="${n.pins_present ? 'yes' : 'no'}">${n.pins_present ? '✓ present' : '✗ none'}</span></div>
      </div>
      ${dom ? `<div class="card"><h3>Domain configs</h3><table><thead><tr><th>Domains</th><th>Cleartext</th><th>Pinned</th></tr></thead><tbody>${dom}</tbody></table></div>` : ""}
      ${findings(DATA.findings.filter(f => f.category === "netsec"))}`;
  }

  function secrets() {
    const s = S().secrets; if (!s) return empty("secrets");
    const eps = (s.endpoints || []).map(u => `<div class="mono">${esc(u)}</div>`).join("");
    const dev = (s.dev_endpoints || []).map(u => `<div class="mono warn">${esc(u)}</div>`).join("");
    const ips = (s.ip_addresses || []).map(ip => {
      const priv = (s.private_ips || []).includes(ip);
      return `<span class="tag ${priv ? 'warn' : ''}">${esc(ip)}${priv ? ' 🔒' : ''}</span>`;
    }).join(" ");
    const emails = (s.emails || []).map(e => `<span class="tag">${esc(e)}</span>`).join(" ");
    return `<h2 class="sec">📦 Secrets, URLs, IPs & leaks</h2>
      ${findings(DATA.findings.filter(f => f.category === "secrets"))}
      ${dev ? `<div class="card"><h3>Non-prod / internal endpoints</h3>${dev}</div>` : ""}
      ${ips ? `<div class="card"><h3>IP addresses (${(s.ip_addresses || []).length}) — 🔒 = private/internal</h3>${ips}</div>` : ""}
      <div class="card"><h3>All endpoints (${s.endpoint_count})</h3>${eps || '<span class="empty">none</span>'}</div>
      ${emails ? `<div class="card"><h3>Emails (${(s.emails || []).length})</h3>${emails}</div>` : ""}`;
  }

  function firebase() {
    const f = S().firebase; if (!f) return empty("firebase");
    if (!f.present) return `<h2 class="sec">🔥 Firebase</h2><div class="card">No Firebase usage detected.</div>`;
    const rtdb = (f.realtime_db || []).map(u => {
      const chk = (f.live_checks || {})[u] || {};
      let badge = '<span class="cf">not checked</span>';
      if (chk.exposed === true) badge = '<span class="bad">⚠ PUBLICLY READABLE (HTTP 200)</span>';
      else if (chk.exposed === false) badge = `<span class="yes">protected (${esc(chk.status)})</span>`;
      else if (chk.error) badge = `<span class="cf">check failed: ${esc(chk.error)}</span>`;
      return `<tr><td class="mono">${esc(u)}</td><td>${badge}</td></tr>`;
    }).join("");
    const gs = f.google_services || {};
    const gsRows = Object.entries(gs).filter(([k]) => k !== "file").map(([k, v]) =>
      `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>`).join("");
    const cfg = Object.entries(f.config_values || {}).map(([k, v]) =>
      `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>`).join("");
    const bkts = (f.storage_buckets || []).map(b => `<span class="tag">${esc(b)}</span>`).join(" ");
    const fsu = (f.firestore_urls || []).map(u => `<div class="mono">${esc(u)}</div>`).join("");
    return `<h2 class="sec">🔥 Firebase</h2>
      ${rtdb ? `<div class="card"><h3>Realtime Database${f.live_enabled ? " (live exposure check)" : ""}</h3>
        <table><thead><tr><th>URL</th><th>Status</th></tr></thead><tbody>${rtdb}</tbody></table></div>` : ""}
      ${bkts ? `<div class="card"><h3>Storage buckets</h3>${bkts}</div>` : ""}
      ${gsRows ? `<div class="card"><h3>google-services.json</h3><div class="kv">${gsRows}</div></div>` : ""}
      ${cfg ? `<div class="card"><h3>Config (resources)</h3><div class="kv">${cfg}</div></div>` : ""}
      ${fsu ? `<div class="card"><h3>Firestore URLs</h3>${fsu}</div>` : ""}
      ${findings(DATA.findings.filter(f2 => f2.category === "firebase"))}`;
  }

  function signing() {
    const s = S().signing; if (!s) return empty("signing");
    const sch = Object.entries(s.schemes || {}).map(([k, v]) =>
      `<span class="tag ${v ? '' : 'no'}">${esc(k)} ${v ? '✓' : '✗'}</span>`).join(" ");
    const certs = (s.certificates || []).map(c => `<div class="card">
      <div class="kv">
        <div>Subject</div><div class="mono">${esc(c.subject)}</div>
        <div>Issuer</div><div class="mono">${esc(c.issuer)}</div>
        <div>Serial</div><div class="mono">${esc(c.serial_number)}</div>
        <div>Signature algo</div><div class="mono">${esc(c.signature_algo)}</div>
        <div>Valid from</div><div class="mono">${esc(c.not_valid_before)}</div>
        <div>Valid to</div><div class="mono">${esc(c.not_valid_after)}</div>
      </div></div>`).join("");
    return `<h2 class="sec">✍️ Code signing</h2>
      <div class="card"><h3>Schemes</h3>${sch}
        <div class="flagrow" style="margin-top:8px"><span>Debug certificate</span>
          <span class="${s.debug_certificate ? 'bad' : 'yes'}">${s.debug_certificate ? '⚠ YES (debug key!)' : 'no'}</span></div>
        ${s.v1_only ? '<div class="flagrow"><span>v1-only (Janus risk)</span><span class="warn">yes</span></div>' : ''}
        ${(s.weak_signature_algos || []).length ? `<div class="flagrow"><span>Weak algo</span><span class="warn">${esc(s.weak_signature_algos.join(", "))}</span></div>` : ''}
      </div>
      ${certs || ''}
      ${findings(DATA.findings.filter(f => f.category === "signing"))}`;
  }

  function obfuscation() {
    const o = S().obfuscation; if (!o || !o.analyzable) return `<h2 class="sec">🧩 Obfuscation</h2><div class="card">Not analyzable (no app classes parsed).</div>`;
    return `<h2 class="sec">🧩 Obfuscation</h2>
      <div class="card"><div class="kv">
        <div>Obfuscated?</div><div><b class="${o.obfuscated ? 'warn' : 'bad'}">${o.obfuscated ? 'YES — ' + esc(o.level) : 'NO — readable code'}</b></div>
        <div>Short-name ratio</div><div>${esc(Math.round(o.short_name_ratio * 100))}%</div>
        <div>Single-segment pkgs</div><div>${esc(Math.round(o.single_seg_ratio * 100))}%</div>
        <div>App classes</div><div>${esc(o.app_class_count)}</div>
      </div></div>
      ${(o.short_name_examples || []).length ? `<div class="card"><h3>Renamed symbol examples</h3><span class="mono">${esc((o.short_name_examples || []).join(", "))}</span></div>` : ""}
      ${(o.readable_examples || []).length ? `<div class="card"><h3>Readable class examples</h3><span class="mono">${esc((o.readable_examples || []).join(", "))}</span></div>` : ""}
      ${findings(DATA.findings.filter(f => f.category === "obfuscation"))}`;
  }

  function insecure() {
    const cats = ["webview", "crypto", "logging", "storage"];
    return `<h2 class="sec">🔍 Insecure configuration</h2>` +
      findings(DATA.findings.filter(f => cats.includes(f.category))) ||
      `<div class="empty">Nothing flagged.</div>`;
  }

  function rootdetect() {
    const r = S().rootdetect; if (!r) return empty("rootdetect");
    if (!r.detected) return `<h2 class="sec">🧠 Root detection</h2><div class="card">No root-detection techniques detected.</div>`;
    const tech = Object.entries(r.techniques || {}).map(([k, v]) =>
      `<tr><td>${esc(v.label)}</td><td class="surface">${esc(v.surface)}</td>
        <td class="mono cf">${esc((v.indicators || []).join(", "))}</td></tr>`).join("");
    return `<h2 class="sec">🧠 Root detection analysis</h2>
      <div class="card"><div class="kv">
        <div>Confidence</div><div><b>${esc(r.confidence)}</b></div>
        <div>Techniques</div><div>${esc(r.technique_count)}</div>
        <div>Enforced?</div><div>${r.enforced_guess === true ? '<span class="yes">likely enforced</span>' : r.enforced_guess === false ? '<span class="warn">not confirmed (maybe log-only)</span>' : 'unknown'}</div>
      </div></div>
      <div class="card"><h3>Detected techniques → validation surface</h3>
        <table><thead><tr><th>Mechanism</th><th>Surface to validate</th><th>Indicators</th></tr></thead><tbody>${tech}</tbody></table></div>
      ${findings(DATA.findings.filter(f => f.category === "root-detection"))}
      ${bypassCards((S().bypass || {}).root, "Possible root-detection bypass methods")}`;
  }

  function sslpinning() {
    const s = S().sslpinning; if (!s) return empty("sslpinning");
    const mech = Object.entries(s.mechanisms || {}).map(([k, v]) =>
      `<tr><td>${esc(v.label || k)}</td><td class="surface">${esc(v.surface)}</td>
        <td class="mono cf">${esc((v.classes || v.indicators || []).join(", "))}</td></tr>`).join("");
    return `<h2 class="sec">🔒 SSL pinning analysis</h2>
      <div class="card"><b>Detected:</b> ${s.detected ? '<span class="yes">YES</span>' : '<span class="warn">NO</span>'}</div>
      ${mech ? `<div class="card"><h3>Mechanisms → instrumentation surface</h3>
        <table><thead><tr><th>Mechanism</th><th>Surface</th><th>Where</th></tr></thead><tbody>${mech}</tbody></table></div>` : ""}
      ${findings(DATA.findings.filter(f => f.category === "ssl-pinning"))}
      ${bypassCards((S().bypass || {}).ssl, "Possible SSL-bypass / interception methods")}`;
  }

  function correlations() {
    const c = S().correlations || [];
    const rows = c.map(x => `<div class="card"><b>${esc(x.type)}</b> — <span class="mono">${esc(x.component)}</span><div class="desc">${esc(x.note)}</div></div>`).join("");
    return `<h2 class="sec">🧩 Correlations</h2>${rows || '<div class="empty">No cross-module correlations.</div>'}
      ${findings(DATA.findings.filter(f => f.category === "correlation"))}`;
  }

  function errors() {
    const e = DATA.errors || [];
    return `<h2 class="sec">Analyzer log</h2><div class="card">${e.length ? e.map(x => `<div class="mono cf">${esc(x)}</div>`).join("") : '<span class="yes">No errors — all modules ran.</span>'}</div>
      <div class="card"><h3>Module timings</h3><div class="kv">${Object.entries((DATA.meta && DATA.meta.timings) || {}).map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}s</div>`).join("")}</div></div>`;
  }

  window.copyCode = function (btn) {
    const pre = btn.parentElement.querySelector("pre");
    navigator.clipboard.writeText(pre.innerText).then(() => {
      const t = btn.textContent; btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = t), 1200);
    }).catch(() => {});
  };
  function codeBlock(code) {
    if (!code) return "";
    return `<div class="codewrap"><button class="copybtn" onclick="copyCode(this)">Copy</button><pre>${esc(code)}</pre></div>`;
  }
  function bypassCards(methods, title) {
    if (!methods || !methods.length) return "";
    const cards = methods.map(mth => `
      <div class="method">
        <h4>${esc(mth.name)}</h4>
        <p class="applies">${esc(mth.applies || "")}</p>
        <div class="toolrow">${(mth.tools || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</div>
        ${(mth.steps || []).length ? `<ol>${mth.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ol>` : ""}
        ${mth.objection ? `<div class="cf" style="font-size:12px">objection command:</div>${codeBlock(mth.objection)}` : ""}
        ${mth.frida ? codeBlock(mth.frida) : ""}
        ${mth.notes ? `<div class="cf" style="font-size:12px;margin-top:6px">${esc(mth.notes)}</div>` : ""}
      </div>`).join("");
    return `<div class="card"><h3>${esc(title)}</h3>
      <div class="bypass-banner">⚠️ For authorized security testing only. Methods are stack-specific — not every one applies.</div>
      ${cards}</div>`;
  }

  // shared technique table (jailbreak / anti-debug / root style)
  function techniqueTable(section, title, cat) {
    const d = section || {};
    if (!d.detected) return `<h2 class="sec">${title}</h2><div class="card">Nothing detected.</div>${findings(DATA.findings.filter(f => f.category === cat))}`;
    const rows = Object.entries(d.techniques || {}).map(([k, v]) =>
      `<tr><td>${esc(v.label)}</td><td class="surface">${esc(v.surface)}</td>
        <td class="mono cf">${esc((v.indicators || []).join(", "))}</td></tr>`).join("");
    return `<h2 class="sec">${title}</h2>
      ${d.note ? `<div class="bypass-banner">ℹ️ ${esc(d.note)}</div>` : ""}
      <div class="card"><table><thead><tr><th>Mechanism</th><th>Surface to validate</th><th>Indicators</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${findings(DATA.findings.filter(f => f.category === cat))}`;
  }
  function antidebug() { return techniqueTable(S().antidebug, "🪪 Anti-debug / Frida", "antidebug"); }
  function iosJailbreak() {
    return techniqueTable(S().jailbreak, "🧠 Jailbreak detection", "jailbreak")
      + bypassCards((S().bypass || {}).jailbreak, "Possible jailbreak-bypass methods");
  }

  function iosPlist() {
    const p = S().plist; if (!p) return empty("plist");
    const ats = p.ats || {};
    const perms = Object.entries(p.permissions || {}).map(([k, v]) =>
      `<div>${esc(k.replace("UsageDescription", ""))}</div><div>${esc(v)}</div>`).join("");
    const schemes = (p.url_schemes || []).map(s => `<span class="tag">${esc(s)}://</span>`).join(" ");
    return `<h2 class="sec">📋 Info.plist / ATS</h2>
      <div class="card"><h3>App Transport Security</h3>
        <div class="flagrow"><span>ATS configured</span><span class="${ats.present ? 'yes' : 'warn'}">${ats.present ? 'yes' : 'no'}</span></div>
        <div class="flagrow"><span>Allows arbitrary loads</span><span class="${ats.allows_arbitrary_loads ? 'bad' : 'yes'}">${ats.allows_arbitrary_loads ? '⚠ yes' : 'no'}</span></div>
        <div class="flagrow"><span>Arbitrary loads in web</span><span class="${ats.allows_arbitrary_web ? 'warn' : 'yes'}">${ats.allows_arbitrary_web ? 'yes' : 'no'}</span></div>
        <div class="flagrow"><span>Exception domains</span><span>${(ats.exception_domains || []).length}</span></div>
      </div>
      ${schemes ? `<div class="card"><h3>Custom URL schemes</h3>${schemes}</div>` : ""}
      ${perms ? `<div class="card"><h3>Permission usage descriptions</h3><div class="kv">${perms}</div></div>` : ""}
      ${(p.file_sharing || []).length ? `<div class="card"><h3>File sharing</h3>${p.file_sharing.map(x => `<span class="tag warn">${esc(x)}</span>`).join(" ")}</div>` : ""}
      ${findings(DATA.findings.filter(f => f.category === "plist" || f.category === "ats"))}`;
  }

  function iosBinary() {
    const b = S().binary; if (!b) return empty("binary");
    const row = (lbl, v, goodWhenTrue) => {
      let cls = "no", txt = v === null || v === undefined ? "unknown" : (v ? "yes" : "no");
      if (v === true) cls = goodWhenTrue ? "yes" : "bad";
      if (v === false) cls = goodWhenTrue ? "bad" : "yes";
      return `<div class="flagrow"><span>${lbl}</span><span class="${cls}">${txt}</span></div>`;
    };
    return `<h2 class="sec">🧱 Binary protections</h2>
      <div class="card">
        <div class="flagrow"><span>Architecture</span><span class="mono">${esc(b.arch || "—")}</span></div>
        ${row("PIE (ASLR)", b.pie, true)}
        ${row("Encrypted (FairPlay)", b.encrypted, true)}
        ${row("Stack canary", b.stack_canary, true)}
        ${row("ARC", b.arc, true)}
        ${row("get-task-allow (debuggable)", b.get_task_allow, false)}
        <div class="flagrow"><span>APS environment</span><span class="${b.aps_environment === 'development' ? 'warn' : ''}">${esc(b.aps_environment || "—")}</span></div>
        <div class="flagrow"><span>Provisioning profile</span><span class="mono">${esc(b.profile || "—")}</span></div>
        <div class="flagrow"><span>Profile expiry</span><span class="mono">${esc(b.profile_expiration || "—")}</span></div>
      </div>
      ${findings(DATA.findings.filter(f => f.category === "binary"))}`;
  }

  function iosStorage() {
    const s = S().storage; if (!s) return empty("storage");
    const row = (lbl, v) => `<div class="flagrow"><span>${lbl}</span><span class="${v ? 'warn' : 'no'}">${v ? 'present' : '—'}</span></div>`;
    return `<h2 class="sec">🗄️ Local storage</h2>
      <div class="card">
        ${row("NSUserDefaults (unencrypted)", s.nsuserdefaults)}
        ${row("Keychain (secure)", s.keychain)}
        ${row("SQLite database", s.sqlite)}
        ${row("Realm database", s.realm)}
        ${row("Core Data", s.coredata)}
      </div>
      ${findings(DATA.findings.filter(f => f.category === "storage"))}`;
  }

  function empty(n) { return `<div class="empty">No data for ${esc(n)}.</div>`; }
})();
