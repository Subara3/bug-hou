"use strict";

const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeUrl = (u) => (/^https:\/\//.test(u || "") ? u : "#");

const NEW_DAYS = 3;
const PAGE = 25;

let meta = null;
let current = null;
const cache = {};
const cveState = { sev: "ALL", q: "", shown: PAGE };
let triage = { updated_at: null, items: {} };
let tab = "all";

// ---------------- Claudeの仕分け
const LEVELS = [
  ["action", "対応が必要"],
  ["check", "確認しておく"],
  ["watch", "様子見"],
  ["none", "未判定"],
  ["all", "すべて"],
];
const levelOf = (id) => triage.items[id]?.level || "none";
const inTab = (id) => tab === "all" || levelOf(id) === tab;

function advice(id) {
  const t = triage.items[id];
  if (!t) return "";
  const label = LEVELS.find(([k]) => k === t.level)?.[1] || "";
  return `<p class="advice lv-${esc(t.level)}"><b>${label}</b>${esc(t.reason)}${t.todo ? `<span class="todo">→ ${esc(t.todo)}</span>` : ""}</p>`;
}

function renderTabs(d) {
  const ids = [...d.cves.map((c) => c.id), ...d.ghsa.map((a) => a.id)];
  const count = (k) => (k === "all" ? ids.length : ids.filter((i) => levelOf(i) === k).length);
  const when = triage.updated_at
    ? `Claudeの仕分け ${new Date(triage.updated_at).toLocaleDateString("ja-JP", { timeZone: "Asia/Tokyo" })}`
    : "Claudeの仕分けはまだありません";
  $("#tabs").innerHTML =
    LEVELS.filter(([k]) => k === "all" || k === tab || count(k))
      .map(
        ([k, label]) =>
          `<button class="tab lv-${k}" data-tab="${k}" aria-selected="${tab === k}" role="tab">${label}<span>${count(k)}</span></button>`
      )
      .join("") + `<span class="tab-note">${when}</span>`;
}

function daysBetween(a, b) {
  return Math.round((new Date(b) - new Date(a)) / 86400000);
}
function today() {
  return (meta?.fetched_at || new Date().toISOString()).slice(0, 10);
}
function isNew(item) {
  const f = item.first_seen;
  return f && f !== "0000-00-00" && daysBetween(f, today()) <= NEW_DAYS;
}
function newTag(item) {
  return isNew(item) ? '<span class="tag new">NEW</span>' : "";
}

async function loadJSON(name) {
  const r = await fetch(`data/${name}?t=${Date.now()}`);
  if (!r.ok) throw new Error(`${name}: ${r.status}`);
  return r.json();
}

// ---------------- ランプの色
function lampOf(t) {
  if (t.kev_recent > 0) return "red";
  const d = cache[t.id];
  if (d) {
    const hot = d.cves.some(
      (c) => (c.severity === "CRITICAL" || c.severity === "HIGH") && daysBetween(c.published, today()) <= 30
    );
    return hot ? "amber" : "green";
  }
  return t.critical + t.high > 0 ? "amber" : "green";
}

function renderNav() {
  $("#nav").innerHTML =
    meta.targets
      .map(
        (t) => `<a href="#${esc(t.id)}" aria-current="${t.id === current}" title="CVE ${t.cves}件・KEV ${t.kev_recent}件">
        <span class="dot ${lampOf(t)}"></span>${esc(t.label)}<span class="count">${t.cves}</span>
      </a>`
      )
      .join("") +
    '<span class="sep"></span>' +
    mineNavLink();
}

// ---------------- 01 バージョン
function eolStatus(r) {
  const now = today();
  const eol = r.eol;
  const sup = r.support;
  if (eol === true || (typeof eol === "string" && eol < now)) return ["eol", "サポート終了"];
  if (typeof sup === "string" && sup < now) return ["sec", "セキュリティ修正のみ"];
  if (sup === true && eol === false) return ["ok", "サポート中"];
  return ["ok", "サポート中"];
}

function lifeBar(r) {
  if (typeof r.eol !== "string" || !r.releaseDate) return "";
  const start = new Date(r.releaseDate), end = new Date(r.eol), now = new Date(today());
  const total = end - start;
  if (total <= 0) return "";
  const pct = Math.min(100, Math.max(0, ((now - start) / total) * 100));
  const secOnly = typeof r.support === "string" && r.support < today();
  return `<div class="life" title="${esc(r.releaseDate)} → ${esc(r.eol)}"><i class="${secOnly ? "sec" : ""}" style="width:${pct.toFixed(1)}%"></i></div>`;
}

function fmtDate(v) {
  if (v === true) return "終了";
  if (v === false || v == null) return "—";
  return v;
}

function renderEol(d) {
  const groups = Object.entries(d.eol || {});
  if (!groups.length) return '<p class="empty">データなし</p>';
  return groups
    .map(([slug, rows]) => {
      const body = rows
        .map((r) => {
          const [cls, label] = eolStatus(r);
          const left = typeof r.eol === "string" ? daysBetween(today(), r.eol) : null;
          return `<tr class="${cls === "eol" ? "dead" : ""}">
            <td class="ver">${esc(r.cycle)}${r.lts ? ' <span class="badge ok">LTS</span>' : ""}</td>
            <td class="mono">${esc(r.latest)}<br><small>${esc(r.latestReleaseDate || "")}</small></td>
            <td class="mono">${esc(fmtDate(r.support))}</td>
            <td class="mono">${esc(fmtDate(r.eol))}${left != null && left >= 0 ? `<br><small>あと${left}日</small>` : ""}</td>
            <td>${lifeBar(r)}</td>
            <td><span class="badge ${cls}">${label}</span></td>
          </tr>`;
        })
        .join("");
      return `<div class="eol-group"><h3>${esc(slug)}</h3>
        <table><thead><tr><th>系列</th><th>最新版</th><th>通常サポート</th><th>サポート終了</th><th>経過</th><th>状態</th></tr></thead>
        <tbody>${body}</tbody></table></div>`;
    })
    .join("");
}

// ---------------- 02 KEV
function renderKev(d) {
  if (!d.kev.length) return '<p class="empty">該当なし</p>';
  const cutoff = new Date(today());
  cutoff.setDate(cutoff.getDate() - (meta.days || 90));
  const c = cutoff.toISOString().slice(0, 10);
  const recent = d.kev.filter((k) => k.added >= c);
  const old = d.kev.filter((k) => k.added < c);
  const row = (k) => `<div class="row">
      <div class="date">${esc(k.added)}</div>
      <div><span class="score CRITICAL" title="KEV">KEV</span></div>
      <div class="body">
        <a class="id" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cve)}" target="_blank" rel="noopener">${esc(k.cve)}</a>
        ${k.ransomware ? '<span class="tag rw">ランサムウェア悪用</span>' : ""}${newTag(k)}
        <p class="desc"><b>${esc(k.vendor)} ${esc(k.product)}</b> — ${esc(k.desc)}</p>
        <div class="meta"><span>対応期限 ${esc(k.due || "—")}</span></div>
      </div>
    </div>`;
  let html = recent.length ? recent.map(row).join("") : `<p class="empty">直近${meta.days}日の追加はなし</p>`;
  if (old.length) {
    html += `<details class="more"><summary class="mono">それ以前の${old.length}件</summary>${old.map(row).join("")}</details>`;
  }
  return html;
}

// ---------------- 03 CVE
function scoreBox(sev, score) {
  if (score == null) return '<span class="score na">未採点</span>';
  return `<span class="score ${esc(sev)}">${Number(score).toFixed(1)}</span>`;
}

function renderCveFilters(d) {
  const base = d.cves.filter((c) => inTab(c.id));
  const counts = { ALL: base.length };
  for (const c of base) counts[c.severity || "未採点"] = (counts[c.severity || "未採点"] || 0) + 1;
  const keys = ["ALL", "KEV", "CRITICAL", "HIGH", "MEDIUM", "LOW", "未採点"];
  counts.KEV = base.filter((c) => c.kev).length;
  $("#cve-filters").innerHTML =
    keys
      .filter((k) => k === "ALL" || counts[k])
      .map((k) => `<button class="chip" data-sev="${k}" aria-pressed="${cveState.sev === k}">${k} ${counts[k] || 0}</button>`)
      .join("") + `<input type="search" id="cve-q" placeholder="絞り込み（例: CWE-79, soap）" value="${esc(cveState.q)}">`;
}

function filteredCves(d) {
  const q = cveState.q.toLowerCase();
  return d.cves.filter((c) => {
    if (!inTab(c.id)) return false;
    if (cveState.sev === "KEV" && !c.kev) return false;
    if (cveState.sev === "未採点" && c.severity) return false;
    if (!["ALL", "KEV", "未採点"].includes(cveState.sev) && c.severity !== cveState.sev) return false;
    if (q && !`${c.id} ${c.desc} ${c.cwe.join(" ")}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

function renderCves(d) {
  const list = filteredCves(d);
  if (!list.length) return '<p class="empty">該当なし</p>';
  const rows = list.slice(0, cveState.shown).map(
    (c) => `<div class="row">
      <div class="date">${esc(c.published)}</div>
      <div>${scoreBox(c.severity, c.score)}</div>
      <div class="body">
        <a class="id" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a>
        ${c.kev ? '<span class="tag kev">KEV</span>' : ""}${newTag(c)}
        ${advice(c.id)}
        <p class="desc clamp" title="クリックで全文">${esc(c.desc)}</p>
        <div class="meta">
          ${c.cvss ? `<span>CVSS ${esc(c.cvss)}</span>` : ""}
          ${c.cwe.length ? `<span>${c.cwe.map(esc).join(" ")}</span>` : ""}
          <span>${esc(c.status || "")}</span>
        </div>
      </div>
    </div>`
  );
  const rest = list.length - cveState.shown;
  return rows.join("") + (rest > 0 ? `<button class="chip more" id="cve-more">残り${rest}件を表示</button>` : "");
}

// ---------------- 04 GHSA
function renderGhsa(d) {
  if (!d.ghsa.length) return '<p class="empty">この対象はパッケージ情報を取得していません</p>';
  const row = (a) => `<div class="row">
      <div class="date">${esc(a.published)}</div>
      <div>${a.score ? scoreBox(a.severity, a.score) : `<span class="score ${esc(a.severity)}" style="font-size:10px">${esc(a.severity || "—")}</span>`}</div>
      <div class="body">
        <a class="id" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">${esc(a.summary)}</a>
        ${a.kev ? '<span class="tag kev">KEV</span>' : ""}${newTag(a)}
        ${advice(a.id)}
        <div class="meta">
          ${a.packages
            .map((p) => `<span><span class="pkg">${esc(p.name)}</span> ${esc(p.range || "")}${p.fixed ? ` → <span class="fix">${esc(p.fixed)}</span>` : ""}</span>`)
            .join("")}
          <span>${esc(a.cve || a.id)}</span>
        </div>
      </div>
    </div>`;
  const list = d.ghsa.filter((a) => inTab(a.id));
  if (!list.length) return '<p class="empty">該当なし</p>';
  const head = list.slice(0, 20).map(row).join("");
  const rest = list.slice(20);
  return head + (rest.length ? `<details class="more"><summary class="mono">残り${rest.length}件</summary>${rest.map(row).join("")}</details>` : "");
}

// ---------------- 05 JVN
function renderJvn(d) {
  if (!d.jvn.length) return '<p class="empty">該当なし</p>';
  return d.jvn
    .map(
      (j) => `<div class="row">
      <div class="date">${esc(j.date)}</div>
      <div><span class="score na">JVN</span></div>
      <div class="body">
        <a class="id" href="${esc(safeUrl(j.url))}" target="_blank" rel="noopener">${esc(j.title)}</a>${newTag(j)}
        <p class="desc">${esc(j.desc)}</p>
        <div class="meta"><span>${esc(j.id)}</span></div>
      </div>
    </div>`
    )
    .join("");
}

// ---------------- 見出しと集計
function renderHead(d, t) {
  const kevCve = d.cves.filter((c) => c.kev).length;
  return `<div class="target-head"><h2>${esc(d.label)}</h2><p>${esc(d.note)}</p></div>
    <dl class="tally">
      <div class="${t.kev_recent ? "hot" : ""}"><dt>KEV（${meta.days}日）</dt><dd>${t.kev_recent}</dd></div>
      <div class="${t.critical ? "hot" : ""}"><dt>CRITICAL</dt><dd>${t.critical}</dd></div>
      <div><dt>HIGH</dt><dd>${t.high}</dd></div>
      <div><dt>CVE（${meta.days}日）</dt><dd>${t.cves}</dd></div>
      <div><dt>うちKEV</dt><dd>${kevCve}</dd></div>
      ${d.ghsa.length ? `<div><dt>パッケージ</dt><dd>${t.ghsa}</dd></div>` : ""}
    </dl>`;
}

function replayAnimation() {
  /* アニメーションはなし */
}

async function show(id) {
  const t = meta.targets.find((x) => x.id === id) || meta.targets[0];
  current = t.id;
  if (!cache[t.id]) cache[t.id] = await loadJSON(`${t.id}.json`);
  const d = cache[t.id];
  cveState.sev = "ALL";
  cveState.q = "";
  cveState.shown = PAGE;
  const hasAction = [...d.cves, ...d.ghsa].some((x) => levelOf(x.id) === "action");
  tab = triage.updated_at ? (hasAction ? "action" : "check") : "all";

  renderNav();
  renderTabs(d);
  $("#head").innerHTML = renderHead(d, t);
  $("#eol").innerHTML = renderEol(d);
  $("#kev").innerHTML = renderKev(d);
  renderCveFilters(d);
  $("#cves").innerHTML = renderCves(d);
  $("#ghsa").innerHTML = renderGhsa(d);
  $("#jvn").innerHTML = renderJvn(d);
  $("#sec-ghsa").hidden = !d.ghsa.length;
  replayAnimation();
  document.title = `${d.label}｜バグ報`;
}

function refreshCves() {
  const d = cache[current];
  renderCveFilters(d);
  $("#cves").innerHTML = renderCves(d);
}

// ---------------- イベント
document.addEventListener("click", (e) => {
  const tb = e.target.closest("#tabs .tab");
  if (tb) {
    tab = tb.dataset.tab;
    cveState.sev = "ALL";
    cveState.shown = PAGE;
    const d = cache[current];
    renderTabs(d);
    refreshCves();
    $("#ghsa").innerHTML = renderGhsa(d);
    return;
  }
  const chip = e.target.closest("#cve-filters .chip");
  if (chip) {
    cveState.sev = chip.dataset.sev;
    cveState.shown = PAGE;
    refreshCves();
    return;
  }
  if (e.target.id === "cve-more") {
    cveState.shown += PAGE * 2;
    $("#cves").innerHTML = renderCves(cache[current]);
    return;
  }
  const desc = e.target.closest(".desc.clamp, .desc.open");
  if (desc) {
    desc.classList.toggle("clamp");
    desc.classList.toggle("open");
  }
});

document.addEventListener("input", (e) => {
  if (e.target.id !== "cve-q") return;
  cveState.q = e.target.value;
  cveState.shown = PAGE;
  $("#cves").innerHTML = renderCves(cache[current]);
});

window.addEventListener("hashchange", () => route());

(async () => {
  try {
    meta = await loadJSON("meta.json");
  } catch (err) {
    $("#fetched").textContent = "データがありません。scripts/fetch.py を実行してください";
    return;
  }
  const at = new Date(meta.fetched_at);
  $("#fetched").textContent = `最終取得 ${at.toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" })}`;
  document.querySelectorAll(".days").forEach((el) => (el.textContent = meta.days));

  const errs = Object.entries(meta.status).filter(([, v]) => v !== "ok");
  $("#status").innerHTML = errs.length
    ? errs.map(([k, v]) => `<p class="err">取得失敗 ${esc(k)}：${esc(v.slice(0, 160))}</p>`).join("")
    : "";

  try {
    triage = await loadJSON("triage.json");
  } catch {
    /* まだ仕分けていない */
  }

  // ランプを正確にするため全対象を先に読む（小さいファイルなので）
  await Promise.all(meta.targets.map(async (t) => (cache[t.id] = await loadJSON(`${t.id}.json`).catch(() => null))));
  for (const k of Object.keys(cache)) if (!cache[k]) delete cache[k];
  await initWatch();
  await route();
})();
