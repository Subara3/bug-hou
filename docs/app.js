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
  ["action", "要対応"],
  ["check", "要確認"],
  ["watch", "様子見"],
  ["read", "既読"],
  ["none", "未判定"],
  ["all", "すべて"],
];
const LEVEL_DESC = {
  action: "すでに悪用されているか、ログインなしで外から攻撃できる深刻なもの。早めに更新してください",
  check: "特定の設定や機能を使っているときだけ影響するもの。自分の環境に当てはまるか確かめてください",
  watch: "影響が小さいか、攻撃される条件が厳しいもの。急ぎではないので、いつもの更新のときに上げれば大丈夫です",
  read: "既読にした要対応です。このブラウザでは要対応の件数に入りません。Claudeの判定が変わると要対応に戻ります",
  none: "まだClaudeが判定していないもの。6時間以内に判定されます",
  all: "期間内のすべて",
};
const levelLabel = (k) => LEVELS.find(([x]) => x === k)?.[1] || "";
function levelCounts(ids) {
  const c = { action: 0, check: 0, watch: 0, read: 0, none: 0 };
  for (const id of ids) c[levelOf(id)]++;
  return c;
}
const idsOf = (d) => [...d.cves.map((c) => c.id), ...d.ghsa.map((a) => a.id)];
const levelOf = (id) => {
  const lv = triage.items[id]?.level || "none";
  return lv === "action" && isRead(id) ? "read" : lv;
};

// ---------------- 既読（このブラウザだけ。要対応を既読にすると件数から外す）
const RKEY = "bughou.read.v1";
let readMap = (() => {
  try {
    return JSON.parse(localStorage.getItem(RKEY)) || {};
  } catch {
    return {};
  }
})();
// 仕分けをやり直したら（KEV入りなど）未読に戻すため、判定の日付とKEVを控えておく
const readStamp = (id) => {
  const t = triage.items[id];
  return t ? `${t.at}/${t.kev ? 1 : 0}` : "";
};
const isRead = (id) => !!readMap[id] && readMap[id] === readStamp(id);
function setRead(ids, on) {
  for (const id of ids) {
    if (on) readMap[id] = readStamp(id);
    else delete readMap[id];
  }
  // 一覧から消えた項目は捨てる
  const alive = new Set(Object.keys(triage.items));
  for (const id of Object.keys(readMap)) if (!alive.has(id)) delete readMap[id];
  localStorage.setItem(RKEY, JSON.stringify(readMap));
}
const CHECK_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function readButton(id) {
  const lv = levelOf(id);
  if (lv !== "action" && lv !== "read") return "";
  const on = lv === "read";
  return `<button class="readcheck" ${on ? "data-unread" : "data-read"}="${esc(id)}" aria-pressed="${on}" title="${on ? "押すと未読に戻ります" : "確認したら押してください"}">
    <span class="box">${CHECK_SVG}</span><span class="lbl">${on ? "既読" : "既読にする"}</span></button>`;
}
const inTab = (id) => tab === "all" || levelOf(id) === tab;

// Claudeの意見は吹き出しで出す（データから分かる事実と分けるため）
const OPINION = {
  action: '<b class="lv-action">要対応</b>だと思うよ',
  check: '<b class="lv-check">要確認</b>だと思うよ',
  watch: '<b class="lv-watch">様子見</b>だと思うよ',
  read: '<b class="lv-action">要対応</b>だと思うよ（既読）',
};
// 線画の星（Claudeの色）。公式ロゴは使わない
const CLAUDE_ICON = `<svg viewBox="0 0 24 24" aria-hidden="true"><g stroke="currentColor" stroke-width="2.4" stroke-linecap="round">${[0, 45, 90, 135]
  .map((r) => `<line x1="12" y1="3.5" x2="12" y2="20.5" transform="rotate(${r} 12 12)"/>`)
  .join("")}</g></svg>`;

// 要対応の急ぎ度（scripts/priority.py がCISAのSSVCの考え方でデータから決めたもの）
let priority = {};
const URGENCY = { now: "今すぐ", soon: "今週中", later: "手が空いたら" };
const URG_ORDER = ["now", "soon", "later", ""];
const urgOf = (id) => priority[id]?.u || "";
const urgTag = (u) => (u ? `<span class="urg urg-${u}">${URGENCY[u]}</span>` : "");
const SSVC_JA = {
  exp: { active: "悪用されている", poc: "攻撃コードが公開されている", none: "悪用の報告なし" },
  auto: { yes: "自動で攻撃できる", no: "自動では攻撃できない" },
  imp: { total: "被害は全面的", partial: "被害は一部" },
};
const SRC_JA = { KEV: "CISA KEV", CISA: "CISAの評価", CVSS: "CVSSから推定" };

// 急ぎ度とその根拠。要対応のものだけに出す
function prioLine(id) {
  const lv = levelOf(id);
  const p = priority[id];
  if (!p || (lv !== "action" && lv !== "read")) return "";
  const part = (k) => {
    const v = p[k];
    const label = v ? SSVC_JA[k][v] : { exp: "", auto: "自動化は不明", imp: "被害の大きさは不明" }[k];
    if (!label) return "";
    const src = p[`${k}_src`];
    return `<span class="ssvc ${v === "active" || v === "yes" || v === "total" ? "hot" : ""}">${label}${src ? `<small>${SRC_JA[src]}</small>` : ""}</span>`;
  };
  const ep = p.epss != null ? `<span class="ssvc ep" title="FIRSTのEPSS。30日以内に悪用される確率の予測（参考）">EPSS ${p.epss >= 0.999 ? "99.9%以上" : (p.epss * 100).toFixed(p.epss < 0.1 ? 1 : 0) + "%"}</span>` : "";
  const now =
    p.u === "now" && lv === "action"
      ? `<p class="prio-now">すぐ更新してください。更新できないなら、機能を切るか外からのアクセスを塞いでください。それもできないなら、更新できるまでサービスを止めてください。<a href="#guide-now">対応のしかた</a></p>`
      : "";
  return `<p class="prio"><span class="prio-k">急ぎ度</span>${urgTag(p.u)}${part("exp")}${part("auto")}${part("imp")}${ep}<a class="prio-how" href="#about-urgency">決め方</a><a class="prio-how" href="#guide-${p.u}">やること</a></p>${now}`;
}

function advice(id) {
  const t = triage.items[id];
  if (!t) return "";
  const lv = levelOf(id);
  const say = OPINION[lv] || "";
  return `${prioLine(id)}<div class="advice lv-${esc(lv)}">
    <span class="claude-icon" title="Claudeの意見">${CLAUDE_ICON}</span>
    <div class="opinion">
      <p class="say">${say}<span class="why">${esc(t.reason)}</span></p>
      ${t.comment && (lv === "action" || lv === "read") ? `<p class="urgency">${esc(t.comment)}</p>` : ""}
      ${t.todo ? `<p class="todo"><span>対処</span>${esc(t.todo)}</p>` : ""}
    </div>
  </div>`;
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
      .join("") + `<span class="tab-note">${when}</span><p class="tab-desc">${esc(LEVEL_DESC[tab])}</p>`;
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
  const d0 = cache[t.id];
  if (triage.updated_at && d0) {
    const c = levelCounts(idsOf(d0));
    return c.action ? "red" : c.check ? "amber" : "green";
  }
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
    `<a href="#" aria-current="${current === "home"}">ホーム</a><a href="#summary" aria-current="${current === "summary"}">まとめ</a><span class="sep"></span>` +
    meta.targets
      .map(
        (t) => {
          const act = cache[t.id] ? levelCounts(idsOf(cache[t.id])).action : 0;
          return `<a href="#${esc(t.id)}" aria-current="${t.id === current}">
        <span class="dot ${lampOf(t)}"></span>${esc(t.label)}${act ? `<span class="count new">確認 ${act}件</span>` : ""}
      </a>`;
        }
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
  let html = recent.length ? recent.map(row).join("") : `<p class="empty">直近${meta.days}日の追加はありません</p>`;
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
        <p class="desc clamp" title="クリックで全文">${esc(c.desc)}</p>
        <div class="meta">
          ${c.cvss ? `<span>CVSS ${esc(c.cvss)}</span>` : ""}
          ${c.cwe.length ? `<span>${c.cwe.map(esc).join(" ")}</span>` : ""}
          <span>${esc(c.status || "")}</span>
        </div>
        ${advice(c.id)}
      </div>
      ${readButton(c.id)}
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
        <div class="meta">
          ${a.packages
            .map((p) => `<span><span class="pkg">${esc(p.name)}</span> ${esc(p.range || "")}${p.fixed ? ` → <span class="fix">${esc(p.fixed)}</span>` : ""}</span>`)
            .join("")}
          <span>${esc(a.cve || a.id)}</span>
        </div>
        ${advice(a.id)}
      </div>
      ${readButton(a.id)}
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
function todoList(items) {
  // 同じ対処はまとめる
  // 急ぐものから並べる
  const sorted = [...items].sort((a, b) => URG_ORDER.indexOf(urgOf(a.id)) - URG_ORDER.indexOf(urgOf(b.id)));
  const by = new Map();
  for (const x of sorted) {
    const t = triage.items[x.id];
    const key = `${urgOf(x.id)}|${t?.todo || t?.reason || x.id}`;
    if (!by.has(key)) by.set(key, []);
    by.get(key).push(x.id);
  }
  return `<ul class="todo-list">${[...by]
    .map(([key, ids]) => {
      const [u, todo] = [key.slice(0, key.indexOf("|")), key.slice(key.indexOf("|") + 1)];
      return `<li>${urgTag(u)}${esc(todo)}<span class="mono">${ids.map(esc).join("、")}</span></li>`;
    })
    .join("")}</ul>`;
}

function verdictBoxes(c, linkable) {
  const tag = linkable ? "button" : "div";
  return `<div class="verdicts">${["action", "check", "watch"]
    .map(
      (k) => `<${tag} ${linkable ? `data-tab="${k}"` : ""} class="vbox lv-${k}${c[k] ? "" : " zero"}">
        <span class="vlabel">${levelLabel(k)}</span><span class="vnum">${c[k]}</span>
        <span class="vdesc">${esc(LEVEL_DESC[k])}</span>
      </${tag}>`
    )
    .join("")}</div>`;
}

function verdictLine(actions, readN = 0) {
  if (!triage.updated_at) return '<p class="verdict-line none">まだ仕分けていません</p>';
  if (!actions.length)
    return readN
      ? `<p class="verdict-line ok"><b>要対応はすべて既読です。</b>既読にした${readN}件は「既読」のタブで見られます。</p>`
      : '<p class="verdict-line ok"><b>要対応はありません。</b>急いで更新が必要なものは出ていません。</p>';
  return `<div class="verdict-line action"><b>要対応が${actions.length}件あります。</b><span class="todo-head">TODO</span>${todoList(actions)}
    <button class="readcheck wide" data-read-all="${esc(actions.map((x) => x.id).join(" "))}"><span class="box">${CHECK_SVG}</span><span class="lbl">${actions.length}件とも既読にする</span></button></div>`;
}

function renderHead(d, t) {
  const all = [...d.cves, ...d.ghsa];
  const c = levelCounts(all.map((x) => x.id));
  const actions = all.filter((x) => levelOf(x.id) === "action");
  return `<div class="target-head"><h2>${esc(d.label)}</h2><p>${esc(d.note)}</p></div>
    ${verdictLine(actions, c.read)}
    ${verdictBoxes(c, true)}
    <p class="facts">直近${meta.days}日のCVE ${t.cves}件（CRITICAL ${t.critical}・HIGH ${t.high}）／KEV追加 ${t.kev_recent}件${d.ghsa.length ? `／パッケージ ${t.ghsa}件` : ""}</p>`;
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

// 既読を切り替えたあと、スクロール位置とタブを保ったまま描き直す
function rerender() {
  renderNav();
  if (current === "home") return renderTimeline();
  if (current === "summary") return showSummary();
  if (current === "mine") return showMine();
  const d = cache[current];
  if (!d) return;
  const t = meta.targets.find((x) => x.id === current);
  renderTabs(d);
  $("#head").innerHTML = renderHead(d, t);
  refreshCves();
  $("#ghsa").innerHTML = renderGhsa(d);
}

// ---------------- イベント
document.addEventListener("click", (e) => {
  const rb = e.target.closest("[data-read], [data-unread], [data-read-all]");
  if (rb) {
    const ids = (rb.dataset.readAll || rb.dataset.read || rb.dataset.unread).split(" ");
    setRead(ids, !rb.dataset.unread);
    rerender();
    return;
  }
  const tb = e.target.closest("#tabs .tab, .verdicts button[data-tab]");
  if (tb) {
    tab = tb.dataset.tab;
    cveState.sev = "ALL";
    cveState.shown = PAGE;
    const d = cache[current];
    renderTabs(d);
    refreshCves();
    $("#ghsa").innerHTML = renderGhsa(d);
    if (tb.closest(".verdicts")) $("#tabs").scrollIntoView({ behavior: "smooth", block: "start" });
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
    priority = (await loadJSON("priority.json")).items || {};
  } catch {
    /* まだ作っていない */
  }
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
