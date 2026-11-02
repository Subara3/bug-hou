"use strict";
// ウォッチリスト：このブラウザに登録した製品・パッケージに当てはまる脆弱性を拾う。
// app.js の後に読み込む（meta / cache / triage / esc などを共有する）。

const WKEY = "bughou.watch.v1";
const SEEN_PREFIX = "bughou.seen.";
const LIVE_PREFIX = "bughou.live.";
const LIVE_TTL = 6 * 3600 * 1000;

// 製品 → 所属する対象・endoflifeのID・説明文で当てるときの語
const PRODUCTS = {
  PHP: { target: "php", eol: "php", rx: /\bphp\b/i },
  WordPress: { target: "wordpress", eol: "wordpress", rx: /wordpress/i },
  "Node.js": { target: "nodejs", eol: "nodejs", rx: /node\.?js/i },
  Python: { target: "python", eol: "python", rx: /python/i },
  "Apache httpd": { target: "webserver", eol: "apache-http-server", rx: /apache http|httpd/i },
  nginx: { target: "webserver", eol: "nginx", rx: /nginx/i },
};
const ECOS = { composer: "Composer（PHP）", npm: "npm（Node.js）", pip: "PyPI（Python）" };

let archive = [];
let feedIndex = {};
const ui = { kind: "product" };

// ---------------- 保存
const loadWatch = () => {
  try {
    return JSON.parse(localStorage.getItem(WKEY)) || [];
  } catch {
    return [];
  }
};
const saveWatch = (list) => localStorage.setItem(WKEY, JSON.stringify(list));
const getSeen = (id) => new Set(JSON.parse(localStorage.getItem(SEEN_PREFIX + id) || "[]"));
const setSeen = (id, ids) => localStorage.setItem(SEEN_PREFIX + id, JSON.stringify([...ids]));

function entryLabel(w) {
  const name = w.kind === "product" ? w.product : w.name;
  return `${name}${w.version ? " " + w.version : ""}`;
}

// ---------------- バージョン比較
function tokens(v) {
  return String(v).toLowerCase().match(/\d+|[a-z]+/g) || [];
}
function cmpVer(a, b) {
  const x = tokens(a), y = tokens(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i], q = y[i];
    if (p === undefined) return /^\d/.test(q) ? -1 : 1; // 1.0 < 1.0.1、1.0 > 1.0rc1
    if (q === undefined) return /^\d/.test(p) ? 1 : -1;
    const pn = /^\d/.test(p), qn = /^\d/.test(q);
    if (pn && qn) {
      const d = Number(p) - Number(q);
      if (d) return Math.sign(d);
    } else if (pn !== qn) {
      return pn ? 1 : -1;
    } else if (p !== q) {
      return p < q ? -1 : 1;
    }
  }
  return 0;
}

// GitHub Advisory の範囲（">= 1.0, < 1.2.3" など）
function inGhsaRange(ver, range) {
  if (!range) return true;
  return range.split(",").every((part) => {
    const m = part.trim().match(/^(>=|<=|>|<|=)?\s*(.+)$/);
    if (!m) return true;
    const c = cmpVer(ver, m[2].trim());
    switch (m[1] || "=") {
      case ">=": return c >= 0;
      case ">": return c > 0;
      case "<=": return c <= 0;
      case "<": return c < 0;
      default: return c === 0;
    }
  });
}

// NVD の範囲（si / se / ei / ee / eq）
function inNvdRange(ver, r) {
  if (r.eq) return cmpVer(ver, r.eq) === 0;
  if (r.si && cmpVer(ver, r.si) < 0) return false;
  if (r.se && cmpVer(ver, r.se) <= 0) return false;
  if (r.ei && cmpVer(ver, r.ei) > 0) return false;
  if (r.ee && cmpVer(ver, r.ee) >= 0) return false;
  return true;
}

// ---------------- 照合
// 返り値: { hit: [...], unknown: [...] }  unknown はバージョン範囲が未登録で判定できないもの
function matchProduct(w) {
  const p = PRODUCTS[w.product];
  const d = p && cache[p.target];
  const hit = [], unknown = [];
  if (!d) return { hit, unknown };
  for (const c of d.cves) {
    const rs = (c.affects || []).filter((r) => r.product === w.product);
    if (rs.length) {
      if (!w.version || rs.some((r) => inNvdRange(w.version, r))) hit.push({ type: "cve", item: c });
    } else if (!(c.affects || []).length && p.rx.test(c.desc)) {
      (w.version ? unknown : hit).push({ type: "cve", item: c });
    }
  }
  return { hit, unknown };
}

function pkgHits(a, w) {
  return (a.packages || []).filter(
    (p) => p.name.toLowerCase() === w.name.toLowerCase() && (!w.version || inGhsaRange(w.version, p.range))
  );
}

function liveCached(w) {
  try {
    const c = JSON.parse(localStorage.getItem(LIVE_PREFIX + w.id) || "null");
    return c && Date.now() - c.at < LIVE_TTL ? c.items : null;
  } catch {
    return null;
  }
}

// GitHubに直接問い合わせて、過去の分も含めて「このバージョンに影響するもの」を取る
async function fetchLive(w) {
  const cached = liveCached(w);
  if (cached) return cached;
  const q = new URLSearchParams({
    ecosystem: w.eco,
    affects: w.version ? `${w.name}@${w.version}` : w.name,
    per_page: "100",
  });
  const r = await fetch(`https://api.github.com/advisories?${q}`, { headers: { Accept: "application/vnd.github+json" } });
  if (!r.ok) throw new Error(r.status === 403 || r.status === 429 ? "GitHubの回数制限" : `GitHub ${r.status}`);
  const rows = await r.json();
  const items = rows.map((a) => {
    const cs = a.cvss_severities || {};
    return {
      id: a.ghsa_id,
      cve: a.cve_id,
      summary: a.summary || "",
      severity: (a.severity || "").toUpperCase(),
      score: cs.cvss_v4?.score || cs.cvss_v3?.score || null,
      published: (a.published_at || "").slice(0, 10),
      url: a.html_url,
      packages: (a.vulnerabilities || [])
        .filter((v) => v.package)
        .map((v) => ({ name: v.package.name, range: v.vulnerable_version_range, fixed: v.first_patched_version })),
    };
  });
  localStorage.setItem(LIVE_PREFIX + w.id, JSON.stringify({ at: Date.now(), items }));
  return items;
}

function matchPackage(w, live) {
  const seen = new Map();
  for (const a of archive) {
    if (a.ecosystem === w.eco && pkgHits(a, w).length) seen.set(a.id, a);
  }
  for (const a of live || []) {
    if (!seen.has(a.id) && pkgHits(a, w).length) seen.set(a.id, a);
  }
  const hit = [...seen.values()]
    .sort((x, y) => (y.published || "").localeCompare(x.published || ""))
    .map((a) => ({ type: "ghsa", item: a }));
  return { hit, unknown: [] };
}

function matchOf(w) {
  return w.kind === "product" ? matchProduct(w) : matchPackage(w, liveCached(w));
}

// ---------------- 未読
function newCount(w) {
  const seen = getSeen(w.id);
  return matchOf(w).hit.filter((h) => !seen.has(h.item.id)).length;
}
function totalNew() {
  return loadWatch().reduce((n, w) => n + newCount(w), 0);
}

function mineNavLink() {
  const n = totalNew();
  const count = loadWatch().length;
  return `<a href="#mine" aria-current="${current === "mine"}">ウォッチリスト<span class="count${n ? " new" : ""}">${n ? `新着 ${n}` : count}</span></a>`;
}

function updateTitleBadge() {
  const n = totalNew();
  const base = current === "mine" ? "ウォッチリスト｜バグ報" : document.title.replace(/^\(\d+\)\s*/, "");
  document.title = (n ? `(${n}) ` : "") + base;
}

// ---------------- フィード
function feedFor(w) {
  if (w.kind === "product") return `feeds/${PRODUCTS[w.product].target}.xml`;
  const rel = feedIndex[w.eco]?.[w.name.toLowerCase()];
  return rel ? `feeds/${rel}` : `feeds/eco/${w.eco}.xml`;
}
const absUrl = (rel) => new URL(rel, location.href).href;

// ---------------- 描画
function eolRow(w) {
  if (w.kind !== "product" || !w.version) return null;
  const p = PRODUCTS[w.product];
  const rows = cache[p.target]?.eol?.[p.eol] || [];
  return rows.find((x) => w.version === String(x.cycle) || w.version.startsWith(x.cycle + ".")) || null;
}
function isEolSeries(w) {
  const r = eolRow(w);
  return !!r && eolStatus(r)[0] === "eol";
}

function eolLine(w) {
  if (w.kind !== "product" || !w.version) return "";
  const p = PRODUCTS[w.product];
  const rows = cache[p.target]?.eol?.[p.eol] || [];
  const r = rows.find((x) => w.version === String(x.cycle) || w.version.startsWith(x.cycle + "."));
  if (!r) return "";
  const [cls, label] = eolStatus(r);
  const behind = r.latest && cmpVer(w.version, r.latest) < 0;
  return `<p class="w-eol"><span class="badge ${cls}">${label}</span>
    ${esc(r.cycle)}系の最新は <b class="mono">${esc(r.latest)}</b>${behind ? '<span class="behind">更新があります</span>' : '<span class="fix">最新です</span>'}
    ${typeof r.eol === "string" ? `<span class="mono">サポート終了 ${esc(r.eol)}</span>` : ""}</p>`;
}

function hitRow(h, isNew) {
  const x = h.item;
  if (h.type === "cve") {
    return `<div class="row">
      <div class="date">${esc(x.published)}</div>
      <div>${scoreBox(x.severity, x.score)}</div>
      <div class="body">
        <a class="id" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(x.id)}" target="_blank" rel="noopener">${esc(x.id)}</a>
        ${x.kev ? '<span class="tag kev">KEV</span>' : ""}${isNew ? '<span class="tag new">NEW</span>' : ""}
        <p class="desc clamp" title="クリックで全文">${esc(x.desc)}</p>
        ${advice(x.id)}
      </div>
    </div>`;
  }
  const pk = (x.packages || [])
    .map((p) => `<span><span class="pkg">${esc(p.name)}</span> ${esc(p.range || "")}${p.fixed ? ` → <span class="fix">${esc(p.fixed)}</span>` : ""}</span>`)
    .join("");
  return `<div class="row">
    <div class="date">${esc(x.published)}</div>
    <div>${x.score ? scoreBox(x.severity, x.score) : `<span class="score ${esc(x.severity)}" style="font-size:10px">${esc(x.severity || "—")}</span>`}</div>
    <div class="body">
      <a class="id" href="${esc(safeUrl(x.url))}" target="_blank" rel="noopener">${esc(x.summary)}</a>
      ${x.kev ? '<span class="tag kev">KEV</span>' : ""}${isNew ? '<span class="tag new">NEW</span>' : ""}
      <div class="meta">${pk}<span>${esc(x.cve || x.id)}</span></div>
      ${advice(x.id)}
    </div>
  </div>`;
}

function entryBlock(w, m, liveNote) {
  const seen = getSeen(w.id);
  const fresh = m.hit.filter((h) => !seen.has(h.item.id)).length;
  const action = m.hit.filter((h) => levelOf(h.item.id) === "action").length;
  const check = m.hit.filter((h) => levelOf(h.item.id) === "check").length;
  const eolDead = isEolSeries(w);
  let v;
  if (action) v = ["action", `要対応 ${action}件`];
  else if (eolDead) v = ["check", "要確認（サポート終了の系列）"];
  else if (check) v = ["check", `要確認 ${check}件`];
  else if (m.unknown.length) v = ["check", "要確認（バージョン情報なし）"];
  else v = ["ok", m.hit.length ? "様子見でよい" : "問題なし"];
  const kind = w.kind === "product" ? "本体" : ECOS[w.eco] || w.eco;
  const rows = m.hit.length
    ? m.hit.slice(0, 30).map((h) => hitRow(h, !seen.has(h.item.id))).join("") +
      (m.hit.length > 30 ? `<p class="empty">ほか${m.hit.length - 30}件</p>` : "")
    : `<p class="empty">${w.version ? "このバージョンに当てはまるものはありません" : "該当なし"}</p>`;
  const unk = m.unknown.length
    ? `<details class="more"><summary class="mono">バージョン情報なし（要確認）${m.unknown.length}件</summary>${m.unknown.map((h) => hitRow(h, false)).join("")}</details>`
    : "";
  return `<article class="w-entry" data-wid="${esc(w.id)}">
    <header class="w-head">
      <span class="w-kind">${esc(kind)}</span>
      <h3>${esc(entryLabel(w))}</h3>
      <span class="verdict lv-${v[0]}">${esc(v[1])}</span>
      <span class="w-stat">
        <span>該当 ${m.hit.length}</span>
        ${fresh ? `<b class="nb">新着 ${fresh}</b>` : ""}
      </span>
      <span class="w-btns">
        <button class="chip" data-act="feed" data-url="${esc(absUrl(feedFor(w)))}">フィードURLをコピー</button>
        <button class="chip ghost" data-act="del">削除</button>
      </span>
    </header>
    ${eolLine(w)}
    ${liveNote ? `<p class="w-note">${esc(liveNote)}</p>` : ""}
    <div class="w-rows">${rows}${unk}</div>
  </article>`;
}

function formHtml() {
  const prodOpts = Object.keys(PRODUCTS).map((p) => `<option>${esc(p)}</option>`).join("");
  const ecoOpts = Object.entries(ECOS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("");
  const names = [...new Set(archive.flatMap((a) => (a.packages || []).map((p) => p.name)))].sort();
  return `<form id="w-form" class="w-form" autocomplete="off">
    <div class="seg" role="radiogroup" aria-label="種類">
      <button type="button" class="chip" data-kind="product" aria-pressed="${ui.kind === "product"}">本体</button>
      <button type="button" class="chip" data-kind="package" aria-pressed="${ui.kind === "package"}">パッケージ</button>
    </div>
    ${
      ui.kind === "product"
        ? `<label>製品<select name="product">${prodOpts}</select></label>`
        : `<label>種類<select name="eco">${ecoOpts}</select></label>
           <label class="grow">パッケージ名<input name="name" list="w-names" placeholder="laravel/framework" required></label>
           <datalist id="w-names">${names.map((n) => `<option value="${esc(n)}">`).join("")}</datalist>`
    }
    <label>バージョン<input name="version" placeholder="${ui.kind === "product" ? "8.3.14" : "12.50.0"}（空欄なら全部）"></label>
    <button class="chip add" type="submit">追加</button>
  </form>`;
}

async function showMine() {
  current = "mine";
  setView("mine");
  renderNav();
  const list = loadWatch();
  const box = $("#mine-view");
  box.innerHTML = `<div class="target-head"><h2>ウォッチリスト</h2><p>登録はこのブラウザに保存されます</p></div>
    ${formHtml()}
    <p class="w-hint">「フィードURLをコピー」で取ったURLをRSSのメール転送サービス（<a href="https://blogtrottr.com/" target="_blank" rel="noopener">Blogtrottr</a>、<a href="https://feedrabbit.com/" target="_blank" rel="noopener">FeedRabbit</a> など）に登録すると、新着がメールで届きます。
    全体の「要対応」だけを受け取るなら <button class="linkish" data-act="feed" data-url="${esc(absUrl("feeds/action.xml"))}">このフィード</button>。</p>
    <div id="w-list">${list.length ? "" : '<p class="empty">まだ登録がありません。上のフォームから製品やパッケージを追加してください。</p>'}</div>`;

  const holder = $("#w-list");
  for (const w of list) {
    const div = document.createElement("div");
    holder.appendChild(div);
    let note = "";
    if (w.kind === "package") {
      div.innerHTML = entryBlock(w, matchPackage(w, liveCached(w)), "GitHubに問い合わせ中…");
      try {
        await fetchLive(w);
      } catch (e) {
        note = `過去分の問い合わせに失敗しました（${e.message}）。直近180日分だけで照合しています`;
      }
    }
    const m = w.kind === "package" ? matchPackage(w, liveCached(w)) : matchProduct(w);
    div.outerHTML = entryBlock(w, m, note);
    // 表示した時点で既読にする（NEWの印は今回の表示には残る）
    setSeen(w.id, new Set(m.hit.map((h) => h.item.id)));
  }
  renderNav();
  updateTitleBadge();
  replayAnimation();
}

function setView(kind) {
  $("#mine-view").hidden = kind !== "mine";
  $("#page-view").hidden = kind !== "page";
  for (const el of document.querySelectorAll("#head, #tabs, .main > section.block")) el.hidden = kind !== "target";
}

async function route() {
  const h = location.hash.slice(1);
  window.scrollTo(0, 0);
  if (h === "mine") await showMine();
  else if (h === "") showTimeline();
  else if (h === "summary") showSummary();
  else if (h === "about") showAbout();
  else {
    setView("target");
    await show(h);
  }
  updateTitleBadge();
}

// ---------------- 操作
document.addEventListener("click", async (e) => {
  const k = e.target.closest("#w-form [data-kind]");
  if (k) {
    ui.kind = k.dataset.kind;
    $("#w-form").outerHTML = formHtml();
    return;
  }
  const btn = e.target.closest("[data-act]");
  if (!btn || !btn.closest("#mine-view")) return;
  if (btn.dataset.act === "feed") {
    try {
      await navigator.clipboard.writeText(btn.dataset.url);
      flash(btn, "コピーしました");
    } catch {
      // クリップボードが使えないときはURLをそのまま見せる
      let code = btn.parentElement.querySelector(".w-url");
      if (!code) {
        code = document.createElement("code");
        code.className = "w-url";
        btn.after(code);
      }
      code.textContent = btn.dataset.url;
    }
  } else if (btn.dataset.act === "del") {
    const id = btn.closest("[data-wid]").dataset.wid;
    saveWatch(loadWatch().filter((w) => w.id !== id));
    localStorage.removeItem(SEEN_PREFIX + id);
    localStorage.removeItem(LIVE_PREFIX + id);
    showMine();
  }
});

function flash(btn, text) {
  const old = btn.textContent;
  btn.textContent = text;
  btn.classList.add("done");
  setTimeout(() => {
    btn.textContent = old;
    btn.classList.remove("done");
  }, 1800);
}

document.addEventListener("submit", async (e) => {
  if (e.target.id !== "w-form") return;
  e.preventDefault();
  const f = new FormData(e.target);
  const version = String(f.get("version") || "").trim();
  const w =
    ui.kind === "product"
      ? { kind: "product", product: f.get("product"), version }
      : { kind: "package", eco: f.get("eco"), name: String(f.get("name") || "").trim(), version };
  if (w.kind === "package" && !w.name) return;
  w.id = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const list = loadWatch();
  if (list.some((x) => entryLabel(x) === entryLabel(w) && x.kind === w.kind && x.eco === w.eco)) return;
  list.push(w);
  saveWatch(list);
  // 登録した時点で出ているものは既読扱いにして、以後に増えたものだけを新着にする
  if (w.kind === "package") {
    try {
      await fetchLive(w);
    } catch {
      /* 表示時にもう一度試す */
    }
  }
  setSeen(w.id, new Set(matchOf(w).hit.map((h) => h.item.id)));
  showMine();
});

async function initWatch() {
  const [a, fi] = await Promise.all([
    loadJSON("ghsa_archive.json").catch(() => []),
    fetch("feeds/index.json").then((r) => (r.ok ? r.json() : {})).catch(() => ({})),
  ]);
  archive = a;
  feedIndex = fi;
}
