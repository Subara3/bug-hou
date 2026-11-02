"use strict";
// ホーム：すべての取得元の動きを日付順に並べる。app.js・watch.js・pages.js の後に読み込む。

const SOURCES = {
  kev: { label: "KEV", desc: "悪用を確認" },
  nvd: { label: "NVD", desc: "CVE公開" },
  ghsa: { label: "GitHub", desc: "パッケージ" },
  jvn: { label: "JVN", desc: "日本語の新着" },
  release: { label: "リリース", desc: "新しい版" },
  eol: { label: "サポート終了", desc: "期限" },
};
const TL_STEP = 60;
const tl = { src: new Set(Object.keys(SOURCES)), target: "all", mine: false, serious: false, shown: TL_STEP };

const fmtDay = (s) => {
  const d = new Date(`${s}T00:00:00+09:00`);
  return d.toLocaleDateString("ja-JP", { month: "long", day: "numeric", weekday: "short", timeZone: "Asia/Tokyo" });
};
const short = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);

// ---------------- 出来事を集める
function collectEvents() {
  const ev = new Map();
  const put = (key, e) => {
    const old = ev.get(key);
    if (old) old.targets.add(e.target);
    else ev.set(key, { ...e, targets: new Set([e.target]) });
  };
  const lastDay = today();
  for (const t of meta.targets) {
    const d = cache[t.id];
    if (!d) continue;
    for (const k of d.kev) {
      put(`kev:${k.cve}`, {
        src: "kev", date: k.added, id: k.cve, target: t.id, item: k,
        title: k.name, sub: `${k.vendor} ${k.product}`, href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cve)}`,
      });
    }
    for (const c of d.cves) {
      put(`nvd:${c.id}`, {
        src: "nvd", date: c.published, id: c.id, target: t.id, item: c,
        title: c.id, sub: short(c.desc, 140), href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}`,
      });
    }
    for (const a of d.ghsa) {
      put(`ghsa:${a.id}`, {
        src: "ghsa", date: a.published, id: a.id, target: t.id, item: a,
        title: a.summary, sub: (a.packages || []).slice(0, 3).map((p) => p.name).join("、"), href: safeUrl(a.url),
      });
    }
    for (const j of d.jvn) {
      put(`jvn:${j.id}`, { src: "jvn", date: j.date, id: j.id, target: t.id, item: j, title: j.title, sub: j.id, href: safeUrl(j.url) });
    }
    for (const [slug, rows] of Object.entries(d.eol || {})) {
      const name = eolName(slug);
      for (const r of rows || []) {
        if (r.latestReleaseDate && daysBetween(r.latestReleaseDate, lastDay) <= meta.days) {
          put(`rel:${slug}:${r.latest}`, {
            src: "release", date: r.latestReleaseDate, slug, target: t.id,
            title: `${name} ${r.latest}`, sub: `${r.cycle}系列の最新版`, href: `https://endoflife.date/${slug}`,
          });
        }
        if (typeof r.eol === "string" && Math.abs(daysBetween(r.eol, lastDay)) <= meta.days) {
          put(`eol:${slug}:${r.cycle}`, {
            src: "eol", date: r.eol, slug, target: t.id,
            title: `${name} ${r.cycle} のサポート終了`, sub: r.eol > lastDay ? "予定" : "終了しました", href: `https://endoflife.date/${slug}`,
          });
        }
      }
    }
  }
  return [...ev.values()].sort((a, b) => b.date.localeCompare(a.date) || order(a) - order(b));
}
const order = (e) => Object.keys(SOURCES).indexOf(e.src);
function eolName(slug) {
  const p = Object.entries(PRODUCTS).find(([, v]) => v.eol === slug);
  return p ? p[0] : slug;
}

// ---------------- ウォッチリストに当たるか
function watchIndex() {
  const ids = new Set();
  const slugs = new Set();
  const rxs = [];
  for (const w of loadWatch()) {
    const m = matchOf(w);
    for (const h of [...m.hit, ...m.unknown]) {
      ids.add(h.item.id);
      if (h.item.cve) ids.add(h.item.cve);
    }
    if (w.kind === "product") {
      slugs.add(PRODUCTS[w.product].eol);
      rxs.push(PRODUCTS[w.product].rx);
    }
  }
  return { ids, slugs, rxs, empty: !loadWatch().length };
}
function onWatch(e, wi) {
  if (e.src === "release" || e.src === "eol") return wi.slugs.has(e.slug);
  if (e.src === "jvn") return [...(e.title.match(/CVE-\d+-\d+/g) || [])].some((c) => wi.ids.has(c)) || wi.rxs.some((r) => r.test(e.title));
  return wi.ids.has(e.id) || (e.item?.cve && wi.ids.has(e.item.cve));
}

const evLevel = (e) => {
  if (e.src === "kev") return "action";
  if (e.src === "nvd" || e.src === "ghsa") return levelOf(e.id);
  return "";
};

// ---------------- 描画
function evRow(e, wi) {
  const lv = evLevel(e);
  const pill = lv && lv !== "none" ? `<span class="verdict lv-${lv}">${lv === "read" ? "要対応・既読" : levelLabel(lv)}</span>` : "";
  const score = e.item?.score ? `<span class="tl-score ${esc(e.item.severity)}">${esc(e.item.score)}</span>` : "";
  const names = [...e.targets].map((id) => cache[id]?.label || id).join("・");
  const mine = !wi.empty && onWatch(e, wi) ? '<span class="tag mine">ウォッチ中</span>' : "";
  return `<li class="tl-item src-${e.src}${e.date > today() ? " future" : ""}">
    <span class="tl-src">${SOURCES[e.src].label}</span>
    <div class="tl-body">
      <p class="tl-title">${pill}${score}<a href="${esc(e.href)}" target="_blank" rel="noopener">${esc(e.title)}</a>${e.item ? newTag(e.item) : ""}${mine}</p>
      <p class="tl-sub">${esc(e.sub)}</p>
      <p class="tl-meta"><a href="#${esc([...e.targets][0])}">${esc(names)}</a></p>
    </div>
  </li>`;
}

// 様子見ものは数が多いので、日ごとにたたんでおく
const isQuiet = (e) => (e.src === "nvd" || e.src === "ghsa") && evLevel(e) === "watch";
function dayItems(items, wi) {
  const loud = items.filter((e) => !isQuiet(e));
  const quiet = items.filter(isQuiet);
  const fold =
    quiet.length && !tl.mine
      ? `<li class="tl-quiet"><details><summary>様子見 ${quiet.length}件</summary><ol class="tl-list">${quiet
          .map((e) => evRow(e, wi))
          .join("")}</ol></details></li>`
      : quiet.map((e) => evRow(e, wi)).join("");
  return loud.map((e) => evRow(e, wi)).join("") + fold;
}

function filtered(all, wi) {
  return all.filter(
    (e) =>
      tl.src.has(e.src) &&
      (tl.target === "all" || e.targets.has(tl.target)) &&
      (!tl.mine || onWatch(e, wi)) &&
      (!tl.serious || ["action", "check"].includes(evLevel(e)) || e.src === "eol")
  );
}

function renderTimeline() {
  const all = collectEvents();
  const wi = watchIndex();
  const day = today();
  const list = filtered(all, wi);
  const future = list.filter((e) => e.date > day).reverse();
  const past = list.filter((e) => e.date <= day);
  const recent = (n) => all.filter((e) => e.date <= day && daysBetween(e.date, day) < n);
  const r1 = recent(1), r7 = recent(7);
  const cnt = (arr, src) => arr.filter((e) => e.src === src).length;

  // 日付ごとにまとめる
  const groups = [];
  for (const e of past.slice(0, tl.shown)) {
    const g = groups[groups.length - 1];
    if (g && g.date === e.date) g.items.push(e);
    else groups.push({ date: e.date, items: [e] });
  }
  const rest = past.length - tl.shown;

  const srcChips = Object.entries(SOURCES)
    .map(([k, s]) => `<button class="chip tl-chip src-${k}" data-tl-src="${k}" aria-pressed="${tl.src.has(k)}"><i></i>${s.label}<span>${all.filter((e) => e.src === k).length}</span></button>`)
    .join("");
  const targetOpts = [["all", "すべての対象"], ...meta.targets.map((t) => [t.id, t.label])]
    .map(([v, l]) => `<option value="${esc(v)}"${tl.target === v ? " selected" : ""}>${esc(l)}</option>`)
    .join("");

  $("#page-view").innerHTML = `
    <div class="target-head"><h2>タイムライン</h2><p>CISA KEV・NVD・GitHub Advisory・JVN・endoflife.dateの動きを日付順に並べています</p></div>
    <div class="tl-stats">
      <div><span class="tl-k">今日（${esc(fmtDay(day))}）</span><span class="tl-n">${r1.length}</span><span class="tl-d">KEV ${cnt(r1, "kev")}・CVE ${cnt(r1, "nvd")}・パッケージ ${cnt(r1, "ghsa")}</span></div>
      <div><span class="tl-k">7日間</span><span class="tl-n">${r7.length}</span><span class="tl-d">KEV ${cnt(r7, "kev")}・CVE ${cnt(r7, "nvd")}・パッケージ ${cnt(r7, "ghsa")}</span></div>
      <div><span class="tl-k">要対応（未読）</span><span class="tl-n ${all.some((e) => evLevel(e) === "action" && e.src !== "kev") ? "hot" : ""}">${all.filter((e) => e.src !== "kev" && evLevel(e) === "action").length}</span><span class="tl-d"><a href="#summary">まとめを見る</a></span></div>
    </div>
    <div class="tl-filters">
      <div class="tl-chips">${srcChips}</div>
      <div class="tl-opts">
        <select id="tl-target" aria-label="対象">${targetOpts}</select>
        <label class="tl-check"><input type="checkbox" id="tl-serious"${tl.serious ? " checked" : ""}>要対応・要確認だけ</label>
        <label class="tl-check${wi.empty ? " off" : ""}" title="${wi.empty ? "ウォッチリストに登録がありません" : ""}"><input type="checkbox" id="tl-mine"${tl.mine ? " checked" : ""}${wi.empty ? " disabled" : ""}>ウォッチリストだけ</label>
      </div>
    </div>
    ${
      future.length
        ? `<section class="tl-future"><h3>これから</h3><ol class="tl-list">${future
            .map((e) => `<li class="tl-day"><span class="tl-date">${esc(fmtDay(e.date))}</span><ol>${evRow(e, wi)}</ol></li>`)
            .join("")}</ol></section>`
        : ""
    }
    ${
      groups.length
        ? `<ol class="tl-list">${groups
            .map(
              (g) => `<li class="tl-day"><span class="tl-date">${esc(fmtDay(g.date))}<small>${g.items.length}件</small></span>
              <ol>${dayItems(g.items, wi)}</ol></li>`
            )
            .join("")}</ol>`
        : '<p class="empty">条件に当てはまるものはありません</p>'
    }
    ${rest > 0 ? `<button class="chip more" id="tl-more">さらに${Math.min(rest, TL_STEP)}件を表示（残り${rest}件）</button>` : ""}`;
}

function showTimeline() {
  current = "home";
  setView("page");
  renderNav();
  renderTimeline();
  document.title = "バグ報｜脆弱性ウォッチャー";
}

document.addEventListener("click", (e) => {
  if (current !== "home") return;
  const c = e.target.closest("[data-tl-src]");
  if (c) {
    const k = c.dataset.tlSrc;
    // すべて選ばれているときに押したら、それだけにする
    if (tl.src.size === Object.keys(SOURCES).length) tl.src = new Set([k]);
    else if (tl.src.has(k)) tl.src.delete(k);
    else tl.src.add(k);
    if (!tl.src.size) tl.src = new Set(Object.keys(SOURCES));
    tl.shown = TL_STEP;
    renderTimeline();
  } else if (e.target.id === "tl-more") {
    tl.shown += TL_STEP;
    renderTimeline();
  }
});
document.addEventListener("change", (e) => {
  if (current !== "home") return;
  if (e.target.id === "tl-target") tl.target = e.target.value;
  else if (e.target.id === "tl-mine") tl.mine = e.target.checked;
  else if (e.target.id === "tl-serious") tl.serious = e.target.checked;
  else return;
  tl.shown = TL_STEP;
  renderTimeline();
});
