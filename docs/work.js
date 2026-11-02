"use strict";
// 仕事で使うための道具：報告用の書き出し、lockファイルの照らし合わせ、記録の書き出し・読み込み。
// app.js・watch.js・pages.js・timeline.js の後に読み込む。

// ================================================================ 報告用の書き出し
function reportRows() {
  const seen = new Set();
  const rows = [];
  for (const t of meta.targets) {
    const d = cache[t.id];
    if (!d) continue;
    const items = [
      ...d.cves.map((c) => ({ id: c.id, url: `https://nvd.nist.gov/vuln/detail/${c.id}`, title: c.desc })),
      ...d.ghsa.map((a) => ({ id: a.id, url: a.url, title: a.summary })),
    ];
    for (const x of items) {
      if (seen.has(x.id) || !markable(x.id)) continue;
      seen.add(x.id);
      const tr = triage.items[x.id];
      const st = stateOf(x.id);
      const live = st?.s && (st.s === "hold" || isRead(x.id)) ? st.s : "";
      // 要確認は数が多いので、状態かメモを付けたものだけ入れる
      if (tr.level === "check" && !live && !st?.memo) continue;
      rows.push({
        target: d.label,
        id: x.id,
        level: levelLabel(tr.level),
        levelKey: tr.level,
        urgency: tr.level === "action" ? URGENCY[urgOf(x.id)] || "" : "",
        u: tr.level === "action" ? urgOf(x.id) : "",
        state: live ? STATES[live] : "未対応",
        stateKey: live || "open",
        at: live ? st.at || "" : "",
        memo: st?.memo || "",
        todo: tr.todo || "",
        reason: tr.reason || "",
        url: x.url,
      });
    }
  }
  const lv = { action: 0, check: 1 };
  return rows.sort(
    (a, b) => lv[a.levelKey] - lv[b.levelKey] || URG_ORDER.indexOf(a.u) - URG_ORDER.indexOf(b.u) || a.target.localeCompare(b.target)
  );
}

function stampLine() {
  const f = fmtAt(meta.fetched_at);
  const t = triage.updated_at ? fmtAt(triage.updated_at) : null;
  return `データ取得 ${f.t}${t ? `、Claudeの判定 ${t.t}` : ""}`;
}

function reportMarkdown(rows) {
  const cell = (s) => String(s || "").replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
  const day = new Date().toLocaleDateString("ja-JP", { timeZone: "Asia/Tokyo" });
  const count = (k) => rows.filter((r) => r.stateKey === k).length;
  const lines = [
    `## 脆弱性の対応状況（${day}時点）`,
    "",
    `要対応 ${rows.filter((r) => r.levelKey === "action").length}件、要確認 ${rows.filter((r) => r.levelKey === "check").length}件。` +
      `未対応 ${count("open")}件、保留 ${count("hold")}件、対応済み ${count("done")}件、該当なし ${count("na")}件、既読 ${count("read")}件。`,
    "",
    "| 対象 | ID | 区分 | 急ぎ度 | 状態 | メモ | 対処 |",
    "|---|---|---|---|---|---|---|",
    ...rows.map((r) =>
      `| ${cell(r.target)} | [${cell(r.id)}](${r.url}) | ${r.level} | ${r.urgency} | ${r.state}${r.at ? `（${r.at}）` : ""} | ${cell(r.memo)} | ${cell(r.todo)} |`
    ),
    "",
    `出典：バグ報 ${location.href.split("#")[0]}（${stampLine()}）`,
  ];
  return lines.join("\n");
}

function reportCsv(rows) {
  const q = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
  const head = ["対象", "ID", "区分", "急ぎ度", "状態", "状態を付けた日", "メモ", "対処", "Claudeの理由", "URL"];
  const body = rows.map((r) => [r.target, r.id, r.level, r.urgency, r.state, r.at, r.memo, r.todo, r.reason, r.url].map(q).join(","));
  // Excelで文字化けしないようにBOMを付ける
  return "﻿" + [head.map(q).join(","), ...body].join("\r\n") + "\r\n";
}

function reportBlock() {
  const rows = reportRows();
  if (!rows.length) return "";
  const n = (k) => rows.filter((r) => r.stateKey === k).length;
  return `<section class="block report">
    <h2>対応の記録</h2>
    <dl class="report-n">
      <div><dt>未対応</dt><dd class="${n("open") ? "hot" : ""}">${n("open")}</dd></div>
      <div><dt>保留</dt><dd>${n("hold")}</dd></div>
      <div><dt>対応済み</dt><dd>${n("done")}</dd></div>
      <div><dt>該当なし</dt><dd>${n("na")}</dd></div>
      <div><dt>既読</dt><dd>${n("read")}</dd></div>
    </dl>
    <p class="report-note">要対応のすべてと、状態かメモを付けた要確認の、あわせて${rows.length}件です。状態とメモは、各項目の下で付けられます。</p>
    <p class="report-btns">
      <button class="chip" data-report="md">Markdownでコピー</button>
      <button class="chip" data-report="csv">CSVで保存</button>
      <span class="report-hint">チケットやチャットにはMarkdown、Excelで開くならCSVです。</span>
    </p>
  </section>`;
}

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-report]");
  if (!b) return;
  const rows = reportRows();
  if (b.dataset.report === "md") {
    const text = reportMarkdown(rows);
    try {
      await navigator.clipboard.writeText(text);
      flash(b, "コピーしました");
    } catch {
      download(`bughou-${todayJST()}.md`, text, "text/markdown");
    }
  } else {
    download(`bughou-${todayJST()}.csv`, reportCsv(rows), "text/csv");
  }
});

function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 0);
}

// ================================================================ lockファイル
// composer.lock・package-lock.json・requirements.txt を読んで、OSVに問い合わせる。
// 送るのはパッケージ名とバージョンだけ。ファイルそのものは送らない。
const LKEY = "bughou.lock.v1";
const OSV = "https://api.osv.dev/v1";
const OSV_ECO = { Packagist: "composer", npm: "npm", PyPI: "pip" };
const lockState = { busy: false, result: null, error: "" };

function parseLock(text) {
  const deps = [];
  const add = (eco, name, version, dev) => {
    if (!name || !version) return;
    version = String(version).replace(/^v(?=\d)/, "");
    if (!/^\d/.test(version)) return; // dev-main などは照らし合わせられない
    deps.push({ eco, name, version, dev: !!dev });
  };
  const s = text.trim();
  if (s.startsWith("{")) {
    const j = JSON.parse(s);
    if (Array.isArray(j.packages)) {
      // composer.lock
      for (const p of j.packages) add("Packagist", p.name, p.version, false);
      for (const p of j["packages-dev"] || []) add("Packagist", p.name, p.version, true);
    } else if (j.packages && typeof j.packages === "object") {
      // package-lock.json v2・v3
      for (const [path, p] of Object.entries(j.packages)) {
        if (!path || p.link) continue;
        const name = p.name || path.slice(path.lastIndexOf("node_modules/") + 13);
        add("npm", name, p.version, p.dev);
      }
    } else if (j.dependencies) {
      // package-lock.json v1
      const walk = (deps0) => {
        for (const [name, p] of Object.entries(deps0 || {})) {
          add("npm", name, p.version, p.dev);
          walk(p.dependencies);
        }
      };
      walk(j.dependencies);
    } else {
      throw new Error("composer.lock か package-lock.json の形ではありません");
    }
  } else {
    // requirements.txt・pip freeze の「名前==バージョン」
    for (const line of s.split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;#,]+)/);
      if (m) add("PyPI", m[1], m[3], false);
    }
  }
  const uniq = new Map(deps.map((d) => [`${d.eco}|${d.name.toLowerCase()}|${d.version}`, d]));
  return [...uniq.values()];
}

async function osvBatch(deps) {
  const out = [];
  for (let i = 0; i < deps.length; i += 1000) {
    const chunk = deps.slice(i, i + 1000);
    const r = await fetch(`${OSV}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk.map((d) => ({ package: { ecosystem: d.eco, name: d.name }, version: d.version })) }),
    });
    if (!r.ok) throw new Error(`OSV ${r.status}`);
    const j = await r.json();
    j.results.forEach((x, k) => out.push({ dep: chunk[k], ids: (x.vulns || []).map((v) => v.id) }));
  }
  return out;
}

async function osvDetails(ids, onProgress) {
  const map = {};
  let i = 0;
  let done = 0;
  const worker = async () => {
    while (i < ids.length) {
      const id = ids[i++];
      try {
        const r = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`);
        if (r.ok) map[id] = await r.json();
      } catch {
        /* 1件の失敗で止めない */
      }
      onProgress(++done, ids.length);
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  return map;
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", ""];
const SEV_CLASS = { CRITICAL: "CRITICAL", HIGH: "HIGH", MODERATE: "MEDIUM", MEDIUM: "MEDIUM", LOW: "LOW" };

function vulnInfo(v, dep) {
  const sev = (v.database_specific?.severity || "").toUpperCase();
  const fixes = [];
  for (const a of v.affected || []) {
    if ((a.package?.name || "").toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const ev of r.events || []) if (ev.fixed) fixes.push(ev.fixed);
  }
  const fixed = fixes.filter((f) => cmpVer(f, dep.version) > 0).sort(cmpVer)[0] || "";
  const cve = (v.aliases || []).find((a) => a.startsWith("CVE-")) || "";
  const tri = triage.items[v.id] || triage.items[cve] || null;
  const url = v.id.startsWith("GHSA-") ? `https://github.com/advisories/${v.id}` : `https://osv.dev/vulnerability/${v.id}`;
  return { id: v.id, cve, sev, fixed, url, tri, summary: v.summary || (v.details || "").slice(0, 160), published: (v.published || "").slice(0, 10) };
}

// パッケージの一覧をOSVに問い合わせて、脆弱性のあるものを返す
async function scanDeps(deps, onProgress) {
  onProgress(`${deps.length}個のパッケージをOSVに問い合わせています…`);
  const hits = (await osvBatch(deps)).filter((x) => x.ids.length);
  const ids = [...new Set(hits.flatMap((x) => x.ids))];
  const det = await osvDetails(ids, (n, all) => onProgress(`脆弱性の詳しい内容を取っています（${n}／${all}）…`));
  const pkgs = hits
    .map((h) => {
      const vulns = h.ids
        .map((id) => det[id])
        .filter((v) => v && !v.withdrawn)
        .map((v) => vulnInfo(v, h.dep))
        .sort((a, b) => SEV_ORDER.indexOf(a.sev) - SEV_ORDER.indexOf(b.sev));
      return { dep: h.dep, vulns, top: vulns[0]?.sev || "" };
    })
    .filter((p) => p.vulns.length)
    .sort((a, b) => SEV_ORDER.indexOf(a.top) - SEV_ORDER.indexOf(b.top) || a.dep.name.localeCompare(b.dep.name));
  return { total: deps.length, pkgs };
}

// getDeps はパッケージの一覧を返す関数（ファイルを読むか、前回の一覧を使う）
async function runLock(getDeps, name) {
  const projName = (document.getElementById("lock-proj")?.value || "").trim();
  lockState.busy = true;
  lockState.error = "";
  lockState.result = null;
  renderLock("ファイルを読んでいます…");
  try {
    const deps = getDeps();
    if (!deps.length) throw new Error("パッケージが見つかりませんでした");
    if (projName) {
      // プロジェクトに保存して、そのプロジェクトの欄で結果を出す
      addProjFile(projByName(projName, true), name, deps);
      lockState.busy = false;
      ui.proj = projName;
      showMine();
      return;
    }
    localStorage.setItem(LKEY, JSON.stringify({ name, at: new Date().toISOString(), deps }));
    lockState.result = { name, ...(await scanDeps(deps, renderLock)) };
  } catch (e) {
    lockState.error = e.message;
  }
  lockState.busy = false;
  renderLock();
}

// seen を渡すと、そこにないものにNEWを付ける。watchBtn はウォッチリストに入れるボタンを出すか
function pkgsHtml(pkgs, { seen = null, watchBtn = true } = {}) {
  const listed = new Set(loadWatch().filter((w) => w.kind === "package").map((w) => `${w.eco}|${w.name.toLowerCase()}`));
  return pkgs
    .map((p) => {
      const eco = OSV_ECO[p.dep.eco];
      const inList = listed.has(`${eco}|${p.dep.name.toLowerCase()}`);
      const fixTo = p.vulns.map((v) => v.fixed).filter(Boolean).sort(cmpVer).pop();
      const btn = !watchBtn
        ? ""
        : inList
          ? '<span class="w-kind">ウォッチ中</span>'
          : `<button class="chip" data-lock-watch="${esc(eco)}|${esc(p.dep.name)}|${esc(p.dep.version)}">ウォッチリストに入れる</button>`;
      return `<article class="lock-pkg">
        <header>
          <span class="pkg">${esc(p.dep.name)}</span><span class="mono">${esc(p.dep.version)}</span>
          ${p.dep.dev ? '<span class="w-kind">開発用</span>' : ""}
          ${fixTo ? `<span class="lock-fix">→ <b class="fix mono">${esc(fixTo)}</b> 以上に上げる</span>` : '<span class="lock-fix none">修正版なし</span>'}
          ${btn}
        </header>
        ${p.vulns
          .map(
            (v) => `<div class="lock-v">
            <span class="score ${SEV_CLASS[v.sev] || "na"}">${esc(v.sev === "MODERATE" ? "MEDIUM" : v.sev || "—")}</span>
            <div>
              <a class="id" href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.id)}</a>
              ${seen && !seen.has(v.id) ? '<span class="tag new">NEW</span>' : ""}
              ${v.tri ? `<span class="verdict lv-${esc(v.tri.level)}">${levelLabel(v.tri.level)}</span>` : ""}
              <span class="lock-meta">${esc(v.cve)}${v.published ? `　${esc(v.published)}` : ""}${v.fixed ? `　<span class="fix">${esc(v.fixed)}で修正</span>` : ""}</span>
              <p>${esc(v.summary)}</p>
            </div>
          </div>`
          )
          .join("")}
      </article>`;
    })
    .join("");
}

function lockResultHtml() {
  const r = lockState.result;
  if (!r) return "";
  if (!r.pkgs.length) {
    return `<p class="lock-sum ok"><b>見つかりませんでした。</b>${esc(r.name)}の${r.total}個のパッケージに、いまのバージョンで当てはまる脆弱性はOSVに登録されていません。</p>`;
  }
  const nv = r.pkgs.reduce((n, p) => n + p.vulns.length, 0);
  return `<p class="lock-sum"><b>${r.pkgs.length}個のパッケージに、脆弱性が${nv}件あります。</b>${esc(r.name)}の${r.total}個を調べました。修正版があるものは、そのバージョン以上に上げてください。</p>
    ${pkgsHtml(r.pkgs)}`;
}

function renderLock(progress) {
  const box = document.getElementById("lock-result");
  if (!box) return;
  box.innerHTML = progress
    ? `<p class="lock-progress">${esc(progress)}</p>`
    : lockState.error
      ? `<p class="lock-sum err">読み込めませんでした（${esc(lockState.error)}）</p>`
      : lockResultHtml();
}

function lockBlock() {
  let last = null;
  try {
    last = JSON.parse(localStorage.getItem(LKEY));
  } catch {
    /* なし */
  }
  return `<section class="lock">
    <h3>lockファイルで調べる</h3>
    <p class="lock-lead"><code>composer.lock</code>・<code>package-lock.json</code>・<code>requirements.txt</code>を読んで、入っているパッケージのバージョンに当てはまる脆弱性を調べます。
      直近だけでなく過去の分も含みます。問い合わせ先は<a href="https://osv.dev/" target="_blank" rel="noopener">OSV</a>（Googleが運営している脆弱性データベース）で、送るのはパッケージ名とバージョンだけです。</p>
    <div class="lock-drop" id="lock-drop">
      <label class="chip add">ファイルを選ぶ<input type="file" id="lock-file" accept=".lock,.json,.txt" hidden></label>
      <span>ここにドラッグしても読めます</span>
      ${last ? `<button class="chip" id="lock-again">前回の${esc(last.name)}（${last.deps.length}個）をもう一度調べる</button>` : ""}
    </div>
    <p class="lock-to"><label>読み込み先のプロジェクト<input id="lock-proj" list="w-projs" placeholder="空欄なら保存しない" value="${esc(ui.proj || "")}"></label>
      <span>名前を入れると、そのプロジェクトに保存して、開くたびに調べ直します。lockファイルがないプロジェクトは、上のフォームで本体やパッケージを個別に入れてください。</span></p>
    <details class="lock-paste"><summary>中身を貼りつける</summary>
      <textarea id="lock-text" rows="6" placeholder="composer.lock などの中身"></textarea>
      <button class="chip" id="lock-run">調べる</button>
    </details>
    <div id="lock-result">${lockResultHtml()}</div>
  </section>`;
}

async function readLockFile(file) {
  if (!file) return;
  const text = await file.text();
  runLock(() => parseLock(text), file.name);
}

document.addEventListener("change", (e) => {
  if (e.target.id === "lock-file") readLockFile(e.target.files[0]);
  if (e.target.id === "backup-file") importBackup(e.target.files[0]);
});
document.addEventListener("dragover", (e) => {
  const z = e.target.closest?.("#lock-drop");
  if (!z) return;
  e.preventDefault();
  z.classList.add("over");
});
document.addEventListener("dragleave", (e) => e.target.closest?.("#lock-drop")?.classList.remove("over"));
document.addEventListener("drop", (e) => {
  const z = e.target.closest?.("#lock-drop");
  if (!z) return;
  e.preventDefault();
  z.classList.remove("over");
  readLockFile(e.dataTransfer.files[0]);
});
document.addEventListener("click", (e) => {
  if (lockState.busy) return;
  if (e.target.id === "lock-run") {
    const t = $("#lock-text").value;
    if (t.trim()) runLock(() => parseLock(t), "貼りつけた内容");
  } else if (e.target.id === "lock-again") {
    // 保存してあるパッケージの一覧で問い合わせ直す（ファイルを選び直さなくていいように）
    const last = JSON.parse(localStorage.getItem(LKEY));
    runLock(() => last.deps, last.name);
  } else {
    const w = e.target.closest("[data-lock-watch]");
    if (!w) return;
    const [eco, name, version] = w.dataset.lockWatch.split("|");
    const list = loadWatch();
    const entry = { kind: "package", eco, name, version, id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}` };
    list.push(entry);
    saveWatch(list);
    setSeen(entry.id, new Set(matchOf(entry).hit.map((h) => h.item.id)));
    showMine();
  }
});

// ================================================================ プロジェクト
// lockファイルの一覧と、本体・パッケージの登録をプロジェクトごとにまとめる。
// 保存したlockファイルは、ウォッチリストを開くたびにOSVへ問い合わせ直す（結果は6時間ためておく）。
const PKEY = "bughou.proj.v1"; // [{id, name, files: [{name, at, deps}]}]
const PLIVE = "bughou.live.p."; // + プロジェクトID → {at, sig, total, pkgs}
const PSEEN = "p.";

function loadProjs() {
  try {
    return JSON.parse(localStorage.getItem(PKEY)) || [];
  } catch {
    return [];
  }
}
const saveProjs = (list) => localStorage.setItem(PKEY, JSON.stringify(list));

function projByName(name, create) {
  const list = loadProjs();
  let p = list.find((x) => x.name === name);
  if (!p && create) {
    p = { id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, name, files: [] };
    list.push(p);
    saveProjs(list);
  }
  return p;
}
function updateProj(id, fn) {
  const list = loadProjs();
  const p = list.find((x) => x.id === id);
  if (p) fn(p);
  saveProjs(list);
}

function addProjFile(p, name, deps) {
  updateProj(p.id, (x) => {
    // 同じ名前のファイルは置き換える（読み直したとき）
    x.files = x.files.filter((f) => f.name !== name);
    x.files.push({ name, at: new Date().toISOString(), deps });
  });
}

function projDeps(p) {
  const m = new Map();
  for (const f of p.files) for (const d of f.deps) m.set(`${d.eco}|${d.name.toLowerCase()}|${d.version}`, d);
  return [...m.values()];
}
const depsSig = (deps) => deps.map((d) => `${d.eco}|${d.name}|${d.version}`).sort().join(",");

function projCache(p, fresh) {
  try {
    const c = JSON.parse(localStorage.getItem(PLIVE + p.id) || "null");
    if (!c || c.sig !== depsSig(projDeps(p))) return null;
    if (fresh && Date.now() - c.at > LIVE_TTL) return null;
    return c;
  } catch {
    return null;
  }
}
const projIds = (res) => res.pkgs.flatMap((x) => x.vulns.map((v) => v.id));
const hasSeen = (key) => localStorage.getItem(SEEN_PREFIX + key) !== null;

function projNew(p) {
  const c = projCache(p, false);
  if (!c || !hasSeen(PSEEN + p.id)) return 0;
  const seen = getSeen(PSEEN + p.id);
  return projIds(c).filter((id) => !seen.has(id)).length;
}
const projNewTotal = () => loadProjs().reduce((n, p) => n + projNew(p), 0);

function projDatalist() {
  return `<datalist id="w-projs">${loadProjs().map((p) => `<option value="${esc(p.name)}">`).join("")}</datalist>`;
}

function moveSelect(w) {
  const projs = loadProjs();
  if (!projs.length) return "";
  const opts = [
    `<option value="">プロジェクトなし</option>`,
    ...projs.map((p) => `<option value="${esc(p.id)}"${p.id === w.proj ? " selected" : ""}>${esc(p.name)}</option>`),
  ];
  return `<select class="w-move" data-wid="${esc(w.id)}" aria-label="プロジェクトを移す">${opts.join("")}</select>`;
}

function projSection(p, nEntries) {
  const empty = !p.files.length && !nEntries;
  return `<section class="proj" data-pid="${esc(p.id)}">
    <header class="proj-head">
      <h3>${esc(p.name)}</h3>
      <span class="proj-n" id="pn-${esc(p.id)}"></span>
      <span class="w-btns">
        <label class="chip">lockファイルを足す<input type="file" class="proj-file" data-pid="${esc(p.id)}" accept=".lock,.json,.txt" hidden></label>
        <button class="chip ghost" data-pact="rename">名前を変える</button>
        <button class="chip ghost" data-pact="del">削除</button>
      </span>
    </header>
    <div class="proj-lock" id="pl-${esc(p.id)}"></div>
    <div class="proj-entries" data-pid="${esc(p.id)}"></div>
    ${empty ? '<p class="empty">まだ何も入っていません。lockファイルを足すか、上のフォームでこのプロジェクト名を入れて本体やパッケージを追加してください。</p>' : ""}
  </section>`;
}

function projFilesHtml(p) {
  if (!p.files.length) return "";
  return `<ul class="proj-files">${p.files
    .map(
      (f) => `<li><span class="mono">${esc(f.name)}</span><span>${f.deps.length}個</span><span class="mono">${esc(md(f.at.slice(0, 10)))}に読み込み</span>
        <button class="linkish" data-pfile-del="${esc(f.name)}">外す</button></li>`
    )
    .join("")}</ul>`;
}

async function renderProjLock(p, force) {
  const el = document.getElementById("pl-" + p.id);
  if (!el) return;
  const deps = projDeps(p);
  const head = projFilesHtml(p);
  if (!deps.length) {
    el.innerHTML = head;
    return;
  }
  let res = force ? null : projCache(p, true);
  let note = "";
  if (!res) {
    try {
      res = await scanDeps(deps, (msg) => (el.innerHTML = head + `<p class="lock-progress">${esc(msg)}</p>`));
      res.at = Date.now();
      res.sig = depsSig(deps);
      localStorage.setItem(PLIVE + p.id, JSON.stringify(res));
    } catch (e) {
      res = projCache(p, false);
      note = `OSVへの問い合わせに失敗しました（${e.message}）。${res ? "前回の結果を出しています" : ""}`;
    }
  }
  if (!res) {
    el.innerHTML = head + `<p class="lock-sum err">${esc(note)}</p>`;
    return;
  }
  // 初めて調べたときに出たものは新着にしない（ウォッチリストの登録と同じ）
  const key = PSEEN + p.id;
  const ids = projIds(res);
  const seen = hasSeen(key) ? getSeen(key) : new Set(ids);
  const fresh = ids.filter((id) => !seen.has(id)).length;
  const nv = ids.length;
  const n = document.getElementById("pn-" + p.id);
  if (n) {
    const act = res.pkgs.flatMap((x) => x.vulns).filter((v) => levelOf(v.tri ? (triage.items[v.id] ? v.id : v.cve) : "") === "action").length;
    n.innerHTML = nv
      ? `${act ? `<span class="verdict lv-action">要対応 ${act}件</span>` : ""}<span class="verdict lv-check">ライブラリの脆弱性 ${nv}件</span>${fresh ? `<b class="nb">新着 ${fresh}</b>` : ""}`
      : '<span class="verdict lv-ok">ライブラリは問題なし</span>';
  }
  const when = new Date(res.at).toLocaleString("ja-JP", { timeZone: "Asia/Tokyo", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const again = `<button class="linkish" data-pact="rescan">いま調べ直す</button>`;
  const sum = nv
    ? `<p class="lock-sum"><b>${res.pkgs.length}個のパッケージに、脆弱性が${nv}件あります。</b>${res.total}個を${when}に調べました。${again}</p>`
    : `<p class="lock-sum ok"><b>見つかりませんでした。</b>${res.total}個のパッケージを${when}に調べました。${again}</p>`;
  const body = nv
    ? `<details class="more proj-pkgs"${fresh || res.pkgs.length <= 5 ? " open" : ""}><summary class="mono">パッケージごとに見る（${res.pkgs.length}個）</summary>${pkgsHtml(res.pkgs, { seen, watchBtn: false })}</details>`
    : "";
  el.innerHTML = head + (note ? `<p class="w-note">${esc(note)}</p>` : "") + sum + body;
  setSeen(key, new Set(ids));
}

document.addEventListener("change", async (e) => {
  const t = e.target;
  if (t.classList?.contains("proj-file")) {
    const file = t.files[0];
    if (!file) return;
    const pid = t.dataset.pid;
    try {
      const deps = parseLock(await file.text());
      if (!deps.length) throw new Error("パッケージが見つかりませんでした");
      addProjFile({ id: pid }, file.name, deps);
      showMine();
    } catch (err) {
      document.getElementById("pl-" + pid)?.insertAdjacentHTML("afterbegin", `<p class="lock-sum err">読み込めませんでした（${esc(err.message)}）</p>`);
    }
  } else if (t.classList?.contains("w-move")) {
    const list = loadWatch();
    const w = list.find((x) => x.id === t.dataset.wid);
    if (!w) return;
    if (t.value) w.proj = t.value;
    else delete w.proj;
    saveWatch(list);
    showMine();
  } else if (t.classList?.contains("proj-rename")) {
    const name = t.value.trim();
    const pid = t.closest("[data-pid]").dataset.pid;
    if (name && !loadProjs().some((x) => x.name === name && x.id !== pid)) updateProj(pid, (x) => (x.name = name));
    showMine();
  }
});

document.addEventListener("click", (e) => {
  const fd = e.target.closest("[data-pfile-del]");
  const b = e.target.closest("[data-pact]");
  const sec = (fd || b)?.closest("section.proj[data-pid]");
  if (!sec) return;
  const pid = sec.dataset.pid;
  if (fd) {
    updateProj(pid, (x) => (x.files = x.files.filter((f) => f.name !== fd.dataset.pfileDel)));
    showMine();
    return;
  }
  const act = b.dataset.pact;
  if (act === "rescan") {
    renderProjLock(loadProjs().find((x) => x.id === pid), true);
  } else if (act === "rename") {
    const h = sec.querySelector(".proj-head h3");
    if (h.querySelector("input")) return;
    h.innerHTML = `<input class="proj-rename" value="${esc(h.textContent)}" aria-label="プロジェクト名">`;
    h.querySelector("input").select();
  } else if (act === "del") {
    // 中の登録ごと消えるので、2回押してもらう
    if (!b.classList.contains("armed")) {
      b.classList.add("armed");
      b.textContent = "もう一度押すと、中の登録ごと消します";
      return;
    }
    const all = loadWatch();
    for (const w of all.filter((x) => x.proj === pid)) {
      localStorage.removeItem(SEEN_PREFIX + w.id);
      localStorage.removeItem(LIVE_PREFIX + w.id);
    }
    saveWatch(all.filter((x) => x.proj !== pid));
    saveProjs(loadProjs().filter((x) => x.id !== pid));
    localStorage.removeItem(PLIVE + pid);
    localStorage.removeItem(SEEN_PREFIX + PSEEN + pid);
    showMine();
  }
});

// ================================================================ 記録の書き出し・読み込み
// 状態・メモ・ウォッチリストはこのブラウザにしかないので、別のパソコンに移すときや控えに使う
function backupBlock() {
  return `<section class="backup">
    <h3>このブラウザの記録</h3>
    <p>ウォッチリスト、状態とメモ、既読は、このブラウザにだけ保存しています。別のパソコンやブラウザに移すときは、書き出したファイルを向こうで読み込んでください。</p>
    <p><button class="chip" id="backup-out">書き出す</button>
      <label class="chip">読み込む<input type="file" id="backup-file" accept=".json" hidden></label></p>
  </section>`;
}
document.addEventListener("click", (e) => {
  if (e.target.id !== "backup-out") return;
  const data = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k.startsWith("bughou.") && !k.startsWith("bughou.live.")) data[k] = localStorage.getItem(k);
  }
  download(`bughou-backup-${todayJST()}.json`, JSON.stringify({ app: "bug-hou", at: new Date().toISOString(), data }, null, 1), "application/json");
});
async function importBackup(file) {
  if (!file) return;
  try {
    const j = JSON.parse(await file.text());
    if (j.app !== "bug-hou" || !j.data) throw new Error("バグ報の書き出しファイルではありません");
    for (const [k, v] of Object.entries(j.data)) if (k.startsWith("bughou.")) localStorage.setItem(k, v);
    location.reload();
  } catch (e) {
    const p = document.querySelector(".backup p:last-child");
    if (p) p.insertAdjacentHTML("beforeend", `<span class="lock-sum err">読み込めませんでした（${esc(e.message)}）</span>`);
  }
}
