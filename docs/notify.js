"use strict";
// デスクトップ通知：このタブを開いているあいだ、30分おきに新しいデータがないか確かめて、
// 今すぐ・KEV入り・公的機関の注意喚起・ウォッチリストの新着が増えたら通知する。
// タブを閉じていると届かない。ほかのファイルの後に読み込む。

const NKEY = "bughou.notify.v1"; // {on, sent: {key: 日付}, watchNew}
const POLL = 30 * 60 * 1000;
const KEV_RECENT_DAYS = 3;

function loadNotify() {
  try {
    return { on: false, sent: {}, watchNew: 0, ...JSON.parse(localStorage.getItem(NKEY)) };
  } catch {
    return { on: false, sent: {}, watchNew: 0 };
  }
}
function saveNotify(n) {
  // 90日より前に送った記録は捨てる
  const cut = new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 10);
  n.sent = Object.fromEntries(Object.entries(n.sent).filter(([, d]) => d >= cut));
  localStorage.setItem(NKEY, JSON.stringify(n));
}
const notifyUsable = () => "Notification" in window && window.isSecureContext;

// 通知するものの一覧（key で2回送らないようにする）
function notifyCandidates() {
  const out = [];
  const seen = new Set();
  const recent = new Date(Date.now() - KEV_RECENT_DAYS * 864e5).toISOString().slice(0, 10);
  for (const t of meta.targets) {
    const d = cache[t.id];
    if (!d) continue;
    const items = [
      ...d.cves.map((c) => ({ id: c.id, text: c.desc })),
      ...d.ghsa.map((a) => ({ id: a.id, text: a.summary })),
    ];
    for (const x of items) {
      if (seen.has(x.id)) continue;
      seen.add(x.id);
      if (priority[x.id]?.u !== "now" || levelOf(x.id) === "read") continue;
      out.push({
        key: `now:${x.id}`,
        title: `${URGENCY[urgOf(x.id)]}：${x.id}（${d.label}）`,
        body: triage.items[x.id]?.comment || triage.items[x.id]?.todo || x.text,
        hash: t.id,
      });
    }
    for (const k of d.kev || []) {
      if (k.added < recent) continue;
      out.push({ key: `kev:${k.cve}`, title: `KEV入り：${k.cve}（${d.label}）`, body: k.name, hash: t.id });
    }
  }
  for (const a of alerts || []) {
    out.push({ key: `alert:${a.id || a.url}`, title: `注意喚起（${a.org || "公的機関"}）`, body: a.title, url: a.url });
  }
  // 同じCVEの「今すぐ」と「KEV入り」は1つにまとめる
  const nowIds = new Set(out.filter((x) => x.key.startsWith("now:")).map((x) => x.key.slice(4)));
  return out.filter((x) => !(x.key.startsWith("kev:") && nowIds.has(x.key.slice(4))));
}

function sendNotification(title, body, onClick) {
  try {
    const n = new Notification(title, { body: String(body || "").slice(0, 180), tag: title, lang: "ja" });
    n.onclick = () => {
      window.focus();
      onClick?.();
      n.close();
    };
  } catch {
    /* 通知を出せない環境 */
  }
}

// 新しいものだけ通知する。first のときは、いまあるものを送ったことにして通知しない
function notifyCheck(first) {
  const n = loadNotify();
  if (!n.on || !meta) return;
  const today = todayJST();
  const fresh = notifyCandidates().filter((x) => !n.sent[x.key]);
  for (const x of fresh) n.sent[x.key] = today;
  const wn = typeof totalNew === "function" ? totalNew() : 0;
  const watchUp = wn > n.watchNew ? wn - n.watchNew : 0;
  n.watchNew = wn;
  saveNotify(n);
  if (first || Notification.permission !== "granted") return;

  // 4件以上は1通にまとめる
  if (fresh.length > 3) {
    sendNotification(`バグ報：新しく${fresh.length}件`, fresh.slice(0, 4).map((x) => x.title).join("\n"), () => (location.hash = ""));
  } else {
    for (const x of fresh) {
      sendNotification(x.title, x.body, () => (x.url ? window.open(x.url, "_blank", "noopener") : (location.hash = x.hash)));
    }
  }
  if (watchUp) sendNotification(`ウォッチリストに新着${watchUp}件`, "登録した製品やパッケージに当てはまるものが増えました", () => (location.hash = "mine"));
}

// データが更新されていたら読み直す（画面はナビと件数だけ更新して、見ている場所は動かさない）
async function pollData() {
  let m;
  try {
    m = await loadJSON("meta.json");
  } catch {
    return;
  }
  let tri = null;
  try {
    tri = await loadJSON("triage.json");
  } catch {
    /* なし */
  }
  const changed = m.fetched_at !== meta.fetched_at || (tri && tri.updated_at !== triage.updated_at);
  if (!changed) return;
  meta = m;
  if (tri) triage = tri;
  try {
    priority = (await loadJSON("priority.json")).items || {};
  } catch {
    /* 前のまま */
  }
  alerts = await loadJSON("alerts.json").catch(() => alerts);
  await Promise.all(
    meta.targets.map(async (t) => {
      const d = await loadJSON(`${t.id}.json`).catch(() => null);
      if (d) cache[t.id] = d;
    })
  );
  showUpdated();
  renderNav();
  updateTitleBadge();
  showReloadHint();
  notifyCheck(false);
}

function showReloadHint() {
  if (document.getElementById("reload-hint")) return;
  $("#fetched").insertAdjacentHTML(
    "beforeend",
    `<button class="linkish" id="reload-hint" onclick="location.reload()">新しいデータで表示し直す</button>`
  );
}

function notifyButton() {
  if (!notifyUsable()) return "";
  const n = loadNotify();
  const on = n.on && Notification.permission === "granted";
  const denied = Notification.permission === "denied";
  return `<button class="about-link notify-btn${on ? " on" : ""}" id="notify-btn" title="${
    denied ? "ブラウザの設定で、このサイトの通知が拒否されています" : "このタブを開いているあいだ、今すぐ・KEV入り・注意喚起・ウォッチリストの新着を通知します"
  }">${on ? "通知オン" : "通知オフ"}</button>`;
}
function renderNotifyButton() {
  const old = document.getElementById("notify-btn");
  const html = notifyButton();
  if (old) old.outerHTML = html || "";
  else if (html) document.querySelector(".topbar-inner .about-link")?.insertAdjacentHTML("beforebegin", html);
}

document.addEventListener("click", async (e) => {
  if (e.target.id !== "notify-btn") return;
  const n = loadNotify();
  if (n.on && Notification.permission === "granted") {
    n.on = false;
    saveNotify(n);
  } else {
    const p = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
    if (p !== "granted") {
      renderNotifyButton();
      return;
    }
    n.on = true;
    saveNotify(n);
    notifyCheck(true);
    const nowCount = notifyCandidates().filter((x) => x.key.startsWith("now:")).length;
    sendNotification("バグ報の通知をオンにしました", `このタブを開いているあいだ、30分おきに確かめます。いま未対応の今すぐは${nowCount}件です。`);
  }
  renderNotifyButton();
});

// 最初の読み込みが終わるのを待ってから始める
(function startNotify() {
  if (!notifyUsable()) return;
  const wait = setInterval(() => {
    if (!meta || !Object.keys(cache).length) return;
    clearInterval(wait);
    renderNotifyButton();
    // 閉じていたあいだに増えたものは、開いたときに通知する
    notifyCheck(false);
    setInterval(pollData, POLL);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible" && Date.now() - (window.__lastPoll || 0) > 5 * 60 * 1000) {
        window.__lastPoll = Date.now();
        pollData();
      }
    });
  }, 500);
})();
