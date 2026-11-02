"use strict";
// まとめ（最初に開くページ）と、このサイトについて。app.js と watch.js の後に読み込む。

function showSummary() {
  current = "summary";
  setView("page");
  renderNav();

  const rows = meta.targets
    .filter((t) => cache[t.id])
    .map((t) => {
      const d = cache[t.id];
      const all = [...d.cves, ...d.ghsa];
      return { t, d, all, c: levelCounts(all.map((x) => x.id)) };
    });
  const total = { action: 0, check: 0, watch: 0, none: 0 };
  for (const r of rows) for (const k in total) total[k] += r.c[k];

  const lead = !triage.updated_at
    ? '<p class="verdict-line none">まだ仕分けていません</p>'
    : total.action
      ? `<p class="verdict-line action"><b>要対応が${total.action}件あります。</b>下の一覧の「対処」を確認してください。</p>`
      : '<p class="verdict-line ok"><b>いま要対応のものはありません。</b>通常の更新で足ります。</p>';

  const groups = rows
    .filter((r) => r.c.action)
    .map((r) => {
      const hits = [
        ...r.d.cves.filter((c) => levelOf(c.id) === "action").map((item) => ({ type: "cve", item })),
        ...r.d.ghsa.filter((a) => levelOf(a.id) === "action").map((item) => ({ type: "ghsa", item })),
      ];
      return `<section class="sum-group">
        <h3><a href="#${esc(r.t.id)}">${esc(r.d.label)}</a><span class="verdict lv-action">要対応 ${hits.length}件</span></h3>
        ${hits.map((h) => hitRow(h, isNew(h.item))).join("")}
      </section>`;
    })
    .join("");

  const table = `<table class="sum-table">
    <thead><tr><th>対象</th><th>要対応</th><th>要確認</th><th>様子見でよい</th><th>未判定</th><th>KEV追加（${meta.days}日）</th></tr></thead>
    <tbody>${rows
      .map(
        (r) => `<tr>
        <td><span class="dot ${lampOf(r.t)}"></span> <a href="#${esc(r.t.id)}">${esc(r.d.label)}</a></td>
        <td class="mono ${r.c.action ? "n-action" : "n-zero"}">${r.c.action}</td>
        <td class="mono ${r.c.check ? "n-check" : "n-zero"}">${r.c.check}</td>
        <td class="mono n-zero">${r.c.watch}</td>
        <td class="mono n-zero">${r.c.none}</td>
        <td class="mono">${r.t.kev_recent}</td>
      </tr>`
      )
      .join("")}</tbody></table>`;

  const when = triage.updated_at
    ? new Date(triage.updated_at).toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" })
    : "—";

  $("#page-view").innerHTML = `
    <div class="target-head"><h2>まとめ</h2><p>直近${meta.days}日の脆弱性を、Claudeが3段階に仕分けた結果です</p></div>
    ${lead}
    ${verdictBoxes(total, false)}
    <p class="facts">Claudeの仕分け ${esc(when)}　／　区分の基準は<a href="#about">このサイトについて</a></p>

    <section class="block">
      <h2>対象ごとの件数</h2>
      ${table}
    </section>

    <section class="block">
      <h2>要対応の一覧</h2>
      ${groups || '<p class="empty">要対応はありません</p>'}
    </section>`;
  document.title = "まとめ｜バグ報";
}

function showAbout() {
  current = "about";
  setView("page");
  renderNav();
  const levelRows = ["action", "check", "watch", "none"]
    .map((k) => `<tr><td><span class="verdict lv-${k}">${levelLabel(k)}</span></td><td>${esc(LEVEL_DESC[k])}</td></tr>`)
    .join("");

  $("#page-view").innerHTML = `
    <div class="target-head"><h2>このサイトについて</h2></div>
    <div class="doc">
      <p class="doc-lead">バグ報は、PHP・WordPress・Node.js・Python・Apache／nginxの脆弱性情報を6時間ごとに集め、対応が必要かどうかを仕分けて表示するページです。「いま何か更新しないといけないものがあるか」を確かめるために使います。</p>

      <h3>見かた</h3>
      <ol>
        <li>最初に開く<a href="#">まとめ</a>で、要対応があるかを確認します。なければ、通常の更新で足ります。</li>
        <li>要対応があれば、一覧の「対処」に書かれているバージョンに更新します。</li>
        <li>自分が使っている製品やパッケージを<a href="#mine">ウォッチリスト</a>に登録しておくと、そのバージョンに当てはまるものだけを確認できます。</li>
      </ol>

      <h3>3つの区分</h3>
      <table class="doc-table"><tbody>${levelRows}</tbody></table>
      <p>仕分けはClaude（Anthropic社のAI）が、各脆弱性の説明文・CVSSスコア・悪用の有無をもとに、次の基準で行っています。</p>
      <ul>
        <li><b>要対応</b>：CISA KEV（悪用が確認された脆弱性の一覧）に載っているもの。本体（PHP、WordPress、Node.js、CPython、Apache httpd、nginx）の脆弱性で、ネットワーク越しに認証なしで突けるCRITICAL・HIGH。広く使われているパッケージ（Laravel、Symfony、express、Django、requestsなど）の、リモートから突けるCRITICAL</li>
        <li><b>要確認</b>：上に当てはまらないHIGH。特定の設定や拡張モジュールを使っているときだけ影響するもの。利用者の少ないパッケージのCRITICAL</li>
        <li><b>様子見でよい</b>：MEDIUM以下。ローカルからしか突けない、管理者権限が前提など、条件が厳しいもの</li>
      </ul>
      <p>判断に迷うものは、一段階上（注意が必要な側）に入れています。基準の全文は<a href="https://github.com/Subara3/bug-hou/blob/main/TRIAGE.md" target="_blank" rel="noopener">TRIAGE.md</a>にあります。</p>

      <h3>色とスコア</h3>
      <table class="doc-table"><tbody>
        <tr><td><span class="dot red"></span> <span class="dot amber"></span> <span class="dot green"></span></td><td>上のメニューの丸。赤は要対応あり、橙は要確認あり、緑はどちらもなし</td></tr>
        <tr><td><span class="score CRITICAL">9.8</span></td><td>CVSSスコア9.0以上（CRITICAL）</td></tr>
        <tr><td><span class="score HIGH">7.5</span></td><td>7.0〜8.9（HIGH）</td></tr>
        <tr><td><span class="score MEDIUM">5.3</span></td><td>4.0〜6.9（MEDIUM）</td></tr>
        <tr><td><span class="tag kev" style="margin:0">KEV</span></td><td>実際に悪用が確認されている</td></tr>
        <tr><td><span class="tag new" style="margin:0">NEW</span></td><td>3日以内に初めて載ったもの（ウォッチリストでは、前回見たとき以降に増えたもの）</td></tr>
      </tbody></table>

      <h3>仕組み</h3>
      <ol class="flow">
        <li><b>集める</b>　GitHub Actionsが6時間ごとに各取得元からデータを取り、リポジトリに保存します</li>
        <li><b>仕分ける</b>　その約30分後に、Claudeがまだ仕分けていないものだけを判定します</li>
        <li><b>表示する</b>　GitHub Pagesでこのページに表示し、同時にフィードも書き出します</li>
      </ol>
      <table class="doc-table"><thead><tr><th>取得元</th><th>内容</th></tr></thead><tbody>
        <tr><td><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV</a></td><td>米国CISAが公開している、実際に悪用が確認された脆弱性の一覧</td></tr>
        <tr><td><a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NVD</a></td><td>米国NISTの脆弱性データベース。CVEの説明、CVSSスコア、影響するバージョンの範囲</td></tr>
        <tr><td><a href="https://github.com/advisories" target="_blank" rel="noopener">GitHub Advisory Database</a></td><td>Composer・npm・PyPIパッケージの脆弱性と修正版</td></tr>
        <tr><td><a href="https://endoflife.date/" target="_blank" rel="noopener">endoflife.date</a></td><td>バージョンごとのサポート期限と最新版</td></tr>
        <tr><td><a href="https://jvn.jp/" target="_blank" rel="noopener">JVN</a></td><td>日本の脆弱性情報（新着）</td></tr>
      </tbody></table>

      <h3>ウォッチリストとメール通知</h3>
      <p><a href="#mine">ウォッチリスト</a>に「PHP 8.3.14」や「laravel/framework 12.50.0」のように登録すると、そのバージョンに当てはまる脆弱性だけを表示し、要対応・要確認・問題なしを判定します。登録内容はこのブラウザのlocalStorageに保存され、サーバーには送りません。</p>
      <p>メールで受け取りたい場合は、ウォッチリストの「フィードURLをコピー」で取れるURLを、RSSをメールに転送するサービス（<a href="https://blogtrottr.com/" target="_blank" rel="noopener">Blogtrottr</a>、<a href="https://feedrabbit.com/" target="_blank" rel="noopener">FeedRabbit</a>など）に登録してください。全体の要対応だけなら <code>${esc(new URL("feeds/action.xml", location.href).href)}</code> です。</p>

      <h3>知っておいてほしいこと</h3>
      <ul>
        <li>表示しているのは直近${meta.days}日に公開されたCVEです。それより前の脆弱性は、ウォッチリストのパッケージ照合でだけ拾います</li>
        <li>NVDの分析が済んでいないCVEは、影響するバージョンの範囲がまだありません。ウォッチリストでは「バージョン情報なし（要確認）」に分けています</li>
        <li>新しく出たものは、次の仕分けまで最大6時間「未判定」になります</li>
        <li>仕分けは説明文とスコアからの自動判定です。自分の環境で使っていない機能の脆弱性が要対応に入ることもあります</li>
      </ul>

      <p class="facts">ソースコード：<a href="https://github.com/Subara3/bug-hou" target="_blank" rel="noopener">github.com/Subara3/bug-hou</a></p>
    </div>`;
  document.title = "このサイトについて｜バグ報";
}
