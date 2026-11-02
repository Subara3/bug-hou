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
  const total = { action: 0, check: 0, watch: 0, read: 0, none: 0 };
  for (const r of rows) for (const k in total) total[k] += r.c[k];

  const lead = !triage.updated_at
    ? '<p class="verdict-line none">まだ仕分けていません</p>'
    : total.action
      ? `<p class="verdict-line action"><b>要対応が${total.action}件あります。</b>下の一覧の「対処」を確認してください。</p>`
      : total.read
        ? `<p class="verdict-line ok"><b>要対応はすべて既読です。</b>既読にした${total.read}件は、各対象の「既読」タブで見られます。</p>`
        : '<p class="verdict-line ok"><b>いま要対応のものはありません。</b>急いで更新が必要なものは出ていません。</p>';

  const groups = rows
    .filter((r) => r.c.action)
    .map((r) => {
      const hits = [
        ...r.d.cves.filter((c) => levelOf(c.id) === "action").map((item) => ({ type: "cve", item })),
        ...r.d.ghsa.filter((a) => levelOf(a.id) === "action").map((item) => ({ type: "ghsa", item })),
      ].sort((a, b) => URG_ORDER.indexOf(urgOf(a.item.id)) - URG_ORDER.indexOf(urgOf(b.item.id)));
      return `<section class="sum-group">
        <h3><a href="#${esc(r.t.id)}">${esc(r.d.label)}</a><span class="verdict lv-action">要対応 ${hits.length}件</span></h3>
        ${hits.map((h) => hitRow(h, isNew(h.item))).join("")}
      </section>`;
    })
    .join("");

  const table = `<table class="sum-table">
    <thead><tr><th>対象</th><th>要対応</th><th>要確認</th><th>様子見</th><th>既読</th><th>未判定</th><th>KEV追加（${meta.days}日）</th></tr></thead>
    <tbody>${rows
      .map(
        (r) => `<tr>
        <td><span class="dot ${lampOf(r.t)}"></span> <a href="#${esc(r.t.id)}">${esc(r.d.label)}</a></td>
        <td class="mono ${r.c.action ? "n-action" : "n-zero"}">${r.c.action}</td>
        <td class="mono ${r.c.check ? "n-check" : "n-zero"}">${r.c.check}</td>
        <td class="mono n-zero">${r.c.watch}</td>
        <td class="mono n-zero">${r.c.read}</td>
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
  const levelRows = ["action", "check", "watch", "read", "none"]
    .map((k) => `<tr><td><span class="verdict lv-${k}">${levelLabel(k)}</span></td><td>${esc(LEVEL_DESC[k])}</td></tr>`)
    .join("");

  $("#page-view").innerHTML = `
    <div class="target-head"><h2>このサイトについて</h2></div>
    <div class="doc">
      <p class="doc-lead">バグ報は、PHP・WordPress・Node.js・Python・Apache／nginxの脆弱性情報を6時間ごとに集め、対応が必要かどうかを仕分けて表示するページです。「いま何か更新しないといけないものがあるか」を確かめるために使います。</p>

      <h3>見かた</h3>
      <ol>
        <li><a href="#summary">まとめ</a>で、要対応があるかを確認します。なければ急ぎの作業はありません。新しく何が出たかは、最初に開く<a href="#">ホーム</a>のタイムラインで日付順に見られます。</li>
        <li>要対応があれば、一覧の「対処」に書かれているバージョンに更新します。確認を終えたものは「既読にする」を押すと、このブラウザでは要対応の件数から外れます。</li>
        <li>自分が使っている製品やパッケージを<a href="#mine">ウォッチリスト</a>に登録しておくと、そのバージョンに当てはまるものだけを確認できます。</li>
      </ol>

      <h3>3つの区分</h3>
      <table class="doc-table"><tbody>${levelRows}</tbody></table>
      <p>仕分けはClaude（Anthropic社のAI）が行っています。各脆弱性の説明文・CVSSスコア・悪用の有無を見て、次の基準で判定します。</p>
      <ul>
        <li><b>要対応</b>：CISA KEV（悪用が確認された脆弱性の一覧）に載っているもの。本体（PHP、WordPress、Node.js、CPython、Apache httpd、nginx）の脆弱性のうち、ログインなしで外から攻撃できるCRITICAL・HIGH。広く使われているパッケージ（Laravel、Symfony、express、Django、requestsなど）の脆弱性のうち、外から攻撃できるCRITICAL</li>
        <li><b>要確認</b>：上に当てはまらないHIGH。特定の設定や拡張モジュールを使っているときだけ影響するもの。利用者の少ないパッケージのCRITICAL</li>
        <li><b>様子見</b>：MEDIUM以下のもの。サーバーにログインできる人しか攻撃できない、管理者の権限が要るなど、攻撃の条件が厳しいもの</li>
      </ul>
      <p>Claudeの判定は、各脆弱性の下にClaudeのアイコンをつけて「要対応だと思うよ」のように出しています。アイコンがついていない部分は、NVDなどの取得元のデータです。</p>
      <p>迷ったものは、重いほうの区分に入れています。基準の全文は<a href="https://github.com/Subara3/bug-hou/blob/main/TRIAGE.md" target="_blank" rel="noopener">TRIAGE.md</a>にあります。</p>

      <h3 id="about-urgency">要対応の急ぎ度</h3>
      <p>要対応には、どれくらい急ぐかを<span class="urg urg-now">今すぐ</span><span class="urg urg-soon">今週中</span><span class="urg urg-later">手が空いたら</span>の3つで付けています。急ぎ度はClaudeではなく、データから機械的に決めています。同じデータなら、いつも同じ結果になります。</p>
      <p>使っているのは、米国CISAが公開している優先度づけの手順<a href="https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc" target="_blank" rel="noopener">SSVC</a>の3つの観点です。</p>
      <table class="doc-table"><thead><tr><th>観点</th><th>値</th><th>どこから取るか</th></tr></thead><tbody>
        <tr><td>悪用されているか</td><td>悪用されている／攻撃コードが公開されている／悪用の報告なし</td><td>CISA KEVに載っていれば「悪用されている」。なければCISAがCVEごとに付けている評価（Vulnrichment）</td></tr>
        <tr><td>自動で攻撃できるか</td><td>できる／できない</td><td>CISAの評価。なければCVSSから推定（ネットワーク越し・攻撃が簡単・ログイン不要・ユーザーの操作不要がすべてそろえば「できる」）</td></tr>
        <tr><td>被害の大きさ</td><td>全面的／一部</td><td>CISAの評価。なければCVSSから推定（情報の漏えいと改ざんがどちらも「高」なら「全面的」）</td></tr>
      </tbody></table>
      <p>3つの組み合わせから、次の表で急ぎ度を決めます。この表はSSVCをもとに、このサイトで決めたものです。SSVC自体は「何日以内」といった期間を決めていません。</p>
      <table class="doc-table"><tbody>
        <tr><td><span class="urg urg-now">今すぐ</span></td><td>悪用されていて、自動で攻撃できるか、被害が全面的なもの。外に公開しているなら、更新できるまで止めることも考えてください</td></tr>
        <tr><td><span class="urg urg-soon">今週中</span></td><td>悪用されている（上に当てはまらないもの）。攻撃コードが公開されていて、自動で攻撃できるか被害が全面的なもの。悪用の報告はないが、自動で攻撃できて被害も全面的なもの</td></tr>
        <tr><td><span class="urg urg-later">手が空いたら</span></td><td>それ以外</td></tr>
      </tbody></table>
      <p>参考として、FIRSTが出しているEPSS（30日以内に悪用される確率の予測）も表示しています。EPSSは急ぎ度の判定には使っていません。</p>
      <p>Claudeは急ぎ度を決めません。急ぎ度を見たうえで「社内だけで使っているなら次の更新で大丈夫」のように、どんな環境なら止めるべきかのひとことを書いています。</p>

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
      <p><a href="#mine">ウォッチリスト</a>に「PHP 8.3.14」や「laravel/framework 12.50.0」のように登録すると、そのバージョンに当てはまる脆弱性だけを表示します。あわせて、要対応・要確認・問題なしのどれに当たるかも出します。登録内容はこのブラウザのlocalStorageに保存され、サーバーには送りません。</p>
      <p>メールで受け取りたい場合は、ウォッチリストの「フィードURLをコピー」でURLを取り、RSSをメールに転送するサービス（<a href="https://blogtrottr.com/" target="_blank" rel="noopener">Blogtrottr</a>、<a href="https://feedrabbit.com/" target="_blank" rel="noopener">FeedRabbit</a>など）に登録してください。全体の要対応だけなら <code>${esc(new URL("feeds/action.xml", location.href).href)}</code> です。</p>

      <h3>知っておいてほしいこと</h3>
      <ul>
        <li>表示しているのは直近${meta.days}日に公開されたCVEです。それより前のものは、ウォッチリストに登録したパッケージの分だけ表示します</li>
        <li>NVDの分析が済んでいないCVEは、影響するバージョンの範囲がまだありません。ウォッチリストでは「バージョン情報なし（要確認）」に分けています</li>
        <li>新しく出たものは、次の仕分けまで最大6時間「未判定」になります</li>
        <li>仕分けは説明文とスコアからの自動判定です。自分の環境で使っていない機能の脆弱性が要対応に入ることもあります</li>
      </ul>

      <p class="facts">ソースコード：<a href="https://github.com/Subara3/bug-hou" target="_blank" rel="noopener">github.com/Subara3/bug-hou</a></p>
    </div>`;
  document.title = "このサイトについて｜バグ報";
}

function showGuide() {
  current = "guide";
  setView("page");
  renderNav();
  $("#page-view").innerHTML = `
    <div class="target-head"><h2>対応のしかた</h2></div>
    <div class="doc">
      <p class="doc-lead">要対応になった脆弱性に、どの順番で何をすればいいかをまとめています。</p>

      <h3>区分と急ぎ度</h3>
      <p>このサイトでは、脆弱性に2つの印を付けています。</p>
      <table class="doc-table"><tbody>
        <tr><td><span class="verdict lv-action">要対応</span><span class="verdict lv-check">要確認</span><span class="verdict lv-watch">様子見</span></td><td><b>区分</b>：よくある使い方で影響が出るかどうか。Claudeが説明文を読んで決めています</td></tr>
        <tr><td><span class="urg urg-now">今すぐ</span><span class="urg urg-soon">今週中</span><span class="urg urg-later">手が空いたら</span></td><td><b>急ぎ度</b>：どれくらい危ないか。悪用されているか・自動で攻撃できるか・被害の大きさから、データで決めています（<a href="#about-urgency">決め方</a>）。要対応のものにだけ付けています</td></tr>
      </tbody></table>
      <p>まず要対応を見て、その中で急ぎ度の高いものから片付けてください。</p>

      <h3 id="guide-now"><span class="urg urg-now">今すぐ</span>のとき</h3>
      <p>すでに悪用されていて、被害も大きいものです。上から順に、できるところまでやってください。</p>
      <ol class="steps">
        <li><b>修正版に更新する</b>　一覧の「対処」に書いてあるバージョンを目安にしてください。</li>
        <li><b>更新できないなら、入り口を塞ぐ</b>　該当する機能や拡張を切る、設定で無効にする、WAFやIP制限で外からのアクセスを止める、などです。回避策は、各脆弱性のリンク先（NVDやGitHub）に書かれていることがあります。</li>
        <li><b>それもできないなら、サービスを止める</b>　更新できるまで止めてください。悪用されている脆弱性を開けたまま動かし続けるのは危険です。</li>
        <li><b>入られていないか確かめる</b>　更新したあとも、ログに不審なアクセスがないか、知らないファイルやアカウントが増えていないかを見てください。悪用されているものなので、更新する前に入られている可能性があります。</li>
      </ol>

      <h3 id="guide-soon"><span class="urg urg-soon">今週中</span>のとき</h3>
      <ol class="steps">
        <li><b>当てはまるか確かめる</b>　そのバージョンや機能を使っているかを見てください。<a href="#mine">ウォッチリスト</a>に登録しておくと、バージョンで絞れます。</li>
        <li><b>数日のうちに更新する</b>　止めるほどではありませんが、後回しにはしないでください。</li>
        <li><b>待つあいだに回避策があれば入れる</b>　すぐ更新できない事情があるときだけで大丈夫です。</li>
      </ol>

      <h3 id="guide-later"><span class="urg urg-later">手が空いたら</span>のとき</h3>
      <p>次の定期的な更新のときに、一緒に上げてください。サービスを止めたり、予定を変えて急いだりする必要はありません。</p>

      <h3>要確認・様子見のとき</h3>
      <ul>
        <li><b>要確認</b>：特定の設定や機能を使っているときだけ影響するものです。自分の環境で使っているかを確かめて、使っていれば要対応と同じように扱ってください。</li>
        <li><b>様子見</b>：影響が小さいか、攻撃の条件が厳しいものです。いつもの更新のときに上げてください。</li>
      </ul>

      <h3>よくある質問</h3>
      <dl class="faq">
        <dt>自分が使っているか分からない</dt>
        <dd><a href="#mine">ウォッチリスト</a>に製品やパッケージをバージョンつきで登録すると、当てはまるものだけが出ます。それでも分からなければ、使っているものとして扱ってください。</dd>
        <dt>修正版がまだ出ていない</dt>
        <dd>入り口を塞ぐ方法（機能を切る、外からのアクセスを止める）で守って、修正版が出たらすぐ更新してください。今すぐのもので塞ぐ方法もなければ、止めてください。</dd>
        <dt>社内だけで使っている</dt>
        <dd>外から直接攻撃されることはありませんが、社内の誰かのパソコンが乗っ取られると、そこから攻撃されます。外に公開しているものより後回しにしてもかまいませんが、更新はしてください。</dd>
        <dt>対応が終わったら</dt>
        <dd>各項目の右にある丸いチェックを押すと既読になり、このブラウザでは要対応の件数から外れます。</dd>
      </dl>

    </div>`;
  document.title = "対応のしかた｜バグ報";
}
