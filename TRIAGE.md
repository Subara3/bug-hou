# 仕分けの手順（クラウドのClaude向け）

このリポジトリの `docs/data/` にある脆弱性を、Webサイトや個人開発の運営者の目線で3段階に仕分ける。

## 手順

1. `git pull` で最新にする
2. `python scripts/triage.py todo > /tmp/todo.json` を実行する。0件なら何もせず終了する
3. `/tmp/todo.json` を読み、全件について判定を `/tmp/decisions.json` に書く（形式は下記）
4. `python scripts/triage.py apply /tmp/decisions.json` を実行する
5. `docs/data/triage.json` だけを `git add` し、`triage: YYYY-MM-DD` のメッセージでコミットしてpushする。pushが競合したら `git pull --rebase` してからもう一度pushする

`docs/data/` のほかのファイルやコードは変更しない。

## 判定の形式

```json
[
 {"id": "CVE-2026-109618", "level": "action", "reason": "PHP本体のRCEで悪用が確認済み", "todo": "8.3.37 / 8.4.28 以降に上げる",
  "urgency": "now", "comment": "外に公開しているなら、更新するまでサービスを止めたほうがいい"},
 {"id": "CVE-2026-20001", "level": "check", "reason": "SOAP拡張を使う場合のみ影響", "todo": ""}
]
```

- `id` … todoに出てきたidをそのまま使う
- `level` … `action` / `check` / `watch` のどれか
- `reason` … 判定の理由。日本語で60字以内
- `todo` … 何をすればよいか。修正版のバージョンが分かれば書く。日本語で60字以内。なければ空文字
- `urgency` … `action` のときだけ付ける。どれくらい急ぐか（下記）
- `comment` … `action` のときだけ付ける。急ぎ度の理由や、止めるべきか・待てるかの目安を、話し言葉で60字以内（例:「社内だけで使っているなら次の更新で大丈夫」）

`todo` の出力には、すでに要対応と判定済みで `urgency` がないものも含まれる。それも全項目を判定し直して書く。

## 判定の基準

**action（要対応）**
- KEVに載っている（`kev: true`）
- 本体（PHP、WordPress、Node.js、CPython、Apache httpd、nginx）の脆弱性で、ログインなしで外から攻撃できて、CRITICALまたはHIGH
- 広く使われているパッケージ（Laravel、Symfony、Guzzle、Monolog、PHPUnit、express、next、axios、lodash、Django、Flask、requests、urllib3、Jinja2、Pillow など）の、外から攻撃できるCRITICAL

**check（要確認）**
- 上に当てはまらないHIGH
- 特定の設定や拡張モジュールを使っているときだけ影響するCRITICAL・HIGH
- 利用者の少ないパッケージのCRITICAL

**watch（様子見）**
- MEDIUM以下
- サーバーにログインできる人しか攻撃できない、管理者の権限が要る、など条件が厳しいもの
- 未採点で説明からも深刻さが読み取れないもの

迷ったら重いほうの区分にする。

## 要対応の急ぎ度（urgency）

**now（今すぐ）** … 更新できるまで、サービスを止めるか、該当機能を切る・WAFで塞ぐなどを考えたほうがいいもの
- KEVに載っている、または悪用の報告があり、ログインなしで外から攻撃できて、乗っ取り（RCE）・認証回避・情報漏えいにつながる

**soon（今週中）** … 止めるほどではないが、数日のうちに更新したいもの
- 外から攻撃できて被害も大きいが、悪用はまだ確認されていない
- KEVに載っているが、攻撃に条件がある（特定の設定、ログインが必要など）

**later（手が空いたら）** … 要対応に入れたが、次の定期更新で直せば間に合うもの
- 被害がサービス停止（DoS）程度にとどまる、攻撃の手順が難しいなど

迷ったら急ぐほうにする。

## 文体

- reasonとtodoは「です・ます」を使わず短く書く（例: 「SOAP拡張を使う場合のみ影響」「8.4.28に更新」）
- 説明文にない事実（攻撃の有無、修正版の番号など）を推測で書かない
- 「足りる」「突ける」「担保」などの硬い言い方や業界の言い回しを使わず、ふだんの言葉で書く
