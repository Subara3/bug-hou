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
 {"id": "CVE-2026-109618", "level": "action", "reason": "PHP本体のRCEで悪用が確認済み", "todo": "8.3.37 / 8.4.28 以降に上げる"}
]
```

- `id` … todoに出てきたidをそのまま使う
- `level` … `action` / `check` / `watch` のどれか
- `reason` … 判定の理由。日本語で60字以内
- `todo` … 何をすればよいか。修正版のバージョンが分かれば書く。日本語で60字以内。なければ空文字

## 判定の基準

**action（要対応）**
- KEVに載っている（`kev: true`）
- 本体（PHP、WordPress、Node.js、CPython、Apache httpd、nginx）の脆弱性で、ログインなしで外から攻撃できて、CRITICALまたはHIGH
- 広く使われているパッケージ（Laravel、Symfony、Guzzle、Monolog、PHPUnit、express、next、axios、lodash、Django、Flask、requests、urllib3、Jinja2、Pillow など）の、外から攻撃できるCRITICAL

**check（要確認）**
- 上に当てはまらないHIGH
- 特定の設定や拡張モジュールを使っているときだけ影響するCRITICAL・HIGH
- 利用者の少ないパッケージのCRITICAL

**watch（様子見でよい）**
- MEDIUM以下
- サーバーにログインできる人しか攻撃できない、管理者の権限が要る、など条件が厳しいもの
- 未採点で説明からも深刻さが読み取れないもの

迷ったら重いほうの区分にする。

## 文体

- reasonとtodoは「です・ます」を使わず短く書く（例: 「SOAP拡張を使う場合のみ影響」「8.4.28に更新」）
- 説明文にない事実（攻撃の有無、修正版の番号など）を推測で書かない
- 「足りる」「突ける」「担保」などの硬い言い方や業界の言い回しを使わず、ふだんの言葉で書く
