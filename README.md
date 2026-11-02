# バグ報（ばくほう）

脆弱性ウォッチャー。

PHP・WordPress・Node.js・Python・Apache/nginxの脆弱性情報を、GitHub Actionsで6時間ごとに集めてGitHub Pagesで表示します。

## 取得元

| 取得元 | 内容 |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 実際に悪用が確認された脆弱性 |
| [NVD API 2.0](https://nvd.nist.gov/developers) | CVEとCVSSスコア（直近90日） |
| [GitHub Advisory Database](https://github.com/advisories) | Composer・npm・PyPIパッケージの脆弱性 |
| [endoflife.date](https://endoflife.date/) | バージョンごとのサポート期限 |
| [JVN](https://jvn.jp/) 新着RSS | 日本語の脆弱性情報 |

This product uses the NVD API but is not endorsed or certified by the NVD.

## 対象を増やす

`targets.json` に追記します。

- `nvd` … `cpe`（CPE名）または `source`（CVEの発行元）。`match` を書くと説明文を正規表現で絞り込む
- `kev` … KEVのベンダー名・製品名に当てる正規表現
- `ghsa` … `composer` `npm` `pip` `maven` `go` `rubygems` `nuget` `rust` など。なければ `null`
- `eol` … endoflife.dateの製品ID
- `jvn` … JVNのタイトル・概要に当てる正規表現

## Claudeの仕分け

クラウドで動くClaude Code（スケジュール実行）が6時間ごとに [TRIAGE.md](TRIAGE.md) の手順で新着を「対応が必要／確認しておく／様子見」に分け、`docs/data/triage.json` に書きます。画面ではCVEとパッケージの欄がこの3つのタブに分かれます。

## 手元で動かす

```sh
python scripts/fetch.py
cd docs && python -m http.server 8765
```

WindowsでSSL証明書の検証に失敗するときは、`CA_BUNDLE` に証明書ファイル（certifiの `cacert.pem` など）を指定します。

## GitHubでの設定

1. Settings → Pages で `main` ブランチの `/docs` を公開元にする
2. （任意）[NVDのAPIキー](https://nvd.nist.gov/developers/request-an-api-key)を Settings → Secrets → Actions に `NVD_API_KEY` で登録する
3. Actionsタブから `watch` を手動実行して動作を確認する
