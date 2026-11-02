"""docs/data/ から Atom フィードを書き出す。

  docs/feeds/action.xml               Claudeが「要対応」とした項目（全対象）
  docs/feeds/{対象}.xml                対象ごとのCVE・KEV・パッケージ
  docs/feeds/eco/{エコシステム}.xml     composer / npm / pip の新着
  docs/feeds/pkg/{エコシステム}/{名前}.xml  パッケージごと（過去180日に脆弱性が出たもの）

RSSをメールに転送するサービスに登録すれば、メールで受け取れる。
エントリの日付には取得時刻ではなく公開日・初出日を使い、内容が変わらなければファイルも変わらないようにしている。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
OUT = ROOT / "docs" / "feeds"
SITE = "https://subara3.github.io/bug-hou/"
LEVEL_JA = {"action": "要対応", "check": "要確認", "watch": "様子見でよい"}
MAX = 50


def load(name, default):
    p = DATA / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def pkg_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._@-]+", "__", name.lower()).strip("_") or "_"


def stamp(d: str) -> str:
    return f"{d}T00:00:00Z" if len(d) == 10 else d


def write_feed(path: Path, title: str, page: str, entries: list[dict]):
    entries = sorted(entries, key=lambda e: (e["date"], e["id"]), reverse=True)[:MAX]
    updated = entries[0]["date"] if entries else "2026-01-01"
    feed_url = SITE + path.relative_to(ROOT / "docs").as_posix()
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="ja">',
        f"<title>{escape(title)}</title>",
        f'<link href="{escape(page)}"/>',
        f'<link rel="self" href="{escape(feed_url)}"/>',
        f"<id>{escape(feed_url)}</id>",
        f"<updated>{stamp(updated)}</updated>",
        "<author><name>バグ報</name></author>",
    ]
    for e in entries:
        parts += [
            "<entry>",
            f"<title>{escape(e['title'])}</title>",
            f'<link href="{escape(e["url"])}"/>',
            f"<id>{escape(e['uid'])}</id>",
            f"<updated>{stamp(e['date'])}</updated>",
            f'<content type="html">{escape(e["html"])}</content>',
            "</entry>",
        ]
    parts.append("</feed>")
    text = "\n".join(parts) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def advice_html(tri: dict | None) -> str:
    if not tri:
        return ""
    s = f"<p><b>Claudeの仕分け：{escape(LEVEL_JA.get(tri['level'], ''))}</b> {escape(tri.get('reason', ''))}"
    if tri.get("todo"):
        s += f"<br>→ {escape(tri['todo'])}"
    return s + "</p>"


def level_prefix(tri):
    return f"[{LEVEL_JA[tri['level']]}] " if tri else ""


def entry_cve(c, label, tri, seen):
    sev = f" {c['score']} {c['severity']}" if c.get("score") is not None else ""
    kev = " ⚠KEV" if c.get("kev") else ""
    return {
        "id": c["id"],
        "uid": f"urn:bug-hou:{c['id']}",
        "title": f"{level_prefix(tri)}{label}: {c['id']}{sev}{kev}",
        "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
        "date": max(c["published"], seen if seen and seen != "0000-00-00" else ""),
        "html": advice_html(tri) + f"<p>{escape(c['desc'])}</p>",
    }


def entry_ghsa(a, label, tri, seen):
    pk = ", ".join(
        f"{p['name']} {p.get('range') or ''}" + (f" → {p['fixed']}" if p.get("fixed") else "")
        for p in a["packages"]
    )
    kev = " ⚠KEV" if a.get("kev") else ""
    return {
        "id": a["id"],
        "uid": f"urn:bug-hou:{a['id']}",
        "title": f"{level_prefix(tri)}{label}: {a['summary']} ({a['severity']}){kev}",
        "url": a["url"],
        "date": max(a["published"], seen if seen and seen != "0000-00-00" else ""),
        "html": advice_html(tri) + f"<p>{escape(pk)}</p><p>{escape(a.get('cve') or a['id'])}</p>",
    }


def entry_kev(k, label, seen):
    return {
        "id": "kev-" + k["cve"],
        "uid": f"urn:bug-hou:kev:{k['cve']}",
        "title": f"[悪用確認] {label}: {k['cve']} {k['vendor']} {k['product']}",
        "url": f"https://nvd.nist.gov/vuln/detail/{k['cve']}",
        "date": k["added"],
        "html": f"<p>{escape(k['name'])}</p><p>{escape(k['desc'])}</p><p>対応期限 {escape(k.get('due') or '')}</p>",
    }


def main():
    meta = load("meta.json", {"targets": []})
    tri = load("triage.json", {"items": {}})["items"]
    seen = load("first_seen.json", {})
    action = []
    eco: dict[str, list] = {}

    for t in meta["targets"]:
        d = load(f"{t['id']}.json", None)
        if not d:
            continue
        entries = []
        for c in d["cves"]:
            e = entry_cve(c, d["label"], tri.get(c["id"]), seen.get(c["id"]))
            entries.append(e)
            if tri.get(c["id"], {}).get("level") == "action":
                action.append(e)
        for a in d["ghsa"]:
            e = entry_ghsa(a, d["label"], tri.get(a["id"]), seen.get(a["id"]))
            entries.append(e)
            eco.setdefault(a.get("ecosystem") or t["id"], []).append(e)
            if tri.get(a["id"], {}).get("level") == "action":
                action.append(e)
        entries += [entry_kev(k, d["label"], seen.get(k["cve"])) for k in d["kev"][:20]]
        write_feed(OUT / f"{t['id']}.xml", f"バグ報｜{d['label']}", f"{SITE}#{t['id']}", entries)

    dedup = {e["id"]: e for e in action}
    write_feed(OUT / "action.xml", "バグ報｜要対応", SITE, list(dedup.values()))

    for name, entries in eco.items():
        write_feed(OUT / "eco" / f"{name}.xml", f"バグ報｜{name} の新着", SITE, list({e["id"]: e for e in entries}.values()))

    # パッケージごと：180日分の蓄積から作る。脆弱性が出たことのあるパッケージだけファイルができる
    pkgs: dict[tuple[str, str], list] = {}
    for a in load("ghsa_archive.json", []):
        e = entry_ghsa(a, a.get("ecosystem", ""), tri.get(a["id"]), seen.get(a["id"]))
        for p in {p["name"] for p in a["packages"]}:
            pkgs.setdefault((a.get("ecosystem", "other"), p), []).append(e)
    # 一度できたフィードは消さない（登録した人のURLが切れないように）
    idx_path = OUT / "index.json"
    index = json.loads(idx_path.read_text(encoding="utf-8")) if idx_path.exists() else {}
    for (ecosys, name), entries in pkgs.items():
        rel = f"pkg/{ecosys}/{pkg_slug(name)}.xml"
        write_feed(OUT / rel, f"バグ報｜{name}（{ecosys}）", SITE, entries)
        index.setdefault(ecosys, {})[name.lower()] = rel
    (OUT / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, sort_keys=True, indent=0) + "\n", encoding="utf-8"
    )
    print(f"フィード：対象{len(meta['targets'])}・要対応{len(dedup)}件・パッケージ{len(pkgs)}個")


if __name__ == "__main__":
    main()
