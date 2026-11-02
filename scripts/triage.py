"""Claudeによる仕分けの補助。判断そのものはClaude（クラウドのroutine）が行う。

  python scripts/triage.py todo          まだ仕分けていない項目をJSONで出す
  python scripts/triage.py apply FILE    Claudeが書いた判定を docs/data/triage.json に取り込む

判定ファイルの形（FILE）:
  [{"id": "CVE-2026-xxxx", "level": "action", "reason": "...", "todo": "..."}, ...]
  level は action（要対応） / check（要確認） / watch（様子見）
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
TRIAGE = DATA / "triage.json"
LEVELS = {"action", "check", "watch"}


def load_triage() -> dict:
    if TRIAGE.exists():
        return json.loads(TRIAGE.read_text(encoding="utf-8"))
    return {"updated_at": None, "items": {}}


def targets() -> list[dict]:
    meta = json.loads((DATA / "meta.json").read_text(encoding="utf-8"))
    return [json.loads((DATA / f"{t['id']}.json").read_text(encoding="utf-8")) for t in meta["targets"]]


def todo():
    done = load_triage()["items"]
    out = []
    for d in targets():
        for c in d["cves"]:
            prev = done.get(c["id"])
            # KEV入りしたら判定をやり直す
            if prev and not (c["kev"] and not prev.get("kev")):
                continue
            out.append(
                {
                    "id": c["id"],
                    "target": d["label"],
                    "kind": "cve",
                    "published": c["published"],
                    "score": c["score"],
                    "severity": c["severity"],
                    "vector": c["vector"],
                    "kev": c["kev"],
                    "cwe": c["cwe"],
                    "desc": c["desc"][:700],
                }
            )
        for a in d["ghsa"]:
            prev = done.get(a["id"])
            if prev and not (a["kev"] and not prev.get("kev")):
                continue
            out.append(
                {
                    "id": a["id"],
                    "target": d["label"],
                    "kind": "package",
                    "published": a["published"],
                    "score": a["score"],
                    "severity": a["severity"],
                    "kev": a["kev"],
                    "cve": a["cve"],
                    "summary": a["summary"],
                    "packages": a["packages"][:5],
                }
            )
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print(f"\n# 未判定 {len(out)} 件", file=sys.stderr)


def apply(path: str):
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    kev_ids = {
        x["id"]
        for d in targets()
        for x in d["cves"] + d["ghsa"]
        if x.get("kev")
    }
    tri = load_triage()
    bad = 0
    for r in rows:
        if r.get("level") not in LEVELS or not r.get("id"):
            bad += 1
            continue
        tri["items"][r["id"]] = {
            "level": r["level"],
            "reason": str(r.get("reason", ""))[:200],
            "todo": str(r.get("todo", ""))[:200],
            "kev": r["id"] in kev_ids,
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        }
    # 一覧から消えた項目の判定は捨てる
    alive = {x["id"] for d in targets() for x in d["cves"] + d["ghsa"]}
    tri["items"] = {k: v for k, v in sorted(tri["items"].items()) if k in alive}
    tri["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    TRIAGE.write_text(json.dumps(tri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"取り込み {len(rows) - bad} 件、不正 {bad} 件、合計 {len(tri['items'])} 件", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "todo":
        todo()
    elif len(sys.argv) >= 3 and sys.argv[1] == "apply":
        apply(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
