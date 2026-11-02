"""急ぎ度（今すぐ・今週中・手が空いたら）をデータから決める。

CISAのSSVC（Stakeholder-Specific Vulnerability Categorization）の3つの判定点を使う。

  悪用（Exploitation）      active / poc / none
  自動化（Automatable）      yes / no
  被害（Technical Impact）   total / partial

値の取り方（上ほど優先）
  悪用   … CISA KEVに載っていれば active。なければCISAがCVEに付けたSSVC（Vulnrichment）。どちらもなければ none
  自動化 … CISAのSSVC。なければCVSSのベクトルから（ネットワーク越し・攻撃が簡単・ログイン不要・操作不要なら yes）
  被害   … CISAのSSVC。なければCVSSのベクトルから（機密性と完全性がどちらもHなら total）

組み合わせ（このサイトで決めたもの。TRIAGE.md と「このサイトについて」に同じ表を載せる）
  now   … 悪用 active で、自動化 yes か 被害 total
  soon  … 悪用 active（上以外）／ 悪用 poc で、自動化 yes か 被害 total ／ 悪用 none で、自動化 yes かつ 被害 total
  later … それ以外

EPSS（FIRSTが出している、30日以内に悪用される確率の予測）は参考として表示するだけで、判定には使わない。

  python scripts/priority.py      docs/data/priority.json を書く
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
from datetime import timedelta

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from fetch import NOW, get_json, load, log, save  # noqa: E402

TODAY = NOW.strftime("%Y-%m-%d")
RECHECK_FOUND = 7  # SSVCが付いているものは7日ごとに見直す（悪用の状況が変わるため）
RECHECK_MISSING = 1  # まだ付いていないものは1日ごと


def items_by_target() -> list[dict]:
    meta = load("meta.json", {"targets": []})
    out = []
    for t in meta["targets"]:
        d = load(f"{t['id']}.json", None)
        if not d:
            continue
        for c in d["cves"]:
            out.append({"id": c["id"], "cve": c["id"], "kev": c["kev"], "vector": c.get("vector")})
        for a in d["ghsa"]:
            out.append({"id": a["id"], "cve": a.get("cve"), "kev": a["kev"], "vector": a.get("vector")})
    return out


# ---------------------------------------------------------------- CISAのSSVC
def cisa_ssvc(cve: str) -> dict | None:
    d = get_json(f"https://cveawg.mitre.org/api/cve/{urllib.parse.quote(cve)}")
    for a in d.get("containers", {}).get("adp", []):
        if a.get("providerMetadata", {}).get("shortName") != "CISA-ADP":
            continue
        for m in a.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                opts = {}
                for kv in o.get("content", {}).get("options", []):
                    opts.update({k.lower(): str(v).lower() for k, v in kv.items()})
                return {
                    "exploitation": opts.get("exploitation"),
                    "automatable": opts.get("automatable"),
                    "impact": opts.get("technical impact"),
                }
    return None


def update_ssvc_cache(cves: set[str]) -> dict:
    cache = load("ssvc.json", {})
    for cve in sorted(cves):
        c = cache.get(cve)
        if c:
            wait = RECHECK_FOUND if c.get("ssvc") else RECHECK_MISSING
            if c.get("checked", "") > (NOW - timedelta(days=wait)).strftime("%Y-%m-%d"):
                continue
        try:
            cache[cve] = {"ssvc": cisa_ssvc(cve), "checked": TODAY}
        except urllib.error.HTTPError as e:
            if e.code == 404:  # CVEのレコードがまだ公開されていない
                cache[cve] = {"ssvc": None, "checked": TODAY}
            else:
                log("SSVC失敗", cve, e)
        except Exception as e:  # 1件の失敗で止めない
            log("SSVC失敗", cve, e)
        time.sleep(0.3)
    return {k: v for k, v in sorted(cache.items()) if k in cves}


# ---------------------------------------------------------------- EPSS
def epss(cves: set[str]) -> dict:
    out = {}
    ids = sorted(cves)
    for i in range(0, len(ids), 80):
        chunk = ids[i : i + 80]
        try:
            d = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(chunk))
        except Exception as e:
            log("EPSS失敗", e)
            continue
        for r in d.get("data", []):
            out[r["cve"]] = {"epss": round(float(r["epss"]), 4), "pct": round(float(r["percentile"]), 4)}
        time.sleep(0.5)
    return out


# ---------------------------------------------------------------- CVSSから
def parse_vector(v: str | None) -> dict:
    if not v:
        return {}
    return dict(p.split(":", 1) for p in v.split("/")[1:] if ":" in p)


def auto_from_cvss(m: dict) -> str | None:
    if not m:
        return None
    easy = m.get("AV") == "N" and m.get("AC") == "L" and m.get("PR") == "N" and m.get("UI") == "N"
    if "AT" in m:  # CVSS 4.0
        easy = easy and m["AT"] == "N"
    return "yes" if easy else "no"


def impact_from_cvss(m: dict) -> str | None:
    if not m:
        return None
    c = m.get("VC", m.get("C"))
    i = m.get("VI", m.get("I"))
    return "total" if c == "H" and i == "H" else "partial"


def decide(exp: str, auto: str | None, imp: str | None) -> str:
    big = auto == "yes" or imp == "total"
    if exp == "active":
        return "now" if big else "soon"
    if exp == "poc":
        return "soon" if big else "later"
    if auto == "yes" and imp == "total":
        return "soon"
    return "later"


def main():
    items = items_by_target()
    cves = {x["cve"] for x in items if x["cve"]}
    log(f"CVE {len(cves)}件のSSVCとEPSSを確認")
    ssvc = update_ssvc_cache(cves)
    save("ssvc.json", ssvc)
    ep = epss(cves)

    out = {}
    for x in items:
        s = (ssvc.get(x["cve"]) or {}).get("ssvc") or {}
        m = parse_vector(x["vector"])
        if x["kev"]:
            exp, exp_src = "active", "KEV"
        elif s.get("exploitation") in ("active", "poc", "none"):
            exp, exp_src = s["exploitation"], "CISA"
        else:
            exp, exp_src = "none", ""
        if s.get("automatable") in ("yes", "no"):
            auto, auto_src = s["automatable"], "CISA"
        else:
            auto, auto_src = auto_from_cvss(m), "CVSS" if m else ""
        if s.get("impact") in ("total", "partial"):
            imp, imp_src = s["impact"], "CISA"
        else:
            imp, imp_src = impact_from_cvss(m), "CVSS" if m else ""
        row = {
            "u": decide(exp, auto, imp),
            "exp": exp, "exp_src": exp_src,
            "auto": auto, "auto_src": auto_src,
            "imp": imp, "imp_src": imp_src,
        }
        if x["cve"] in ep:
            row.update(ep[x["cve"]])
        out[x["id"]] = row

    old = load("priority.json", {})
    # 急ぎ度が変わったら、いつ・何が理由で変わったかを残す（画面に「変更の記録」として出す）
    for id_, row in out.items():
        prev = old.get("items", {}).get(id_)
        if not prev:
            continue
        hist = list(prev.get("hist", []))
        if prev.get("u") != row["u"]:
            why = [
                f"{k}:{prev.get(k)}>{row[k]}"
                for k in ("exp", "auto", "imp")
                if prev.get(k) != row[k]
            ]
            hist.append({"at": TODAY, "from": prev.get("u"), "to": row["u"], "why": why,
                         "src": row["exp_src"] if prev.get("exp") != row["exp"] else ""})
        if hist:
            row["hist"] = hist[-5:]

    # 中身が変わらなければ書き換えない（コミットを増やさないため）
    if old.get("items") != out:
        save("priority.json", {"updated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "items": dict(sorted(out.items()))})
    counts = {k: sum(1 for v in out.values() if v["u"] == k) for k in ("now", "soon", "later")}
    log("急ぎ度", counts)


if __name__ == "__main__":
    main()
