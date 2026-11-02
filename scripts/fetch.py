"""脆弱性情報を集めて docs/data/ にJSONで書き出す。標準ライブラリのみ。

取得元:
  - CISA KEV (悪用が確認された脆弱性の一覧)
  - NVD API 2.0 (CVE本体とCVSS)
  - GitHub Advisory Database (パッケージの脆弱性)
  - endoflife.date (バージョンごとのサポート期限)
  - JVN 新着RSS (日本語の脆弱性情報。直近分しか載らないので貯めていく)

環境変数:
  NVD_API_KEY   あればNVDの待ち時間が短くなる
  GITHUB_TOKEN  あればGitHub APIの回数制限が緩くなる
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
UA = "vuln-watcher (+https://github.com/)"

NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
NVD_WAIT = 0.8 if NVD_KEY else 6.5  # キーなしは30秒に5回まで

NOW = datetime.now(timezone.utc)

# 手元のWindowsで証明書ストアの都合により検証に失敗するとき用。
# CA_BUNDLE に証明書ファイルを指定すると、そのファイルだけで検証する。
_ca = os.environ.get("CA_BUNDLE", "").strip()
SSL_CTX = ssl.create_default_context(cafile=_ca) if _ca else None


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def get(url: str, headers: dict | None = None, retries: int = 3) -> bytes:
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=60, context=SSL_CTX) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 500, 502, 503, 504):
                time.sleep(10 * (i + 1))
                continue
            raise
        except urllib.error.URLError as e:
            last = e
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"{url}: {last}")


def get_json(url: str, headers: dict | None = None):
    return json.loads(get(url, headers).decode("utf-8"))


def load(name: str, default):
    p = DATA / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return default


def save(name: str, obj):
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / name).write_text(
        json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------- KEV
def fetch_kev() -> list[dict]:
    d = get_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    return d["vulnerabilities"]


def kev_for(kev: list[dict], pattern: str) -> list[dict]:
    rx = re.compile(pattern, re.I)
    out = []
    for v in kev:
        if rx.search(f"{v['vendorProject']} {v['product']}"):
            out.append(
                {
                    "cve": v["cveID"],
                    "vendor": v["vendorProject"],
                    "product": v["product"],
                    "name": v["vulnerabilityName"],
                    "added": v["dateAdded"],
                    "due": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                    "desc": v.get("shortDescription", ""),
                }
            )
    out.sort(key=lambda x: x["added"], reverse=True)
    return out


# ---------------------------------------------------------------- NVD
def nvd_fmt(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_query(params: dict, days: int) -> list[dict]:
    start = NOW - timedelta(days=min(days, 119))
    base = {
        "pubStartDate": nvd_fmt(start),
        "pubEndDate": nvd_fmt(NOW),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    base.update(params)
    headers = {"apiKey": NVD_KEY} if NVD_KEY else None
    items = []
    while True:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(base)
        d = get_json(url, headers)
        time.sleep(NVD_WAIT)
        items += [v["cve"] for v in d.get("vulnerabilities", [])]
        base["startIndex"] += d.get("resultsPerPage", 0)
        if base["startIndex"] >= d.get("totalResults", 0) or not d.get("resultsPerPage"):
            break
    return items


def nvd_score(cve: dict):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            # NVD自身の採点 (Primary) を優先
            rows = sorted(m[key], key=lambda r: r.get("type") != "Primary")
            c = rows[0]["cvssData"]
            sev = c.get("baseSeverity") or rows[0].get("baseSeverity")
            return c.get("baseScore"), (sev or "").upper(), c.get("vectorString"), c.get("version")
    return None, "", None, None


def nvd_for(target: dict, days: int, kev_ids: set[str]) -> list[dict]:
    seen: dict[str, dict] = {}
    for q in target["nvd"]:
        if "cpe" in q:
            params = {"virtualMatchString": q["cpe"]}
        else:
            params = {"sourceIdentifier": q["source"]}
        rx = re.compile(q["match"], re.I) if q.get("match") else None
        for cve in nvd_query(params, days):
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
            )
            if rx and not rx.search(desc):
                continue
            score, sev, vec, ver = nvd_score(cve)
            seen[cve["id"]] = {
                "id": cve["id"],
                "published": cve["published"][:10],
                "modified": cve["lastModified"][:10],
                "status": cve.get("vulnStatus"),
                "score": score,
                "severity": sev,
                "vector": vec,
                "cvss": ver,
                "desc": desc.strip(),
                "kev": cve["id"] in kev_ids,
                "cwe": sorted(
                    {
                        d["value"]
                        for w in cve.get("weaknesses", [])
                        for d in w.get("description", [])
                        if d["value"].startswith("CWE-")
                    }
                ),
            }
    return sorted(seen.values(), key=lambda x: x["published"], reverse=True)


# ---------------------------------------------------------------- GHSA
def ghsa_for(ecosystem: str, kev_ids: set[str], limit: int = 60) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    q = urllib.parse.urlencode(
        {
            "ecosystem": ecosystem,
            "type": "reviewed",
            "sort": "published",
            "direction": "desc",
            "per_page": limit,
        }
    )
    rows = get_json(f"https://api.github.com/advisories?{q}", headers)
    out = []
    for a in rows:
        cs = a.get("cvss_severities") or {}
        score = (cs.get("cvss_v4") or {}).get("score") or (cs.get("cvss_v3") or {}).get("score")
        out.append(
            {
                "id": a["ghsa_id"],
                "cve": a.get("cve_id"),
                "summary": a.get("summary", ""),
                "severity": (a.get("severity") or "").upper(),
                "score": score or None,
                "published": (a.get("published_at") or "")[:10],
                "url": a["html_url"],
                "kev": bool(a.get("cve_id")) and a["cve_id"] in kev_ids,
                "packages": [
                    {
                        "name": v["package"]["name"],
                        "range": v.get("vulnerable_version_range"),
                        "fixed": v.get("first_patched_version"),
                    }
                    for v in a.get("vulnerabilities", [])
                    if v.get("package")
                ],
            }
        )
    return out


# ---------------------------------------------------------------- EOL
def eol_for(slug: str) -> list[dict]:
    rows = get_json(f"https://endoflife.date/api/{slug}.json")
    keep = ("cycle", "releaseDate", "support", "eol", "latest", "latestReleaseDate", "lts")
    return [{k: r.get(k) for k in keep} for r in rows[:8]]


# ---------------------------------------------------------------- JVN
def fetch_jvn() -> list[dict]:
    ns = {
        "rss": "http://purl.org/rss/1.0/",
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    root = ET.fromstring(get("https://jvn.jp/rss/jvn.rdf"))
    out = []
    for it in root.findall("rss:item", ns):
        out.append(
            {
                "id": it.findtext("dc:identifier", "", ns),
                "title": it.findtext("rss:title", "", ns).strip(),
                "url": it.findtext("rss:link", "", ns),
                "desc": it.findtext("rss:description", "", ns).strip(),
                "date": it.findtext("dc:date", "", ns)[:10],
            }
        )
    return out


# ---------------------------------------------------------------- main
def main():
    cfg = json.loads((ROOT / "targets.json").read_text(encoding="utf-8"))
    days = cfg.get("days", 90)
    status: dict[str, str] = {}
    first_seen: dict[str, str] = load("first_seen.json", {})
    today = NOW.strftime("%Y-%m-%d")
    first_run = not first_seen

    try:
        kev = fetch_kev()
        status["kev"] = "ok"
    except Exception as e:  # noqa: BLE001
        log("KEV失敗", e)
        kev = []
        status["kev"] = f"error: {e}"
    kev_ids = {v["cveID"] for v in kev}

    # JVNは直近分しか出ないので前回までの分と合わせて保持する
    jvn_all = {x["url"]: x for x in load("jvn.json", [])}
    try:
        for x in fetch_jvn():
            jvn_all[x["url"]] = x
        status["jvn"] = "ok"
    except Exception as e:  # noqa: BLE001
        log("JVN失敗", e)
        status["jvn"] = f"error: {e}"
    cutoff = (NOW - timedelta(days=days)).strftime("%Y-%m-%d")
    jvn_list = sorted(
        (x for x in jvn_all.values() if x["date"] >= cutoff),
        key=lambda x: x["date"],
        reverse=True,
    )
    save("jvn.json", jvn_list)

    summary = []
    current: set[str] = set()
    for t in cfg["targets"]:
        tid = t["id"]
        log("==", tid)
        prev = load(f"{tid}.json", {})
        data = {"id": tid, "label": t["label"], "note": t.get("note", "")}

        data["kev"] = kev_for(kev, t["kev"]) if kev else prev.get("kev", [])

        def step(key, fn):
            try:
                data[key] = fn()
                status[f"{tid}.{key}"] = "ok"
            except Exception as e:  # noqa: BLE001
                log(f"{tid}.{key} 失敗", e)
                data[key] = prev.get(key, [])
                status[f"{tid}.{key}"] = f"error: {e}"

        step("cves", lambda: nvd_for(t, days, kev_ids))
        if t.get("ghsa"):
            step("ghsa", lambda: ghsa_for(t["ghsa"], kev_ids))
        else:
            data["ghsa"] = []
        step("eol", lambda: {slug: eol_for(slug) for slug in t["eol"]})

        rx = re.compile(t["jvn"], re.I) if t.get("jvn") else None
        data["jvn"] = [x for x in jvn_list if rx and rx.search(x["title"] + x["desc"])]

        # 初めて見た日を記録して、画面で「新着」を出せるようにする
        for key, idf in (("cves", "id"), ("ghsa", "id"), ("kev", "cve"), ("jvn", "url")):
            for item in data[key]:
                k = item[idf]
                current.add(k)
                if k not in first_seen:
                    first_seen[k] = "0000-00-00" if first_run else today
                item["first_seen"] = first_seen[k]

        save(f"{tid}.json", data)
        summary.append(
            {
                "id": tid,
                "label": t["label"],
                "cves": len(data["cves"]),
                "critical": sum(1 for c in data["cves"] if c["severity"] == "CRITICAL"),
                "high": sum(1 for c in data["cves"] if c["severity"] == "HIGH"),
                "kev_recent": sum(1 for k in data["kev"] if k["added"] >= cutoff),
                "kev_total": len(data["kev"]),
                "ghsa": len(data["ghsa"]),
                "jvn": len(data["jvn"]),
            }
        )

    # 一覧から消えたものは記録も消す（ファイルが膨らみ続けないように）
    save("first_seen.json", {k: v for k, v in sorted(first_seen.items()) if k in current})
    save(
        "meta.json",
        {
            "fetched_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": days,
            "targets": summary,
            "status": status,
        },
    )
    errors = [k for k, v in status.items() if v != "ok"]
    log("完了。失敗:", errors or "なし")


if __name__ == "__main__":
    main()
