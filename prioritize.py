#!/usr/bin/env python3
"""Rank vulnerability findings by real-world risk, not CVSS alone.

Joins scanner findings with CISA KEV (exploited in the wild) and FIRST EPSS
(probability of exploitation in the next 30 days), then adds asset context
(criticality, internet exposure). Every ranking comes with plain reasons.
"""
import argparse
import csv
import json
import re
import sys
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
HEADERS = {"User-Agent": "vuln-prioritizer/0.1"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_HIGH = 0.10  # 10%+ chance of exploitation in 30 days; a common FIRST-suggested cut line
TIERS = ["Fix now", "Fix this week", "Fix this cycle", "Track"]


def fetch_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=30) as r:
        return json.load(r)


def read_json(path):
    with open(path) as f:
        return json.load(f)


def load_kev(path=None):
    data = read_json(path) if path else fetch_json(KEV_URL)
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def load_epss(cves, path=None):
    if path:
        rows = read_json(path)["data"]
    else:
        rows, cves = [], sorted(cves)
        for i in range(0, len(cves), 50):
            rows += fetch_json(EPSS_URL + ",".join(cves[i:i + 50]))["data"]
    return {r["cve"]: float(r["epss"]) for r in rows}


def load_assets(path):
    with open(path, newline="") as f:
        return {
            row["asset_id"].strip(): {
                "hostname": row["hostname"].strip(),
                "criticality": int(row["criticality"]),
                "internet_facing": row["internet_facing"].strip().lower() in ("yes", "true", "1"),
            }
            for row in csv.DictReader(f)
        }


def load_findings(path):
    findings = []
    with open(path, newline="") as f:
        for n, row in enumerate(csv.DictReader(f), start=2):
            cve = row["cve"].strip().upper()
            if not CVE_RE.match(cve):
                print(f"skipping line {n}: bad CVE id {row['cve']!r}", file=sys.stderr)
                continue
            findings.append({"asset_id": row["asset_id"].strip(), "cve": cve, "cvss": float(row["cvss"])})
    return findings


def rank(findings, assets, kev, epss):
    ranked = []
    for f in findings:
        asset = assets.get(f["asset_id"])
        known = asset is not None
        asset = asset or {"hostname": "?", "criticality": 3, "internet_facing": False}
        k, scored, cvss = kev.get(f["cve"]), epss.get(f["cve"]), f["cvss"]
        e = scored or 0.0
        exposed, crit = asset["internet_facing"], asset["criticality"]
        important = exposed or crit >= 4

        if k and important:
            tier = 0
        elif k or (e >= EPSS_HIGH and important):
            tier = 1
        elif e >= EPSS_HIGH or cvss >= 7.0:
            tier = 2
        else:
            tier = 3

        why = []
        if k:
            why.append(f"on CISA KEV since {k['dateAdded']} (exploited in the wild)")
            if k.get("knownRansomwareCampaignUse") == "Known":
                why.append("used in ransomware campaigns")
        why.append(f"EPSS {e:.1%} chance of exploitation in 30 days" if scored is not None else "no EPSS score yet")
        why.append(f"CVSS {cvss}")
        if exposed:
            why.append("internet-facing")
        why.append(f"asset criticality {crit}/5" if known else "asset NOT in inventory (criticality assumed 3)")

        ranked.append({**f, "hostname": asset["hostname"], "tier": tier, "epss": e, "kev": bool(k),
                       "criticality": crit, "why": "; ".join(why)})
    return sorted(ranked, key=lambda r: (r["tier"], -r["epss"], -r["cvss"], -r["criticality"]))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--assets", default="sample/assets.csv")
    p.add_argument("--findings", default="sample/findings.csv")
    p.add_argument("--kev-file", help="local KEV JSON instead of downloading")
    p.add_argument("--epss-file", help="local EPSS JSON instead of calling the API")
    p.add_argument("--csv", help="also write results to this CSV file")
    a = p.parse_args(argv)

    findings = load_findings(a.findings)
    ranked = rank(findings, load_assets(a.assets), load_kev(a.kev_file),
                  load_epss({f["cve"] for f in findings}, a.epss_file))

    for i, r in enumerate(ranked, 1):
        print(f"{i:>2}. [{TIERS[r['tier']]}] {r['cve']} on {r['hostname']} ({r['asset_id']})")
        print(f"    why: {r['why']}")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["rank", "tier", "cve", "asset_id", "hostname", "cvss", "epss", "kev", "criticality", "why"])
            w.writeheader()
            for i, r in enumerate(ranked, 1):
                w.writerow({"rank": i, **{k: r[k] for k in w.fieldnames if k != "rank"}, "tier": TIERS[r["tier"]]})


if __name__ == "__main__":
    main()
