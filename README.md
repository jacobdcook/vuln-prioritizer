# vuln-prioritizer

[![tests](https://github.com/jacobdcook/vuln-prioritizer/actions/workflows/tests.yml/badge.svg)](https://github.com/jacobdcook/vuln-prioritizer/actions/workflows/tests.yml)

Ranks vulnerability scan findings by real-world risk instead of CVSS alone.

CVSS tells you how bad a bug *could* be. It does not tell you whether anyone is
exploiting it, or whether the box it sits on matters. This tool joins scanner
findings with two free public feeds and your asset inventory:

| Signal | Source | Question it answers |
|---|---|---|
| KEV | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is this being exploited in the wild right now? |
| EPSS | [FIRST EPSS API](https://www.first.org/epss/) | How likely is exploitation in the next 30 days? |
| CVSS | your scanner export | How severe is it in theory? |
| Asset context | your inventory CSV | Is the box internet-facing? How critical is it (1-5)? |

Every result comes with a plain-language "why", so the ranking can be checked by
a human instead of trusted blindly.

## Tiers

| Tier | Rule |
|---|---|
| Fix now | On KEV **and** (internet-facing or criticality 4-5) |
| Fix this week | On KEV, or EPSS >= 10% on an internet-facing / critical asset |
| Fix this cycle | EPSS >= 10%, or CVSS >= 7.0 |
| Track | Everything else |

Within a tier: higher EPSS first, then CVSS, then asset criticality.

## Run

Python 3.9+, standard library only, no installs.

```
python3 prioritize.py                         # sample data, live KEV + EPSS
python3 prioritize.py --assets my_assets.csv --findings my_scan.csv --csv ranked.csv
python3 prioritize.py --kev-file kev.json --epss-file epss.json   # offline
python3 -m unittest discover -s tests
```

Input formats: see `sample/assets.csv` (`asset_id,hostname,criticality,internet_facing`)
and `sample/findings.csv` (`asset_id,cve,cvss`). Invalid CVE ids are skipped with a
warning. Findings on assets missing from the inventory are kept and flagged.

## Sample output

The assets and findings are made up; the CVEs and feed data are real (live pull).
Note the three CVSS 9.8 findings landing *below* an 8.8 and an 8.1: the 8.8 is
actively exploited, and the 8.1 has a 99% exploit probability on a critical
database server.

```
 1. [Fix now] CVE-2024-3400 on vpn-gw-01 (A1)
    why: on CISA KEV since 2024-04-12 (exploited in the wild); used in ransomware campaigns; EPSS >99.9% chance of exploitation in 30 days; CVSS 10.0; internet-facing; asset criticality 5/5
 2. [Fix now] CVE-2021-44228 on web-portal-01 (A2)
    why: on CISA KEV since 2021-12-10 (exploited in the wild); used in ransomware campaigns; EPSS >99.9% chance of exploitation in 30 days; CVSS 10.0; internet-facing; asset criticality 4/5
 3. [Fix this week] CVE-2021-34527 on print-srv-02 (A4)
    why: on CISA KEV since 2021-11-03 (exploited in the wild); used in ransomware campaigns; EPSS 99.8% chance of exploitation in 30 days; CVSS 8.8; asset criticality 2/5
 4. [Fix this week] CVE-2024-6387 on hr-db-01 (A3)
    why: EPSS 99.5% chance of exploitation in 30 days; CVSS 8.1; asset criticality 5/5
 5. [Fix this cycle] CVE-2022-42889 on dev-test-07 (A5)
    why: EPSS 99.9% chance of exploitation in 30 days; CVSS 9.8; asset criticality 1/5
 6. [Fix this cycle] CVE-2025-1889 on dev-test-07 (A5)
    why: EPSS 0.4% chance of exploitation in 30 days; CVSS 9.8; asset criticality 1/5
 7. [Fix this cycle] CVE-2024-47092 on monitor-01 (A6)
    why: EPSS 0.4% chance of exploitation in 30 days; CVSS 9.8; asset criticality 4/5
 8. [Track] CVE-2025-1906 on print-srv-02 (A4)
    why: EPSS 0.4% chance of exploitation in 30 days; CVSS 4.7; asset criticality 2/5
```

## Limits

- CVSS comes from the scanner export; the tool does not look it up.
- The 10% EPSS cut line and the tier rules are a starting point, not a standard.
  Tune them to your environment.
- No ticketing or scanner integration yet; output is terminal text or CSV.
