import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import prioritize as p  # noqa: E402

FX = os.path.join(HERE, "fixtures")


def run():
    findings = p.load_findings(os.path.join(FX, "findings.csv"))
    return p.rank(findings, p.load_assets(os.path.join(FX, "assets.csv")),
                  p.load_kev(os.path.join(FX, "kev.json")),
                  p.load_epss(None, os.path.join(FX, "epss.json")))


class RankTest(unittest.TestCase):
    def test_bad_cve_ids_are_dropped(self):
        self.assertEqual(len(run()), 6)

    def test_exploited_and_exposed_beats_cvss_10(self):
        ranked = run()
        self.assertEqual((ranked[0]["cve"], p.TIERS[ranked[0]["tier"]]), ("CVE-2000-0001", "Fix now"))
        self.assertIn("ransomware", ranked[0]["why"])
        cvss10 = next(r for r in ranked if r["cvss"] == 10.0)
        self.assertEqual(p.TIERS[cvss10["tier"]], "Fix this cycle")

    def test_kev_on_low_value_asset_is_this_week(self):
        r = next(r for r in run() if r["cve"] == "CVE-2000-0002")
        self.assertEqual(p.TIERS[r["tier"]], "Fix this week")

    def test_high_epss_on_critical_asset_is_this_week(self):
        r = next(r for r in run() if r["cve"] == "CVE-2000-0004")
        self.assertEqual(p.TIERS[r["tier"]], "Fix this week")

    def test_unknown_asset_is_flagged_not_dropped(self):
        r = next(r for r in run() if r["asset_id"] == "X9")
        self.assertIn("NOT in inventory", r["why"])
        self.assertEqual(p.TIERS[r["tier"]], "Track")

    def test_missing_epss_says_so(self):
        r = next(r for r in run() if r["cve"] == "CVE-2000-0099")
        self.assertIn("no EPSS score", r["why"])

    def test_epss_rounding_never_shows_certainty_or_zero(self):
        self.assertEqual(p.pct(0.99999), ">99.9%")
        self.assertEqual(p.pct(0.9979), "99.8%")
        self.assertEqual(p.pct(0.00395), "0.4%")
        self.assertEqual(p.pct(0.0004), "<0.1%")
        r = p.rank([{"asset_id": "X1", "cve": "CVE-2000-0005", "cvss": 9.0}], {}, {}, {"CVE-2000-0005": 0.99999})[0]
        self.assertIn("EPSS >99.9% chance", r["why"])


if __name__ == "__main__":
    unittest.main()
