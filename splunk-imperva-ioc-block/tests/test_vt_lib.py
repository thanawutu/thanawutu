import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "TA-imperva-ioc-block", "bin"))
import vt_lib as vt  # noqa: E402

SAMPLE = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 25, "timeout": 0},
    "reputation": -12, "country": "NL", "continent": "EU", "asn": 49870,
    "as_owner": "Alsycon B.V.", "network": "45.95.147.0/24", "last_analysis_date": 1730000000}}}


def v(mal=0, sus=0, rep=0, status="ok"):
    return {"vt_status": status, "vt_malicious": mal, "vt_suspicious": sus, "vt_reputation": rep}


class TestParse(unittest.TestCase):
    def test_parse(self):
        r = vt.parse_vt_response("45.95.147.236", SAMPLE)
        self.assertEqual(r["vt_malicious"], 7)
        self.assertEqual(r["vt_engines"], 93)
        self.assertEqual(r["vt_country"], "NL")
        self.assertEqual(r["vt_as_owner"], "Alsycon B.V.")
        self.assertTrue(r["vt_link"].endswith("45.95.147.236"))

    def test_parse_empty(self):
        r = vt.parse_vt_response("8.8.8.8", {})
        self.assertEqual(r["vt_malicious"], 0)
        self.assertEqual(r["vt_country"], "-")


class TestSuggest(unittest.TestCase):
    def s(self, vtinfo, count=400, ip="45.95.147.236", **kw):
        return vt.suggest(dict(vtinfo, ip=ip), attack_count=count, **kw)[0]

    def test_block_on_many_engines(self):
        self.assertEqual(self.s(v(mal=5)), "BLOCK")

    def test_review_on_few_engines(self):
        self.assertEqual(self.s(v(mal=1)), "REVIEW")
        self.assertEqual(self.s(v(sus=2)), "REVIEW")
        self.assertEqual(self.s(v(rep=-5)), "REVIEW")

    def test_few_engines_plus_high_volume_blocks(self):
        self.assertEqual(self.s(v(mal=1), count=5000), "BLOCK")

    def test_clean(self):
        self.assertEqual(self.s(v()), "MONITOR")
        self.assertEqual(self.s(v(), count=5000), "REVIEW")

    def test_vt_unavailable(self):
        self.assertEqual(self.s(v(status="rate_limited")), "REVIEW")
        self.assertEqual(self.s(v(status="error"), count=5000), "BLOCK")

    def test_never_block(self):
        self.assertEqual(self.s(v(mal=50), ip="10.1.2.3"), "DO_NOT_BLOCK")
        self.assertEqual(self.s(v(mal=50), protected=True), "DO_NOT_BLOCK")

    def test_custom_threshold(self):
        self.assertEqual(self.s(v(mal=2), thresholds={"block_malicious": 2}), "BLOCK")


class TestCache(unittest.TestCase):
    def test_roundtrip_and_ttl(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "c.json")
        c = vt.VTCache(p, ttl_seconds=100)
        c.put("1.2.3.4", {"vt_malicious": 3}, now=1000)
        c.save()
        c2 = vt.VTCache(p, ttl_seconds=100)
        self.assertEqual(c2.get("1.2.3.4", now=1050), {"vt_malicious": 3})
        self.assertIsNone(c2.get("1.2.3.4", now=1200))


if __name__ == "__main__":
    unittest.main()
