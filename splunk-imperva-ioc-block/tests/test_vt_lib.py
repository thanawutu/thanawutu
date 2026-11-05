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


class FakeVT(object):
    def __init__(self, limit_after=None):
        self.calls, self.limit_after = [], limit_after

    def lookup_ip(self, ip):
        self.calls.append(ip)
        if self.limit_after is not None and len(self.calls) > self.limit_after:
            raise vt.VTRateLimited("429")
        if ip == "9.9.9.9":
            raise vt.VTError("boom")
        return {"vt_status": "ok", "vt_malicious": 1}


class TestLookupMany(unittest.TestCase):
    def setUp(self):
        self.t, self.sleeps = [0.0], []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t[0] += s

    def run_(self, client, ips, **kw):
        return vt.lookup_many(client, ips, _sleep=self.sleep, _now=lambda: self.t[0], **kw)

    def test_rate_spacing_and_private(self):
        c = FakeVT()
        out = self.run_(c, ["8.8.8.8", "10.0.0.1", "1.1.1.1", "8.8.8.8"], rpm=4)
        self.assertEqual(c.calls, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(self.sleeps, [15.0])
        self.assertEqual(out["10.0.0.1"]["vt_status"], "private_ip")

    def test_max_lookups(self):
        out = self.run_(FakeVT(), ["1.1.1.1", "8.8.8.8", "8.8.4.4"], rpm=600, max_lookups=2)
        self.assertEqual(out["8.8.4.4"]["vt_status"], "not_checked (max_lookups_per_run)")

    def test_429_stops_calls(self):
        c = FakeVT(limit_after=1)
        out = self.run_(c, ["1.1.1.1", "8.8.8.8", "8.8.4.4"], rpm=600)
        self.assertEqual(c.calls, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual([out[i]["vt_status"] for i in ("8.8.8.8", "8.8.4.4")], ["rate_limited"] * 2)

    def test_429_waits_and_retries_until_all_ips_done(self):
        class Quota(FakeVT):          # 2 calls per "minute", then HTTP 429 until 60 s passed
            def __init__(self, clock):
                FakeVT.__init__(self)
                self.clock, self.window, self.used = clock, 0.0, 0

            def lookup_ip(self, ip):
                if self.clock[0] - self.window >= 60:
                    self.window, self.used = self.clock[0], 0
                self.calls.append(ip)
                if self.used >= 2:
                    raise vt.VTRateLimited("429")
                self.used += 1
                return {"vt_status": "ok", "vt_malicious": 0}
        ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.10", "208.67.222.222"]
        c = Quota(self.t)
        out = self.run_(c, ips, rpm=600, max_lookups=0, retry_wait=60, max_wait=600)
        self.assertEqual([out[i]["vt_status"] for i in ips], ["ok"] * 6)
        self.assertEqual(self.sleeps.count(60), 2)          # waited twice for the quota window

    def test_429_wait_budget_then_rate_limited(self):
        c = FakeVT(limit_after=1)                            # quota never comes back
        out = self.run_(c, ["1.1.1.1", "8.8.8.8", "8.8.4.4"], rpm=600, retry_wait=60, max_wait=120)
        self.assertEqual(self.sleeps.count(60), 2)
        self.assertEqual([out[i]["vt_status"] for i in ("1.1.1.1", "8.8.8.8", "8.8.4.4")],
                         ["ok", "rate_limited", "rate_limited"])

    def test_no_limit_when_max_lookups_zero(self):
        ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        out = self.run_(FakeVT(), ips, rpm=600, max_lookups=0)
        self.assertEqual([out[i]["vt_status"] for i in ips], ["ok"] * 3)

    def test_error_kept_per_ip(self):
        out = self.run_(FakeVT(), ["9.9.9.9", "1.1.1.1"], rpm=600)
        self.assertEqual((out["9.9.9.9"]["vt_status"], out["1.1.1.1"]["vt_status"]), ("error", "ok"))


if __name__ == "__main__":
    unittest.main()
