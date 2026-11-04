"""Exclude list: CIDR normalisation, Splunk -> SOAR protected union, impervaexclude command."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))
import imperva_lib as il  # noqa: E402
import test_soar_e2e as e2e  # noqa: E402
from test_soar_e2e import FakeImperva, FakeVirusTotal, POLICY, SOAR_NS  # noqa: E402,F401


class TestNormalize(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(il.normalize_cidr("1.2.3.4"), ("1.2.3.4/32", None))
        self.assertEqual(il.normalize_cidr(" 18.143.202.7/24 "), ("18.143.202.0/24", None))
        self.assertEqual(il.normalize_cidr("2001:db8::1")[0], "2001:db8::1/128")
        self.assertIsNone(il.normalize_cidr("abc")[0])
        self.assertIsNone(il.normalize_cidr("10.0.0.0/7")[0])
        self.assertIsNone(il.normalize_cidr("")[0])
        self.assertEqual(il.exclude_key("18.143.202.0/24"), "18.143.202.0_24")


class TestSoarUnion(e2e.TestSoarE2E):
    def test_splunk_exclude_list_enforced_by_soar(self):
        rows = self.bridge.execute("block", ["18.143.202.10"], ["1777"], False, {}, "a",
                                   protected=["18.143.202.0/24"])
        self.assertEqual(rows[0]["status"], "rejected")
        self.assertIn("SOAR: overlaps protected network 18.143.202.0/24", rows[0]["detail"])
        self.assertEqual(FakeImperva.puts, [])
        req = [a for c in e2e.FakeSoar.store["containers"].values() for a in c["artifacts"]
               if a["name"] == "imperva_request"][-1]["cef"]
        self.assertEqual(req["protected_networks"], "18.143.202.0/24")

    def test_soar_own_list_still_applies_when_splunk_sends_none(self):
        rows = self.bridge.execute("block", ["45.33.32.9"], ["1777"], False, {}, "a")
        self.assertEqual(rows[0]["status"], "rejected")


class TestImpervaExcludeCommand(unittest.TestCase):
    def setUp(self):
        import impervaexclude as ie
        self.ie = ie
        self.store, self.out, self.logs = {}, {}, []
        ie.load_conf_stanza = lambda k, c, s: {"protected_networks": "45.33.32.0/24"}
        ie.kv_get = lambda k, key, col: self.store.get(key)
        ie.kv_upsert = lambda k, docs, col: [self.store.__setitem__(d["_key"], d) for d in docs]
        ie.kv_delete = lambda k, key, col: self.store.pop(key)
        import splunk_helpers as sh
        sh.kv_list = lambda k, col: list(self.store.values())
        ie.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "alice"})
        ie.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        ie.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        ie.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: self.logs.append(a[0] % a[1:]),
                                                  "error": lambda s, *a: None})()

    def run_(self, *argv):
        self.out.clear()
        sys.argv = ["impervaexclude.py"] + list(argv)
        self.ie.main()
        return self.out

    def test_add_list_remove(self):
        o = self.run_("action=add", 'cidr="18.143.202.7/24"', 'description="Authorised', 'scanner"')
        self.assertEqual((o["rows"][0]["status"], o["rows"][0]["cidr"]), ("excluded", "18.143.202.0/24"))
        self.assertEqual(self.store["18.143.202.0_24"]["description"], "Authorised scanner")
        self.assertIn("action=exclude_add ip=18.143.202.0/24", self.logs[-1])
        self.assertEqual(self.run_("action=add", "cidr=18.143.202.0/24")["rows"][0]["status"], "no_change")
        rows = self.run_()["rows"]
        self.assertEqual([(r["cidr"], r["source"]) for r in rows],
                         [("45.33.32.0/24", "conf"), ("18.143.202.0/24", "dashboard")])
        self.assertEqual(self.run_("action=remove", "cidr=18.143.202.0/24")["rows"][0]["status"], "removed")
        self.assertEqual(self.store, {})
        r = self.run_("action=remove", "cidr=45.33.32.0/24")["rows"][0]
        self.assertEqual(r["status"], "not_found")
        self.assertIn("imperva.conf", r["detail"])

    def test_invalid(self):
        self.assertIn("invalid", self.run_("action=add", "cidr=hello")["err"])
        self.assertIn("/8", self.run_("action=add", "cidr=10.0.0.0/6")["err"])


if __name__ == "__main__":
    unittest.main()
