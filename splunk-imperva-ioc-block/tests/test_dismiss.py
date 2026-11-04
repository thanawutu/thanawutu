"""impervadismiss: 'Not block' decisions (hide until detected again, restore)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))


class TestDismiss(unittest.TestCase):
    def setUp(self):
        import impervadismiss as d
        self.d, self.store, self.out, self.logs = d, {}, {}, []
        d.kv_get = lambda k, key, col: self.store.get(key)
        d.kv_upsert = lambda k, docs, col: [self.store.__setitem__(x["_key"], x) for x in docs]
        d.kv_delete = lambda k, key, col: self.store.pop(key)
        d.kv_list = lambda k, col: list(self.store.values())
        d.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "alice"})
        d.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        d.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        d.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: self.logs.append(a[0] % a[1:]),
                                                 "error": lambda s, *a: None})()

    def run_(self, *argv):
        self.out.clear()
        sys.argv = ["impervadismiss.py"] + list(argv)
        self.d.main()
        return self.out

    def test_dismiss_list_restore(self):
        r = self.run_("action=add", "ip=8.8.4.4", 'reason="false', 'positive', 'scanner"', "incident_no=INC-9")["rows"][0]
        self.assertEqual((r["status"], r["reason"], r["incident_no"]), ("dismissed", "false positive scanner", "INC-9"))
        self.assertEqual(self.store["8.8.4.4"]["dismissed_by"], "alice")
        self.assertIn("action=dismiss ip=8.8.4.4", self.logs[-1])
        self.assertEqual([x["ip"] for x in self.run_()["rows"]], ["8.8.4.4"])
        self.assertEqual(self.run_("action=remove", "ip=8.8.4.4")["rows"][0]["status"], "restored")
        self.assertEqual(self.store, {})
        self.assertIn("action=restore", self.logs[-1])
        self.assertEqual(self.run_("action=remove", "ip=8.8.4.4")["rows"][0]["status"], "not_found")

    def test_invalid_ip(self):
        self.assertIn("invalid IP", self.run_("action=add", "ip=not-an-ip")["err"])


if __name__ == "__main__":
    unittest.main()
