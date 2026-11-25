"""impervablock command: Ticket / Description options, registry, policy-cache reset."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))


class FakeBackend(object):
    mode = "soar"

    def __init__(self, status):
        self.status, self.calls = status, []

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        self.calls.append((action, list(ips), dict(meta)))
        return [{"ip": ip, "site_id": "2169031", "status": self.status, "verified_in_waf": "yes",
                 "detail": "ok", "soar_container": 77} for ip in ips]


class TestBlockCommand(unittest.TestCase):
    def setUp(self):
        import impervablock as c
        self.c, self.reg, self.out, self.logs, self.dropped = c, {}, {}, [], []
        c.load_conf_stanza = lambda *a: {"max_ips_per_action": "50"}
        c.load_credential = lambda *a: ("u", "p")
        c.kv_get = lambda k, key: self.reg.get(key)
        c.kv_upsert = lambda k, docs: [self.reg.__setitem__(d["_key"], d) for d in docs]
        c.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "alice"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: self.logs.append(a[0] % a[1:]),
                                                 "error": lambda s, *a: self.logs.append(a[0] % a[1:])})()

    def run_(self, status, *argv):
        self.backend = FakeBackend(status)
        self.c.get_backend = lambda *a, **k: self.backend
        self.out.clear()
        sys.argv = ["impervablock.py"] + list(argv)
        self.c.main()
        return self.out

    def test_block_with_ticket_and_description(self):
        rows = self.run_("blocked", "action=block", 'ip="8.8.4.4,', '1.1.1.1"', 'incident_no="ITHM', '1234567"',
                         'description="credential', 'stuffing"')["rows"]
        self.assertEqual([(r["ip"], r["status"], r["incident_no"], r["comment"]) for r in rows],
                         [("8.8.4.4", "blocked", "ITHM 1234567", "credential stuffing"),
                          ("1.1.1.1", "blocked", "ITHM 1234567", "credential stuffing")])
        doc = self.reg["2169031_8.8.4.4"]
        self.assertEqual((doc["status"], doc["incident_no"], doc["comment"], doc["blocked_by"]),
                         ("blocked", "ITHM 1234567", "credential stuffing", "alice"))
        self.assertIn('incident_no="ITHM 1234567" comment="credential stuffing"', self.logs[0])
        self.assertNotIn("threat", str(self.backend.calls[0][2].get("threat_actor")))

    def test_unblock_description_is_the_reason(self):
        self.run_("blocked", "action=block", "ip=8.8.4.4", "incident_no=ITHM-1", "description=x")
        self.run_("unblocked", "action=unblock", "ip=8.8.4.4", "incident_no=ITHM-2", 'description="false', 'positive"')
        doc = self.reg["2169031_8.8.4.4"]
        self.assertEqual((doc["status"], doc["unblock_reason"], doc["unblock_incident_no"]),
                         ("unblocked", "false positive", "ITHM-2"))

    def test_no_change_status(self):
        rows = self.run_("no_change", "action=block", "ip=8.8.4.4")["rows"]
        self.assertEqual(rows[0]["status"], "no_change")


if __name__ == "__main__":
    unittest.main()
