"""V2: single Search / add box - impervafind (where are the typed IPs) and the views that use it."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2")
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(APP, "bin"))

import auto_unblock as au  # noqa: E402

T0 = 1_790_000_000


def E(cidr, pid, action="BLOCK", name=None, enabled=True, kind="setting"):
    return {"cidr": cidr, "policy_id": pid, "policy_name": name or "Policy %s" % pid, "policy_type": "ACL",
            "action": action, "kind": kind, "enabled": enabled}


ENTRIES = [E("185.220.101.47", "1000001", name="Block DDoS policy"),
           E("54.245.198.114", "2169031", name="BlockIOCsFromSplunk"),
           E("20.20.20.20", "1000002", action="ALLOW", name="Allow partner DC"),
           E("45.95.147.0/24", "1000003", name="Block IOC attack"),
           E("1.1.1.1", "1000009", enabled=False)]


class TestFind(unittest.TestCase):
    def setUp(self):
        import impervafind as c
        import impervapolicycheck as pc
        self.c, self.pc = c, pc
        self.saved = pc.load_entries
        pc.load_entries = lambda sk, conf, log, force=False: (ENTRIES, ["2169031"], "cache")
        self.kv = {
            "imperva_block_registry": [
                {"_key": "2169031_54.245.198.114", "site_id": "2169031", "ip": "54.245.198.114", "status": "blocked",
                 "blocked_at": T0, "blocked_by": "analyst01", "incident_no": "1000090", "comment": "credential stuffing"},
                {"_key": "2169031_8.8.4.4", "site_id": "2169031", "ip": "8.8.4.4", "status": "blocked",
                 "blocked_at": T0, "blocked_by": "analyst02", "incident_no": "1000140", "comment": "just blocked"},
                {"_key": "2169031_9.9.9.9", "site_id": "2169031", "ip": "9.9.9.9", "status": "unblocked"}],
            "imperva_ioc_dismissed": [{"_key": "77.88.8.8", "ip": "77.88.8.8", "dismissed_by": "analyst02",
                                       "dismissed_at": T0, "incident_no": "-", "reason": "quiet"}],
            au.STATE: [{"_key": au.entry_key("1000001", "185.220.101.47"), "first_listed": T0}],
        }

        def kv_query(sk, col, q):
            docs = self.kv.get(col, [])
            if "ip" in q:
                return [d for d in docs if d.get("ip") in q["ip"]["$in"]]
            return [d for d in docs if d.get("_key") in q["_key"]["$in"]]
        c.kv_query = kv_query
        c.kv_list = lambda sk, col: list(self.kv.get(col, []))
        c.load_conf_stanza = lambda sk, conf, stanza: {"policy_ids": "2169031", "cloud_providers": "amazon|aws",
                                                       "shared_ip_providers": "wireless",
                                                       "protected_networks": "203.0.113.0/24"}
        self.saved_owners = c.ip_owner.cached_owners
        c.ip_owner.cached_owners = lambda sk, ips, log: dict((ip, {"52.88.145.123": "Amazon.com, Inc."}.get(ip)) for ip in ips)
        self.out = {}
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: None, "warning": lambda s, *a: None,
                                                  "error": lambda s, *a: None})()

    def tearDown(self):
        self.pc.load_entries = self.saved
        self.c.ip_owner.cached_owners = self.saved_owners

    def run_(self, rows, *argv):
        self.c.si.getOrganizedResults = lambda: (rows, None, {"sessionKey": "k"})
        sys.argv = ["impervafind.py", "field=ip"] + list(argv)
        self.out.clear()
        self.c.main()
        if "err" in self.out:
            raise AssertionError(self.out["err"])
        return dict((r.get("ip") or "text", r) for r in self.out["rows"])

    def lines(self, r):
        return r["find_lines"].split(" ‖ ")

    def test_every_case(self):
        ips = ["185.220.101.47", "54.245.198.114", "20.20.20.20", "45.95.147.236", "1.1.1.1", "8.8.4.4",
               "77.88.8.8", "52.88.145.123", "10.1.2.3", "203.0.113.10"]
        r = self.run_([{"ip": ip} for ip in ips])
        other = self.lines(r["185.220.101.47"])
        self.assertEqual(r["185.220.101.47"]["find_blockable"], "no")
        self.assertTrue(other[0].startswith("no¦already BLOCKED in policy 1000001 Block DDoS policy · on the policy since "), other)
        own = self.lines(r["54.245.198.114"])[0]
        self.assertTrue(own.startswith("no¦already BLOCKED in policy 2169031 BlockIOCsFromSplunk · blocked "), own)
        self.assertIn("by analyst01 · ticket 1000090", own)
        self.assertEqual((self.lines(r["20.20.20.20"])[0], r["20.20.20.20"]["find_blockable"]),
                         ("al¦ALLOWED by policy 1000002 Allow partner DC (20.20.20.20) - cannot be blocked", "no"))
        self.assertIn("(rule 45.95.147.0/24)", self.lines(r["45.95.147.236"])[0])
        self.assertEqual((self.lines(r["1.1.1.1"]), r["1.1.1.1"]["find_blockable"]),
                         (["ok¦not on the WAF and not blocked from Splunk - can be blocked"], "yes"))   # disabled policy ignored
        self.assertIn("(policy cache refresh pending)", self.lines(r["8.8.4.4"])[0])
        self.assertEqual(r["8.8.4.4"]["find_blockable"], "no")
        nb = self.lines(r["77.88.8.8"])
        self.assertEqual((nb[0][:3], r["77.88.8.8"]["find_blockable"]), ("ok¦", "yes"))
        self.assertTrue(nb[1].startswith("pg¦hidden by Not block (analyst02, ") and nb[1].endswith("- can still be blocked"), nb)
        cl = r["52.88.145.123"]
        self.assertEqual((cl["find_blockable"], cl["find_cloud"]), ("yes", "Amazon.com, Inc."))
        self.assertIn("pg¦cloud provider (Amazon.com, Inc.) - short block: auto unblock after 7 days without an attack", self.lines(cl))
        for bad in ("10.1.2.3", "203.0.113.10"):                 # private / protected network
            self.assertEqual(r[bad]["find_blockable"], "no")
            self.assertTrue(self.lines(r[bad])[0].startswith("no¦cannot be blocked: "), r[bad])

    def test_text_search_counts(self):
        r = self.run_([{"_text": "1000090"}], "text_field=_text")["text"]
        self.assertEqual(self.lines(r), ["pg¦1 blocked from Splunk (Blocked IPs page)", "pg¦0 IP rules in other WAF policies",
                                         "pg¦0 in the Not block list"])
        r = self.run_([{"_text": "ddos"}], "text_field=_text")["text"]
        self.assertEqual(self.lines(r)[1], "pg¦1 IP rules in other WAF policies")
        r = self.run_([{"_text": "quiet"}], "text_field=_text")["text"]
        self.assertEqual(self.lines(r)[2], "pg¦1 in the Not block list")


class TestViews(unittest.TestCase):
    def read(self, v):
        return open(os.path.join(APP, "default", "data", "ui", "views", v), encoding="utf-8").read()

    def test_find_search_on_both_detection_pages(self):
        for v, p in (("imperva_ioc_block.xml", "d"), ("imperva_ioc_history.xml", "h")):
            x = self.read(v)
            self.assertIn('<search id="%s_find">' % p, x)
            self.assertIn("| impervafind field=ip text_field=_text", x)
            self.assertIn('"\\"imperva_no_ip_typed\\""', x)                     # never an unfiltered notable search
            self.assertIn('mvjoin(mvmap(t, "\\"".t."\\""), " OR ")', x)
            self.assertIn("| table ip found find_blockable find_cloud", x)
            self.assertGreaterEqual(x.count("_hit=if(coalesce(_iptok, 0)&gt;0") + x.count("_hit=if(coalesce(_iptok, 0)>0"), 2)
            self.assertIn("Search or add IPs", x)

    def test_virustotal_is_one_clickable_column(self):
        macros = open(os.path.join(APP, "default", "macros.conf"), encoding="utf-8").read()
        self.assertNotIn('VirusTotal="🔗"', macros)
        self.assertEqual(macros.count("| rename vt_score AS VirusTotal, "), 2)
        x = self.read("imperva_ioc_block.xml")
        self.assertIn("https://www.virustotal.com/gui/ip-address/$row.src|n$", x)
        self.assertNotIn("vt_score AS VT", x)

    def test_command_registered(self):
        self.assertIn("[impervafind]\nfilename = impervafind.py", open(os.path.join(APP, "default", "commands.conf")).read())
        self.assertIn("[commands/impervafind]", open(os.path.join(APP, "metadata", "default.meta")).read())


if __name__ == "__main__":
    unittest.main()
