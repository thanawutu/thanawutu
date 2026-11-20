"""Dashboards never wait for VirusTotal (cache_only) + caches shared by the cluster (KV imperva_cache)."""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "var", "run", "splunk"))
        os.makedirs(os.path.join(self.tmp, "var", "log", "splunk"))
        os.environ["SPLUNK_HOME"] = self.tmp
        self.kv, self.out, self.api = {}, {}, []

    def kv_query(self, sk, col, q):
        return [self.kv[k] for k in q["_key"]["$in"] if k in self.kv]

    def kv_upsert(self, sk, docs, col=None):
        for d in docs:
            self.kv[d["_key"]] = dict(d)


class TestVtcheckCacheOnly(Base):
    def run_(self, rows, *argv):
        import vtcheck as c
        c.load_conf_stanza = lambda sk, conf, st: {"vt_via": "direct"} if st == "virustotal" else {}
        c.kv_query, c.kv_upsert = self.kv_query, self.kv_upsert
        c.load_credential = lambda *a: ("u", "key")

        class FakeVT(object):
            def __init__(s, *a, **k):
                pass

            def lookup_ip(s, ip):
                self.api.append(ip)
                return {"vt_status": "ok", "vt_malicious": 5, "vt_link": "x"}
        c.vt.VTClient = FakeVT
        c.si.getOrganizedResults = lambda: ([dict(r) for r in rows], None, {"sessionKey": "k"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        sys.argv = ["vtcheck.py"] + list(argv)
        c.main()
        return self.out

    def test_dashboard_never_calls_vt_and_reads_shared_cache(self):
        self.kv["vt_8.8.4.4"] = {"_key": "vt_8.8.4.4", "ts": time.time(),
                                 "data": json.dumps({"vt_status": "ok", "vt_malicious": 4})}
        rows = self.run_([{"src": "8.8.4.4"}, {"src": "1.1.1.1"}], "check_waf=false", "cache_only=true")["rows"]
        self.assertEqual(self.api, [])                               # no VirusTotal call at all
        self.assertEqual((rows[0]["vt_status"], rows[0]["vt_malicious"], rows[0]["suggestion"]), ("ok", "4", "BLOCK"))
        self.assertEqual((rows[1]["vt_status"], rows[1]["suggestion"]), ("pending", "REVIEW"))

    def test_warmup_looks_up_and_shares_with_other_members(self):
        self.run_([{"src": "1.1.1.1"}], "check_waf=false", "max_lookups=0")
        self.assertEqual(self.api, ["1.1.1.1"])
        self.assertEqual(json.loads(self.kv["vt_1.1.1.1"]["data"])["vt_malicious"], 5)
        os.remove(os.path.join(self.tmp, "var", "run", "splunk", "ta_imperva_vt_cache.json"))  # "other member"
        rows = self.run_([{"src": "1.1.1.1"}], "check_waf=false", "cache_only=true")["rows"]
        self.assertEqual((rows[0]["vt_status"], rows[0]["vt_cached"]), ("ok", "yes"))
        self.assertEqual(self.api, ["1.1.1.1"])

    def test_expired_shared_entry_is_pending(self):
        self.kv["vt_8.8.4.4"] = {"_key": "vt_8.8.4.4", "ts": time.time() - 2 * 86400,
                                 "data": json.dumps({"vt_status": "ok"})}
        rows = self.run_([{"src": "8.8.4.4"}], "check_waf=false", "cache_only=true")["rows"]
        self.assertEqual(rows[0]["vt_status"], "pending")


class TestPolicyCacheShared(Base):
    def setUp(self):
        Base.setUp(self)
        import impervapolicycheck as c
        self.c = c
        c.kv_get = lambda sk, key, col: self.kv.get(key)
        c.kv_upsert = self.kv_upsert
        self.calls = []

        class FakeBackend(object):
            targets, mode = ["2169031"], "soar"

            def policy_entries(s):
                self.calls.append(1)
                return [{"policy_id": "1", "policy_name": "Allow DC", "action": "ALLOW", "value": "20.20.20.0/24",
                         "enabled": True, "applies_to_all": True}]
        c.get_backend = lambda *a, **k: FakeBackend()

    def test_member_without_file_uses_shared_cache(self):
        log = type("L", (), {"warning": lambda *a: None})()
        e1, _t, via1 = self.c.load_entries("k", {}, log)
        self.assertEqual((len(self.calls), via1), (1, "soar"))
        os.remove(self.c.cache_path())                                  # "other member"
        e2, _t, via2 = self.c.load_entries("k", {}, log)
        self.assertEqual((len(self.calls), via2, e2), (1, "shared cache", e1))
        self.c.load_entries("k", {}, log, force=True)                   # refresh search
        self.assertEqual(len(self.calls), 2)


class TestPolicyCheckCommand(Base):
    def run_(self, rows):
        import impervapolicycheck as c
        c.load_conf_stanza = lambda *a: {}
        c.load_entries = lambda *a, **k: ([
            {"policy_id": "9", "policy_name": "Off", "action": "BLOCK", "cidr": "0.0.0.0/0", "kind": "rule",
             "enabled": False},
            {"policy_id": "1667692", "policy_name": "Block IOC", "action": "BLOCK", "cidr": "35.165.106.69",
             "kind": "rule", "enabled": True}], ["2169031"], "cache")
        c.si.getOrganizedResults = lambda: ([dict(r) for r in rows], None, {"sessionKey": "k"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        sys.argv = ["impervapolicycheck.py", "field=ip"]
        c.main()
        return self.out["rows"]

    def test_disabled_policies_hidden_and_empty_ip_row_kept(self):
        rows = self.run_([{"ip": "35.165.106.69"}, {"ip": "18.236.104.225"}, {"ip": ""}])
        self.assertEqual([r.get("waf_policy_verdict") for r in rows], ["BLOCKED_ELSEWHERE", "NONE", None])
        self.assertEqual(rows[0]["waf_policies"], "BLOCK in 1667692 Block IOC (35.165.106.69)")
        self.assertEqual(rows[1]["waf_policies"], "-")              # disabled 0.0.0.0/0 not shown

    def test_summary_without_ip_field(self):
        self.assertEqual(self.run_([{"_time": "1"}]), [{"policies_ip_rules": 2, "read_via": "cache"}])


if __name__ == "__main__":
    unittest.main()
