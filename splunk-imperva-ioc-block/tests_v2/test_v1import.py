"""V2: impervav1import copies V1 data (KV store, credentials, audit CSV) without overwriting V2."""
import csv
import json
import os
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))

V1, V2 = "TA-imperva-ioc-block", "TA-imperva-ioc-block-v2"


class Resp(object):
    def __init__(self, status=200):
        self.status = status


class FakeSplunk(object):
    def __init__(self):
        self.kv = {V1: {}, V2: {}}          # app -> collection -> {key: doc}
        self.pw = {V1: [], V2: []}          # app -> [content]
        self.posts = []

    def coll(self, app, c):
        return self.kv[app].setdefault(c, {})

    def __call__(self, path, sessionKey=None, method="GET", jsonargs=None, rawData=None, raiseAllErrors=False, **k):
        p = urllib.parse.urlparse(path)
        parts = p.path.split("/")              # /servicesNS/nobody/<app>/storage/...
        app = parts[3]
        if parts[4:6] == ["storage", "collections"]:
            c = parts[7]
            if method == "GET":
                return Resp(), json.dumps(list(self.coll(app, c).values()))
            if method == "POST" and parts[-1] == "batch_save":
                for d in json.loads(jsonargs):
                    self.coll(app, c)[d["_key"]] = d
                return Resp(), "[]"
            if method == "DELETE":
                self.coll(app, c).pop(parts[8], None)
                return Resp(), ""
        if parts[4:6] == ["storage", "passwords"]:
            if method == "GET":
                return Resp(), json.dumps({"entry": [{"acl": {"app": app}, "content": c} for c in self.pw[app]]})
            body = dict(urllib.parse.parse_qsl(rawData))
            self.posts.append(body)
            self.pw[app].append({"realm": body["realm"], "username": body["name"], "clear_password": body["password"]})
            return Resp(201), ""
        raise AssertionError("unexpected REST call %s %s" % (method, path))


class TestImport(unittest.TestCase):
    def setUp(self):
        import impervav1import as m
        import ioc_rules as ir
        self.m, self.ir = m, ir
        self.fake = FakeSplunk()
        m.rest.simpleRequest = self.fake
        self.out = {}
        m.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "admin"})
        m.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        m.si.generateErrorResults = lambda msg: self.out.__setitem__("err", msg)
        m.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: None, "error": lambda s, *a: None})()
        self.tmp = tempfile.mkdtemp()
        os.environ["SPLUNK_HOME"] = self.tmp

    def run_(self, action):
        self.out.clear()
        sys.argv = ["impervav1import.py", "action=" + action]
        self.m.main()
        if "err" in self.out:
            raise AssertionError(self.out["err"])
        return self.out["rows"]

    def test_kv_copies_only_new_documents(self):
        f = self.fake
        f.coll(V1, "imperva_block_registry").update({"2169031_1.1.1.1": {"_key": "2169031_1.1.1.1", "ip": "1.1.1.1", "_user": "nobody"},
                                                     "2169031_2.2.2.2": {"_key": "2169031_2.2.2.2", "ip": "2.2.2.2", "status": "old"}})
        f.coll(V2, "imperva_block_registry")["2169031_2.2.2.2"] = {"_key": "2169031_2.2.2.2", "ip": "2.2.2.2", "status": "v2"}
        f.coll(V1, "imperva_cache").update({"vt_1.1.1.1": {"_key": "vt_1.1.1.1", "data": "{}"}, "policies": {"_key": "policies"}})
        rows = dict((r["what"], r) for r in self.run_("kv"))
        self.assertEqual(rows["imperva_block_registry"]["items"], 1)
        self.assertEqual(f.coll(V2, "imperva_block_registry")["2169031_2.2.2.2"]["status"], "v2")      # V2 wins
        self.assertNotIn("_user", f.coll(V2, "imperva_block_registry")["2169031_1.1.1.1"])
        self.assertEqual(sorted(f.coll(V2, "imperva_cache")), ["vt_1.1.1.1"])                         # no policy cache
        self.assertEqual(rows["imperva_ioc_rules"]["status"], "skipped")                             # V1 has none

    def test_rules_replace_v2_defaults_only(self):
        ir, f = self.ir, self.fake
        for p, mode, n in ir.DEFAULT_RULES:
            f.coll(V2, ir.COLLECTION)[ir.rule_key(p, mode)] = {"_key": ir.rule_key(p, mode), "pattern": p, "mode": mode}
        f.coll(V2, ir.COLLECTION)[ir.SEED_KEY] = {"_key": ir.SEED_KEY, "mode": "meta"}
        k = ir.rule_key("*Threat Hunting (IP)*", "include")
        f.coll(V1, ir.COLLECTION).update({k: {"_key": k, "pattern": "*Threat Hunting (IP)*", "mode": "include"},
                                          ir.SEED_KEY: {"_key": ir.SEED_KEY, "mode": "meta"}})
        rows = dict((r["what"], r) for r in self.run_("kv"))
        self.assertEqual(rows["imperva_ioc_rules"]["status"], "copied")
        self.assertEqual(sorted(f.coll(V2, ir.COLLECTION)), sorted([k, ir.SEED_KEY]))
        f.coll(V2, ir.COLLECTION)["mine"] = {"_key": "mine", "pattern": "*x*", "mode": "exclude"}
        rows = dict((r["what"], r) for r in self.run_("kv"))
        self.assertEqual(rows["imperva_ioc_rules"]["status"], "skipped")

    def test_credentials_copied_without_showing_secrets(self):
        f = self.fake
        f.pw[V1] = [{"realm": "splunk_soar", "username": "splunk-automation", "clear_password": "S3cr3t+/="},
                    {"realm": "imperva_waf", "username": "12345", "clear_password": "uuid-key"},
                    {"realm": "other", "username": "x", "clear_password": "y"}]
        f.pw[V2] = [{"realm": "imperva_waf", "username": "12345", "clear_password": "uuid-key"}]
        rows = self.run_("credentials")
        st = dict((r["what"], r["status"]) for r in rows)
        self.assertEqual(st, {"credential imperva_waf": "exists", "credential splunk_soar": "copied", "credential virustotal": "skipped"})
        self.assertEqual(f.posts, [{"name": "splunk-automation", "password": "S3cr3t+/=", "realm": "splunk_soar"}])
        self.assertNotIn("S3cr3t", json.dumps(rows))

    def test_audit_rows_not_yet_in_v2(self):
        cols = ["time", "user", "action", "ip", "ticket", "description", "status", "verified", "policy", "backend", "soar_container", "detail"]
        for app, rows in ((V1, [["1", "a", "block", "1.1.1.1", "ITHM 1", "x", "blocked", "yes", "2169031", "soar", "9", "ok"],
                                ["2", "a", "unblock", "1.1.1.1", "-", "fp", "unblocked", "removed", "2169031", "soar", "10", "ok"]]),
                          (V2, [["1", "a", "block", "1.1.1.1", "ITHM 1", "x", "blocked", "yes", "2169031", "soar", "9", "ok"]])):
            d = os.path.join(self.tmp, "etc", "apps", app, "lookups")
            os.makedirs(d)
            with open(os.path.join(d, "imperva_audit.csv"), "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                w.writerows(rows)
        out = self.run_("audit")
        self.assertEqual([(r["time"], r["action"]) for r in out], [("2", "unblock")])

    def test_audit_missing_v1_file(self):
        self.out.clear()
        sys.argv = ["impervav1import.py", "action=audit"]
        self.m.main()
        self.assertIn("V1 audit CSV not found", self.out["err"])


if __name__ == "__main__":
    unittest.main()
