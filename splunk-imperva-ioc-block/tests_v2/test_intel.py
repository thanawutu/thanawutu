"""V2: AbuseIPDB + GreyNoise - library, SOAR actions (generated playbook), intelcheck command, config."""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2")
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(APP, "bin"))
sys.path.insert(0, os.path.join(HERE, "..", "soar"))

import build_global_code  # noqa: E402
import intel_lib as il    # noqa: E402

ABUSE_JSON = {"data": {"ipAddress": "185.220.101.47", "isPublic": True, "ipVersion": 4, "isWhitelisted": False,
                       "abuseConfidenceScore": 100, "countryCode": "DE", "usageType": "Data Center/Web Hosting/Transit",
                       "isp": "Example Hosting GmbH", "domain": "example.net", "hostnames": [], "isTor": True,
                       "totalReports": 1520, "numDistinctUsers": 310, "lastReportedAt": "2026-11-13T22:41:05+00:00"}}
GN_JSON = {"ip": "185.220.101.47", "noise": True, "riot": False, "classification": "malicious",
           "name": "unknown", "link": "https://viz.greynoise.io/ip/185.220.101.47", "last_seen": "2026-11-13",
           "message": "Success"}
GN_404 = {"ip": "203.0.113.200", "noise": False, "riot": False,
          "message": "IP not observed scanning the internet or contained in RIOT data set."}


class Server(object):
    """Local HTTP server answering like AbuseIPDB / GreyNoise; records the requests."""
    def __init__(self, routes):
        self.seen, routes_ = [], routes

        class H(BaseHTTPRequestHandler):
            def do_GET(h):  # noqa: N805
                self.seen.append({"path": h.path, "headers": dict((k.lower(), v) for k, v in h.headers.items())})
                code, body = routes_(h.path)
                h.send_response(code)
                h.send_header("Content-Type", "application/json")
                h.end_headers()
                h.wfile.write(json.dumps(body).encode())

            def log_message(h, *a):  # noqa: N805
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_port

    def close(self):
        self.srv.shutdown()


class TestParse(unittest.TestCase):
    def test_abuse_fields(self):
        r = il.parse_abuse_response("185.220.101.47", ABUSE_JSON)
        self.assertEqual((r["abuse_status"], r["abuse_score"], r["abuse_reports"], r["abuse_users"]), ("ok", 100, 1520, 310))
        self.assertEqual((r["abuse_tor"], r["abuse_whitelisted"], r["abuse_country"]), ("yes", "no", "DE"))
        self.assertEqual(r["abuse_last_reported"], "2026-11-13 22:41")
        self.assertEqual(r["abuse_link"], "https://www.abuseipdb.com/check/185.220.101.47")

    def test_abuse_missing_fields_do_not_break(self):
        r = il.parse_abuse_response("1.2.3.4", {"data": {}})
        self.assertEqual((r["abuse_score"], r["abuse_reports"], r["abuse_usage"], r["abuse_last_reported"]), (0, 0, "-", "-"))

    def test_gn_fields(self):
        r = il.parse_gn_response("185.220.101.47", GN_JSON)
        self.assertEqual((r["gn_status"], r["gn_noise"], r["gn_riot"], r["gn_classification"]), ("ok", "yes", "no", "malicious"))
        r = il.parse_gn_response("203.0.113.200", GN_404, status="not_found")
        self.assertEqual((r["gn_status"], r["gn_classification"], r["gn_link"]),
                         ("not_found", "-", "https://viz.greynoise.io/ip/203.0.113.200"))

    def test_names_do_not_collide_with_vt_or_imperva_lib(self):
        import re
        mine = set(re.findall(r"^(?:def|class) (\w+)|^(\w+) *=", open(os.path.join(APP, "bin", "intel_lib.py")).read(), re.M))
        mine = set(a or b for a, b in mine)
        for other in ("vt_lib.py", "imperva_lib.py"):
            theirs = set(a or b for a, b in re.findall(r"^(?:def|class) (\w+)|^(\w+) *=",
                                                       open(os.path.join(APP, "bin", other)).read(), re.M))
            self.assertEqual(mine & theirs, set(), other)


class TestClients(unittest.TestCase):
    def setUp(self):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"

    def test_abuseipdb_request_and_answer(self):
        s = Server(lambda path: (200, ABUSE_JSON))
        try:
            r = il.AbuseIPDBClient("KEY1", base_url=s.url + "/api/v2", max_age_days=30).lookup_ip("185.220.101.47")
        finally:
            s.close()
        self.assertEqual(r["abuse_score"], 100)
        self.assertEqual(s.seen[0]["path"], "/api/v2/check?ipAddress=185.220.101.47&maxAgeInDays=30")
        self.assertEqual((s.seen[0]["headers"].get("key"), s.seen[0]["headers"].get("accept")), ("KEY1", "application/json"))

    def test_abuseipdb_errors(self):
        for code, exc in ((429, il.IntelRateLimited), (401, il.IntelError)):
            s = Server(lambda path, c=code: (c, {"errors": [{"detail": "x", "status": c}]}))
            try:
                with self.assertRaises(exc):
                    il.AbuseIPDBClient("K", base_url=s.url).lookup_ip("1.2.3.4")
            finally:
                s.close()
        self.assertRaises(il.IntelError, il.AbuseIPDBClient, "")

    def test_greynoise_ok_404_429_and_key(self):
        s = Server(lambda path: (200, GN_JSON) if path.endswith("185.220.101.47") else
                   ((404, GN_404) if path.endswith("203.0.113.200") else (429, {"message": "limit"})))
        try:
            c = il.GreyNoiseClient("GNKEY", base_url=s.url + "/v3")
            self.assertEqual(c.lookup_ip("185.220.101.47")["gn_classification"], "malicious")
            self.assertEqual(c.lookup_ip("203.0.113.200")["gn_status"], "not_found")
            self.assertRaises(il.IntelRateLimited, c.lookup_ip, "8.8.4.4")
            il.GreyNoiseClient(None, base_url=s.url + "/v3").lookup_ip("185.220.101.47")
        finally:
            s.close()
        self.assertEqual(s.seen[0]["path"], "/v3/community/185.220.101.47")
        self.assertEqual(s.seen[0]["headers"].get("key"), "GNKEY")             # header names are case-insensitive
        self.assertNotIn("key", s.seen[-1]["headers"])            # Community API without a key


class FakeClient(object):
    prefix, gui = "abuse", il.ABUSE_GUI

    def __init__(self, limited=0, fail=()):
        self.calls, self.limited, self.fail = [], limited, fail

    def lookup_ip(self, ip):
        self.calls.append(ip)
        if self.limited:
            self.limited -= 1
            raise il.IntelRateLimited("429")
        if ip in self.fail:
            raise il.IntelError("boom")
        return {"abuse_status": "ok", "abuse_score": 50, "abuse_link": il.ABUSE_GUI + ip}


class TestLookupMany(unittest.TestCase):
    def run_(self, client, ips, **kw):
        t = {"now": 0.0}
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            t["now"] += s
        return il.intel_lookup_many(client, ips, _sleep=sleep, _now=lambda: t["now"], **kw), sleeps

    def test_private_limit_error(self):
        c = FakeClient(fail=("8.8.8.8",))
        out, _ = self.run_(c, ["10.0.0.1", "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.1"], max_lookups=2)
        self.assertEqual(out["10.0.0.1"]["abuse_status"], "private_ip")
        self.assertEqual(out["1.1.1.1"]["abuse_status"], "ok")
        self.assertEqual((out["8.8.8.8"]["abuse_status"], out["8.8.8.8"]["abuse_error"]), ("error", "boom"))
        self.assertEqual(out["9.9.9.9"]["abuse_status"], "not_checked (max_lookups_per_run)")
        self.assertEqual(c.calls, ["1.1.1.1", "8.8.8.8"])

    def test_rate_limit_wait_then_stop(self):
        out, sleeps = self.run_(FakeClient(limited=1), ["1.1.1.1", "2.2.2.2"], rpm=60, retry_wait=60, max_wait=60)
        self.assertEqual(set(i["abuse_status"] for i in out.values()), {"ok"})
        self.assertIn(60, sleeps)
        out, _ = self.run_(FakeClient(limited=5), ["1.1.1.1", "2.2.2.2"], max_wait=0)
        self.assertEqual(set(i["abuse_status"] for i in out.values()), {"rate_limited"})


class TestAdjust(unittest.TestCase):
    A = staticmethod(il.intel_adjust)

    def test_matrix(self):
        ok = lambda score, **kw: dict({"abuse_status": "ok", "abuse_score": score, "abuse_reports": 9}, **kw)  # noqa: E731
        self.assertEqual(self.A("MONITOR", "VT clean", ok(92))[0], "BLOCK")
        self.assertEqual(self.A("MONITOR", "VT clean", ok(30))[0], "REVIEW")
        self.assertEqual(self.A("REVIEW", "x", ok(10)), ("REVIEW", "x"))                 # nothing to add
        self.assertEqual(self.A("MONITOR", "x", {"gn_status": "ok", "gn_classification": "malicious", "gn_riot": "no"})[0], "REVIEW")
        s, why = self.A("BLOCK", "5 VT engines", {"gn_status": "ok", "gn_riot": "yes", "gn_name": "Google", "gn_classification": "benign"})
        self.assertEqual(s, "REVIEW")
        self.assertIn("GreyNoise RIOT known service (Google) - check before blocking", why)
        self.assertEqual(self.A("BLOCK", "x", ok(90, abuse_whitelisted="yes"))[0], "REVIEW")
        for keep in ("DO_NOT_BLOCK", "ALREADY_BLOCKED"):
            self.assertEqual(self.A(keep, "r", ok(100))[0], keep)
        self.assertEqual(self.A("MONITOR", "r", {"abuse_status": "pending", "gn_status": "pending"}), ("MONITOR", "r"))
        self.assertEqual(self.A("MONITOR", "r", ok(60), {"abuse_block_score": "50"})[0], "BLOCK")
        self.assertIn("AbuseIPDB 92% (9 reports)", self.A("MONITOR", "VT clean", ok(92))[1])

    def test_summary(self):
        self.assertEqual(il.intel_summary({"abuse_status": "ok", "abuse_score": 100, "abuse_reports": 3,
                                           "gn_status": "not_found"}), "AbuseIPDB 100% (3 reports) · GreyNoise not observed")
        self.assertEqual(il.intel_summary({}), "")


class TestSoarPlaybook(unittest.TestCase):
    """The generated playbook code, run stand-alone as SOAR would."""
    @classmethod
    def setUpClass(cls):
        cls.ns = {"__name__": "soar_playbook"}
        exec(compile(build_global_code.build(), "global_code.py", "exec"), cls.ns)

    def test_vt_names_intact(self):
        self.assertIn("vt_status", self.ns["lookup_many"].__doc__)          # VirusTotal's, not replaced
        self.assertIn("intel_lookup_many", self.ns)

    def factory(self, source):
        c = FakeClient()
        if source == "greynoise":
            c.prefix, c.gui = "gn", il.GN_GUI
            c.lookup_ip = lambda ip: {"gn_status": "ok", "gn_classification": "malicious", "gn_link": il.GN_GUI + ip}
        return c

    def test_abusecheck_and_gncheck(self):
        for action, field in (("abusecheck", "abuse_status"), ("gncheck", "gn_status")):
            res = self.ns["process_request"]({"request_id": "r1", "action": action, "ips": "185.220.101.47,10.1.1.1",
                                              "intel_max_lookups": "5"}, env={}, intel_client_factory=self.factory)
            self.assertEqual(res["status"], "ok", res["error"])
            rows = dict((r["ip"], r) for r in json.loads(res["result_json"]))
            self.assertEqual((rows["185.220.101.47"][field], rows["10.1.1.1"][field]), ("ok", "private_ip"))

    def test_missing_abuseipdb_key_is_an_error_greynoise_is_not(self):
        res = self.ns["process_request"]({"request_id": "r", "action": "abusecheck", "ips": "1.1.1.1"}, env={})
        self.assertEqual((res["status"], res["error"]), ("error", "ABUSEIPDB_API_KEY is not set on SOAR"))
        cfg = {}
        self.ns["intel_client"] = lambda source, key, **kw: cfg.update(source=source, key=key, **kw) or self.factory(source)
        try:
            res = self.ns["process_request"]({"request_id": "r", "action": "gncheck", "ips": "1.1.1.1"},
                                             env={"IMPERVA_PROXY": "http://proxy:8080"})
        finally:
            self.ns["intel_client"] = il.intel_client
        self.assertEqual(res["status"], "ok")
        self.assertEqual((cfg["source"], cfg["key"], cfg["proxy"]), ("greynoise", None, "http://proxy:8080"))

    def test_old_actions_unchanged_and_unknown_refused(self):
        res = self.ns["process_request"]({"request_id": "r", "action": "explode"}, env={})
        self.assertEqual(res["status"], "error")
        self.assertIn("unknown action", res["error"])

    def test_settings_block_lists_the_new_keys(self):
        block = build_global_code.build_code_block()
        self.assertIn('"ABUSEIPDB_API_KEY": ""', block)
        self.assertIn('"GREYNOISE_API_KEY": ""', block)


class FakeBridge(object):
    wait_seconds = 90

    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def intel_lookup(self, action, ips, **kw):
        self.calls.append((action, list(ips), kw))
        if self.fail:
            raise RuntimeError(self.fail)
        if action == "abusecheck":
            return [{"ip": ip, "abuse_status": "ok", "abuse_score": 88, "abuse_reports": 40, "soar_container": 7} for ip in ips]
        return [{"ip": ip, "gn_status": "not_found", "gn_classification": "-", "soar_container": 7} for ip in ips]


class TestCommand(unittest.TestCase):
    def setUp(self):
        import intelcheck as c
        self.c = c
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "var", "run", "splunk"))
        self.kv, self.out, self.conf = {}, {}, {"settings": {"api_mode": "soar"}, "abuseipdb": {}, "greynoise": {}}
        self.bridge = FakeBridge()
        c.splunk_home = lambda: self.tmp
        c.load_conf_stanza = lambda sk, conf, stanza: dict(self.conf.get(stanza, {}))
        c.kv_query = lambda sk, col, q: [self.kv[k] for k in q["_key"]["$in"] if k in self.kv]
        c.kv_upsert = lambda sk, docs, col=None: [self.kv.__setitem__(d["_key"], dict(d)) for d in docs]
        c.get_soar_bridge = lambda iconf, lc, sk: self.bridge
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: None, "warning": lambda s, *a: None,
                                                  "error": lambda s, *a: None})()
        c.si.getOrganizedResults = lambda: (self.rows, None, {"sessionKey": "k"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)

    def run_(self, *argv, rows=None):
        self.rows = rows if rows is not None else [{"src": "185.220.101.47", "suggestion": "MONITOR",
                                                    "suggestion_reason": "VT clean"}, {"src": "-"}]
        self.out.clear()
        sys.argv = ["intelcheck.py"] + list(argv)
        self.c.main()
        if "err" in self.out:
            raise AssertionError(self.out["err"])
        return self.out["rows"]

    def test_cache_only_never_calls_soar(self):
        r = self.run_("cache_only=true")[0]
        self.assertEqual((r["abuse_status"], r["gn_status"]), ("pending", "pending"))
        self.assertEqual(self.bridge.calls, [])
        self.assertEqual(r["suggestion"], "MONITOR")

    def test_soar_lookup_cache_and_adjust(self):
        r = self.run_()[0]
        self.assertEqual((r["abuse_status"], r["abuse_score"], r["gn_status"]), ("ok", "88", "not_found"))
        self.assertEqual(r["suggestion"], "BLOCK")
        self.assertIn("AbuseIPDB 88% (40 reports)", r["suggestion_reason"])
        self.assertEqual([c[0] for c in self.bridge.calls], ["abusecheck", "gncheck"])
        self.assertEqual(self.bridge.calls[0][2]["max_lookups"], 40)            # [abuseipdb] default per run
        self.assertIn("abuse_185.220.101.47", self.kv)
        self.assertIn("gn_185.220.101.47", self.kv)
        self.bridge.calls = []
        r = self.run_("cache_only=true")[0]                                     # from the cache now
        self.assertEqual((r["abuse_status"], r["abuse_cached"]), ("ok", "yes"))
        self.assertEqual(self.bridge.calls, [])

    def test_kv_cache_of_another_member_is_used(self):
        import time as _t
        self.kv["abuse_185.220.101.47"] = {"_key": "abuse_185.220.101.47", "ts": _t.time(),
                                           "data": json.dumps({"abuse_status": "ok", "abuse_score": 5})}
        r = self.run_("cache_only=true", "sources=abuseipdb")[0]
        self.assertEqual((r["abuse_score"], r["gn_status"]), ("5", "off"))

    def test_disabled_source_and_adjust_false(self):
        self.conf["greynoise"] = {"enabled": "false"}
        r = self.run_("adjust=false")[0]
        self.assertEqual((r["gn_status"], r["suggestion"]), ("off", "MONITOR"))
        self.assertEqual([c[0] for c in self.bridge.calls], ["abusecheck"])

    def test_soar_error_is_shown_per_row(self):
        self.bridge = FakeBridge(fail="SOAR HTTP 401")
        r = self.run_()[0]
        self.assertEqual((r["abuse_status"], r["abuse_error"]), ("error", "SOAR HTTP 401"))
        self.assertEqual(self.kv, {})                                           # errors are not cached

    def test_direct_mode_uses_the_credential(self):
        self.conf["settings"] = {"api_mode": "v2_policy"}
        seen = {}
        self.c.load_credential = lambda sk, realm: ("x", "KEY-" + realm) if realm == "abuseipdb" else (_ for _ in ()).throw(RuntimeError("none"))

        def client(source, key, **kw):
            seen[source] = key
            f = FakeClient()
            if source == "greynoise":
                f.prefix, f.gui = "gn", il.GN_GUI
                f.lookup_ip = lambda ip: {"gn_status": "ok", "gn_classification": "benign", "gn_riot": "yes", "gn_name": "X"}
            return f
        saved = self.c.il.intel_client
        self.c.il.intel_client = client
        try:
            r = self.run_()[0]
        finally:
            self.c.il.intel_client = saved
        self.assertEqual(seen, {"abuseipdb": "KEY-abuseipdb", "greynoise": None})
        self.assertEqual((r["abuse_status"], r["gn_classification"]), ("ok", "benign"))
        self.assertEqual(r["suggestion"], "REVIEW")                             # AbuseIPDB 50% -> REVIEW, RIOT caps it

    def test_unknown_source(self):
        with self.assertRaises(AssertionError):
            self.run_("sources=shodan")


class TestBridge(unittest.TestCase):
    def test_intel_lookup_sends_action_and_limits_and_deletes_container(self):
        import soar_bridge as sb
        b = sb.SoarBridge("https://soar", "t", delete_list_containers=True)
        sent, deleted = {}, []
        b.submit = lambda req: sent.update(req) or 41
        b.wait_result = lambda cid, rid, w=None: [{"ip": "1.1.1.1", "abuse_status": "ok"}]
        b.delete_container = lambda cid: deleted.append(cid)
        rows = b.intel_lookup("abusecheck", ["1.1.1.1"], max_lookups=40, max_wait=0, retry_wait=60)
        self.assertEqual((sent["action"], sent["ips"], sent["intel_max_lookups"], sent["intel_max_wait"]),
                         ("abusecheck", "1.1.1.1", "40", "0"))
        self.assertEqual((rows[0]["soar_container"], deleted), (41, [41]))


class TestConfig(unittest.TestCase):
    def read(self, *p):
        return open(os.path.join(APP, *p), encoding="utf-8").read()

    def test_conf_spec_commands_saved_search(self):
        conf = self.read("default", "imperva.conf")
        for k in ("[abuseipdb]", "[greynoise]", "block_score = 75", "review_score = 25", "max_lookups_per_run = 40",
                  "soar_label = imperva_ioc_block_v2"):
            self.assertIn(k, conf)
        self.assertIn("[abuseipdb]", self.read("README", "imperva.conf.spec"))
        self.assertIn("[intelcheck]\nfilename = intelcheck.py", self.read("default", "commands.conf"))
        self.assertIn("[commands/intelcheck]", self.read("metadata", "default.meta"))
        ss = self.read("default", "savedsearches.conf")
        self.assertIn("[Imperva V2 - AbuseIPDB / GreyNoise cache warm-up]", ss)
        self.assertIn("| intelcheck field=src adjust=false", ss)

    def test_dashboards_read_the_cache_only_and_show_the_columns(self):
        macros = self.read("default", "macros.conf")
        i, j = macros.index("| vtcheck field=src count_field=count check_waf=false cache_only=true"), macros.index("| intelcheck field=src cache_only=true")
        self.assertLess(i, j)
        self.assertLess(j, macros.index("| eval prio=case(suggestion"))       # the adjusted suggestion is sorted
        self.assertEqual(macros.count('rename abuse_score_txt AS "AbuseIPDB %", gn_txt AS GreyNoise'), 2)
        for v in ("imperva_ioc_block.xml", "imperva_ioc_history.xml"):
            x = self.read("default", "data", "ui", "views", v)
            self.assertIn("https://www.abuseipdb.com/check/$row.src|n$", x)
            self.assertIn("https://viz.greynoise.io/ip/$row.IP|n$", x)
            self.assertIn("| intelcheck field=src cache_only=true adjust=false", x)


if __name__ == "__main__":
    unittest.main()
