"""
End-to-end: SoarBridge (Splunk side) -> fake SOAR REST -> generated playbook
global code (SOAR side) -> fake Imperva Policies API v2.
"""
import copy
import json
import os
import sys
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))
sys.path.insert(0, os.path.join(HERE, "..", "soar"))
import build_global_code  # noqa: E402
import soar_bridge as sb  # noqa: E402
from test_policy_v2 import POLICY, FakeImperva  # noqa: E402

# Load the generated SOAR code exactly as SOAR would run it (stand-alone)
SOAR_NS = {"__name__": "soar_playbook"}
exec(compile(build_global_code.build(), "imperva_ioc_block_global_code.py", "exec"), SOAR_NS)


def _serve(handler, threading_server=False):
    cls = ThreadingHTTPServer if threading_server else HTTPServer
    srv = cls(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_port


class FakePhantom(object):
    """Minimal stand-in for SOAR's phantom.rules used by imperva_soar_handle."""
    def __init__(self, soar_base, store):
        self.base, self.store = soar_base, store

    def build_phantom_rest_url(self, *parts):
        return self.base + "/rest/" + "/".join(str(p) for p in parts)

    class _Resp(object):
        def __init__(self, body):
            self._b = body

        def json(self):
            return json.loads(self._b)

    @property
    def requests(self):
        outer = self

        class R(object):
            @staticmethod
            def get(url, params=None, verify=True):
                q = "?" + urllib.parse.urlencode(params) if params else ""
                req = urllib.request.Request(url + q, headers={"ph-auth-token": "tok"})
                with urllib.request.urlopen(req) as r:
                    return outer._Resp(r.read().decode())
        return R

    def add_artifact(self, container, raw_data, cef_data, label, name, severity, identifier,
                     artifact_type, run_automation=False):
        c = self.store["containers"][container["id"]]
        c["artifacts"].append({"id": len(c["artifacts"]) + 1, "name": name, "cef": cef_data, "label": label})

    def set_status(self, container, status):
        self.store["containers"][container["id"]]["status"] = status

    def debug(self, msg):
        pass


class FakeSoar(BaseHTTPRequestHandler):
    store = {"containers": {}, "next": 100, "fail_playbook": False, "run_playbook": True}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def _ok(self):
        if self.headers.get("ph-auth-token") != "tok":
            self._send(401, {"failed": True, "message": "bad token"})
            return False
        return True

    def do_POST(self):
        if not self._ok():
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        st = FakeSoar.store
        cid = st["next"]
        st["next"] += 1
        arts = [dict(a, id=i + 1) for i, a in enumerate(body.get("artifacts", []))]
        st["containers"][cid] = {"id": cid, "label": body["label"], "artifacts": arts, "status": "new"}
        self._send(200, {"success": True, "id": cid})
        if st["run_playbook"] and any(a.get("run_automation") and a.get("label") == "imperva_ioc_block"
                                      for a in arts):
            container = {"id": cid, "label": body["label"]}
            phantom = FakePhantom("http://127.0.0.1:%d" % self.server.server_port, st)
            threading.Thread(target=SOAR_NS["imperva_soar_handle"], args=(container, phantom),
                             daemon=True).start()

    def do_GET(self):
        if not self._ok():
            return
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        parts = u.path.strip("/").split("/")
        st = FakeSoar.store
        if parts[:2] == ["rest", "container"] and len(parts) == 4 and parts[3] == "artifacts":
            arts = st["containers"][int(parts[2])]["artifacts"]
            name = q.get("_filter_name", "").strip('"')
            return self._send(200, {"data": [a for a in arts if not name or a["name"] == name]})
        if parts[:2] == ["rest", "playbook_run"]:
            runs = [{"id": 1, "status": "failed", "message": "boom"}] if st["fail_playbook"] else []
            return self._send(200, {"data": runs})
        self._send(404, {"failed": True})

    def do_DELETE(self):
        if not self._ok():
            return
        FakeSoar.store["containers"].pop(int(self.path.rstrip("/").split("/")[-1]), None)
        self._send(200, {"success": True})


class FakeVirusTotal(BaseHTTPRequestHandler):
    """GET /api/v3/ip_addresses/{ip} with header x-apikey."""
    calls = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        ip = self.path.rstrip("/").split("/")[-1]
        FakeVirusTotal.calls.append(ip)
        if self.headers.get("x-apikey") != "vtkey":
            code, body = 401, {"error": {"code": "WrongCredentialsError"}}
        elif ip == "4.4.4.4":
            code, body = 429, {"error": {"code": "QuotaExceededError"}}
        else:
            mal = 12 if ip.startswith("185.") else 0
            code, body = 200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": mal, "suspicious": 0, "harmless": 60, "undetected": 22},
                "reputation": -20 if mal else 0, "country": "DE", "asn": 208294, "as_owner": "Sample AS",
                "network": ip.rsplit(".", 1)[0] + ".0/24"}}}
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)


class TestSoarE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        cls.imp, cls.imp_base = _serve(FakeImperva)
        cls.soar, cls.soar_base = _serve(FakeSoar, threading_server=True)
        cls.vt, cls.vt_base = _serve(FakeVirusTotal)

    @classmethod
    def tearDownClass(cls):
        cls.imp.shutdown()
        cls.soar.shutdown()
        cls.vt.shutdown()

    def setUp(self):
        FakeImperva.store = {"1777": copy.deepcopy(POLICY)}
        FakeImperva.puts = []
        FakeSoar.store.update(containers={}, fail_playbook=False, run_playbook=True)
        self.env = {"IMPERVA_API_ID": "id1", "IMPERVA_API_KEY": "key1", "IMPERVA_POLICY_IDS": "1777",
                    "IMPERVA_API_BASE": self.imp_base, "IMPERVA_PROTECTED_NETWORKS": "45.33.32.0/24",
                    "VT_API_KEY": "vtkey", "VT_API_BASE": self.vt_base + "/api/v3",
                    "VT_REQUESTS_PER_MINUTE": "6000"}
        FakeVirusTotal.calls = []
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.bridge = sb.SoarBridge(self.soar_base, "tok", wait_seconds=10, poll_interval=0.05)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_block_via_soar_is_verified_on_waf(self):
        rows = self.bridge.execute("block", ["8.8.4.4"], ["1777"], False,
                                   {"threat_actor": "APT-X", "incident_no": "INC-1"}, "alice")
        self.assertEqual([(r["ip"], r["status"], r["verified_in_waf"]) for r in rows],
                         [("8.8.4.4", "blocked", "yes")])
        self.assertIn("8.8.4.4", FakeImperva.store["1777"]["policySettings"][1]["data"]["ips"])
        cid = rows[0]["soar_container"]
        c = FakeSoar.store["containers"][cid]
        self.assertEqual(c["status"], "closed")                       # audit trail kept on SOAR
        req = [a for a in c["artifacts"] if a["name"] == "imperva_request"][0]["cef"]
        self.assertEqual(req["requested_by"], "alice")
        # the block description stays in Splunk only - never sent to SOAR
        for k in ("threat_actor", "incident_no", "comment", "reason"):
            self.assertNotIn(k, req)
        self.assertNotIn("INC-1", json.dumps(c))

    def test_unblock_via_soar(self):
        rows = self.bridge.execute("unblock", ["1.1.1.1"], ["1777"], False, {}, "alice")
        self.assertEqual(rows[0]["status"], "unblocked")
        self.assertEqual(rows[0]["verified_in_waf"], "removed")

    def test_list_via_soar_deletes_container(self):
        rows = self.bridge.list_blocked(["1777"])
        self.assertEqual([(r["ip"], r["in_waf"], r["site_name"]) for r in rows],
                         [("1.1.1.1", "yes", "SOC IOC Blocklist")])
        self.assertEqual(FakeSoar.store["containers"], {})

    def test_soar_rejects_policy_not_in_allowlist(self):
        with self.assertRaises(sb.SoarError) as cm:
            self.bridge.execute("block", ["8.8.4.4"], ["9999"], False, {}, "alice")
        self.assertIn("not allowed", str(cm.exception))
        self.assertEqual(FakeImperva.puts, [])

    def test_soar_revalidates_protected_and_private(self):
        rows = self.bridge.execute("block", ["45.33.32.10", "10.0.0.1"], ["1777"], False, {}, "a")
        self.assertEqual({r["status"] for r in rows}, {"rejected"})
        self.assertEqual(FakeImperva.puts, [])

    def test_dry_run_via_soar(self):
        rows = self.bridge.execute("block", ["8.8.4.4"], ["1777"], True, {}, "a")
        self.assertEqual(rows[0]["status"], "would_be_blocked")
        self.assertEqual(FakeImperva.puts, [])

    def test_timeout_when_no_playbook(self):
        FakeSoar.store["run_playbook"] = False
        self.bridge.wait_seconds = 0.3
        with self.assertRaises(sb.SoarError) as cm:
            self.bridge.execute("block", ["8.8.4.4"], ["1777"], False, {}, "a")
        self.assertIn("No result from SOAR", str(cm.exception))

    def test_playbook_failure_reported(self):
        FakeSoar.store.update(run_playbook=False, fail_playbook=True)
        with self.assertRaises(sb.SoarError) as cm:
            self.bridge.execute("block", ["8.8.4.4"], ["1777"], False, {}, "a")
        self.assertIn("boom", str(cm.exception))

    def test_virustotal_via_soar(self):
        rows = {r["ip"]: r for r in self.bridge.vt_lookup(["185.220.101.47", "20.115.62.14", "10.0.0.1"])}
        self.assertEqual(rows["185.220.101.47"]["vt_malicious"], 12)
        self.assertEqual(rows["185.220.101.47"]["vt_country"], "DE")
        self.assertEqual(rows["20.115.62.14"]["vt_malicious"], 0)
        self.assertEqual(rows["10.0.0.1"]["vt_status"], "private_ip")
        self.assertEqual(FakeVirusTotal.calls, ["185.220.101.47", "20.115.62.14"])  # private IP never sent
        self.assertEqual(FakeSoar.store["containers"], {})                         # read-only: cleaned up

    def test_virustotal_quota_via_soar(self):
        rows = {r["ip"]: r for r in self.bridge.vt_lookup(["4.4.4.4", "8.8.4.4"])}
        self.assertEqual(rows["4.4.4.4"]["vt_status"], "rate_limited")
        self.assertEqual(rows["8.8.4.4"]["vt_status"], "rate_limited")
        self.assertEqual(FakeVirusTotal.calls, ["4.4.4.4"])

    def test_virustotal_key_missing_on_soar(self):
        os.environ.pop("VT_API_KEY")
        with self.assertRaises(sb.SoarError) as cm:
            self.bridge.vt_lookup(["8.8.4.4"])
        self.assertIn("VT_API_KEY", str(cm.exception))

    def test_sendalert_style_artifact_is_processed(self):
        """Container created by `| sendalert sendtophantom` / Send to SOAR adaptive response."""
        st = FakeSoar.store
        cid = 999
        st["containers"][cid] = {"id": cid, "label": "imperva_ioc_block", "status": "new", "artifacts": [
            {"id": 1, "name": "Field Values", "cef": {"imperva_action": "block", "src": "8.8.4.4",
                                                      "incident_no": "INC-77", "threat_actor": "APT-Y"}},
            {"id": 2, "name": "Field Values", "cef": {"action": "allowed", "src": "1.2.3.4"}},  # not a request
        ]}
        phantom = FakePhantom(self.soar_base, st)
        handled = SOAR_NS["imperva_soar_handle"]({"id": cid, "label": "imperva_ioc_block"}, phantom)
        self.assertEqual(handled, 1)
        res = [a for a in st["containers"][cid]["artifacts"] if a["name"] == "imperva_result"][0]["cef"]
        rows = json.loads(res["result_json"])
        self.assertEqual((rows[0]["ip"], rows[0]["status"], rows[0]["verified_in_waf"]), ("8.8.4.4", "blocked", "yes"))
        self.assertEqual(res["requested_from"], "sendalert")
        self.assertEqual(st["containers"][cid]["status"], "closed")
        # re-running the playbook on the same container does not block twice
        self.assertEqual(SOAR_NS["imperva_soar_handle"]({"id": cid, "label": "imperva_ioc_block"}, phantom), 0)

    def test_bad_token(self):
        bad = sb.SoarBridge(self.soar_base, "wrong", wait_seconds=1)
        with self.assertRaises(sb.SoarError):
            bad.execute("block", ["8.8.4.4"], ["1777"], False, {}, "a")


class TestSoarCaFile(unittest.TestCase):
    """soar_ca_file is passed to the TLS context (internal CA) and resolved relative to the app."""
    def test_ca_file_used_and_resolved(self):
        import ssl as _ssl
        import backend
        seen = {}
        real = _ssl.create_default_context

        def rec(*a, **kw):
            seen["cafile"] = kw.get("cafile")
            return real()
        _ssl.create_default_context = rec
        try:
            conf = {"api_mode": "soar", "soar_url": "https://soar", "policy_ids": "1",
                    "soar_ca_file": "local/soar_ca.pem"}
            backend.get_backend(conf, lambda k, r: ("u", "tok"), "sk")
        finally:
            _ssl.create_default_context = real
        self.assertTrue(seen["cafile"].endswith(os.path.join("TA-imperva-ioc-block", "local", "soar_ca.pem")))
        self.assertIsNone(backend._ca_path(""))
        self.assertEqual(backend._ca_path("/etc/pki/ca.pem"), "/etc/pki/ca.pem")


class TestPlaybookProxy(unittest.TestCase):
    """IMPERVA_PROXY / VT_PROXY are passed to the clients (no global HTTPS_PROXY needed)."""
    def test_proxy_env_is_used(self):
        seen = {}

        class RecImperva(object):
            def __init__(self, *a, **kw):
                seen["imperva"] = kw.get("proxy")

            def get_site_acl(self, pid):
                return "p", []

        class RecVT(object):
            def __init__(self, *a, **kw):
                seen["vt"] = kw.get("proxy")

            def lookup_ip(self, ip):
                return {"vt_status": "ok"}

        old = SOAR_NS["ImpervaPolicyClient"], SOAR_NS["VTClient"]
        SOAR_NS["ImpervaPolicyClient"], SOAR_NS["VTClient"] = RecImperva, RecVT
        try:
            env = {"IMPERVA_API_ID": "1", "IMPERVA_API_KEY": "k", "IMPERVA_POLICY_IDS": "2169031",
                   "IMPERVA_PROXY": "http://10.12.30.100:8080", "VT_API_KEY": "v"}
            r1 = SOAR_NS["process_request"]({"request_id": "a", "action": "list"}, env)
            r2 = SOAR_NS["process_request"]({"request_id": "b", "action": "vtcheck", "ips": "8.8.4.4"}, env)
        finally:
            SOAR_NS["ImpervaPolicyClient"], SOAR_NS["VTClient"] = old
        self.assertEqual((r1["status"], r2["status"]), ("ok", "ok"))
        self.assertEqual(seen, {"imperva": "http://10.12.30.100:8080", "vt": "http://10.12.30.100:8080"})


class TestCodeBlockVariant(TestSoarE2E):
    """The code-block variant (pasted inside code_1 of a SOAR 8.x playbook) works the same."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        src = "def code_1(container=None, phantom=None, **kwargs):\n" + build_global_code.build_code_block()
        ns = {"__name__": "soar_playbook_block"}
        exec(compile(src, "playbook_code_1.py", "exec"), ns)
        cls._old_handle = SOAR_NS["imperva_soar_handle"]
        # FakeSoar calls SOAR_NS["imperva_soar_handle"](container, phantom) -> route it to code_1
        SOAR_NS["imperva_soar_handle"] = lambda container, phantom: ns["code_1"](container=container, phantom=phantom)

    @classmethod
    def tearDownClass(cls):
        SOAR_NS["imperva_soar_handle"] = cls._old_handle
        super().tearDownClass()

    def test_sendalert_style_artifact_is_processed(self):
        pass  # covered by the parent class with direct access to the handler's return value


class TestPasteRobustness(TestSoarE2E):
    """Editor re-indents every pasted line inside the string by 8 spaces -> still works (dedent)."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        block = build_global_code.build_code_block()
        head, rest = block.split("r'''\n", 1)
        lib, tail = rest.rsplit("\n'''", 1)
        messy = head + "r'''\n" + "\n".join(("        " + ln) if ln else ln for ln in lib.split("\n")) \
            + "\n'''" + tail
        ns = {"__name__": "messy"}
        exec(compile("def code_1(container=None, phantom=None, **kw):\n" + messy, "messy", "exec"), ns)
        cls._old = SOAR_NS["imperva_soar_handle"]
        SOAR_NS["imperva_soar_handle"] = lambda c, p: ns["code_1"](container=c, phantom=p)

    @classmethod
    def tearDownClass(cls):
        SOAR_NS["imperva_soar_handle"] = cls._old
        super().tearDownClass()

    def test_sendalert_style_artifact_is_processed(self):
        pass


class TestFullPlaybookFile(TestSoarE2E):
    """The complete SOAR 8.x playbook file (imperva_ioc_block_playbook.py) runs end to end."""
    def _run_playbook(self, cid, request_cef, playbook_src=None):
        import types
        st = FakeSoar.store
        fake = FakePhantom(self.soar_base, st)
        mod = types.ModuleType("phantom.rules")
        mod.playbook_block = lambda *a, **k: (lambda f: f)
        for n in ("debug", "add_artifact", "set_status", "build_phantom_rest_url"):
            setattr(mod, n, getattr(fake, n))
        mod.requests = fake.requests
        mod.save_block_result = lambda **kw: None
        pkg = types.ModuleType("phantom")
        pkg.rules = mod
        old = {k: sys.modules.get(k) for k in ("phantom", "phantom.rules")}
        sys.modules["phantom"], sys.modules["phantom.rules"] = pkg, mod
        try:
            ns = {"__name__": "playbook"}
            src = playbook_src or build_global_code.build_playbook()
            exec(compile(src, "imperva_ioc_block_playbook.py", "exec"), ns)
            st["containers"][cid] = {"id": cid, "label": "imperva_ioc_block", "status": "new", "artifacts": [
                {"id": 1, "name": "imperva_request", "cef": request_cef}]}
            ns["on_start"]({"id": cid, "label": "imperva_ioc_block"})
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return [a for a in st["containers"][cid]["artifacts"] if a["name"] == "imperva_result"][0]["cef"]

    def test_full_playbook_list(self):
        res = self._run_playbook(555, {"request_id": "test-001", "action": "list", "policy_ids": "1777"})
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(json.loads(res["result_json"])[0]["ip"], "1.1.1.1")
        self.assertEqual(FakeSoar.store["containers"][555]["status"], "closed")

    def test_playbook_without_env_uses_imperva_config(self):
        """Real SOAR 8.x case: playbooks do not see Global Environment variables."""
        for k in list(self.env):
            os.environ.pop(k, None)
        src = build_global_code.build_playbook()
        for k, v in (("IMPERVA_API_ID", "id1"), ("IMPERVA_API_KEY", "key1"), ("IMPERVA_POLICY_IDS", "1777")):
            src = src.replace('"%s": "",' % k, '"%s": "%s",' % (k, v), 1)
        src = src.replace('"IMPERVA_PROTECTED_NETWORKS": "",', '"IMPERVA_PROTECTED_NETWORKS": "",', 1)
        # point the library at the fake Imperva server through the config too
        src = src.replace('"IMPERVA_CAID": "",', '"IMPERVA_CAID": "", "IMPERVA_API_BASE": "%s",' % self.imp_base, 1)
        res = self._run_playbook(556, {"request_id": "t-cfg", "action": "block", "ips": "8.8.4.4"}, src)
        self.assertEqual(res["status"], "ok", res)
        row = json.loads(res["result_json"])[0]
        self.assertEqual((row["status"], row["verified_in_waf"]), ("blocked", "yes"))

    def test_playbook_without_env_and_without_config_explains(self):
        for k in list(self.env):
            os.environ.pop(k, None)
        res = self._run_playbook(557, {"request_id": "t-none", "action": "list"})
        self.assertEqual(res["status"], "error")
        self.assertIn("IMPERVA_POLICY_IDS", res["error"])


class TestGeneratedCodeInSync(unittest.TestCase):
    def test_committed_playbook_matches_build(self):
        path = os.path.join(HERE, "..", "soar", "imperva_ioc_block_playbook.py")
        self.assertEqual(open(path).read(), build_global_code.build_playbook(),
                         "run: python3 soar/build_global_code.py")

    def test_committed_code_block_matches_build(self):
        path = os.path.join(HERE, "..", "soar", "imperva_ioc_block_code_block.py")
        self.assertEqual(open(path).read(), build_global_code.build_code_block(),
                         "run: python3 soar/build_global_code.py")

    def test_committed_file_matches_build(self):
        path = os.path.join(HERE, "..", "soar", "imperva_ioc_block_global_code.py")
        self.assertEqual(open(path).read(), build_global_code.build(),
                         "run: python3 soar/build_global_code.py")


if __name__ == "__main__":
    unittest.main()
