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


class TestSoarE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        cls.imp, cls.imp_base = _serve(FakeImperva)
        cls.soar, cls.soar_base = _serve(FakeSoar, threading_server=True)

    @classmethod
    def tearDownClass(cls):
        cls.imp.shutdown()
        cls.soar.shutdown()

    def setUp(self):
        FakeImperva.store = {"1777": copy.deepcopy(POLICY)}
        FakeImperva.puts = []
        FakeSoar.store.update(containers={}, fail_playbook=False, run_playbook=True)
        self.env = {"IMPERVA_API_ID": "id1", "IMPERVA_API_KEY": "key1", "IMPERVA_POLICY_IDS": "1777",
                    "IMPERVA_API_BASE": self.imp_base, "IMPERVA_PROTECTED_NETWORKS": "45.33.32.0/24"}
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
        self.assertEqual((req["requested_by"], req["incident_no"]), ("alice", "INC-1"))

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

    def test_bad_token(self):
        bad = sb.SoarBridge(self.soar_base, "wrong", wait_seconds=1)
        with self.assertRaises(sb.SoarError):
            bad.execute("block", ["8.8.4.4"], ["1777"], False, {}, "a")


class TestGeneratedCodeInSync(unittest.TestCase):
    def test_committed_file_matches_build(self):
        path = os.path.join(HERE, "..", "soar", "imperva_ioc_block_global_code.py")
        self.assertEqual(open(path).read(), build_global_code.build(),
                         "run: python3 soar/build_global_code.py")


if __name__ == "__main__":
    unittest.main()
