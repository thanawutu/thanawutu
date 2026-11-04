"""End-to-end test of ImpervaPolicyClient against a local fake Policies API v2."""
import copy
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "TA-imperva-ioc-block", "bin"))
import imperva_lib as il  # noqa: E402

POLICY = {
    "id": 1777, "name": "SOC IOC Blocklist", "description": "managed by Splunk", "enabled": True,
    "accountId": 42, "policyType": "ACL", "isMarkedAsDefault": False,
    "policySettings": [
        {"settingsAction": "BLOCK", "policySettingType": "GEO", "data": {"geo": {"countries": ["KP"]}}},
        {"settingsAction": "BLOCK", "policySettingType": "IP", "data": {"ips": ["1.1.1.1"]},
         "policyDataExceptions": [{"data": [{"exceptionType": "URL", "values": ["/health"]}], "comment": "keep"}]},
    ],
    "defaultPolicyConfig": [{"accountId": 42, "assetType": "WEBSITE", "policyId": 1777}],
}


class FakeImperva(BaseHTTPRequestHandler):
    store = {}
    puts = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        return self.headers.get("x-API-Id") == "id1" and self.headers.get("x-API-Key") == "key1"

    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"isError": True})
        pid = self.path.split("?")[0].rsplit("/", 1)[-1]
        if pid not in self.store:
            return self._send(404, {"isError": True})
        self._send(200, {"value": self.store[pid], "isError": False})

    def do_PUT(self):
        if not self._auth_ok():
            return self._send(401, {"isError": True})
        pid = self.path.split("?")[0].rsplit("/", 1)[-1]
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeImperva.puts.append(body)
        new = dict(body, id=int(pid), isMarkedAsDefault=False)
        self.store[pid] = new
        self._send(200, {"value": new, "isError": False})


class TestPolicyV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeImperva)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeImperva.store = {"1777": copy.deepcopy(POLICY),
                             "9": dict(copy.deepcopy(POLICY), id=9, policyType="WAF_RULES")}
        FakeImperva.puts = []
        self.c = il.ImpervaPolicyClient("id1", "key1", base_url=self.base)

    def test_read(self):
        self.assertEqual(self.c.get_site_acl("1777"), ("SOC IOC Blocklist", ["1.1.1.1"]))

    def test_block_verify_and_keep_other_settings(self):
        res = il.apply_action(self.c, "1777", ["8.8.4.4", "1.1.1.1"], "block")
        self.assertEqual(res["changed"], ["8.8.4.4"])
        self.assertEqual(res["unchanged"], ["1.1.1.1"])
        self.assertEqual(res["not_applied"], [])
        put = FakeImperva.puts[-1]
        self.assertNotIn("id", put)
        self.assertNotIn("isMarkedAsDefault", put)
        geo = [s for s in put["policySettings"] if s["policySettingType"] == "GEO"]
        ip = [s for s in put["policySettings"] if s["policySettingType"] == "IP"][0]
        self.assertEqual(geo[0]["data"]["geo"]["countries"], ["KP"])
        self.assertEqual(ip["data"]["ips"], ["1.1.1.1", "8.8.4.4"])
        self.assertEqual(ip["policyDataExceptions"][0]["comment"], "keep")
        self.assertEqual(put["defaultPolicyConfig"], POLICY["defaultPolicyConfig"])

    def test_unblock_last_ip_drops_setting(self):
        res = il.apply_action(self.c, "1777", ["1.1.1.1"], "unblock")
        self.assertEqual(res["changed"], ["1.1.1.1"])
        types = [s["policySettingType"] for s in FakeImperva.puts[-1]["policySettings"]]
        self.assertEqual(types, ["GEO"])
        self.assertEqual(self.c.get_blacklist("1777"), [])

    def test_create_ip_setting_when_missing(self):
        FakeImperva.store["1777"]["policySettings"] = []
        il.apply_action(self.c, "1777", ["8.8.4.4"], "block")
        self.assertEqual(self.c.get_blacklist("1777"), ["8.8.4.4"])

    def test_refuses_non_acl_policy(self):
        with self.assertRaises(il.ImpervaError):
            il.apply_action(self.c, "9", ["8.8.4.4"], "block")
        self.assertEqual(FakeImperva.puts, [])

    def test_bad_key(self):
        bad = il.ImpervaPolicyClient("id1", "wrong", base_url=self.base)
        with self.assertRaises(il.ImpervaError):
            bad.get_blacklist("1777")

    def test_make_client(self):
        c, ids, mode = il.make_client({"policy_ids": "1777, 1778"}, "a", "b")
        self.assertEqual((type(c).__name__, ids, mode), ("ImpervaPolicyClient", ["1777", "1778"], "v2_policy"))
        c, ids, mode = il.make_client({"api_mode": "v1_site", "site_ids": "5"}, "a", "b")
        self.assertEqual((type(c).__name__, ids), ("ImpervaClient", ["5"]))
        with self.assertRaises(il.ImpervaError):
            il.make_client({}, "a", "b")


if __name__ == "__main__":
    unittest.main()
