"""Checking an IP against every WAF policy of the account."""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))
import imperva_lib as il  # noqa: E402
import test_soar_e2e as e2e  # noqa: E402
from test_policy_v2 import POLICY, FakeImperva  # noqa: E402

POLICIES = [
    {"id": 1364280, "name": "Block DDOS Attack 2025", "policyType": "ACL", "enabled": True,
     "policySettings": [{"settingsAction": "BLOCK", "policySettingType": "IP", "data": {"ips": ["5.6.7.0/24", "9.9.9.1-9.9.9.9"]}},
                        {"settingsAction": "BLOCK", "policySettingType": "GEO", "data": {"geo": {"countries": ["KP"]}},
                         "policyDataExceptions": [{"data": [{"exceptionType": "IP", "values": ["77.77.77.77"]}]}]}]},
    {"id": 2168965, "name": "Allow IP DC MY", "policyType": "WHITELIST", "enabled": True,
     "policySettings": [{"settingsAction": "ALLOW", "policySettingType": "IP", "data": {"ips": ["20.20.20.20"]}}]},
    {"id": 1819039, "name": "API-Block-IOCS", "policyType": "ACL", "enabled": False,
     "policySettings": [{"settingsAction": "BLOCK", "policySettingType": "IP", "data": {"ips": ["30.30.30.30"]}}]},
    {"id": 2169031, "name": "BlockIOCsFromSplunk", "policyType": "ACL", "enabled": False,
     "policySettings": [{"settingsAction": "BLOCK", "policySettingType": "IP", "data": {"ips": ["40.40.40.40"]}}]},
]


class TestVerdict(unittest.TestCase):
    def setUp(self):
        self.e = il.policy_ip_entries(POLICIES)

    def v(self, ip):
        return il.policy_verdict(il.match_policies(ip, self.e), ["2169031"])

    def test_cases(self):
        self.assertEqual(self.v("5.6.7.8")[0], "BLOCKED_ELSEWHERE")          # CIDR
        self.assertEqual(self.v("9.9.9.5")[0], "BLOCKED_ELSEWHERE")          # range a-b
        self.assertEqual(self.v("20.20.20.20")[0], "ALLOWLISTED")            # allowlist policy
        self.assertEqual(self.v("77.77.77.77")[0], "ALLOWLISTED")              # IP exception of a rule
        v, texts = self.v("30.30.30.30")                                     # only in a disabled policy
        self.assertEqual(v, "NONE")
        self.assertIn("[disabled]", texts[0])
        self.assertEqual(self.v("1.1.1.1"), ("NONE", []))
        self.assertIn("Block DDOS Attack 2025", self.v("5.6.7.8")[1][0])

    def test_allowlist_conflicts(self):
        c = il.allowlist_conflicts(self.e, ["20.20.20.20", "5.6.7.8", "1.1.1.1"])
        self.assertEqual(list(c), ["20.20.20.20"])
        self.assertIn("Allow IP DC MY", c["20.20.20.20"])


class TestSoarAllPolicies(e2e.TestSoarE2E):
    def setUp(self):
        super().setUp()
        FakeImperva.store.update({str(p["id"]): copy.deepcopy(p) for p in POLICIES})
        FakeImperva.store["1777"] = copy.deepcopy(POLICY)

    def test_soar_refuses_ip_allowed_by_another_policy(self):
        rows = self.bridge.execute("block", ["20.20.20.20", "8.8.8.4"], ["1777"], False, {}, "a")
        by = {r["ip"]: r for r in rows}
        self.assertEqual(by["20.20.20.20"]["status"], "rejected")
        self.assertIn("allowed by WAF policy", by["20.20.20.20"]["detail"])
        self.assertEqual(by["8.8.8.4"]["status"], "blocked")

    def test_policy_entries_via_soar(self):
        rows = self.bridge.policy_entries()
        self.assertIn({"cidr": "20.20.20.20", "policy_id": "2168965", "action": "ALLOW"},
                      [{k: r[k] for k in ("cidr", "policy_id", "action")} for r in rows])
        self.assertEqual(e2e.FakeSoar.store["containers"], {})   # read-only container removed


if __name__ == "__main__":
    unittest.main()
