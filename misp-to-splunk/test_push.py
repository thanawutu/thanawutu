"""ทดสอบ logic การวางแผนและการรวมรายการ โดยไม่ต่อ API จริง:  python3 -m unittest -v test_push"""
import configparser
import unittest

import push_blocklists as p


def ioc(v, t="ip", e="1"):
    return p.Ioc(v, t, e, "test event", 0)


class PlanTest(unittest.TestCase):
    def test_add_remove_keep(self):
        owned = {"1.1.1.1": {}, "2.2.2.2": {}}
        plan = p.make_plan("x", [ioc("2.2.2.2"), ioc("3.3.3.3")], owned, 0)
        self.assertEqual([i.value for i in plan.add], ["3.3.3.3"])
        self.assertEqual(plan.remove, ["1.1.1.1"])
        self.assertEqual(plan.keep, 1)

    def test_cap_keeps_newest(self):
        plan = p.make_plan("x", [ioc("a"), ioc("b"), ioc("c")], {}, 2)
        self.assertEqual([i.value for i in plan.add], ["a", "b"])
        self.assertEqual(plan.dropped_over_cap, 1)

    def test_dedup_case_insensitive(self):
        plan = p.make_plan("x", [ioc("AB", "sha1"), ioc("ab", "sha1")], {}, 0)
        self.assertEqual(len(plan.add), 1)


class FakeResp:
    def __init__(self, body):
        self.body, self.status_code, self.content = body, 200, b"x"

    def json(self):
        return self.body

    def raise_for_status(self):
        pass


class FakeSession:
    def __init__(self, current):
        self.current, self.sent = current, None

    def post(self, url, data=None, timeout=None):
        if url.endswith("/sites/status"):
            return FakeResp({"res": 0, "security": {"acls": {"rules": [
                {"id": "api.acl.blacklisted_ips", "ips": self.current}]}}})
        self.sent = data
        return FakeResp({"res": 0})


class ImpervaTest(unittest.TestCase):
    def test_keeps_manual_ips_and_replaces_ours(self):
        cp = configparser.ConfigParser()
        cp.read_dict({"imperva": {"site_ids": "42", "api_id": "x", "api_key": "y"}})
        ad = p.ImpervaWaf(cp["imperva"], True)
        ad.s = FakeSession(["9.9.9.9", "1.1.1.1"])          # 9.9.9.9 = SOC ใส่เอง, 1.1.1.1 = ของเราเดิม
        owned = {"1.1.1.1": {}}
        plan = p.make_plan("imperva", [ioc("3.3.3.3")], owned, 0)
        ad.apply(plan, owned)
        self.assertEqual(ad.s.sent["ips"], "3.3.3.3,9.9.9.9")
        self.assertEqual(ad.s.sent["rule_id"], "api.acl.blacklisted_ips")


class RoutingTest(unittest.TestCase):
    def test_wants(self):
        cp = configparser.ConfigParser()
        cp.read_dict({"sentinelone": {"url": "https://s1", "hash_types": "sha1,sha256"},
                      "proofpoint": {"mode": "csv"}})
        s1, pp = p.SentinelOne(cp["sentinelone"], True), p.Proofpoint(cp["proofpoint"], True)
        self.assertTrue(s1.wants(ioc("x", "sha256")))
        self.assertFalse(s1.wants(ioc("x", "md5")))
        self.assertTrue(pp.wants(ioc("a@b.c", "email")))
        self.assertTrue(pp.wants(ioc("evil.example", "domain")))
        self.assertFalse(pp.wants(ioc("1.2.3.4", "ip")))


if __name__ == "__main__":
    unittest.main()
