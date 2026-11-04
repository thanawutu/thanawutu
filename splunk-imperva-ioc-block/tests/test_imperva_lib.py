import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "TA-imperva-ioc-block", "bin"))
import imperva_lib as il  # noqa: E402


class FakeClient(object):
    def __init__(self, current):
        self.current = list(current)
        self.writes = []

    def get_blacklist(self, site_id):
        return list(self.current)

    def set_blacklist(self, site_id, ips):
        self.writes.append((site_id, list(ips)))
        self.current = list(ips)


class TestParse(unittest.TestCase):
    def test_split_and_dedupe(self):
        self.assertEqual(il.parse_ip_list(' 8.8.8.8, "1.1.1.1"\n8.8.8.8;9.9.9.9 '),
                         ["8.8.8.8", "1.1.1.1", "9.9.9.9"])

    def test_empty(self):
        self.assertEqual(il.parse_ip_list(None), [])
        self.assertEqual(il.parse_ip_list(""), [])


class TestValidate(unittest.TestCase):
    def test_rules(self):
        ok, bad = il.validate_ips(
            ["8.8.8.8", "10.0.0.1", "127.0.0.1", "abc", "1.2.3.0/16", "1.2.3.0/24",
             "203.0.113.5", "45.33.32.156", "2606:4700::1111", "224.0.0.1"],
            protected_networks=["45.33.32.0/24"])
        self.assertEqual(ok, ["8.8.8.8", "1.2.3.0/24", "2606:4700::1111"])
        reasons = dict(bad)
        self.assertIn("non-public", reasons["10.0.0.1"])
        self.assertIn("non-public", reasons["127.0.0.1"])
        self.assertIn("non-public", reasons["203.0.113.5"])
        self.assertIn("non-public", reasons["224.0.0.1"])
        self.assertIn("invalid", reasons["abc"])
        self.assertIn("wider", reasons["1.2.3.0/16"])
        self.assertIn("protected", reasons["45.33.32.156"])

    def test_host_cidr_normalised(self):
        ok, _ = il.validate_ips(["8.8.8.8/32"])
        self.assertEqual(ok, ["8.8.8.8"])


class TestApply(unittest.TestCase):
    def test_block_merges_not_overwrites(self):
        c = FakeClient(["1.1.1.1"])
        res = il.apply_action(c, "123", ["8.8.8.8", "1.1.1.1"], "block")
        self.assertEqual(c.current, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(res["changed"], ["8.8.8.8"])
        self.assertEqual(res["unchanged"], ["1.1.1.1"])

    def test_idempotent_no_write(self):
        c = FakeClient(["8.8.8.8"])
        il.apply_action(c, "123", ["8.8.8.8"], "block")
        self.assertEqual(c.writes, [])

    def test_dry_run_no_write(self):
        c = FakeClient([])
        res = il.apply_action(c, "123", ["8.8.8.8"], "block", dry_run=True)
        self.assertEqual(c.writes, [])
        self.assertEqual(res["changed"], ["8.8.8.8"])

    def test_unblock(self):
        c = FakeClient(["1.1.1.1", "8.8.8.8"])
        res = il.apply_action(c, "123", ["8.8.8.8", "9.9.9.9"], "unblock")
        self.assertEqual(c.current, ["1.1.1.1"])
        self.assertEqual(res["changed"], ["8.8.8.8"])
        self.assertEqual(res["unchanged"], ["9.9.9.9"])


if __name__ == "__main__":
    unittest.main()
