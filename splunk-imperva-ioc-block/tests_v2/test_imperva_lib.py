import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "TA-imperva-ioc-block-v2", "bin"))
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


class LyingClient(FakeClient):
    """WAF accepts the write but the IP does not show up on re-read."""
    def set_blacklist(self, site_id, ips):
        self.writes.append((site_id, list(ips)))


class TestVerify(unittest.TestCase):
    def test_verified(self):
        c = FakeClient([])
        res = il.apply_action(c, "1", ["8.8.8.8"], "block")
        self.assertEqual(res["changed"], ["8.8.8.8"])
        self.assertEqual(res["not_applied"], [])

    def test_not_confirmed_on_reread(self):
        c = LyingClient([])
        res = il.apply_action(c, "1", ["8.8.8.8"], "block")
        self.assertEqual(res["changed"], [])
        self.assertEqual(res["not_applied"], ["8.8.8.8"])


class TestRegistry(unittest.TestCase):
    META = {"threat_actor": "APT-X", "incident_no": "INC-1", "comment": "c", "reason": "r"}

    def test_block_creates_record(self):
        d = il.build_registry_doc(None, "k", "1", "8.8.8.8", "block", "blocked", "bob", 100, self.META)
        self.assertEqual((d["status"], d["blocked_at"], d["threat_actor"], d["incident_no"]),
                         ("blocked", 100, "APT-X", "INC-1"))

    def test_no_change_keeps_original(self):
        old = {"_key": "k", "status": "blocked", "blocked_at": 50}
        self.assertIsNone(il.build_registry_doc(old, "k", "1", "8.8.8.8", "block", "no_change", "bob", 100, self.META))

    def test_no_change_registers_outside_block(self):
        d = il.build_registry_doc(None, "k", "1", "8.8.8.8", "block", "no_change", "bob", 100, self.META)
        self.assertIn("already in WAF", d["source"])

    def test_unblock_keeps_history(self):
        old = {"_key": "k", "status": "blocked", "blocked_at": 50, "threat_actor": "APT-X", "_user": "nobody"}
        d = il.build_registry_doc(old, "k", "1", "8.8.8.8", "unblock", "unblocked", "amy", 100, {"reason": "FP"})
        self.assertEqual((d["status"], d["blocked_at"], d["threat_actor"], d["unblocked_by"]),
                         ("unblocked", 50, "APT-X", "amy"))
        self.assertNotIn("_user", d)

    def test_errors_not_stored(self):
        self.assertIsNone(il.build_registry_doc(None, "k", "1", "8.8.8.8", "block", "error", "b", 1, {}))


class TestImpervaRetry(unittest.TestCase):
    def test_retries_on_429_then_succeeds(self):
        import imperva_lib as il
        calls, sleeps = [], []

        def fn():
            calls.append(1)
            if len(calls) < 3:
                raise il.ImpervaRateLimited("429", retry_after=7 if len(calls) == 1 else None)
            return {"ok": True}
        self.assertEqual(il._with_retry(fn, waits=(5, 15, 30), _sleep=sleeps.append), {"ok": True})
        self.assertEqual(sleeps, [7, 15])

    def test_gives_up_and_other_errors_not_retried(self):
        import imperva_lib as il

        def limited():
            raise il.ImpervaRateLimited("429")
        with self.assertRaises(il.ImpervaRateLimited):
            il._with_retry(limited, waits=(1, 1), _sleep=lambda s: None)
        n = []

        def bad():
            n.append(1)
            raise il.ImpervaError("400")
        with self.assertRaises(il.ImpervaError):
            il._with_retry(bad, waits=(1, 1), _sleep=lambda s: None)
        self.assertEqual(n, [1])


if __name__ == "__main__":
    unittest.main()
