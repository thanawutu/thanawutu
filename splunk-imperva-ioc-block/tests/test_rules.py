"""Detection rules (KV store imperva_ioc_rules): matching, defaults, impervarules command."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))

import ioc_rules as ir  # noqa: E402


class TestRuleLogic(unittest.TestCase):
    def test_wildcards(self):
        self.assertTrue(ir.wildcard_match("*WAF*", "[ORG]-WAF-DDoS Behavior Detection"))
        self.assertTrue(ir.wildcard_match("*waf*", "Imperva WAF - x"))           # case-insensitive
        self.assertFalse(ir.wildcard_match("WAF*", "Imperva WAF - x"))
        self.assertTrue(ir.wildcard_match("Exact (name) [1]", "exact (name) [1]"))  # regex chars literal
        self.assertFalse(ir.wildcard_match("a.c", "abc"))

    def test_defaults_include_waf_exclude_404(self):
        rules = ir.real_rules(ir.default_docs("admin", 1))
        self.assertEqual(ir.verdict("ORG-Partner -WAF", rules), (True, "included by *WAF*"))
        used, why = ir.verdict("WAF Monitor Error code 404", rules)
        self.assertFalse(used)
        self.assertIn("excluded", why)
        self.assertEqual(ir.verdict("Endpoint - Malware", rules), (False, "no include rule"))
        self.assertEqual(ir.search_terms(rules, "include"), ["*WAF*"])
        self.assertEqual(ir.search_terms(rules, "exclude"), ["*WAF Monitor Error code 404*"])

    def test_disabled_and_empty(self):
        rules = [{"_key": "a", "pattern": "*WAF*", "mode": "include", "enabled": "0"}]
        self.assertEqual(ir.search_terms(rules, "include"), [ir.NO_RULE])
        self.assertEqual(ir.search_terms([], "exclude"), [ir.NO_RULE])
        self.assertFalse(ir.verdict("x WAF", rules)[0])

    def test_clean_pattern(self):
        self.assertEqual(ir.clean_pattern(' "*WAF*"\n'), "*WAF*")
        self.assertEqual(ir.rule_key("*WAF*", "include"), ir.rule_key("*waf*", "include"))
        self.assertNotEqual(ir.rule_key("*WAF*", "include"), ir.rule_key("*WAF*", "exclude"))


class TestRulesCommand(unittest.TestCase):
    def setUp(self):
        import impervarules as c
        self.c, self.store, self.out, self.logs = c, {}, {}, []
        c.kv_list = lambda k, col: [dict(v) for v in self.store.values()]
        c.kv_upsert = lambda k, docs, col: [self.store.__setitem__(x["_key"], dict(x)) for x in docs]
        c.kv_delete = lambda k, key, col: self.store.pop(key)
        c.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "alice"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: self.logs.append(a[0] % a[1:]),
                                                 "error": lambda s, *a: None})()

    def run_(self, *argv):
        self.out.clear()
        sys.argv = ["impervarules.py"] + list(argv)
        self.c.main()
        return self.out

    def test_seed_once_then_manage(self):
        rows = self.run_()["rows"]
        self.assertEqual([(r["pattern"], r["mode"], r["enabled"]) for r in rows],
                         [("*WAF*", "include", "on"), ("*WAF Monitor Error code 404*", "exclude", "on")])
        self.assertIn(ir.SEED_KEY, self.store)
        self.assertEqual(self.run_("action=terms", "mode=include")["rows"], [{"search_name": "*WAF*"}])

        r = self.run_("action=add", 'pattern="Bot', '-', 'Credential', 'Stuffing"', "mode=include",
                      'note="login', 'API"')["rows"][0]
        self.assertEqual((r["action"], r["status"], r["comment"]),
                         ("rule_add", "added", "include Bot - Credential Stuffing"))
        self.assertIn("action=rule_add", self.logs[-1])
        terms = [x["search_name"] for x in self.run_("action=terms", "mode=include")["rows"]]
        self.assertEqual(terms, ["*WAF*", "Bot - Credential Stuffing"])

        key = ir.rule_key("*WAF*", "include")
        self.assertEqual(self.run_("action=disable", "key=" + key)["rows"][0]["status"], "disabled")
        self.assertEqual([x["search_name"] for x in self.run_("action=terms", "mode=include")["rows"]],
                         ["Bot - Credential Stuffing"])
        self.assertEqual(self.run_("action=enable", "key=" + key)["rows"][0]["status"], "enabled")

        # removing every rule must not bring the defaults back
        for k in [x["key"] for x in self.run_()["rows"]]:
            self.assertEqual(self.run_("action=remove", "key=" + k)["rows"][0]["status"], "removed")
        self.assertEqual(self.run_()["rows"], [])
        self.assertEqual(self.run_("action=terms", "mode=include")["rows"], [{"search_name": ir.NO_RULE}])

    def test_errors(self):
        self.assertIn("pattern is empty", self.run_("action=add", "pattern=-")["err"])
        self.assertIn("mode must be", self.run_("action=add", "pattern=x", "mode=both")["err"])
        self.assertIn("not found", self.run_("action=remove", "key=nope")["err"])
        self.assertIn("action must be", self.run_("action=drop")["err"])


class TestRegistryUnblock(unittest.TestCase):
    def test_unblock_of_ip_already_gone_closes_registry(self):
        import imperva_lib as il
        old = {"_key": "k", "site_id": "1", "ip": "1.2.3.4", "status": "blocked", "_user": "nobody"}
        doc = il.build_registry_doc(old, "k", "1", "1.2.3.4", "unblock", "no_change", "bob", 9,
                                    {"incident_no": "ITHM 1", "reason": "gone"})
        self.assertEqual((doc["status"], doc["unblocked_by"], doc["unblock_reason"]), ("unblocked", "bob", "gone"))
        self.assertIsNone(il.build_registry_doc(None, "k", "1", "1.2.3.4", "unblock", "no_change", "b", 9, {}))


class TestRuleCheckCommand(unittest.TestCase):
    def test_annotate(self):
        import impervarulecheck as c
        out = {}
        c.kv_list = lambda k, col: []          # empty collection -> defaults
        c.si.getOrganizedResults = lambda: ([{"search_name": "X WAF y", "count": "3"},
                                             {"search_name": "WAF Monitor Error code 404"}], None, {"sessionKey": "k"})
        c.si.outputResults = lambda r: out.__setitem__("rows", r)
        sys.argv = ["impervarulecheck.py", "field=search_name"]
        c.main()
        self.assertEqual([r["rule_used"] for r in out["rows"]], ["yes", "no"])


if __name__ == "__main__":
    unittest.main()
