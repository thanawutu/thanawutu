"""V2 Auto unblock: plan (pure logic) and the impervaautounblock command."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))

import auto_unblock as au  # noqa: E402

DAY = 86400
T = 1_800_000_000.0           # "now"
OWN = ["2169031"]


def E(cidr, pid="2169031", action="BLOCK", kind="setting", enabled=True, name=None):
    return {"cidr": cidr, "policy_id": pid, "policy_name": name or ("BlockIOCsFromSplunk" if pid == "2169031" else "Other %s" % pid),
            "policy_type": "ACL", "action": action, "kind": kind, "enabled": enabled}


ENTRIES = [
    E("203.0.113.10", enabled=False),                 # own policy, disabled -> still handled
    E("54.245.198.114"),                              # own, AWS
    E("198.51.100.0/24", pid="1000001"),              # other enabled policy, CIDR
    E("192.0.2.77", pid="1000001"),                   # other enabled policy
    E("192.0.2.88", pid="1000009", enabled=False),    # other DISABLED policy -> ignored
    E("192.0.2.99", pid="1000001", action="ALLOW"),   # allow rule -> never touched
    E("192.0.2.98", pid="1000001", kind="exception", action="EXCEPTION(BLOCK WAF)"),
    E("192.0.2.1-192.0.2.9", pid="1000001"),          # range -> not handled
]
CLOUD = lambda o: ("cloud", o) if o and "Amazon" in o else (("shared", o) if o and "Wireless" in o else None)  # noqa: E731


def plan(states=None, seen=None, registry=None, owners=None, now=T, entries=ENTRIES):
    items, new = au.plan(now, entries, OWN, states or {}, seen or {}, registry or {},
                         owners or {"54.245.198.114": "Amazon.com, Inc."}, CLOUD)
    return dict((i["cidr"], i) for i in items), new


def st(cidr, pid="2169031", first=T, rule="default"):
    return {au.entry_key(pid, cidr): {"_key": au.entry_key(pid, cidr), "policy_id": pid, "cidr": cidr,
                                      "first_listed": first, "rule": rule}}


class TestPlan(unittest.TestCase):
    def test_candidates(self):
        items, new = plan()
        self.assertEqual(sorted(items), ["192.0.2.77", "198.51.100.0/24", "203.0.113.10", "54.245.198.114"])
        self.assertEqual(len(new), 4)
        self.assertTrue(all(n["first_listed"] == int(T) for n in new))      # countdown starts today

    def test_first_day_nothing_due(self):
        items, _ = plan()
        self.assertEqual(set(i["status"] for i in items.values()), {"quiet"})
        self.assertEqual(items["54.245.198.114"]["days"], 7)                 # cloud
        self.assertEqual(items["192.0.2.77"]["days"], 60)

    def test_due_after_quiet_period_counted_from_install(self):
        states = {}
        states.update(st("54.245.198.114", first=T - 8 * DAY))
        states.update(st("192.0.2.77", "1000001", first=T - 91 * DAY))
        states.update(st("203.0.113.10", first=T - 50 * DAY))
        items, new = plan(states)
        self.assertEqual(items["54.245.198.114"]["status"], "due")
        self.assertEqual(items["192.0.2.77"]["status"], "due")
        self.assertEqual(items["203.0.113.10"]["status"], "quiet")
        self.assertEqual([n["cidr"] for n in new], ["198.51.100.0/24"])

    def test_attack_restarts_the_countdown(self):
        states = st("192.0.2.77", "1000001", first=T - 200 * DAY)
        items, _ = plan(states, seen={"192.0.2.77": T - 2 * 3600})
        self.assertEqual(items["192.0.2.77"]["status"], "attacking")
        self.assertAlmostEqual(items["192.0.2.77"]["unblock_on"], T - 2 * 3600 + 60 * DAY)
        items, _ = plan(states, seen={"192.0.2.77": T - 55 * DAY})
        self.assertEqual(items["192.0.2.77"]["status"], "soon")               # 5 days left
        items, _ = plan(states, seen={"192.0.2.77": T - 65 * DAY})
        self.assertEqual(items["192.0.2.77"]["status"], "due")

    def test_cidr_uses_requests_from_any_ip_inside(self):
        states = st("198.51.100.0/24", "1000001", first=T - 200 * DAY)
        items, _ = plan(states, seen={"198.51.100.7": T - 10 * DAY, "198.51.101.1": T})
        self.assertEqual(items["198.51.100.0/24"]["last_seen"], T - 10 * DAY)
        self.assertEqual(items["198.51.100.0/24"]["status"], "quiet")

    def test_block_date_counts_when_later(self):
        states = st("203.0.113.10", first=T - 200 * DAY)
        reg = {("2169031", "203.0.113.10"): {"blocked_at": T - 30 * DAY, "incident_no": "1000101", "comment": "scanner"}}
        items, _ = plan(states, registry=reg)
        i = items["203.0.113.10"]
        self.assertEqual((i["status"], i["ticket"], i["description"]), ("quiet", "1000101", "scanner"))
        self.assertAlmostEqual(i["unblock_on"], T + 30 * DAY)

    def test_rules_keep_and_days(self):
        states = st("192.0.2.77", "1000001", first=T - 500 * DAY, rule="keep")
        states.update(st("54.245.198.114", first=T - 10 * DAY, rule="30"))
        items, _ = plan(states)
        self.assertEqual(items["192.0.2.77"]["status"], "kept")
        self.assertEqual((items["54.245.198.114"]["days"], items["54.245.198.114"]["status"]), (30, "quiet"))

    def test_every_enabled_policy_is_handled(self):
        states = st("192.0.2.77", "1000001", first=T - 100 * DAY)        # other policy
        states.update(st("203.0.113.10", first=T - 100 * DAY))           # own policy, disabled
        items, _ = plan(states)
        self.assertEqual((items["192.0.2.77"]["status"], items["203.0.113.10"]["status"]), ("due", "due"))
        self.assertEqual(sorted(i["cidr"] for i in au.due_items(list(items.values()))), ["192.0.2.77", "203.0.113.10"])
        self.assertNotIn("managed", items["192.0.2.77"])

    def test_due_items_order_and_limit(self):
        states = {}
        for k, ip in enumerate(["192.0.2.77", "54.245.198.114", "203.0.113.10"]):
            pid = "1000001" if ip == "192.0.2.77" else "2169031"
            states.update(st(ip, pid, first=T - (300 + k) * DAY))
        items, _ = plan(states)
        due = au.due_items(sorted(items.values(), key=lambda i: i["unblock_on"]))
        self.assertEqual([i["cidr"] for i in due], ["54.245.198.114", "203.0.113.10", "192.0.2.77"])   # no limit

    def test_attacks_in_the_last_24h(self):
        items, _ = au.plan(T, ENTRIES, OWN, {}, {}, {}, {}, CLOUD,
                           {"192.0.2.77": 412, "198.51.100.7": 30, "198.51.100.9": 12, "8.8.8.8": 5})
        by = dict((i["cidr"], i["attacks_24h"]) for i in items)
        self.assertEqual((by["192.0.2.77"], by["198.51.100.0/24"], by["203.0.113.10"]), (412, 42, 0))
        items, _ = au.plan(T, ENTRIES, OWN, {}, {}, {}, {}, CLOUD)          # no hits data yet
        self.assertEqual(set(i["attacks_24h"] for i in items), {0})

    def test_shared_ip_gets_the_short_period(self):
        entries = [E("49.228.105.17", pid="1000001"), E("49.228.105.18", pid="1000001")]
        states = {}
        states.update(st("49.228.105.17", "1000001", first=T - 8 * DAY))
        states.update(st("49.228.105.18", "1000001", first=T - 8 * DAY))
        owners = {"49.228.105.17": "Advanced Wireless Network Company Limited", "49.228.105.18": "TOT Public Company Limited"}
        items, _ = plan(states, owners=owners, entries=entries)
        i = items["49.228.105.17"]
        self.assertEqual((i["short"], i["shared"], i["days"], i["status"]), ("shared", owners["49.228.105.17"], 7, "due"))
        self.assertEqual((items["49.228.105.18"]["short"], items["49.228.105.18"]["days"], items["49.228.105.18"]["status"]), ("", 60, "quiet"))
        self.assertIn("shared IP (Advanced Wireless Network Company Limited), no attack for 7 days", au.reason_text(i))

    def test_conf_shared_words_match_macro(self):
        root = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "default")
        conf = open(os.path.join(root, "imperva.conf"), encoding="utf-8").read()
        macros = open(os.path.join(root, "macros.conf"), encoding="utf-8").read()
        words = [l.split("=", 1)[1].strip() for l in conf.splitlines() if l.startswith("shared_ip_providers")][0]
        self.assertIn('definition = "\\b(%s)\\b"' % words, macros)

    def test_reason_text(self):
        self.assertEqual(au.reason_text({"days": 90, "last_seen": 0, "blocked_at": 1, "cloud": ""}),
                         "auto unblock: no attack for 90 days (no attack seen since the block)")
        self.assertIn("cloud provider IP (Amazon.com, Inc.), no attack for 7 days",
                      au.reason_text({"days": 7, "last_seen": 0, "blocked_at": 0, "cloud": "Amazon.com, Inc."}))

    def test_fixed_values(self):
        self.assertEqual((au.CLOUD_DAYS, au.DEFAULT_DAYS, au.BATCH_SIZE), (7, 60, 10))
        self.assertFalse(hasattr(au, "MAX_PER_RUN"))                         # no daily limit any more
        self.assertFalse(any(hasattr(au, n) for n in ("normalize_settings", "merge_settings", "load_settings")))
        self.assertEqual(au.rule_of("Keep"), "keep")
        self.assertEqual(au.rule_of("30"), 30)
        self.assertRaises(ValueError, au.rule_of, "0")

    def test_no_settings_left_in_conf_or_page(self):
        root = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2")
        conf = open(os.path.join(root, "default", "imperva.conf"), encoding="utf-8").read()
        spec = open(os.path.join(root, "README", "imperva.conf.spec"), encoding="utf-8").read()
        page = open(os.path.join(root, "default", "data", "ui", "views", "imperva_ioc_blocked.xml"), encoding="utf-8").read()
        self.assertNotIn("[auto_unblock]", conf + spec)
        for gone in ("action=settings", "SAVE SETTINGS", "due_not_managed", 'token="a_en"', "scope"):
            self.assertNotIn(gone, page)
        for shown in ("AUTO UNBLOCK ON", "<b>7 days</b>", "<b>60 days</b>", "All enabled policies",
                      "Rounds of <b>10</b> IPs, each confirmed on the WAF · no daily limit"):
            self.assertIn(shown, page)


class FakeBackend(object):
    mode = "soar"

    def __init__(self, pid, fail=None):
        self.pid, self.fail_on = pid, fail

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        CALLS.append((self.pid, action, list(ips), user))
        if self.fail_on:
            raise RuntimeError(self.fail_on)
        return [{"ip": ip, "site_id": self.pid, "status": "error" if ip in NOT_REMOVED else "unblocked",
                 "verified_in_waf": "no" if ip in NOT_REMOVED else "removed",
                 "detail": "write accepted but NOT confirmed on re-read from WAF" if ip in NOT_REMOVED else "ok",
                 "soar_container": 9} for ip in ips]


CALLS = []
NOT_REMOVED = set()          # IPs the fake WAF still has after the write (re-read)
MANY = [E("100.64.%d.%d" % (k // 200, k % 200 + 1), pid="1000001") for k in range(25)] + [E("203.0.113.10", enabled=False)]


class TestCommand(unittest.TestCase):
    def setUp(self):
        import impervaautounblock as c
        self.c = c
        del CALLS[:]
        NOT_REMOVED.clear()
        self.kv = {au.STATE: {}, au.SEEN: {}, "imperva_block_registry": {}}
        self.out, self.refreshed, self.fail_on = {}, [], {}
        c.load_conf_stanza = lambda sk, conf, stanza: {"policy_ids": "2169031", "cloud_providers": "amazon|aws"}
        c.load_entries = lambda sk, conf, log: (ENTRIES, OWN)
        c.refresh_entries = lambda sk, conf, log: self.refreshed.append(1)
        c.kv_list = lambda sk, col: list(self.kv[col].values())
        c.kv_upsert = lambda sk, docs, col="imperva_block_registry": [self.kv[col].__setitem__(d["_key"], dict(d)) for d in docs]
        c.kv_delete = lambda sk, key, col: self.kv[col].pop(key, None)
        c.kv_get = lambda sk, key, col="imperva_block_registry": self.kv[col].get(key)
        c.ip_owner.cached_owners = lambda sk, ips, log: dict((ip, "Amazon.com, Inc." if ip == "54.245.198.114" else None) for ip in ips)
        c.get_backend = lambda conf, lc, sk, override_ids=None: FakeBackend(override_ids, self.fail_on.get(override_ids))
        c.si.getOrganizedResults = lambda: (self.input, None, {"sessionKey": "k", "owner": "alice"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: None, "error": lambda s, *a: None})()
        self.input = [{"_time": 1}]

    def run_(self, *argv):
        self.out.clear()
        sys.argv = ["impervaautounblock.py"] + list(argv)
        self.c.main()
        if "err" in self.out:
            raise AssertionError(self.out["err"])
        return self.out["rows"]

    def age_all(self, days):
        for d in self.kv[au.STATE].values():
            if d.get("_key") != au.OLD_SETTINGS_KEY:
                d["first_listed"] = d["first_listed"] - days * DAY

    def test_list_records_first_seen_and_lists_rules(self):
        rows = self.run_("action=list")
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(self.kv[au.STATE]), 4)                 # countdown starts now
        r = dict((x["ip"], x) for x in rows)["54.245.198.114"]
        self.assertEqual((r["cloud_provider"], r["unblock_after"], r["status"]), ("Amazon.com, Inc.", "cloud 7 d quiet", "Quiet 0 d"))

    def test_run_unblocks_due_rules_per_policy(self):
        self.run_("action=list")
        self.kv["imperva_block_registry"]["2169031_54.245.198.114"] = {
            "_key": "2169031_54.245.198.114", "site_id": "2169031", "ip": "54.245.198.114", "status": "blocked",
            "blocked_at": 1, "incident_no": "1000101", "comment": "AWS bot"}
        self.age_all(100)
        rows = self.run_("action=run")
        self.assertEqual(sorted((c[0], tuple(sorted(c[2])), c[3]) for c in CALLS),
                         [("1000001", ("192.0.2.77", "198.51.100.0/24"), "auto-unblock"),
                          ("2169031", ("203.0.113.10", "54.245.198.114"), "auto-unblock")])
        self.assertEqual(set(r["status"] for r in rows), {"unblocked"})
        aws = [r for r in rows if r["ip"] == "54.245.198.114"][0]
        self.assertEqual((aws["user"], aws["action"], aws["incident_no"]), ("auto-unblock", "unblock", "1000101"))
        self.assertIn("cloud provider IP (Amazon.com, Inc.), no attack for 7 days", aws["comment"])
        self.assertEqual(self.kv["imperva_block_registry"]["2169031_54.245.198.114"]["status"], "unblocked")
        self.assertEqual([k for k in self.kv[au.STATE]], [])          # countdown restarts if added again
        self.assertEqual(self.refreshed, [1])

    def test_old_settings_document_is_ignored(self):
        old = {"_key": "settings", "enabled": "off", "default_days": 365, "scope": "own", "max_per_run": 1}
        self.kv[au.STATE]["settings"] = dict(old)
        self.assertEqual(len(self.run_("action=list")), 4)            # not taken for an IP rule
        self.age_all(100)
        rows = self.run_("action=run")                                # always on, all policies, no limit of 1
        self.assertEqual(sorted(r["ip"] for r in rows), ["192.0.2.77", "198.51.100.0/24", "203.0.113.10", "54.245.198.114"])
        self.assertEqual(self.kv[au.STATE]["settings"], old)

    def test_run_policy_not_allowed_on_soar(self):
        self.run_("action=list")
        self.age_all(100)
        self.fail_on["1000001"] = "policy ids ['1000001'] are not allowed on SOAR (IMPERVA_POLICY_IDS)"
        rows = self.run_("action=run")
        err = [r for r in rows if r["site_id"] == "1000001"]
        self.assertEqual(set(r["status"] for r in err), {"error"})
        self.assertIn("add the policy ID to IMPERVA_POLICY_IDS on SOAR", err[0]["detail"])
        self.assertTrue(any(k.startswith("e_1000001_") for k in self.kv[au.STATE]))   # retried next run
        self.assertEqual(set(r["status"] for r in rows if r["site_id"] == "2169031"), {"unblocked"})

    def test_run_has_no_limit_and_goes_in_rounds_of_10(self):
        self.c.load_entries = lambda sk, conf, log: (MANY, OWN)
        self.run_("action=list")
        self.age_all(100)
        rows = self.run_("action=run")
        self.assertEqual([(c[0], len(c[2])) for c in CALLS], [("1000001", 10), ("1000001", 10), ("1000001", 5), ("2169031", 1)])
        self.assertEqual(len(rows), 26)
        self.assertEqual(set(r["status"] for r in rows), {"unblocked"})
        self.assertEqual(self.kv[au.STATE], {})                               # every countdown done

    def test_a_round_not_confirmed_stops_that_policy_only(self):
        self.c.load_entries = lambda sk, conf, log: (MANY, OWN)
        self.run_("action=list")
        self.age_all(100)
        first = sorted(i["cidr"] for i in MANY if i["policy_id"] == "1000001")
        NOT_REMOVED.add("100.64.0.10")                                      # in the first round
        rows = self.run_("action=run")
        self.assertEqual([(c[0], len(c[2])) for c in CALLS], [("1000001", 10), ("2169031", 1)])   # rounds 2 and 3 not sent
        skipped = [r for r in rows if r["status"] == "skipped"]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["detail"], "15 more IP rule(s) of policy 1000001 not sent: 1 of 10 IP(s) of the round "
                                               "before not confirmed removed on the WAF - retried at the next run")
        self.assertEqual([r["status"] for r in rows if r["ip"] == "100.64.0.10"], ["error"])
        self.assertIn(au.entry_key("1000001", "100.64.0.10"), self.kv[au.STATE])            # still due next run
        self.assertEqual(sum(1 for k in self.kv[au.STATE] if k.startswith("e_1000001_")), 16)
        self.assertTrue(first)

    def test_error_of_a_round_stops_that_policy_and_time_budget(self):
        self.c.load_entries = lambda sk, conf, log: (MANY, OWN)
        self.run_("action=list")
        self.age_all(100)
        self.fail_on["1000001"] = "SOAR HTTP 500"
        rows = self.run_("action=run")
        self.assertEqual([(c[0], len(c[2])) for c in CALLS], [("1000001", 10), ("2169031", 1)])
        self.assertIn("the round before failed (SOAR HTTP 500)", [r for r in rows if r["status"] == "skipped"][0]["detail"])
        del CALLS[:]
        self.fail_on.clear()
        saved, self.c.au.RUN_TIME_BUDGET = self.c.au.RUN_TIME_BUDGET, -1
        try:
            rows = self.run_("action=run")
        finally:
            self.c.au.RUN_TIME_BUDGET = saved
        self.assertEqual(CALLS, [])
        self.assertEqual(sorted(r["site_id"] for r in rows), ["1000001"])     # own rule unblocked by the run above
        self.assertIn("time budget of this run used up", rows[0]["detail"])

    def test_set_keep_and_default(self):
        self.run_("action=list")
        rows = self.run_("action=set", "ip=192.0.2.77", "rule=keep", 'reason="C2', 'server"')
        self.assertEqual((rows[0]["action"], rows[0]["status"], rows[0]["comment"]), ("auto_unblock_rule", "saved", "C2 server"))
        self.assertEqual(self.kv[au.STATE][au.entry_key("1000001", "192.0.2.77")]["rule"], "keep")
        self.age_all(500)
        self.assertNotIn("192.0.2.77", [r["ip"] for r in self.run_("action=run")])
        self.run_("action=set", "ip=192.0.2.77", "rule=default")
        self.assertEqual(self.kv[au.STATE][au.entry_key("1000001", "192.0.2.77")]["rule"], "default")
        self.assertEqual(self.run_("action=set", "ip=8.8.8.8", "rule=keep")[0]["status"], "not_found")

    def test_settings_action_is_gone(self):
        with self.assertRaises(AssertionError) as ctx:
            self.run_("action=settings", "default_days=90")
        self.assertIn("action must be list, run, set, unblock, policies or annotate", str(ctx.exception))
        self.assertEqual(self.kv[au.STATE], {})

    def test_unblock_now_from_the_policy_that_holds_each_ip(self):
        self.run_("action=list")
        self.kv["imperva_block_registry"]["2169031_54.245.198.114"] = {
            "_key": "2169031_54.245.198.114", "site_id": "2169031", "ip": "54.245.198.114", "status": "blocked",
            "blocked_at": 1, "incident_no": "1000101", "comment": "AWS bot"}
        rows = self.run_("action=unblock", 'ip="192.0.2.77,', '54.245.198.114"', "incident_no=1000123",
                         'description="false', 'positive"')
        self.assertEqual(sorted((c[0], tuple(c[2]), c[3]) for c in CALLS),
                         [("1000001", ("192.0.2.77",), "alice"), ("2169031", ("54.245.198.114",), "alice")])
        by = dict((r["ip"], r) for r in rows)
        self.assertEqual((by["192.0.2.77"]["user"], by["192.0.2.77"]["action"], by["192.0.2.77"]["status"],
                          by["192.0.2.77"]["incident_no"], by["192.0.2.77"]["comment"], by["192.0.2.77"]["site_id"]),
                         ("alice", "unblock", "unblocked", "1000123", "false positive", "1000001"))
        reg = self.kv["imperva_block_registry"]["2169031_54.245.198.114"]
        self.assertEqual((reg["status"], reg.get("unblocked_by", reg.get("updated_by", "alice"))), ("unblocked", "alice"))
        self.assertNotIn(au.entry_key("1000001", "192.0.2.77"), self.kv[au.STATE])     # countdown cleared
        self.assertIn(au.entry_key("2169031", "203.0.113.10"), self.kv[au.STATE])      # others untouched
        self.assertEqual(self.refreshed, [1])

    def test_unblock_ip_not_in_the_policy_cache_goes_to_the_own_policy(self):
        self.kv["imperva_block_registry"]["2169031_198.51.100.200"] = {
            "_key": "2169031_198.51.100.200", "site_id": "2169031", "ip": "198.51.100.200", "status": "blocked",
            "blocked_at": 1, "incident_no": "1000140", "comment": "removed outside Splunk"}
        rows = self.run_("action=unblock", "ip=198.51.100.200", "incident_no=-")
        self.assertEqual([(c[0], c[2]) for c in CALLS], [("2169031", ["198.51.100.200"])])
        self.assertEqual(rows[0]["status"], "unblocked")
        self.assertEqual(self.kv["imperva_block_registry"]["2169031_198.51.100.200"]["status"], "unblocked")

    def test_unblock_keeps_the_ticket_of_the_ip_when_none_given_and_checks_input(self):
        self.kv["imperva_block_registry"]["2169031_54.245.198.114"] = {
            "_key": "2169031_54.245.198.114", "site_id": "2169031", "ip": "54.245.198.114", "status": "blocked",
            "blocked_at": 1, "incident_no": "1000101", "comment": "AWS bot"}
        rows = self.run_("action=unblock", "ip=54.245.198.114")
        self.assertEqual((rows[0]["incident_no"], rows[0]["comment"]), ("1000101", "-"))
        rows = self.run_("action=unblock", "ip=not-an-ip")
        self.assertEqual(rows[0]["status"], "rejected")
        with self.assertRaises(AssertionError) as ctx:
            self.run_("action=unblock", "ip=-")
        self.assertIn("no IP selected", str(ctx.exception))
        with self.assertRaises(AssertionError):
            self.run_("action=set", "ip=-", "rule=keep")

    def test_unblock_error_of_one_policy_does_not_stop_the_other(self):
        self.fail_on["1000001"] = "policy ids ['1000001'] are not allowed on SOAR (IMPERVA_POLICY_IDS)"
        rows = dict((r["ip"], r) for r in self.run_("action=unblock", 'ip="192.0.2.77,', '54.245.198.114"'))
        self.assertEqual(rows["192.0.2.77"]["status"], "error")
        self.assertIn("add the policy ID to IMPERVA_POLICY_IDS on SOAR", rows["192.0.2.77"]["detail"])
        self.assertEqual(rows["54.245.198.114"]["status"], "unblocked")

    def test_annotate_gives_status_code_owner_and_policy_name(self):
        self.input = [{"ip": "54.245.198.114", "site_id": "2169031"}]
        r = self.run_("action=annotate", "field=ip", "policy_field=site_id")[0]
        self.assertEqual((r["auto_status_code"], r["auto_owner"], r["auto_policy_name"]),
                         ("quiet", "Amazon.com, Inc.", "BlockIOCsFromSplunk"))

    def test_list_and_annotate_show_attacks_24h(self):
        self.kv[au.SEEN]["192.0.2.77"] = {"_key": "192.0.2.77", "src": "192.0.2.77", "last_seen": 1, "hits_24h": 412}
        rows = dict((r["ip"], r) for r in self.run_("action=list"))
        self.assertEqual((rows["192.0.2.77"]["attacks_24h"], rows["54.245.198.114"]["attacks_24h"]), (412, 0))
        self.input = [{"ip": "192.0.2.77", "site_id": "1000001"}]
        self.assertEqual(self.run_("action=annotate", "field=ip", "policy_field=site_id")[0]["auto_attacks_24h"], 412)
        pol = dict((p["policy_id"], p) for p in self.run_("action=policies"))
        self.assertEqual(pol["1000001"]["attacks_24h"], 412)

    def test_policies_and_annotate(self):
        pol = self.run_("action=policies")
        self.assertEqual([(p["policy_id"], p["block_ip_rules"], p["own_policy"]) for p in pol],
                         [("2169031", 2, "yes"), ("1000001", 2, "no")])
        self.input = [{"ip": "54.245.198.114", "site_id": "2169031"}, {"ip": "9.9.9.9", "site_id": "2169031"}]
        rows = self.run_("action=annotate", "field=ip", "policy_field=site_id")
        self.assertEqual(rows[0]["auto_unblock_after"], "cloud 7 d quiet")
        self.assertNotIn("auto_status", rows[1])



class TestMergedPage(unittest.TestCase):
    """Blocked IPs / Unblock and Auto unblock are one page since mockup v3.15."""
    def setUp(self):
        root = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "default", "data", "ui")
        self.views = os.path.join(root, "views")
        self.page = open(os.path.join(self.views, "imperva_ioc_blocked.xml"), encoding="utf-8").read()
        self.nav = open(os.path.join(root, "nav", "default.xml"), encoding="utf-8").read()

    def test_old_auto_unblock_page_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(self.views, "imperva_ioc_auto_unblock.xml")))
        self.assertNotIn("imperva_ioc_auto_unblock", self.nav)
        self.assertIn('<view name="imperva_ioc_blocked" />', self.nav)

    def test_one_table_of_every_policy(self):
        p = self.page
        self.assertIn("| impervalist", p)                                              # own policy: live
        self.assertIn('| append [| makeresults | impervaautounblock action=list | where own_policy="no"', p)
        self.assertIn("| impervaautounblock action=annotate field=ip policy_field=site_id", p)
        for f in ("all", "own", "other", "cloud", "attacking", "soon", "due", "kept", "not_on_waf"):
            self.assertIn('<choice value="%s">' % f, p)
        self.assertIn('<set token="b_sel">$b_sel$,$row.ip$,</set>', p)

    def test_actions(self):
        p = self.page
        self.assertIn("| impervaautounblock action=unblock ip=$b_exec_ips|s$ incident_no=$b_exec_tk|s$ description=$b_exec_desc|s$", p)
        self.assertNotIn("impervablock action=unblock", p)
        self.assertIn("| makeresults | impervaautounblock action=set ip=$b_rule_ips|s$ rule=$b_rule_val|s$ reason=$b_rule_why|s$", p)
        self.assertIn("""<condition match="'click.name2'==&quot;Apply&quot; AND 'row.selected_ips'!=&quot;-&quot;">""", p)  # no IP: no run
        for moved in ("impervaautounblock action=run", "impervaautounblock action=policies", "Unblock / auto unblock log"):
            self.assertNotIn(moved, p)                     # on the Audit log page since the merged page review
        audit = open(os.path.join(self.views, "imperva_ioc_audit.xml"), encoding="utf-8").read()
        self.assertIn("| makeresults | impervaautounblock action=run\n| eval _r=$au_run_now|s$", audit)
        self.assertIn("| makeresults | impervaautounblock action=list\n| eval _r=$au_refresh|s$", audit)
        self.assertIn("| makeresults | impervaautounblock action=policies\n| eval _r=$au_refresh|s$", audit)
        self.assertIn("Unblock / auto unblock log – last 30 days", audit)
        self.assertIn('<set token="au_refresh">init</set>', audit)
        for k in ("Blocked on the WAF", "Attacking now", "Attacks in the last 24 h", "Due now", "Kept", "Unblocked 7 days"):
            self.assertIn("<title>%s</title>" % k, p)


if __name__ == "__main__":
    unittest.main()
