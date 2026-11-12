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
CLOUD = lambda o: o if o and "Amazon" in o else None  # noqa: E731
S = au.normalize_settings({})


def plan(states=None, seen=None, registry=None, owners=None, settings=S, now=T, entries=ENTRIES):
    items, new = au.plan(now, entries, OWN, settings, states or {}, seen or {}, registry or {},
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
        self.assertEqual(items["192.0.2.77"]["days"], 90)

    def test_due_after_quiet_period_counted_from_install(self):
        states = {}
        states.update(st("54.245.198.114", first=T - 8 * DAY))
        states.update(st("192.0.2.77", "1000001", first=T - 91 * DAY))
        states.update(st("203.0.113.10", first=T - 60 * DAY))
        items, new = plan(states)
        self.assertEqual(items["54.245.198.114"]["status"], "due")
        self.assertEqual(items["192.0.2.77"]["status"], "due")
        self.assertEqual(items["203.0.113.10"]["status"], "quiet")
        self.assertEqual([n["cidr"] for n in new], ["198.51.100.0/24"])

    def test_attack_restarts_the_countdown(self):
        states = st("192.0.2.77", "1000001", first=T - 200 * DAY)
        items, _ = plan(states, seen={"192.0.2.77": T - 2 * 3600})
        self.assertEqual(items["192.0.2.77"]["status"], "attacking")
        self.assertAlmostEqual(items["192.0.2.77"]["unblock_on"], T - 2 * 3600 + 90 * DAY)
        items, _ = plan(states, seen={"192.0.2.77": T - 85 * DAY})
        self.assertEqual(items["192.0.2.77"]["status"], "soon")               # 5 days left
        items, _ = plan(states, seen={"192.0.2.77": T - 95 * DAY})
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
        self.assertAlmostEqual(i["unblock_on"], T + 60 * DAY)

    def test_rules_keep_and_days(self):
        states = st("192.0.2.77", "1000001", first=T - 500 * DAY, rule="keep")
        states.update(st("54.245.198.114", first=T - 10 * DAY, rule="30"))
        items, _ = plan(states)
        self.assertEqual(items["192.0.2.77"]["status"], "kept")
        self.assertEqual((items["54.245.198.114"]["days"], items["54.245.198.114"]["status"]), (30, "quiet"))

    def test_scope_own(self):
        states = st("192.0.2.77", "1000001", first=T - 100 * DAY)
        items, _ = plan(states, settings=au.normalize_settings({"scope": "own"}))
        self.assertEqual((items["192.0.2.77"]["status"], items["192.0.2.77"]["managed"]), ("due_not_managed", False))
        self.assertEqual(au.due_items(list(items.values()), 50), [])

    def test_start_time_floor(self):
        states = st("192.0.2.77", "1000001", first=T - 100 * DAY)
        items, _ = plan(states, settings=au.normalize_settings({"start_time": str(int(T - 10 * DAY))}))
        self.assertEqual(items["192.0.2.77"]["status"], "quiet")

    def test_due_items_order_and_limit(self):
        states = {}
        for k, ip in enumerate(["192.0.2.77", "54.245.198.114", "203.0.113.10"]):
            pid = "1000001" if ip == "192.0.2.77" else "2169031"
            states.update(st(ip, pid, first=T - (300 + k) * DAY))
        items, _ = plan(states)
        due = au.due_items(sorted(items.values(), key=lambda i: i["unblock_on"]), 2)
        self.assertEqual([i["cidr"] for i in due], ["54.245.198.114", "203.0.113.10"])

    def test_reason_text(self):
        self.assertEqual(au.reason_text({"days": 90, "last_seen": 0, "blocked_at": 1, "cloud": ""}),
                         "auto unblock: no attack for 90 days (no attack seen since the block)")
        self.assertIn("cloud provider IP (Amazon.com, Inc.), no attack for 7 days",
                      au.reason_text({"days": 7, "last_seen": 0, "blocked_at": 0, "cloud": "Amazon.com, Inc."}))

    def test_settings(self):
        s = au.merge_settings({"enabled": "on", "default_days": "90", "cloud_days": "7", "scope": "all"},
                              {"_key": "settings", "default_days": 60, "scope": "own", "enabled": ""})
        self.assertEqual((s["enabled"], s["default_days"], s["cloud_days"], s["scope"]), ("on", 60, 7, "own"))
        self.assertEqual(au.normalize_settings({"default_days": "0", "cloud_days": "x", "enabled": "off"})["default_days"], 1)
        self.assertEqual(au.normalize_settings({"cloud_days": "x"})["cloud_days"], 7)
        self.assertEqual(au.rule_of("Keep"), "keep")
        self.assertEqual(au.rule_of("30"), 30)
        self.assertRaises(ValueError, au.rule_of, "0")

    def test_conf_defaults_match(self):
        conf = open(os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "default", "imperva.conf")).read()
        part = conf.split("\n[auto_unblock]\n")[1]
        for k, v in (("enabled", "on"), ("default_days", "90"), ("cloud_days", "7"), ("scope", "all"), ("max_per_run", "50")):
            self.assertIn("\n%s = %s\n" % (k, v), part)


class FakeBackend(object):
    mode = "soar"

    def __init__(self, pid, fail=None):
        self.pid, self.fail_on = pid, fail

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        CALLS.append((self.pid, action, list(ips), user))
        if self.fail_on:
            raise RuntimeError(self.fail_on)
        return [{"ip": ip, "site_id": self.pid, "status": "unblocked", "verified_in_waf": "removed",
                 "detail": "ok", "soar_container": 9} for ip in ips]


CALLS = []


class TestCommand(unittest.TestCase):
    def setUp(self):
        import impervaautounblock as c
        self.c = c
        del CALLS[:]
        self.kv = {au.STATE: {}, au.SEEN: {}, "imperva_block_registry": {}}
        self.out, self.refreshed, self.fail_on = {}, [], {}
        self.settings = dict(S)
        c.load_conf_stanza = lambda sk, conf, stanza: {"policy_ids": "2169031", "cloud_providers": "amazon|aws"}
        c.au.load_settings = lambda sk, conf=None: dict(self.settings)
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
            if d.get("_key") != au.SETTINGS_KEY:
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

    def test_run_off_does_nothing(self):
        self.run_("action=list")
        self.age_all(100)
        self.settings["enabled"] = "off"
        self.assertEqual(self.run_("action=run"), [])
        self.assertEqual(CALLS, [])

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

    def test_run_respects_max_per_run(self):
        self.run_("action=list")
        self.age_all(100)
        self.settings["max_per_run"] = 1
        self.assertEqual(len(self.run_("action=run")), 1)

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

    def test_settings_show_and_save(self):
        self.assertEqual(self.run_("action=settings")[0]["default_days"], 90)
        rows = self.run_("action=settings", "default_days=60", "cloud_days=3", "scope=own", "enabled=on", "max_per_run=25")
        self.assertEqual((rows[0]["action"], rows[0]["status"]), ("auto_unblock_settings", "saved"))
        doc = self.kv[au.STATE][au.SETTINGS_KEY]
        self.assertEqual((doc["default_days"], doc["cloud_days"], doc["scope"], doc["max_per_run"], doc["updated_by"]),
                         (60, 3, "own", 25, "alice"))

    def test_policies_and_annotate(self):
        pol = self.run_("action=policies")
        self.assertEqual([(p["policy_id"], p["block_ip_rules"], p["own_policy"]) for p in pol],
                         [("2169031", 2, "yes"), ("1000001", 2, "no")])
        self.input = [{"ip": "54.245.198.114", "site_id": "2169031"}, {"ip": "9.9.9.9", "site_id": "2169031"}]
        rows = self.run_("action=annotate", "field=ip", "policy_field=site_id")
        self.assertEqual(rows[0]["auto_unblock_after"], "cloud 7 d quiet")
        self.assertNotIn("auto_status", rows[1])


if __name__ == "__main__":
    unittest.main()
