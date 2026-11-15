"""V2: a block without ticket / description gets them from the ES finding for 24 h (impervaticketfill)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2")
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(APP, "bin"))

NOW = 1_790_000_000
H = 3600


def R(ip, at, tk="-", comment="-", status="blocked", site="2169031", **kw):
    d = {"_key": "%s_%s" % (site, ip), "_user": "nobody", "site_id": site, "ip": ip, "status": status,
         "blocked_at": at, "blocked_by": "analyst01", "incident_no": tk, "comment": comment, "reason": comment,
         "source": "splunk"}
    d.update(kw)
    return d


class TestTicketFill(unittest.TestCase):
    def setUp(self):
        import impervaticketfill as c
        self.c = c
        self.reg = {d["_key"]: d for d in [
            R("198.51.100.48", NOW - 2 * H),                                   # nothing yet: waits for both
            R("198.51.100.72", NOW - 3 * H, tk="1000854"),                      # ticket typed, no description
            R("198.51.100.68", NOW - 5 * H, comment="credential stuffing"),     # description typed, no ticket
            R("198.51.100.18", NOW - 25 * H),                                    # blocked more than 24 h ago
            R("198.51.100.213", NOW - 1 * H, tk="1000900", comment="typed"),     # complete
            R("198.51.100.211", NOW - 1 * H, status="unblocked"),                # not blocked any more
            R("203.0.113.0/24", NOW - 1 * H),                                  # CIDR: no finding search
            R("198.51.100.193", NOW - 1 * H, tk=""),                           # empty string = missing
        ]}
        self.reg0 = dict((k, dict(v)) for k, v in self.reg.items())
        self.saved = []
        c.kv_query = lambda sk, col, q: [dict(d) for d in self.reg.values() if d.get("status") == q.get("status")]
        def kv_upsert(sk, docs, col):
            self.saved.append((col, [dict(d) for d in docs]))
            self.reg.update((d["_key"], dict(d)) for d in docs)          # batch_save replaces the document
        c.kv_upsert = kv_upsert
        self._clock = c.time.time
        c.time.time = lambda: NOW                                          # global time module: restored
        self.out = {}
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: type("L", (), {"info": lambda s, *a: None, "warning": lambda s, *a: None,
                                                  "error": lambda s, *a: None})()

    def tearDown(self):
        self.c.time.time = self._clock

    def run_(self, rows, *argv):
        self.c.si.getOrganizedResults = lambda: (rows, None, {"sessionKey": "k"})
        sys.argv = ["impervaticketfill.py"] + list(argv)
        self.out.clear()
        self.c.main()
        if "err" in self.out:
            raise AssertionError(self.out["err"])
        return self.out["rows"]

    def test_terms_are_the_waiting_ips_only(self):
        rows = self.run_([{}], "action=terms")
        self.assertEqual(rows, [{"search": '("198.51.100.193" OR "198.51.100.48" OR "198.51.100.68" OR "198.51.100.72")'}])

    def test_no_waiting_ip_never_searches_every_finding(self):
        self.reg.clear()
        self.assertEqual(self.run_([{}], "action=terms"), [{"search": '"imperva_no_ip_pending"'}])

    def test_pending_lists_what_each_ip_waits_for(self):
        rows = dict((r["ip"], r) for r in self.run_([{}], "action=pending"))
        self.assertEqual(sorted(rows), ["198.51.100.193", "198.51.100.48", "198.51.100.68", "198.51.100.72"])
        self.assertEqual(rows["198.51.100.48"]["waiting_for"], "ticket, description")
        self.assertEqual(rows["198.51.100.72"]["waiting_for"], "description")
        self.assertEqual(rows["198.51.100.68"]["waiting_for"], "ticket")
        self.assertEqual(rows["198.51.100.48"]["hours_left"], 22.0)

    def again(self):
        """Back to the registry of setUp (the next case of the same test)."""
        self.reg.clear()
        self.reg.update((k, dict(v)) for k, v in self.reg0.items())
        self.saved.clear()

    def F(self, ip, t, rule, notes="", comment=""):
        return {"ip": ip, "finding_time": str(t), "rule_name": rule, "ithm_times": notes, "comment_ithm": comment}

    def test_update_fills_only_what_is_empty(self):
        b48, b72, b68 = NOW - 2 * H, NOW - 3 * H, NOW - 5 * H
        found = [
            self.F("198.51.100.48", b48 - 30 * 60, "Threat - WAF burst - Rule", "1000555@%d" % (b48 + H)),
            self.F("198.51.100.72", b72 - 600, "WAF - SQLi", "1000777@%d" % (b72 + 60)),
            self.F("198.51.100.72", b72 - 86400, "WAF - XSS"),
            self.F("198.51.100.68", b68 - 60, "WAF - Brute force", "1000888@%d, 1000889@%d" % (b68 + 10, b68 + 20)),
            self.F("198.51.100.18", NOW - 26 * H, "old", "1000999@%d" % NOW),             # window over
            self.F("198.51.100.213", NOW - 2 * H, "x", "1000111@%d" % NOW),               # complete
            self.F("192.0.2.8", NOW - H, "x", "1000222@%d" % NOW),                           # not blocked
        ]
        audit = self.run_(found, "action=update")
        self.assertEqual(len(self.saved), 1)
        col, docs = self.saved[0]
        self.assertEqual(col, "imperva_block_registry")
        by = dict((d["ip"], d) for d in docs)
        self.assertEqual(sorted(by), ["198.51.100.48", "198.51.100.68", "198.51.100.72"])
        self.assertEqual((by["198.51.100.48"]["incident_no"], by["198.51.100.48"]["comment"]),
                         ("1000555", "Threat - WAF burst - Rule"))
        self.assertEqual((by["198.51.100.72"]["incident_no"], by["198.51.100.72"]["comment"]),
                         ("1000854", "WAF - XSS; WAF - SQLi"))                  # typed ticket kept, rules of 7 days
        self.assertEqual((by["198.51.100.68"]["incident_no"], by["198.51.100.68"]["comment"]),
                         ("1000888, 1000889", "credential stuffing"))           # typed description kept
        d = by["198.51.100.48"]
        self.assertNotIn("_user", d)
        self.assertEqual((d["_key"], d["status"], d["blocked_at"], d["blocked_by"], d["site_id"], d["reason"]),
                         ("2169031_198.51.100.48", "blocked", b48, "analyst01", "2169031",
                          "Threat - WAF burst - Rule"))                     # whole document kept
        self.assertEqual((d["ticket_filled_at"], d["comment_filled_at"]), (NOW, NOW))
        a = dict((r["ip"], r) for r in audit)
        self.assertEqual(sorted(a), sorted(by))
        self.assertEqual((a["198.51.100.48"]["user"], a["198.51.100.48"]["action"], a["198.51.100.48"]["status"],
                          a["198.51.100.48"]["incident_no"], a["198.51.100.48"]["comment"]),
                         ("auto-ticket", "ticket_update", "updated", "1000555", "Threat - WAF burst - Rule"))
        self.assertEqual(a["198.51.100.48"]["detail"], "ticket 1000555 from a new note of the ES finding · description = "
                                                        "detection rule name (filled after the block)")
        self.assertEqual(a["198.51.100.72"]["detail"], "description = detection rule name (filled after the block)")

    def test_old_ticket_of_a_previous_incident_is_never_taken(self):
        b = NOW - 2 * H                                                       # an older ticket of the same IP
        found = [self.F("198.51.100.48", b - 30 * 60, "Threat - WAF burst from a single source - Rule"),
                 self.F("198.51.100.48", b - 71 * 86400, "Threat - Threat Hunting (IP) - Rule",
                        "1000263@%d" % (b - 70 * 86400), "ITHM 1000263")]
        self.run_(found, "action=update")
        doc = self.saved[0][1][0]
        self.assertEqual((doc["incident_no"], doc["comment"]),
                         ("-", "Threat - WAF burst from a single source - Rule"))
        self.assertNotIn("ticket_filled_at", doc)

    def test_note_just_before_the_block_counts_and_comment_numbers_count_from_the_finding_time(self):
        b = NOW - 2 * H
        self.run_([self.F("198.51.100.48", b - 600, "R", "1000300@%d" % (b - 50 * 60))], "action=update")
        self.assertEqual(self.saved[0][1][0]["incident_no"], "1000300")       # 50 min before: still new
        self.again()
        self.run_([self.F("198.51.100.48", b - 2 * H, "R", "1000301@%d" % (b - 2 * H))], "action=update")
        self.assertEqual(self.saved[0][1][0]["incident_no"], "-")             # 2 h before: an older number
        self.again()
        self.run_([self.F("198.51.100.48", b + 600, "R", "", "ITHM 1000302")], "action=update")
        self.assertEqual(self.saved[0][1][0]["incident_no"], "1000302")       # comment of a finding after the block

    def test_description_falls_back_to_the_latest_finding_before_then_the_first_after(self):
        b = NOW - 2 * H
        self.run_([self.F("198.51.100.48", b - 40 * 86400, "Older rule A"),
                   self.F("198.51.100.48", b - 20 * 86400, "Older rule B")], "action=update")
        self.assertEqual(self.saved[0][1][0]["comment"], "Older rule B")       # blocked from Older detections
        self.again()
        self.run_([self.F("198.51.100.48", b + 3 * H, "After 1"), self.F("198.51.100.48", b + 5 * H, "After 2")],
                  "action=update")
        self.assertEqual(self.saved[0][1][0]["comment"], "After 1")            # IP typed in, finding came later

    def test_finding_without_ithm_fills_the_description_and_keeps_waiting_for_the_ticket(self):
        b = NOW - 2 * H
        self.run_([self.F("198.51.100.48", b - 60, "WAF - Scanner")], "action=update")
        doc = self.saved[0][1][0]
        self.assertEqual((doc["incident_no"], doc["comment"]), ("-", "WAF - Scanner"))
        self.reg[doc["_key"]] = dict(doc, _user="nobody")
        self.assertIn('"198.51.100.48"', self.run_([{}], "action=terms")[0]["search"])     # still waiting: ticket
        self.saved.clear()
        self.run_([self.F("198.51.100.48", b - 60, "WAF - Scanner", "1000600@%d" % (b + H)),
                   self.F("198.51.100.48", b + H, "other rule")], "action=update")
        doc = self.saved[0][1][0]
        self.assertEqual((doc["incident_no"], doc["comment"]), ("1000600", "WAF - Scanner"))   # description not replaced
        self.reg[doc["_key"]] = dict(doc)
        self.assertNotIn('"198.51.100.48"', self.run_([{}], "action=terms")[0]["search"])  # complete: done

    def test_nothing_found_saves_nothing(self):
        self.assertEqual(self.run_([{"ip": "198.51.100.48", "finding_time": "", "rule_name": "-"}], "action=update"), [])
        self.assertEqual(self.saved, [])

    def test_long_rule_names_are_cut(self):
        self.run_([self.F("198.51.100.48", NOW - 2 * H, ["R%03d %s" % (i, "x" * 40) for i in range(10)])], "action=update")
        self.assertEqual(len(self.saved[0][1][0]["comment"]), 250)
        self.assertTrue(self.saved[0][1][0]["comment"].endswith("…"))

    def test_reset_clears_only_what_was_filled_automatically(self):
        self.reg["2169031_198.51.100.48"].update(incident_no="1000263", ticket_filled_at=NOW - 60,
                                                   comment="WAF burst", reason="WAF burst", comment_filled_at=NOW - 60)
        self.reg["2169031_198.51.100.72"].update(comment="WAF - SQLi", reason="WAF - SQLi", comment_filled_at=NOW - 60)
        rows = self.run_([{}], "action=reset", 'ip="198.51.100.48,', '198.51.100.68"')
        docs = dict((d["ip"], d) for d in self.saved[0][1])
        self.assertEqual(sorted(docs), ["198.51.100.48"])                    # 198.51.100.68: typed values, untouched
        d = docs["198.51.100.48"]
        self.assertEqual((d["incident_no"], d["comment"], d["reason"]), ("-", "-", "-"))
        self.assertNotIn("ticket_filled_at", d)
        self.assertNotIn("comment_filled_at", d)
        self.assertEqual((rows[0]["status"], rows[0]["detail"]),
                         ("reset", "auto-filled ticket and description cleared - filled again by the next run"))
        self.saved.clear()
        rows = self.run_([{}], "action=reset", "ip=all")
        self.assertEqual([(d["ip"], d["incident_no"], d["comment"]) for d in self.saved[0][1]],
                         [("198.51.100.72", "1000854", "-")])                 # typed ticket kept
        self.saved.clear()
        self.reg["2169031_198.51.100.18"].update(comment="old rule", comment_filled_at=NOW - 24 * H)   # 25 h after block
        self.assertEqual(self.run_([{}], "action=reset", "ip=all"), [])                    # all: inside the window only
        rows = self.run_([{}], "action=reset", "ip=198.51.100.18")                        # named: allowed, said so
        self.assertEqual(rows[0]["detail"], "auto-filled description cleared - not filled again (more than 24 h after the block)")
        with self.assertRaises(AssertionError):
            self.run_([{}], "action=reset")

    def test_bad_action(self):
        with self.assertRaises(AssertionError) as ctx:
            self.run_([{}], "action=delete")
        self.assertIn("action must be terms, update, pending or reset", str(ctx.exception))


class TestConf(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(APP, *p), encoding="utf-8") as f:
            return f.read()

    def test_saved_search(self):
        s = self.read("default", "savedsearches.conf")
        i = s.index("[Imperva V2 - Ticket / description of new blocks (every 10 min)]")
        st = s[i:s.index("\n\n", i)]
        for line in ("cron_schedule = 7-59/10 * * * *", "dispatch.earliest_time = -90d@d", "enableSched = 1",
                     "search = `imperva_ioc_notables` [| makeresults | impervaticketfill action=terms] \\",
                     "| join type=left max=1 _finding_guid [| impervanotes | rename finding_guid AS _finding_guid | fields _finding_guid ithm ithm_times] \\",
                     "| eval finding_time=_time, rule_name=ioc_rule, comment_ithm=mvjoin(ioc_ithm, \", \") \\",
                     "| table ioc_ip finding_time rule_name ithm_times comment_ithm \\",
                     "| impervaticketfill action=update \\", "| `imperva_audit_write`"):
            self.assertIn(line, st)
        self.assertNotIn("soar", st.lower())                                  # nothing is sent to SOAR

    def test_registered_and_shown(self):
        self.assertIn("[impervaticketfill]\nfilename = impervaticketfill.py", self.read("default", "commands.conf"))
        self.assertIn("[commands/impervaticketfill]", self.read("metadata", "default.meta"))
        audit = self.read("default", "data", "ui", "views", "imperva_ioc_audit.xml")
        self.assertIn('<choice value="ticket_update">ticket / description filled from the ES finding</choice>', audit)
        self.assertIn("gets them for 24 hours from the ES finding", self.read("default", "data", "ui", "views", "imperva_ioc_blocked.xml"))


if __name__ == "__main__":
    unittest.main()
