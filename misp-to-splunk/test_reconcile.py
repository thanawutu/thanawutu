"""ทดสอบ logic การเปรียบเทียบ:  python3 -m unittest -v test_reconcile"""
import unittest

import reconcile_misp_splunk as r


def m(u, ev="1", t="domain", v="evil.example", ids=True, ts=100, lvl="1"):
    return {"attr_uuid": u, "event_id": ev, "event_info": "e" + ev, "orgc_id": "9", "attr_type": t,
            "value": v, "to_ids": ids, "attr_timestamp": ts, "threat_level_id": lvl, "object": "attribute"}


def s(u, t="domain", v="evil.example", ids=True, ts=100, copies=1):
    return {"attr_uuid": u, "attr_type": t, "value": v, "event_id": "1", "to_ids": ids,
            "attr_timestamp": ts, "threat_level_id": "1", "org": "x", "copies": copies}


class CompareTest(unittest.TestCase):
    def setUp(self):
        misp = {"a": m("a"), "b": m("b", lvl="2", t="ip-dst", v="45.33.32.156"),
                "c": m("c", ev="2", ts=200), "d": m("d", ev="3")}
        splunk = {"a": s("a", copies=3), "c": s("c", ts=100), "d": s("d", ids=False), "z": s("z")}
        self.res = r.compare(misp, splunk)

    def test_counts(self):
        x = self.res["summary"]
        self.assertEqual(x["missing_in_splunk"], 1)
        self.assertEqual(x["extra_in_splunk"], 1)
        self.assertEqual(x["missing_pct"], 25.0)
        self.assertEqual(x["missing_by_threat_level"], {"medium": 1})
        self.assertEqual(x["splunk_duplicate_factor"], 1.5)

    def test_mismatch_kinds(self):
        diffs = {d["attr_uuid"]: d["diff"] for d in self.res["mismatched"]}
        self.assertEqual(diffs, {"c": "stale", "d": "to_ids"})

    def test_events(self):
        x = self.res["summary"]
        self.assertEqual(x["events_partially_missing"], 1)   # event 1: b ขาด, a มี
        self.assertEqual(x["events_fully_missing"], 0)

    def test_value_case_insensitive(self):
        res = r.compare({"a": m("a", v="Evil.Example")}, {"a": s("a", v="evil.example")})
        self.assertEqual(res["mismatched"], [])


if __name__ == "__main__":
    unittest.main()
