"""impervanotes: ITHM numbers from ES 8 finding notes (mc_notes)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))
import impervanotes as n  # noqa: E402

G1 = "11111111-2222-3333-4444-555555555555"
G2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NOTES = [
    {"notable_id": G1 + "@@notable@@time1793804470", "create_time": 100.5,
     "content": "ITHM%201234567%20%7C%20Sev%203%20%7C%20TEAM%20%7C%20WAF%20attack%20%5BAbC123%5D"},
    {"notable_id": G1 + "@@notable@@time1793804470", "create_time": 200.0,
     "content": "Internal%20Use%20Only%20:%20RE:%20ITHM%201234567%20%7C%20Sev%203%20%5BCompleted%5D%0D%0A"},
    {"notable_id": G2.upper() + "@@notable@@" + G2.replace("-", ""), "create_time": 50,
     "content": "ithm-7654321%20and%20ITHM%207654322"},
    {"notable_id": None, "content": "ITHM%201"},
    {"notable_id": G1 + "@@notable@@x", "content": "no incident number here"},
]


class TestNotes(unittest.TestCase):
    def test_ithm_numbers(self):
        self.assertEqual(n.ithm_numbers(NOTES[0]["content"]), ["ITHM 1234567"])
        self.assertEqual(n.ithm_numbers(NOTES[2]["content"]), ["ITHM 7654321", "ITHM 7654322"])
        self.assertEqual(n.ithm_numbers(""), [])

    def test_rows_grouped_by_finding_guid(self):
        rows = {r["finding_guid"]: r for r in n.notes_to_rows(NOTES)}
        self.assertEqual(sorted(rows), [G1, G2])                       # case-insensitive guid
        self.assertEqual(rows[G1]["ithm"], "ITHM 1234567")             # duplicate note -> once
        self.assertEqual(rows[G1]["note_time"], 200.0)
        self.assertEqual(rows[G2]["ithm"], "ITHM 7654321, ITHM 7654322")


if __name__ == "__main__":
    unittest.main()
