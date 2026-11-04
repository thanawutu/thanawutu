import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stubs"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "TA-imperva-ioc-block", "bin"))
import splunk_helpers as sh  # noqa: E402

K = ("action", "ip", "dry_run", "reason", "threat_actor", "incident_no", "comment")


class TestParseOptions(unittest.TestCase):
    def test_words_split_by_splunk(self):
        # what Splunk hands a legacy command for comment="setup test from Splunk"
        argv = ['action=block', 'ip=1.2.3.4', 'threat_actor=TEST', 'incident_no=TEST-001',
                'comment="setup', 'test', 'from', 'Splunk"']
        o = sh.parse_options(argv, K)
        self.assertEqual(o["comment"], "setup test from Splunk")
        self.assertEqual((o["action"], o["ip"], o["incident_no"]), ("block", "1.2.3.4", "TEST-001"))

    def test_quotes_already_stripped(self):
        o = sh.parse_options(['comment=setup', 'test', 'from', 'Splunk', 'dry_run=true'], K)
        self.assertEqual((o["comment"], o["dry_run"]), ("setup test from Splunk", "true"))

    def test_single_argv_string(self):
        o = sh.parse_options(['reason="Imperva attack: Attack_IP=1.2.3.4, WAF_Action=blocked"'], K)
        self.assertEqual(o["reason"], "Imperva attack: Attack_IP=1.2.3.4, WAF_Action=blocked")

    def test_unknown_key_value_stays_in_text(self):
        o = sh.parse_options(['comment="see', 'url=http://x', 'for', 'details"', 'ip=8.8.8.8'], K)
        self.assertEqual((o["comment"], o["ip"]), ("see url=http://x for details", "8.8.8.8"))

    def test_apostrophe(self):
        o = sh.parse_options(['comment="can\'t', 'reach"', 'ip=8.8.8.8'], K)
        self.assertEqual((o["comment"], o["ip"]), ("can't reach", "8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
