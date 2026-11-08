"""ทดสอบ logic การกรอง/แปลง IOC โดยไม่ต้องต่อ MISP/Splunk:  python3 -m unittest -v"""
import os
import tempfile
import time
import unittest

import misp_to_splunk as m


def cfg(allow_path):
    return m.Settings(
        misp_url="https://misp", misp_key="x", misp_verify=True, proxy=None,
        types=list(m.TYPE_MAP), lookback="1h", initial_lookback="90d", page_size=1000,
        published_only=True, to_ids_only=True, enforce_warninglist=True,
        allowed_tlp={"tlp:clear", "tlp:white", "tlp:green", "tlp:amber"},
        exclude_tags={"tlp:red", "false-positive"}, allowlist_file=allow_path,
        ttl_days={"ip": 30, "domain": 90, "url": 90, "hash": 365, "email": 90},
        splunk_url="https://splunk:8089", splunk_token="t", splunk_app="TA", collection="c",
        splunk_verify=True)


class T(unittest.TestCase):
    def setUp(self):
        fd, self.allow = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write("203.0.113.0/24\nexamplebank.co.th\n")
        self.cfg = cfg(self.allow)
        self.al = m.Allowlist(self.allow)
        self.now = int(time.time())

    def tearDown(self):
        os.remove(self.allow)

    def n(self, **attr):
        base = {"uuid": "u1", "type": "ip-dst", "value": "45.33.32.156", "to_ids": True,
                "timestamp": str(self.now), "Event": {"info": "Phishing", "uuid": "e1"},
                "Tag": [{"name": "tlp:green"}]}
        base.update(attr)
        return m.normalize(base, self.cfg, self.al, m.Stats(), self.now)

    def test_ip_ok(self):
        recs, drop = self.n()
        self.assertEqual(recs[0]["indicator"], "45.33.32.156")
        self.assertEqual(recs[0]["tlp"], "tlp:green")
        self.assertEqual(drop, [])

    def test_composite_domain_ip(self):
        recs, _ = self.n(type="domain|ip", value="Evil.Example.|45.33.32.157")
        self.assertEqual({(r["indicator_type"], r["indicator"]) for r in recs},
                         {("domain", "evil.example"), ("ip", "45.33.32.157")})

    def test_allowlist_cidr_and_subdomain_and_private(self):
        self.assertEqual(self.n(value="203.0.113.5")[0], [])
        self.assertEqual(self.n(value="10.1.1.1")[0], [])
        self.assertEqual(self.n(type="url", value="https://login.examplebank.co.th/x")[0], [])

    def test_red_and_revoked(self):
        recs, drop = self.n(Tag=[{"name": "tlp:red"}])
        self.assertEqual((recs, drop), ([], ["u1:0"]))
        recs, drop = self.n(deleted=True)
        self.assertEqual((recs, drop), ([], ["u1:0"]))
        recs, drop = self.n(to_ids=False)
        self.assertEqual((recs, drop), ([], ["u1:0"]))

    def test_expired(self):
        recs, drop = self.n(timestamp=str(self.now - 40 * 86400))
        self.assertEqual((recs, drop), ([], ["u1:0"]))
        recs, _ = self.n(type="sha256", value="A" * 64, timestamp=str(self.now - 40 * 86400))
        self.assertEqual(recs[0]["indicator"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
