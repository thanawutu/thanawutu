"""Cloud provider IPs (AWS, Google Cloud, ...) are never blocked: ip_owner + impervablock."""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin"))

import ip_owner  # noqa: E402

WORDS = "amazon|aws|google|microsoft|azure|cloudflare|akamai|fastly|oracle|alibaba|tencent|ibm"


class Log(object):
    def __init__(self):
        self.lines = []

    def info(self, msg, *a):
        self.lines.append(msg % a)

    error = warning = info


def vt_info(owner, status="ok"):
    return {"vt_status": status, "vt_as_owner": owner, "vt_asn": "1"}


class TestMatch(unittest.TestCase):
    def test_provider_words(self):
        rx = ip_owner.cloud_regex(WORDS)
        for owner in ("Amazon.com, Inc.", "AMAZON-02", "GOOGLE-CLOUD-PLATFORM", "Google LLC",
                      "Microsoft Corporation", "Cloudflare, Inc.", "Alibaba (US) Technology Co., Ltd.",
                      "Oracle Corporation", "Akamai Technologies, Inc.", "Tencent Building"):
            self.assertEqual(ip_owner.cloud_owner(owner, rx), owner, owner)
        for owner in ("DigitalOcean, LLC", "Lawson Inc", "TOT Public Company Limited", "OVH SAS",
                      "Advanced Wireless Network Company Limited", "-", "", None):
            self.assertIsNone(ip_owner.cloud_owner(owner, rx), owner)

    def test_empty_list_is_off(self):
        self.assertIsNone(ip_owner.cloud_regex(""))
        self.assertIsNone(ip_owner.cloud_regex(None))
        self.assertIsNone(ip_owner.cloud_owner("Amazon.com", None))

    def test_lookup_ip(self):
        self.assertEqual(ip_owner.lookup_ip("54.245.198.114"), "54.245.198.114")
        self.assertEqual(ip_owner.lookup_ip("54.245.198.0/24"), "54.245.198.0")
        self.assertEqual(ip_owner.lookup_ip("2001:db8::/48"), "2001:db8::")
        self.assertIsNone(ip_owner.lookup_ip("not-an-ip"))

    def test_macro_has_the_same_words(self):
        root = os.path.join(HERE, "..", "TA-imperva-ioc-block", "default")
        conf = open(os.path.join(root, "imperva.conf"), encoding="utf-8").read()
        macros = open(os.path.join(root, "macros.conf"), encoding="utf-8").read()
        self.assertIn("cloud_providers = " + WORDS + "\n", conf)
        self.assertIn('definition = "\\b(%s)\\b"' % WORDS, macros)


class TestSplit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "var", "run", "splunk"))
        os.environ["SPLUNK_HOME"] = self.tmp
        self.kv, self.asked, self.log = {}, [], Log()
        ip_owner.kv_query = lambda sk, col, q: [self.kv[k] for k in q["_key"]["$in"] if k in self.kv]
        ip_owner.kv_upsert = lambda sk, docs, col=None: [self.kv.__setitem__(d["_key"], dict(d)) for d in docs]
        self.vt = {}
        self.fail = False

        def lookup(sk, iconf, vconf, ips):
            self.asked.append(list(ips))
            if self.fail:
                raise RuntimeError("SOAR down")
            return dict((ip, self.vt[ip]) for ip in ips if ip in self.vt)
        ip_owner._vt_lookup = lookup

    def cached(self, ip, owner):
        self.kv[ip_owner.cache_key_ip(ip)] = {"_key": ip_owner.cache_key_ip(ip), "ts": time.time(),
                                             "data": json.dumps(vt_info(owner))}

    def split(self, ips, **conf):
        iconf = dict({"cloud_providers": WORDS}, **conf)
        return ip_owner.split_cloud("k", iconf, {}, ips, self.log)

    def test_cached_owner(self):
        self.cached("54.245.198.114", "Amazon.com, Inc.")
        self.cached("211.24.84.19", "TM Net, Internet Service Provider")
        acc, rej, unk = self.split(["54.245.198.114", "211.24.84.19"])
        self.assertEqual(acc, ["211.24.84.19"])
        self.assertEqual(rej, [("54.245.198.114", ip_owner.REJECT_REASON % "Amazon.com, Inc.")])
        self.assertEqual(unk, set())
        self.assertEqual(self.asked, [])           # no VirusTotal call when cached

    def test_lookup_then_cache(self):
        self.vt = {"35.240.10.8": vt_info("Google LLC"), "203.0.113.10": vt_info("Example ISP")}
        acc, rej, unk = self.split(["35.240.10.8", "203.0.113.10"])
        self.assertEqual((acc, [r[0] for r in rej], unk), (["203.0.113.10"], ["35.240.10.8"], set()))
        self.assertEqual(self.asked, [["203.0.113.10", "35.240.10.8"]])
        self.assertIn(ip_owner.cache_key_ip("35.240.10.8"), self.kv)   # shared with the dashboards
        self.asked = []
        self.split(["35.240.10.8"])
        self.assertEqual(self.asked, [])           # second time from the cache

    def test_cidr_uses_first_address(self):
        self.cached("52.88.0.0", "AMAZON-02")
        acc, rej, unk = self.split(["52.88.0.0/24"])
        self.assertEqual((acc, [r[0] for r in rej]), ([], ["52.88.0.0/24"]))

    def test_unknown_owner_is_fail_open(self):
        self.fail = True
        acc, rej, unk = self.split(["198.51.100.7"])
        self.assertEqual((acc, rej, unk), (["198.51.100.7"], [], {"198.51.100.7"}))
        self.assertTrue(any("lookup failed" in x for x in self.log.lines))
        self.fail = False
        self.vt = {"198.51.100.8": {"vt_status": "rate_limited"}}
        acc, rej, unk = self.split(["198.51.100.8"])
        self.assertEqual(unk, {"198.51.100.8"})

    def test_lookup_limit(self):
        self.vt = dict(("192.0.2.%d" % i, vt_info("Example ISP")) for i in range(1, 7))
        acc, rej, unk = self.split(["192.0.2.%d" % i for i in range(1, 7)], cloud_check_max_lookups="2")
        self.assertEqual(len(self.asked[0]), 2)
        self.assertEqual(len(acc), 6)
        self.assertEqual(len(unk), 4)

    def test_check_off(self):
        acc, rej, unk = ip_owner.split_cloud("k", {"cloud_providers": ""}, {}, ["54.245.198.114"], self.log)
        self.assertEqual((acc, rej, unk), (["54.245.198.114"], [], set()))
        self.assertEqual(self.asked, [])


class FakeBackend(object):
    mode = "soar"

    def __init__(self):
        self.calls = []

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        self.calls.append((action, list(ips)))
        return [{"ip": ip, "site_id": "2169031", "status": "blocked" if action == "block" else "unblocked",
                 "verified_in_waf": "yes", "detail": "ok"} for ip in ips]


class TestBlockCommand(unittest.TestCase):
    def setUp(self):
        import impervablock as c
        self.c, self.out, self.reg = c, {}, {}
        self.owner = {"54.245.198.114": "Amazon.com, Inc.", "211.24.84.19": "TM Net", "77.88.8.8": None}
        c.load_conf_stanza = lambda sk, conf, stanza: ({"max_ips_per_action": "50", "cloud_providers": WORDS}
                                                       if stanza == "settings" else {})
        c.load_credential = lambda *a: ("u", "p")
        c.kv_get = lambda k, key: self.reg.get(key)
        c.kv_upsert = lambda k, docs: [self.reg.__setitem__(d["_key"], d) for d in docs]
        c.si.getOrganizedResults = lambda: ([], None, {"sessionKey": "k", "owner": "alice"})
        c.si.outputResults = lambda r: self.out.__setitem__("rows", r)
        c.si.generateErrorResults = lambda m: self.out.__setitem__("err", m)
        c.get_logger = lambda *a: Log()
        self.backend = FakeBackend()
        c.get_backend = lambda *a, **k: self.backend
        self.saved = c.ip_owner.owners
        c.ip_owner.owners = lambda sk, iconf, vconf, ips, log, max_lookups=4: dict((ip, self.owner.get(ip)) for ip in ips)

    def tearDown(self):
        self.c.ip_owner.owners = self.saved

    def run_(self, *argv):
        self.out.clear()
        sys.argv = ["impervablock.py"] + list(argv)
        self.c.main()
        return self.out.get("rows") or self.out

    def test_cloud_rejected_others_blocked(self):
        rows = self.run_("action=block", 'ip="54.245.198.114,', '211.24.84.19,', '77.88.8.8"',
                         "incident_no=1000101", "description=x")
        by = dict((r["ip"], r) for r in rows)
        self.assertEqual(by["54.245.198.114"]["status"], "rejected")
        self.assertIn("cloud provider IP (Amazon.com, Inc.)", by["54.245.198.114"]["detail"])
        self.assertEqual(by["211.24.84.19"]["status"], "blocked")
        self.assertEqual(by["211.24.84.19"]["detail"], "ok")
        self.assertEqual(by["77.88.8.8"]["status"], "blocked")
        self.assertIn("owner of the IP unknown", by["77.88.8.8"]["detail"])
        self.assertEqual(self.backend.calls, [("block", ["211.24.84.19", "77.88.8.8"])])
        self.assertNotIn("2169031_54.245.198.114", self.reg)

    def test_only_cloud_ips(self):
        rows = self.run_("action=block", "ip=54.245.198.114")
        self.assertEqual([r["status"] for r in rows], ["rejected"])
        self.assertEqual(self.backend.calls, [])

    def test_unblock_not_checked(self):
        rows = self.run_("action=unblock", "ip=54.245.198.114")
        self.assertEqual([r["status"] for r in rows], ["unblocked"])


if __name__ == "__main__":
    unittest.main()
