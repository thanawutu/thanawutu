"""V2: cloud provider IPs MAY be blocked (short block); ip_owner gives the owner to Auto unblock."""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))

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
        for owner in ("Amazon.com, Inc.", "AMAZON-02", "GOOGLE-CLOUD-PLATFORM", "Microsoft Corporation"):
            self.assertEqual(ip_owner.cloud_owner(owner, rx), owner)
        for owner in ("DigitalOcean, LLC", "Lawson Inc", "TOT Public Company Limited", "-", None):
            self.assertIsNone(ip_owner.cloud_owner(owner, rx))

    def test_macro_has_the_same_words(self):
        root = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "default")
        conf = open(os.path.join(root, "imperva.conf"), encoding="utf-8").read()
        macros = open(os.path.join(root, "macros.conf"), encoding="utf-8").read()
        self.assertIn("cloud_providers = " + WORDS + "\n", conf)
        self.assertIn('definition = "\\b(%s)\\b"' % WORDS, macros)
        self.assertNotIn("DO_NOT_BLOCK", macros)          # V2 never overrides the suggestion

    def test_no_reject_left(self):
        self.assertFalse(hasattr(ip_owner, "split_cloud"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "var", "run", "splunk"))
        os.environ["SPLUNK_HOME"] = self.tmp
        self.kv, self.asked, self.log = {}, [], Log()
        ip_owner.kv_query = lambda sk, col, q: [self.kv[k] for k in q["_key"]["$in"] if k in self.kv]
        ip_owner.kv_upsert = lambda sk, docs, col=None: [self.kv.__setitem__(d["_key"], dict(d)) for d in docs]
        self.vt = {}

        def lookup(sk, iconf, vconf, ips):
            self.asked.append(list(ips))
            return dict((ip, self.vt[ip]) for ip in ips if ip in self.vt)
        ip_owner._vt_lookup = lookup

    def cached(self, ip, owner, age=0):
        self.kv[ip_owner.cache_key_ip(ip)] = {"_key": ip_owner.cache_key_ip(ip), "ts": time.time() - age,
                                             "data": json.dumps(vt_info(owner))}


class TestOwners(Base):
    def test_cached_owners_ignore_age_and_never_look_up(self):
        self.cached("54.245.198.114", "Amazon.com, Inc.", age=400 * 86400)
        out = ip_owner.cached_owners("k", ["54.245.198.114", "77.88.8.8"], self.log)
        self.assertEqual(out, {"54.245.198.114": "Amazon.com, Inc.", "77.88.8.8": None})
        self.assertEqual(self.asked, [])

    def test_cloud_notes(self):
        self.cached("54.245.198.114", "Amazon.com, Inc.")
        self.vt = {"35.240.10.8": vt_info("Google LLC"), "77.88.8.8": vt_info("YANDEX LLC")}
        notes = ip_owner.cloud_notes("k", {"cloud_providers": WORDS}, {}, ["54.245.198.114", "35.240.10.8", "77.88.8.8"],
                                     self.log, 7)
        self.assertEqual(sorted(notes), ["35.240.10.8", "54.245.198.114"])
        self.assertIn("unblocked automatically after 7 days without an attack", notes["35.240.10.8"])
        self.assertIn(ip_owner.cache_key_ip("35.240.10.8"), self.kv)      # cached for Auto unblock
        self.assertEqual(ip_owner.cloud_notes("k", {"cloud_providers": ""}, {}, ["54.245.198.114"], self.log, 7), {})

    def test_shared_ip_note(self):
        self.cached("49.228.105.17", "Advanced Wireless Network Company Limited")
        notes = ip_owner.cloud_notes("k", {"cloud_providers": WORDS, "shared_ip_providers": "mobile|wireless"}, {},
                                     ["49.228.105.17"], self.log, 7)
        self.assertEqual(notes["49.228.105.17"],
                         "shared IP (Advanced Wireless Network Company Limited): unblocked automatically after 7 days without an attack")
        self.assertEqual(ip_owner.short_class("Amazon.com", ip_owner.cloud_regex(WORDS), ip_owner.cloud_regex("mobile")), ("cloud", "Amazon.com"))
        self.assertIsNone(ip_owner.short_class("OVH SAS", ip_owner.cloud_regex(WORDS), ip_owner.cloud_regex("mobile")))


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
        self.owner = {"54.245.198.114": "Amazon.com, Inc.", "211.24.84.19": "TM Net"}
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

    def test_cloud_ip_is_blocked_with_a_note(self):
        sys.argv = ["impervablock.py", "action=block", 'ip="54.245.198.114,', '211.24.84.19"', "incident_no=1000101"]
        self.c.main()
        by = dict((r["ip"], r) for r in self.out["rows"])
        self.assertEqual(by["54.245.198.114"]["status"], "blocked")
        self.assertIn("cloud provider IP (Amazon.com, Inc.): unblocked automatically after 7 days", by["54.245.198.114"]["detail"])
        self.assertEqual(by["211.24.84.19"]["detail"], "ok")
        self.assertEqual(self.backend.calls, [("block", ["54.245.198.114", "211.24.84.19"])])
        self.assertIn("2169031_54.245.198.114", self.reg)


if __name__ == "__main__":
    unittest.main()
