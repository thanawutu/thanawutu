# -*- coding: utf-8 -*-
"""Unit tests for the Rapid7 VM CVE Response app (no Splunk needed).

Run:  python3 -m unittest discover -s splunk/tests -v
"""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

BIN = os.path.join(os.path.dirname(__file__), "..", "rapid7_vm_cve", "bin")
sys.path.insert(0, os.path.abspath(BIN))

import r7_lib as L  # noqa: E402
import r7_query as Q  # noqa: E402


class VersionTests(unittest.TestCase):
    def test_numeric_compare(self):
        self.assertEqual(L.compare_versions("2.4.10", "2.4.9"), 1)
        self.assertEqual(L.compare_versions("9.10", "9.8"), 1)
        self.assertEqual(L.compare_versions("8.1.34", "8.1.34"), 0)
        self.assertEqual(L.compare_versions("8.7p1", "9.8"), -1)
        self.assertEqual(L.compare_versions("2.4.62-1.el9", "2.4.63"), -1)

    def test_ranges(self):
        r = "8.1 < 8.1.34 ; 8.2 < 8.2.29 ; 8.3 < 8.3.27"
        self.assertTrue(L.in_range("8.1.27", r))
        self.assertFalse(L.in_range("8.1.34", r))
        self.assertTrue(L.in_range("8.2.20", r))
        self.assertFalse(L.in_range("7.4.33", r))   # branch not listed
        self.assertFalse(L.in_range("8.3.27", r))
        self.assertTrue(L.in_range("2.4.58", "< 2.4.63"))
        self.assertTrue(L.in_range("7.2.5", ">= 7.2.0 <= 7.2.10"))
        self.assertTrue(L.in_range("7.2.10", "7.2.0 - 7.2.10"))
        self.assertTrue(L.in_range("9.0.83", "9.0.*"))
        self.assertFalse(L.in_range("9.1.1", "9.0.*"))
        self.assertTrue(L.in_range("9.10", "<= 9.10"))
        with self.assertRaises(ValueError):
            L.parse_ranges("lower than nine")

    def test_range_status_distro(self):
        self.assertEqual(L.range_status("2.4.6-99.el7_9.1", "< 2.4.63"), "Check advisory")
        self.assertEqual(L.range_status("2.4.58", "< 2.4.63"), "In range")
        self.assertEqual(L.range_status("2.4.66", "< 2.4.63"), "Not in range")
        self.assertEqual(L.range_status("", "< 2.4.63"), "Unknown")

    def test_software_match(self):
        self.assertTrue(L.software_matches("php", "PHP Group", "PHP"))
        self.assertTrue(L.software_matches("Apache*HTTP*", "Apache", "HTTP Server"))
        self.assertFalse(L.software_matches("Apache*HTTP*", "Apache", "Tomcat"))


class VerdictTests(unittest.TestCase):
    ANN = "2026-11-18"
    ADDED = "2026-11-19"

    def v(self, **row):
        base = {"version": "8.1.27", "ranges": "8.1 < 8.1.34", "last_scan": "2026-11-20T01:00:00Z",
                "credentialed": True, "r7_vulnerable": False}
        base.update(row)
        has_check = row.pop("has_check", True) if "has_check" in row else True
        base.pop("has_check", None)
        return L.verdict(base, self.ANN, self.ADDED, has_check, 7)

    def test_confirmed_by_rapid7(self):
        self.assertEqual(self.v(r7_vulnerable=True)["verdict"], "Affected")
        r = self.v(r7_vulnerable=False, version="8.1.34")
        self.assertEqual((r["r7_result"], r["verdict"]), ("Not vulnerable", "Not affected"))

    def test_scan_before_check_added_uses_version(self):
        r = self.v(last_scan="2026-11-15T21:30:00Z")
        self.assertEqual(r["r7_result"], "Not run: scan before check added")
        self.assertEqual((r["freshness"], r["verdict"]), ("OK", "Likely affected"))

    def test_stale(self):
        r = self.v(last_scan="2026-10-08T23:05:00Z")
        self.assertEqual((r["freshness"], r["verdict"]), ("Stale", "Unknown"))

    def test_no_credentials(self):
        r = self.v(credentialed=False, version="")
        self.assertEqual(r["verdict"], "Unknown")
        self.assertIn("credentials", r["action"])

    def test_no_check_yet(self):
        r = L.verdict({"version": "2.4.58", "ranges": "< 2.4.63", "last_scan": "2026-11-17",
                       "credentialed": True, "r7_vulnerable": False}, "2026-11-18", "", False, 7)
        self.assertEqual((r["r7_result"], r["verdict"]), ("No Rapid7 check yet", "Likely affected"))

    def test_findings_not_collected(self):
        r = self.v(r7_vulnerable=None, last_scan="2026-11-17")
        self.assertEqual(r["r7_result"], "Finding data not collected")
        self.assertEqual(r["verdict"], "Likely affected")


class CompareTests(unittest.TestCase):
    def c(self, before, after, has_check=True):
        return L.compare_result(before, after, has_check)

    def test_fixed_by_update(self):
        r = self.c({"installed": True, "version": "8.1.27", "r7_vulnerable": True},
                   {"installed": True, "version": "8.1.34", "r7_vulnerable": False, "assessed": True, "credentialed": True})
        self.assertEqual((r["installed"], r["version_change"], r["cve_result"]), ("Yes", "Updated", "CVE fixed"))

    def test_fixed_by_removal(self):
        r = self.c({"installed": True, "version": "7.4.33", "r7_vulnerable": True},
                   {"installed": False, "version": "", "r7_vulnerable": False, "assessed": True, "credentialed": True})
        self.assertEqual((r["installed"], r["version_change"], r["cve_result"]), ("Removed", "Removed", "CVE fixed"))

    def test_login_failed_is_not_fixed(self):
        r = self.c({"installed": True, "version": "8.1.27", "r7_vulnerable": True},
                   {"installed": False, "version": "", "r7_vulnerable": False, "assessed": True, "credentialed": False})
        self.assertEqual(r["cve_result"], "Not verified")
        self.assertEqual(r["installed"], "Unknown")

    def test_not_assessed(self):
        r = self.c({"installed": True, "version": "8.2.20", "r7_vulnerable": True},
                   {"installed": True, "version": "8.2.20", "r7_vulnerable": None, "assessed": False, "credentialed": True})
        self.assertEqual(r["cve_result"], "Not verified")

    def test_newly_found_and_still(self):
        self.assertEqual(self.c({"installed": True, "version": "8.2.20", "r7_vulnerable": None},
                                {"installed": True, "version": "8.2.20", "r7_vulnerable": True, "assessed": True,
                                 "credentialed": True})["cve_result"], "Newly found")
        r = self.c({"installed": True, "version": "8.2.20", "r7_vulnerable": True},
                   {"installed": True, "version": "8.2.20", "r7_vulnerable": True, "assessed": True, "credentialed": True})
        self.assertEqual((r["version_change"], r["cve_result"]), ("No change", "Still vulnerable"))

    def test_no_check(self):
        r = self.c({"installed": True, "version": "7.2.8"},
                   {"installed": True, "version": "7.2.11", "assessed": True, "credentialed": True}, has_check=False)
        self.assertEqual((r["version_change"], r["cve_result"]), ("Updated", "No Rapid7 check yet"))


# --------------------------------------------------------------------------
# Fake Rapid7 console over HTTP
# --------------------------------------------------------------------------

class FakeConsole(BaseHTTPRequestHandler):
    posted = []
    scan_status = {"901": "running"}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = parse_qs(u.query)
        page = int(q.get("page", ["0"])[0])
        p = u.path
        if self.headers.get("Authorization") != "Basic dXNlcjpwYXNz":
            return self._send(401, {"message": "unauthorized"})
        if p == "/api/3/sites":
            return self._send(200, {"resources": [{"id": 1, "name": "DC1-Servers"}, {"id": 2, "name": "DC2-Servers"}],
                                    "page": {"totalPages": 1}})
        if p == "/api/3/sites/1/assets":
            res = [{"id": 11 + page, "ip": "10.0.0.%d" % (11 + page), "hostName": "PRDWEB0%d" % (1 + page),
                    "history": [{"type": "SCAN", "date": "2026-11-19T22:10:00.000Z", "scanId": 500}],
                    "osFingerprint": {"vendor": "Red Hat", "product": "Enterprise Linux", "version": "9.4"}}]
            return self._send(200, {"resources": res, "page": {"totalPages": 2}})
        if p == "/api/3/sites/2/assets":
            return self._send(200, {"resources": [{"id": 21, "ip": "10.0.1.21", "hostName": "DRWEB01",
                                                   "history": []}], "page": {"totalPages": 1}})
        if p.startswith("/api/3/assets/") and p.endswith("/software"):
            aid = p.split("/")[4]
            if aid == "21":
                return self._send(200, {"resources": []})
            ver = "8.1.34" if aid == "11" else "8.2.20"
            return self._send(200, {"resources": [{"vendor": "PHP", "product": "PHP", "version": ver,
                                                   "cpe": {"v2.3": "cpe:2.3:a:php:php:%s" % ver}},
                                                  {"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.7p1"}]})
        if "/vulnerabilities/" in p:
            aid = p.split("/")[4]
            if aid == "12":
                return self._send(200, {"id": "php-cve-2026-20517", "status": "vulnerable"})
            return self._send(404, {"message": "not found"})
        if p.startswith("/api/3/assets/") and p.endswith("/vulnerabilities"):
            return self._send(200, {"resources": [{"id": "php-cve-2026-20517"}], "page": {"totalPages": 1}})
        if p.startswith("/api/3/assets/"):
            aid = p.split("/")[4]
            hist = [{"type": "SCAN", "date": "2026-11-20T10:40:00Z", "scanId": 901}] if aid != "21" else []
            return self._send(200, {"id": int(aid), "history": hist})
        if p.startswith("/api/3/scans/"):
            sid = p.split("/")[-1]
            return self._send(200, {"id": int(sid), "status": FakeConsole.scan_status.get(sid, "finished"),
                                    "engineName": "engine-dc1"})
        if p == "/api/3/vulnerabilities":
            res = [{"id": "php-cve-2026-20517", "title": "PHP issue", "cves": ["CVE-2026-20517"],
                    "severity": "Critical", "cvss": {"v3": {"score": 9.8}}, "added": "2026-11-19",
                    "published": "2026-11-18", "modified": "2026-11-23"},
                   {"id": "old-check", "cves": [], "modified": "2020-01-01"}]
            return self._send(200, {"resources": res, "page": {"totalPages": 5}})
        return self._send(404, {"message": "no route " + p})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n).decode())
        FakeConsole.posted.append((self.path, body))
        if self.path.startswith("/api/3/sites/") and self.path.endswith("/scans"):
            return self._send(201, {"id": 901})
        return self._send(404, {})


class ConsoleCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeConsole)
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()
        cls.client = L.Rapid7Client("http://127.0.0.1:%d" % cls.srv.server_port, "user", "pass",
                                    verify_ssl=False, retries=0)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()


class ClientTests(ConsoleCase):
    def test_paging_and_404(self):
        assets = list(self.client.site_assets(1))
        self.assertEqual([a["id"] for a in assets], [11, 12])
        self.assertTrue(self.client.asset_has_vuln(12, "php-cve-2026-20517"))
        self.assertFalse(self.client.asset_has_vuln(11, "php-cve-2026-20517"))
        self.assertEqual(L.asset_last_scan(assets[0]).isoformat(), "2026-11-19T22:10:00")

    def test_bad_password(self):
        bad = L.Rapid7Client(self.client.base, "user", "wrong", verify_ssl=False, retries=0)
        with self.assertRaises(L.Rapid7Error) as cm:
            bad.sites()
        self.assertEqual(cm.exception.status, 401)

    def test_start_scan_body(self):
        FakeConsole.posted[:] = []
        sid = self.client.start_site_scan(1, ["10.0.0.11"], "Splunk JOB-1 CVE-2026-20517", "full-audit")
        self.assertEqual(sid, 901)
        self.assertEqual(FakeConsole.posted[0], ("/api/3/sites/1/scans",
                                                 {"name": "Splunk JOB-1 CVE-2026-20517", "hosts": ["10.0.0.11"],
                                                  "templateId": "full-audit"}))


class FakeEW(object):
    def __init__(self):
        self.events, self.logs = [], []

    def write_event(self, ev):
        self.events.append(ev)

    def log(self, level, msg):
        self.logs.append((level, msg))


def _events(ew, st):
    return [json.loads(e.data) for e in ew.events if e.sourceType == st]


class CollectorTests(ConsoleCase):
    SETTINGS = dict(L.load_settings(None), threads="2", page_size="500",
                    vuln_content_first_days="30", vuln_content_overlap_days="2", vuln_content_max_pages="5")

    def test_software_collector(self):
        from r7_collect import SoftwareCollector
        ew = FakeEW()
        n = SoftwareCollector().collect(self.client, self.SETTINGS, ew, "rapid7", "RUN1", "", "daily")
        sites = _events(ew, "rapid7:vm:asset_site")
        sw = _events(ew, "rapid7:vm:software")
        self.assertEqual(sorted(s["asset_id"] for s in sites), ["11", "12", "21"])
        dr = [s for s in sites if s["asset_id"] == "21"][0]
        self.assertEqual((dr["credentialed"], dr["site_name"], dr["last_scan"]), (False, "DC2-Servers", ""))
        php = [s for s in sw if s["product"] == "PHP"]
        self.assertEqual(sorted(p["version"] for p in php), ["8.1.34", "8.2.20"])
        os_rows = [s for s in sw if s["type"] == "Operating System"]
        self.assertEqual(len(os_rows), 2)
        self.assertTrue(all(e["run_id"] == "RUN1" for e in sites + sw))
        self.assertTrue(all(e.data.endswith("\n") for e in ew.events))  # one event per line for Splunk
        self.assertEqual(n, len(ew.events))

    def test_vuln_content_stops_at_cutoff(self):
        import tempfile
        from r7_collect import VulnContentCollector
        ew = FakeEW()
        d = tempfile.mkdtemp()
        n = VulnContentCollector().collect(self.client, self.SETTINGS, ew, "rapid7", "RUN1", d, "rapid7_vuln_content://x")
        rows = _events(ew, "rapid7:vm:vuln_content")
        self.assertEqual(n, 1)
        self.assertEqual((rows[0]["vuln_id"], rows[0]["cves"], rows[0]["cvss_v3"]),
                         ("php-cve-2026-20517", ["CVE-2026-20517"], 9.8))
        self.assertTrue(os.listdir(d))  # checkpoint written

    def test_asset_vulns(self):
        from r7_collect import AssetVulnCollector
        ew = FakeEW()
        AssetVulnCollector().collect(self.client, self.SETTINGS, ew, "rapid7", "RUN2", "", "daily")
        rows = _events(ew, "rapid7:vm:asset_vuln")
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["vuln_ids"], ["php-cve-2026-20517"])


# --------------------------------------------------------------------------
# Poller state machine with the fake console
# --------------------------------------------------------------------------

class PollerTests(ConsoleCase):
    def setUp(self):
        import r7scanpoll
        self.mod = r7scanpoll
        self.settings = dict(L.load_settings(None), max_servers_per_job="50", max_job_hours="12")
        self.job = {
            "job_id": "JOB-1", "status": "Requested", "cve": "CVE-2026-20517", "software": "PHP",
            "ranges": "8.1 < 8.1.34 ; 8.2 < 8.2.29", "has_check": True, "vuln_ids": ["php-cve-2026-20517"],
            "launched_by": "analyst1", "created": L.iso(L.utcnow()), "template_id": "",
            "groups": [{"site_id": "1", "site_name": "DC1-Servers", "hosts": ["10.0.0.11", "10.0.0.12"],
                        "scan_id": "", "scan_status": "", "error": ""},
                       {"site_id": "2", "site_name": "DC2-Servers", "hosts": ["10.0.1.21"],
                        "scan_id": "", "scan_status": "", "error": ""}],
            "targets": [
                {"asset_id": "11", "hostname": "PRDWEB01", "ip": "10.0.0.11", "env_label": "Prod · DC",
                 "before": {"installed": True, "version": "8.1.27", "r7_vulnerable": True}},
                {"asset_id": "12", "hostname": "PRDWEB02", "ip": "10.0.0.12", "env_label": "Prod · DC",
                 "before": {"installed": True, "version": "8.2.20", "r7_vulnerable": None}},
                {"asset_id": "21", "hostname": "DRWEB01", "ip": "10.0.1.21", "env_label": "Prod · DR",
                 "before": {"installed": True, "version": "8.2.20", "r7_vulnerable": True}}],
            "results": []}

    def poller(self):
        p = self.mod.R7ScanPoll.__new__(self.mod.R7ScanPoll)
        return p

    def test_full_cycle(self):
        p = self.poller()
        orig = L.user_capabilities
        L.user_capabilities = lambda svc, user: {"rapid7_cve_rescan"}
        try:
            p._launch(None, self.settings, self.client, self.job)
        finally:
            L.user_capabilities = orig
        self.assertEqual(self.job["status"], "Running")
        self.assertEqual([g["scan_id"] for g in self.job["groups"]], ["901", "901"])

        FakeConsole.scan_status = {"901": "running"}
        p._poll(self.settings, self.client, self.job)
        self.assertEqual(self.job["status"], "Running")

        FakeConsole.scan_status = {"901": "finished"}
        p._poll(self.settings, self.client, self.job)
        self.assertEqual(self.job["status"], "Collecting")

        p._collect(self.client, self.job)
        self.assertEqual(self.job["status"], "Finished")
        res = dict((r["hostname"], r) for r in self.job["results"])
        self.assertEqual((res["PRDWEB01"]["version_change"], res["PRDWEB01"]["cve_result"]), ("Updated", "CVE fixed"))
        self.assertEqual(res["PRDWEB02"]["cve_result"], "Newly found")
        self.assertEqual(res["DRWEB01"]["cve_result"], "Not verified")  # not assessed, no software data

    def test_launch_requires_capability(self):
        p = self.poller()
        orig = L.user_capabilities
        L.user_capabilities = lambda svc, user: set()
        try:
            with self.assertRaises(PermissionError):
                p._launch(None, self.settings, self.client, self.job)
        finally:
            L.user_capabilities = orig


# --------------------------------------------------------------------------
# Query engine with canned search results
# --------------------------------------------------------------------------

class QueryTests(unittest.TestCase):
    def setUp(self):
        self.orig = L.oneshot

        def fake(service, spl, earliest="-3d", latest="now", count=0):
            if "rapid7:vm:vuln_content" in spl:
                return [{"vuln_id": "php-cve-2026-20517", "title": "PHP", "severity": "Critical", "cvss_v3": "9.8",
                         "added": "2026-11-19", "published": "2026-11-18"}]
            if "stats latest(run_id)" in spl:
                return [{"run_id": "R1"}]
            if 'sourcetype="rapid7:vm:asset_site"' in spl:
                mk = lambda aid, host, env, grp, status, scan, cred, site: {  # noqa: E731
                    "asset_id": aid, "hostname": host, "ip": "10.0.0." + aid, "env_label": env, "env_group": grp,
                    "cmdb_status": status, "last_scan": scan, "credentialed": cred, "site_id": site,
                    "site_name": "S" + site, "appname": ["Customer portal"], "cmdb_host": host}
                return [mk("1", "PRDWEB01", "Prod · DC", "Prod", "WORKING_ACTIVE", "2026-11-20T01:00:00Z", "true", "1"),
                        mk("2", "PRDAPI03", "Prod · DC", "Prod", "WORKING_ACTIVE", "2026-10-08T23:05:00Z", "true", "1"),
                        mk("3", "UATWEB01", "Non-prod · UAT", "Non-prod", "WORKING_ACTIVE", "2026-11-20T08:00:00Z", "true", "3"),
                        mk("4", "OLDWEB", "Prod · DC", "Prod", "DECOMMISSION", "2026-11-19T20:40:00Z", "true", "1")]
            if 'sourcetype="rapid7:vm:software"' in spl:
                return [{"asset_id": "1", "version": "8.1.27", "vendor": "PHP", "product": "PHP"},
                        {"asset_id": "2", "version": "8.1.20", "vendor": "PHP", "product": "PHP"},
                        {"asset_id": "3", "version": "8.3.27", "vendor": "PHP", "product": "PHP"},
                        {"asset_id": "4", "version": "8.1.20", "vendor": "PHP", "product": "PHP"}]
            if 'sourcetype="rapid7:vm:asset_vuln"' in spl:
                return [{"asset_id": "1", "vuln_ids": ["php-cve-2026-20517", "other"]}]
            raise AssertionError("unexpected search: " + spl)
        L.oneshot = fake

    def tearDown(self):
        L.oneshot = self.orig

    def test_build_rows(self):
        settings = dict(L.load_settings(None))
        rows, info = Q.build_rows(None, settings, {"cve": "CVE-2026-20517", "software": "php",
                                                   "ranges": "8.1 < 8.1.34 ; 8.3 < 8.3.27", "announced": "2026-11-18"})
        by = dict((r["hostname"], r) for r in rows)
        self.assertTrue(info["has_check"])
        self.assertNotIn("OLDWEB", by)  # DECOMMISSION hidden
        self.assertEqual(by["PRDWEB01"]["verdict"], "Affected")
        self.assertEqual((by["PRDAPI03"]["freshness"], by["PRDAPI03"]["verdict"]), ("Stale", "Unknown"))
        self.assertEqual(by["UATWEB01"]["verdict"], "Not affected")

        rows, _ = Q.build_rows(None, settings, {"cve": "CVE-2026-20517", "software": "php", "ranges": "8.1 < 8.1.34",
                                                "env": ["Non-prod"]})
        self.assertEqual([r["hostname"] for r in rows], ["UATWEB01"])

        rows, _ = Q.build_rows(None, settings, {"cve": "CVE-2026-20517", "software": "php", "include_inactive": True})
        self.assertIn("OLDWEB", [r["hostname"] for r in rows])


if __name__ == "__main__":
    unittest.main()


class PasswordLookupTests(unittest.TestCase):
    class Svc(object):
        def __init__(self, entries):
            self.entries, self.calls = entries, []

        def get(self, path, **kw):
            self.calls.append((path, kw))
            body = json.dumps({"entry": self.entries}).encode()

            class R(object):
                class B(object):
                    def read(self_inner):
                        return body
                body_ = B()
            r = R()
            r.body = R.B()
            return r

    def test_reuse_other_app_credential(self):
        svc = self.Svc([
            {"content": {"realm": "rapid7_insightvm_121", "username": "apisiem_va", "clear_password": "pw1"},
             "acl": {"app": "rapid7_insightvm_app", "sharing": "app"}},
            {"content": {"realm": "other", "username": "apisiem_va", "clear_password": "nope"},
             "acl": {"app": "rapid7_insightvm_app", "sharing": "app"}}])
        self.assertEqual(L.get_password(svc, "apisiem_va", "rapid7_insightvm_app", "rapid7_insightvm_121"), "pw1")
        self.assertEqual(svc.calls[0][1]["app"], "rapid7_insightvm_app")

    def test_own_realm_default(self):
        svc = self.Svc([
            {"content": {"realm": "rapid7_insightvm_121", "username": "u", "clear_password": "x"}, "acl": {}},
            {"content": {"realm": "rapid7_vm_cve", "username": "u", "clear_password": "mine"}, "acl": {}}])
        self.assertEqual(L.get_password(svc, "u"), "mine")
        with self.assertRaises(L.Rapid7Error):
            L.get_password(svc, "nobody-here")
