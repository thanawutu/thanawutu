# -*- coding: utf-8 -*-
"""End-to-end tests: run the search commands as Splunk would (chunked protocol v2)
against a fake splunkd that answers searches, the KV store and current-context."""
import json
import os
import re
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rapid7_vm_cve", "bin"))


class FakeSplunkd(BaseHTTPRequestHandler):
    kv = {}            # collection -> {key: doc}
    caps = ["search"]
    searches = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def _kv(self, path):
        m = re.search(r"/storage/collections/data/([^/]+)(?:/(.*))?$", path)
        return (m.group(1), unquote(m.group(2)) if m.group(2) else None) if m else (None, None)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path.endswith("/server/info"):
            xml = (b'<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest">'
                   b'<entry><title>server-info</title><content type="text/xml"><s:dict>'
                   b'<s:key name="version">9.2.0</s:key></s:dict></content></entry></feed>')
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(xml)))
            self.end_headers()
            self.wfile.write(xml)
            return
        if u.path.endswith("authentication/current-context"):
            return self._send(200, {"entry": [{"content": {"username": "analyst1", "capabilities": self.caps}}]})
        coll, key = self._kv(u.path)
        if coll:
            docs = self.kv.setdefault(coll, {})
            if key:
                if key not in docs:
                    return self._send(404, {"messages": [{"type": "ERROR", "text": "not found"}]})
                return self._send(200, docs[key])
            items = list(docs.values())
            if "query" in q:
                flt = json.loads(q["query"][0])
                def ok(d):
                    for k, v in flt.items():
                        if isinstance(v, dict) and "$in" in v:
                            if d.get(k) not in v["$in"]:
                                return False
                        elif d.get(k) != v:
                            return False
                    return True
                items = [d for d in items if ok(d)]
            return self._send(200, items)
        return self._send(404, {"messages": [{"type": "ERROR", "text": "no route " + u.path}]})

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        if u.path.rstrip("/").endswith(("/search/jobs", "/search/v2/jobs")):
            form = parse_qs(body)
            spl = form.get("search", [""])[0]
            FakeSplunkd.searches.append(spl)
            return self._send(200, {"results": search_results(spl), "messages": []})
        if u.path.endswith("/batch_save"):
            coll = re.search(r"/storage/collections/data/([^/]+)/batch_save", u.path).group(1)
            for d in json.loads(body):
                self.kv.setdefault(coll, {})[d["_key"]] = d
            return self._send(200, [d["_key"] for d in json.loads(body)])
        return self._send(404, {})

    def do_DELETE(self):
        coll, key = self._kv(urlparse(self.path).path)
        self.kv.get(coll, {}).pop(key, None)
        return self._send(200, {})


def search_results(spl):
    if "inputlookup r7_vuln_catalog_lookup" in spl:
        return [{"vuln_id": "php-cve-2026-20517", "title": "Red Hat: CVE-2026-20517: PHP: issue", "severity": "Critical",
                 "cvss_v3": "9.8", "added": "2026-11-19", "published": "2026-11-18", "cves_str": "CVE-2026-20517"},
                {"vuln_id": "other-check", "title": "x", "severity": "Severe", "cvss_v3": "5", "added": "2026-11-19",
                 "published": "2026-11-18", "cves_str": "CVE-2026-205170"}]
    if "rapid7:vm:vuln_content" in spl:
        return [{"vuln_id": "php-cve-2026-20517", "title": "PHP issue", "severity": "Critical", "cvss_v3": "9.8",
                 "added": "2026-11-19", "published": "2026-11-18"}]
    if "stats latest(run_id)" in spl:
        return [{"run_id": "R1"}]
    if 'sourcetype="rapid7:vm:asset_site"' in spl:
        def mk(aid, host, env, grp, status, scan, site):
            return {"asset_id": aid, "hostname": host, "ip": "10.0.0." + aid, "env_label": env, "env_group": grp,
                    "cmdb_status": status, "last_scan": scan, "credentialed": "true", "site_id": site,
                    "site_name": "Site" + site, "appname": ["Customer portal"], "cmdb_host": host}
        return [mk("1", "PRDWEB01", "Prod · DC", "Prod", "WORKING_ACTIVE", "2026-11-20T01:00:00Z", "1"),
                mk("2", "PRDAPI03", "Prod · DC", "Prod", "WORKING_ACTIVE", "2026-10-08T23:05:00Z", "1"),
                mk("3", "DRWEB01", "Prod · DR", "Prod", "WORKING_ACTIVE", "2026-10-30T02:15:00Z", "2"),
                mk("4", "UATWEB01", "Non-prod · UAT", "Non-prod", "WORKING_ACTIVE", "2026-11-20T08:00:00Z", "3"),
                mk("5", "OLDWEB", "Prod · DC", "Prod", "INACTIVE", "2026-11-19T20:40:00Z", "1")]
    if 'sourcetype="rapid7:vm:software"' in spl:
        return [{"asset_id": a, "version": v, "vendor": "PHP", "product": "PHP"}
                for a, v in (("1", "8.1.27"), ("2", "8.1.20"), ("3", "8.2.20"), ("4", "8.3.27"), ("5", "8.1.20"))]
    if 'sourcetype="rapid7:vm:asset_vuln"' in spl:
        return [{"asset_id": "1", "vuln_ids": ["php-cve-2026-20517"]}]
    return []


def chunk(meta, body=""):
    m, b = json.dumps(meta).encode(), body.encode()
    return b"chunked 1.0,%d,%d\n" % (len(m), len(b)) + m + b


def parse_output(raw):
    """Return (rows, messages) from a chunked protocol response."""
    rows, msgs, pos = [], [], 0
    import csv
    import io
    while pos < len(raw):
        nl = raw.index(b"\n", pos)
        _, mlen, blen = raw[pos:nl].decode().split(",")
        meta = json.loads(raw[nl + 1:nl + 1 + int(mlen)])
        body = raw[nl + 1 + int(mlen):nl + 1 + int(mlen) + int(blen)].decode()
        pos = nl + 1 + int(mlen) + int(blen)
        msgs += (meta.get("inspector") or {}).get("messages", [])
        if body.strip():
            rd = csv.DictReader(io.StringIO(body))
            rows += [dict((k, v) for k, v in r.items() if not k.startswith("__mv_")) for r in rd]
    return rows, msgs


class CommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeSplunkd)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.uri = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def run_cmd(self, name, args):
        si = {"args": args, "splunkd_uri": self.uri, "session_key": "k", "username": "analyst1",
              "app": "search", "owner": "analyst1", "dispatch_dir": "/tmp", "sid": "1",
              "splunk_version": "9.2.0", "search": "| " + name, "earliest_time": "0", "latest_time": "0",
              "command": name, "maxresultrows": 50000}
        data = chunk({"action": "getinfo", "preview": False, "searchinfo": si}) + \
            chunk({"action": "execute", "finished": True}, "")
        env = dict(os.environ)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env.pop(k, None)
        p = subprocess.run([sys.executable, os.path.join(BIN, name + ".py")], input=data,
                           capture_output=True, timeout=60, cwd=BIN, env=env)
        rows, msgs = parse_output(p.stdout)
        errors = [m for m in msgs if m[0] == "ERROR"]
        return rows, errors, p.stderr.decode(errors="replace")

    def test_1_watchlist_add_and_list(self):
        rows, errors, err = self.run_cmd("r7cvewatch", ["action=add", "cve=CVE-2026-20517", "announced=2026-11-18",
                                                        "software=PHP", "ranges=8.1 < 8.1.34 ; 8.2 < 8.2.29"])
        self.assertEqual(errors, [], err)
        self.assertEqual(rows[0]["result"], "saved")
        rows, errors, err = self.run_cmd("r7cvewatch", ["action=add", "cve=CVE-2026-20517", "software=PHP"])
        self.assertTrue(errors and "already saved" in errors[0][1])
        rows, errors, err = self.run_cmd("r7cvewatch", ["action=list", "with_counts=true"])
        self.assertEqual(errors, [], err)
        self.assertEqual((rows[0]["cve"], rows[0]["rapid7_check"]), ("CVE-2026-20517", "Yes (2026-11-19)"))
        # PRDWEB01 affected, PRDAPI03 + DRWEB01 stale/unknown; UATWEB01 8.3 not in listed ranges; OLDWEB inactive
        self.assertEqual((rows[0]["affected_now"], rows[0]["prod_dc"], rows[0]["prod_dr"]), ("3", "2", "1"))

    def test_2_r7cve_saved(self):
        self.run_cmd("r7cvewatch", ["action=add", "cve=CVE-2026-20517", "announced=2026-11-18", "software=PHP",
                                    "ranges=8.1 < 8.1.34 ; 8.2 < 8.2.29"])
        rows, errors, err = self.run_cmd("r7cve", ["cve=CVE-2026-20517"])
        self.assertEqual(errors, [], err)
        by = dict((r["hostname"], r) for r in rows)
        self.assertNotIn("OLDWEB", by)
        self.assertEqual(by["PRDWEB01"]["verdict"], "Affected")
        self.assertEqual((by["DRWEB01"]["freshness"], by["DRWEB01"]["verdict"]), ("Stale", "Unknown"))
        rows, errors, err = self.run_cmd("r7cve", ["cve=CVE-2026-20517", "env=Prod · DR"])
        self.assertEqual([r["hostname"] for r in rows], ["DRWEB01"])

    def test_3_rescan_dryrun_and_launch(self):
        self.run_cmd("r7cvewatch", ["action=add", "cve=CVE-2026-20517", "announced=2026-11-18", "software=PHP",
                                    "ranges=8.1 < 8.1.34 ; 8.2 < 8.2.29"])
        rows, errors, err = self.run_cmd("r7rescan", ["cve=CVE-2026-20517", "env=Prod", "dryrun=true", "detail=true"])
        self.assertEqual(errors, [], err)
        acts = dict((r["hostname"], (r["action"], r["reason"])) for r in rows)
        self.assertEqual(acts["OLDWEB"], ("skip", "INACTIVE in CMDB"))
        self.assertEqual(acts["PRDWEB01"][0], "scan")
        self.assertNotIn("UATWEB01", acts)

        FakeSplunkd.caps = ["search"]
        rows, errors, err = self.run_cmd("r7rescan", ["cve=CVE-2026-20517", "env=Prod", "dryrun=false"])
        self.assertTrue(errors and "rapid7_cve_rescan" in errors[0][1], (rows, errors))

        FakeSplunkd.caps = ["search", "rapid7_cve_rescan"]
        rows, errors, err = self.run_cmd("r7rescan", ["cve=CVE-2026-20517", "env=Prod", "dryrun=false",
                                                      "request_id=REQ-1", "launched_from=Test"])
        self.assertEqual(errors, [], err)
        job_id = rows[0]["job_id"]
        self.assertEqual((rows[0]["status"], rows[0]["servers"], rows[0]["rapid7_scans"]), ("Requested", "3", "2"))
        job = FakeSplunkd.kv["r7_scan_jobs"][job_id]
        self.assertEqual(sorted(t["hostname"] for t in job["targets"]), ["DRWEB01", "PRDAPI03", "PRDWEB01"])
        self.assertEqual(job["launched_by"], "analyst1")

        rows, errors, err = self.run_cmd("r7rescan", ["cve=CVE-2026-20517", "env=Prod", "dryrun=false",
                                                      "request_id=REQ-1"])
        self.assertEqual(rows[0]["job_id"], job_id)
        self.assertIn("not launched again", rows[0]["message"])

        rows, errors, err = self.run_cmd("r7rescan", ["software=PHP", "ranges=< 9", "hosts=", "only_hosts=true",
                                                      "dryrun=true"])
        self.assertTrue(errors and "No servers picked" in errors[0][1])

        rows, errors, err = self.run_cmd("r7scanstatus", ["job=" + job_id])
        self.assertEqual(errors, [], err)
        self.assertEqual(sorted(r["rapid7_site"] for r in rows), ["Site1", "Site2"])
        self.assertTrue(all(r["scan_status"] == "waiting for poller" for r in rows))


    def test_4_catalog_lookup_exact_cve(self):
        self.run_cmd("r7cvewatch", ["action=add", "cve=CVE-2026-20517", "announced=2026-11-18", "software=PHP",
                                    "ranges=8.1 < 8.1.34"])
        FakeSplunkd.searches[:] = []
        rows, errors, err = self.run_cmd("r7cve", ["cve=CVE-2026-20517"])
        self.assertEqual(errors, [], err)
        self.assertEqual(rows[0]["vuln_ids"], "php-cve-2026-20517")  # CVE-2026-205170 not matched as a prefix
        self.assertFalse(any("rapid7:vm:vuln_content" in q for q in FakeSplunkd.searches))  # catalog was enough

    def test_5_plain_host_rescan(self):
        rows, errors, err = self.run_cmd("r7rescan", ["hosts=PRDWEB01,OLDWEB,NOPE", "only_hosts=true", "dryrun=true",
                                                      "detail=true"])
        self.assertEqual(errors, [], err)
        acts = dict((r["hostname"], (r["action"], r["reason"])) for r in rows)
        self.assertEqual(acts["PRDWEB01"][0], "scan")
        self.assertEqual(acts["OLDWEB"], ("skip", "INACTIVE in CMDB"))
        self.assertEqual(acts["nope"][0], "skip")

    def test_6_asset_fix_requests(self):
        rows, errors, err = self.run_cmd("r7assetaction", ["action=request", "hosts=PPRAPI02, PRDAPP31",
                                                           "issue=Environment differs", "note=Move to PROD site",
                                                           "request_id=RQ1"])
        self.assertEqual(errors, [], err)
        rid = rows[0]["id"]
        self.assertEqual((rows[0]["status"], rows[0]["assets"]), ("Open", "2"))
        rows, errors, err = self.run_cmd("r7assetaction", ["action=request", "hosts=PPRAPI02", "request_id=RQ1"])
        self.assertIn("Already recorded", rows[0]["message"])
        rows, errors, err = self.run_cmd("r7assetaction", ["action=request", "hosts="])
        self.assertTrue(errors and "at least one asset" in errors[0][1])
        rows, errors, err = self.run_cmd("r7assetaction", ["action=done", "id=" + rid, "note=moved by R7 team"])
        self.assertEqual(rows[0]["status"], "Done")
        rows, errors, err = self.run_cmd("r7assetaction", ["action=list"])
        self.assertTrue(any(r["id"] == rid and r["status"] == "Done" for r in rows))


if __name__ == "__main__":
    unittest.main()
