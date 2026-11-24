# -*- coding: utf-8 -*-
"""Collectors (modular inputs). Run on the heavy forwarder that holds the
Rapid7 credential (SIEMFWDPR01). Each run writes run_id on every event so
searches can use the latest complete snapshot."""
from __future__ import absolute_import

import calendar
import datetime
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import r7_lib as L
from splunklib.modularinput import Script, Scheme, Argument, Event


class _Base(Script):
    TITLE = ""
    DESCRIPTION = ""

    def get_scheme(self):
        s = Scheme(self.TITLE)
        s.description = self.DESCRIPTION
        s.use_external_validation = False
        s.use_single_instance = False
        a = Argument("note")
        a.title = "Note (optional)"
        a.data_type = Argument.data_type_string
        a.required_on_create = False
        s.add_argument(a)
        return s

    def stream_events(self, inputs, ew):
        md = inputs.metadata
        svc = L.app_service(md["server_uri"], md["session_key"])
        settings = L.load_settings(svc)
        for name, item in inputs.inputs.items():
            index = item.get("index") or settings["index"]
            started = time.time()
            run_id = L.utcnow().strftime("%Y%m%dT%H%M%SZ")
            status, count, err, calls = "success", 0, "", 0
            try:
                client = L.make_client(svc, settings, role="collector")
                count = self.collect(client, settings, ew, index, run_id, md.get("checkpoint_dir", ""), name)
                calls = client.calls
            except Exception as e:  # report and keep the input alive
                status, err = "error", str(e)[:1000]
                ew.log("ERROR", "%s failed: %s" % (name, e))
            run = {"collector": self.KIND, "status": status, "events": count, "run_id": run_id,
                   "api_calls": calls, "duration_s": round(time.time() - started, 1), "error": err}
            ew.write_event(Event(data=json.dumps(run) + "\n", sourcetype="rapid7:vm:run", index=index, stanza=name))

    def write(self, ew, index, sourcetype, obj, when=None, sort_keys=True):
        ew.write_event(Event(data=json.dumps(obj, sort_keys=sort_keys) + "\n", sourcetype=sourcetype, index=index,
                             time="%.3f" % (when if when else time.time())))


def _asset_index(client):
    """{asset_id: {'asset': Asset, 'sites': [(id, name), ...]}} across all sites."""
    out = {}
    for site in client.sites():
        for a in client.site_assets(site.get("id")):
            rec = out.setdefault(str(a.get("id")), {"asset": a, "sites": []})
            rec["sites"].append((str(site.get("id")), site.get("name") or ""))
    return out


class SoftwareCollector(_Base):
    KIND = "software"
    TITLE = "Rapid7 software inventory"
    DESCRIPTION = "Daily: installed software and OS per asset (/assets/{id}/software)."

    def collect(self, client, settings, ew, index, run_id, checkpoint_dir, name):
        assets = _asset_index(client)
        n = 0
        threads = max(1, int(settings.get("threads") or 4))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = dict((pool.submit(client.asset_software, aid), aid) for aid in assets)
            for f in as_completed(futures):
                aid = futures[f]
                rec = assets[aid]
                a = rec["asset"]
                try:
                    sw = f.result()
                except Exception as e:
                    ew.log("WARN", "software for asset %s failed: %s" % (aid, e))
                    sw = []
                fp = a.get("osFingerprint") or {}
                last = L.asset_last_scan(a)
                base = {"asset_id": aid, "hostname": L.asset_hostname(a), "ip": a.get("ip") or "",
                        "last_scan": L.iso(last), "run_id": run_id}
                self.write(ew, index, "rapid7:vm:asset_site", dict(
                    base, mac=a.get("mac") or "", os=a.get("os") or fp.get("description") or "",
                    os_vendor=fp.get("vendor") or "", os_family=fp.get("family") or "",
                    os_product=fp.get("product") or "", os_version=fp.get("version") or "",
                    site_id=rec["sites"][0][0] if rec["sites"] else "",
                    site_name=rec["sites"][0][1] if rec["sites"] else "",
                    site_ids=[s[0] for s in rec["sites"]], site_names="; ".join(s[1] for s in rec["sites"]),
                    software_count=len(sw), credentialed=bool(sw), risk_score=a.get("riskScore")))
                n += 1
                if fp.get("product") or fp.get("family"):
                    self.write(ew, index, "rapid7:vm:software", dict(
                        base, vendor=fp.get("vendor") or "", product=fp.get("product") or fp.get("family") or "",
                        version=fp.get("version") or "", family=fp.get("family") or "", type="Operating System",
                        cpe=((fp.get("cpe") or {}).get("v2.3") or "")))
                    n += 1
                for s in sw:
                    self.write(ew, index, "rapid7:vm:software", dict(base, **L.software_row(s)))
                    n += 1
        return n


class VulnContentCollector(_Base):
    KIND = "vuln_content"
    TITLE = "Rapid7 vulnerability content"
    DESCRIPTION = "Every 6 h: new and updated Rapid7 checks, newest-modified first, with a lookback limit."

    def collect(self, client, settings, ew, index, run_id, checkpoint_dir, name):
        ck_path = os.path.join(checkpoint_dir or ".", "vuln_content_%s.json"
                               % "".join(c if c.isalnum() else "_" for c in name))
        state = {}
        if os.path.exists(ck_path):
            try:
                with open(ck_path) as fh:
                    state = json.load(fh)
            except Exception:
                state = {}
        now = L.utcnow()
        last = L.parse_date(state.get("last_run"))
        if last:
            cutoff = last - datetime.timedelta(days=int(settings["vuln_content_overlap_days"]))
        else:
            cutoff = now - datetime.timedelta(days=int(settings["vuln_content_first_days"]))
        max_pages = int(settings["vuln_content_max_pages"])
        n, prev, unsorted = 0, None, False
        for v in client.paged("/api/3/vulnerabilities", {"sort": "modified,DESC"},
                              size=int(settings["page_size"]), max_pages=max_pages):
            mod = L.parse_date(v.get("modified"))
            if prev and mod and mod > prev + datetime.timedelta(days=1):
                unsorted = True  # API ignored sort: keep reading up to max_pages
            if mod and mod < cutoff:
                if unsorted:
                    continue
                break
            prev = mod or prev
            cvss = v.get("cvss") or {}
            self.write(ew, index, "rapid7:vm:vuln_content", {
                # short fields first: Splunk's automatic JSON extraction stops after ~10 KB and some
                # rollup checks list thousands of CVEs, so the long lists go last
                "vuln_id": v.get("id"), "title": v.get("title"),
                "severity": v.get("severity"), "severity_score": v.get("severityScore"),
                "cvss_v3": (cvss.get("v3") or {}).get("score"), "cvss_v2": (cvss.get("v2") or {}).get("score"),
                "published": v.get("published"), "added": v.get("added"), "modified": v.get("modified"),
                "risk_score": v.get("riskScore"), "run_id": run_id, "cve_count": len(v.get("cves") or []),
                "categories": v.get("categories") or [], "cves": v.get("cves") or [],
            }, when=calendar.timegm(mod.timetuple()) if mod else None, sort_keys=False)
            n += 1
        if unsorted:
            ew.log("WARN", "vuln_content: API did not return results sorted by modified; read up to %d pages"
                   % max_pages)
        try:
            with open(ck_path, "w") as fh:
                json.dump({"last_run": L.iso(now)}, fh)
        except Exception as e:
            ew.log("WARN", "cannot write checkpoint %s: %s" % (ck_path, e))
        return n


class AssetVulnCollector(_Base):
    KIND = "asset_vulns"
    TITLE = "Rapid7 asset findings"
    DESCRIPTION = "Daily: one event per asset listing its current vulnerability IDs."

    def collect(self, client, settings, ew, index, run_id, checkpoint_dir, name):
        assets = _asset_index(client)
        n = 0
        threads = max(1, int(settings.get("threads") or 4))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = dict((pool.submit(client.asset_vuln_ids, aid), aid) for aid in assets)
            for f in as_completed(futures):
                aid = futures[f]
                a = assets[aid]["asset"]
                try:
                    ids = f.result()
                except Exception as e:
                    ew.log("WARN", "findings for asset %s failed: %s" % (aid, e))
                    continue
                self.write(ew, index, "rapid7:vm:asset_vuln", {
                    "asset_id": aid, "hostname": L.asset_hostname(a), "ip": a.get("ip") or "",
                    "last_scan": L.iso(L.asset_last_scan(a)), "vuln_ids": sorted(ids), "vuln_count": len(ids),
                    "run_id": run_id})
                n += 1
        return n
