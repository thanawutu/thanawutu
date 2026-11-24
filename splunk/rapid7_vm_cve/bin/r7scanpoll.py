#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7scanpoll   (run by the scheduled search "Rapid7 CVE - scan job poller", every minute)

Moves scan jobs through: Requested -> Running -> Collecting -> Finished (or Failed).
  Requested : re-checks the requester's capability and the server limit, then starts
              one Rapid7 scan per site with the scan account.
  Running   : GET /api/3/scans/{id} for each scan until all are finished/stopped/error.
  Collecting: re-reads software and the CVE's findings for each target and compares
              them with the snapshot saved at launch.
Every state change and each server result is written to the index
(sourcetype rapid7:vm:scan_job and rapid7:vm:scan_result).
"""
from __future__ import absolute_import

import json
import sys

import r7_lib as L
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

ACTIVE = ["Requested", "Running", "Collecting"]


@Configuration(type="reporting")
class R7ScanPoll(GeneratingCommand):
    max_jobs = Option(require=False, default=20, validate=validators.Integer(1, 200))

    @L.safe
    def generate(self):
        svc = L.command_service(self)
        settings = L.load_settings(svc)
        jobs = L.kv(svc, L.SCAN_JOBS)
        active = jobs.query(query=json.dumps({"status": {"$in": ACTIVE}}), sort="created:1",
                            limit=int(self.max_jobs))
        if not active:
            yield {"job_id": "", "status": "idle", "message": "No active scan jobs"}
            return
        try:
            client = L.make_client(svc, settings, role="scan")
        except Exception as e:
            for j in active:
                yield {"job_id": j["job_id"], "status": j["status"], "message": "Cannot reach Rapid7: %s" % e}
            return
        index = settings["index"]
        for job in active:
            before = job["status"]
            try:
                if job["status"] == "Requested":
                    self._launch(svc, settings, client, job)
                elif job["status"] == "Running":
                    self._poll(settings, client, job)
                if job["status"] == "Collecting":
                    self._collect(client, job)
            except Exception as e:
                job["status"], job["error"] = "Failed", str(e)[:1000]
            job["updated"] = L.iso(L.utcnow())
            jobs.batch_save(L.clean_doc(job))
            if job["status"] != before:
                self._emit_job(svc, index, job)
                if job["status"] == "Finished":
                    self._emit_results(svc, index, job)
            yield {"job_id": job["job_id"], "status": job["status"], "previous": before,
                   "message": job.get("error") or ""}

    # ------------------------------------------------------------------
    def _launch(self, svc, settings, client, job):
        cap = settings["rescan_capability"]
        if cap not in L.user_capabilities(svc, job.get("launched_by")):
            raise PermissionError("%s does not have the %s capability" % (job.get("launched_by"), cap))
        n = len(job.get("targets") or [])
        if n == 0 or n > int(settings["max_servers_per_job"]):
            raise ValueError("Job has %d servers; limit is %s" % (n, settings["max_servers_per_job"]))
        started = 0
        for g in job.get("groups") or []:
            if g.get("scan_id"):
                started += 1
                continue
            try:
                name = "Splunk %s %s" % (job["job_id"], job.get("cve") or job.get("software") or "")
                g["scan_id"] = str(client.start_site_scan(g["site_id"], g["hosts"], name.strip()[:100],
                                                          job.get("template_id") or ""))
                g["scan_status"], g["started"] = "dispatched", L.iso(L.utcnow())
                started += 1
            except Exception as e:
                g["scan_status"], g["error"] = "error", str(e)[:500]
        if started == 0:
            raise RuntimeError("No Rapid7 scan could be started: %s"
                               % "; ".join(g.get("error", "") for g in job.get("groups") or []))
        job["status"], job["launched"] = "Running", L.iso(L.utcnow())

    def _poll(self, settings, client, job):
        done = True
        for g in job.get("groups") or []:
            if not g.get("scan_id") or g.get("scan_status") in L.TERMINAL_SCAN_STATES:
                continue
            s = client.scan(g["scan_id"])
            g["scan_status"] = str(s.get("status") or "").lower()
            g["assets"] = s.get("assets")
            g["engine"] = s.get("engineName") or s.get("engineId") or ""
            if g["scan_status"] not in L.TERMINAL_SCAN_STATES:
                done = False
        launched = L.parse_date(job.get("launched") or job.get("created"))
        hours = (L.utcnow() - launched).total_seconds() / 3600.0 if launched else 0
        if not done and hours > float(settings["max_job_hours"]):
            raise RuntimeError("Timed out after %.1f h waiting for Rapid7 scans" % hours)
        if done:
            if not any(g.get("scan_status") == "finished" for g in job.get("groups") or []):
                raise RuntimeError("No Rapid7 scan finished: %s" % ", ".join(
                    "%s=%s" % (g.get("scan_id"), g.get("scan_status")) for g in job.get("groups") or []))
            job["status"], job["scans_done"] = "Collecting", L.iso(L.utcnow())

    def _collect(self, client, job):
        scan_ids = set(str(g.get("scan_id")) for g in job.get("groups") or [] if g.get("scan_id"))
        has_check = bool(job.get("has_check"))
        results = []
        for t in job.get("targets") or []:
            aid = t["asset_id"]
            asset = client.asset(aid) or {}
            assessed = bool(scan_ids & L.asset_scan_ids(asset))
            sw = client.asset_software(aid)
            match = [L.software_row(x) for x in sw
                     if job.get("software") and L.software_matches(job["software"], x.get("vendor"), x.get("product"))]
            versions = sorted(set(m["version"] for m in match if m["version"]),
                              key=lambda v: L.version_parts(v), reverse=True)
            vuln = None
            if has_check and assessed:
                vuln = any(client.asset_has_vuln(aid, vid) for vid in job.get("vuln_ids") or [])
            after = {"installed": bool(match), "version": versions[0] if versions else "",
                     "r7_vulnerable": vuln, "assessed": assessed, "credentialed": len(sw) > 0}
            before = t.get("before") or {}
            cmp_ = L.compare_result(before, after, has_check)
            last = L.asset_last_scan(asset)
            rs = L.range_status(after["version"], job.get("ranges")) if (after["version"] and job.get("ranges")) else ""
            results.append(dict(cmp_, asset_id=aid, hostname=t.get("hostname"), ip=t.get("ip"),
                                env_label=t.get("env_label"), appname=t.get("appname"),
                                version_before=before.get("version") or "", last_scan_before=before.get("last_scan") or "",
                                version_after=after["version"] or ("not installed" if after["credentialed"] and assessed else ""),
                                all_versions_after=versions, range_status_after=rs,
                                scan_login="OK" if after["credentialed"] else "No software data (login failed?)",
                                assessed_by_this_job=assessed, last_scan_after=L.iso(last)))
        job["results"] = results
        job["status"], job["finished"] = "Finished", L.iso(L.utcnow())

    # ------------------------------------------------------------------
    @staticmethod
    def _emit_job(svc, index, job):
        ev = dict((k, job.get(k)) for k in ("job_id", "status", "cve", "software", "ranges", "reason",
                                             "launched_by", "launched_from", "created", "launched", "finished",
                                             "error", "scope", "env", "app"))
        ev["servers"] = len(job.get("targets") or [])
        ev["scans"] = [{"site": g.get("site_name"), "scan_id": g.get("scan_id"), "status": g.get("scan_status")}
                       for g in job.get("groups") or []]
        if job.get("results"):
            counts = {}
            for r in job["results"]:
                counts[r["cve_result"]] = counts.get(r["cve_result"], 0) + 1
            ev["result_counts"] = counts
        _submit(svc, index, ev, "rapid7:vm:scan_job")

    @staticmethod
    def _emit_results(svc, index, job):
        for r in job.get("results") or []:
            ev = dict(r, job_id=job["job_id"], cve=job.get("cve"), software=job.get("software"),
                      launched_by=job.get("launched_by"))
            _submit(svc, index, ev, "rapid7:vm:scan_result")


def _submit(svc, index, event, sourcetype):
    try:
        svc.indexes[index].submit(json.dumps(event), sourcetype=sourcetype, source="r7scanpoll")
    except Exception:
        pass  # KV store keeps the job; index write is best effort


if __name__ == "__main__":
    dispatch(R7ScanPoll, sys.argv, sys.stdin, sys.stdout, __name__)
