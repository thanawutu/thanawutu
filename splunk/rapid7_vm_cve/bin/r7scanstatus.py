#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7scanstatus [job=JOB-...] [view=summary|scans|results] [limit=50]

Without job=, lists recent jobs. With job=, shows the per-server before/after
result once the job has finished, or the Rapid7 scan status while it runs.
"""
from __future__ import absolute_import

import json
import sys

import r7_lib as L
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration(type="reporting")
class R7ScanStatus(GeneratingCommand):
    job = Option(require=False)
    view = Option(require=False, default="auto")
    limit = Option(require=False, default=50, validate=validators.Integer(1, 1000))

    @L.safe
    def generate(self):
        svc = L.command_service(self)
        data = L.kv(svc, L.SCAN_JOBS)
        if not self.job:
            for j in data.query(sort="created:-1", limit=int(self.limit)):
                yield summary(j)
            return
        j = data.query_by_id(self.job)
        if not j:
            raise ValueError("Job %s not found" % self.job)
        view = self.view
        if view == "auto":
            view = "results" if j.get("status") == "Finished" else "scans"
        if view == "summary":
            yield summary(j)
        elif view == "scans":
            for g in j.get("groups") or []:
                yield {"job_id": j["job_id"], "job_status": j["status"], "rapid7_site": g.get("site_name"),
                       "scan_id": g.get("scan_id"), "scan_status": g.get("scan_status") or "waiting for poller",
                       "servers": len(g.get("hosts") or []), "engine": g.get("engine", ""),
                       "started": g.get("started", ""), "error": g.get("error") or j.get("error") or ""}
        else:
            for r in j.get("results") or []:
                yield dict((k, v) for k, v in r.items() if k != "all_versions_after")


def summary(j):
    counts = {}
    for r in j.get("results") or []:
        counts[r.get("cve_result")] = counts.get(r.get("cve_result"), 0) + 1
    scans = j.get("groups") or []
    done = sum(1 for g in scans if g.get("scan_status") in L.TERMINAL_SCAN_STATES)
    return {
        "job_id": j.get("job_id"), "status": j.get("status"), "reason": j.get("reason"),
        "cve": j.get("cve"), "software": j.get("software"), "launched_from": j.get("launched_from"),
        "launched_by": j.get("launched_by"), "servers": len(j.get("targets") or []),
        "rapid7_scans": "%d/%d finished" % (done, len(scans)), "created": j.get("created"),
        "finished": j.get("finished", ""), "error": j.get("error", ""),
        "result": ", ".join("%d %s" % (n, k) for k, n in sorted(counts.items())) if counts else "",
        "hosts": " ".join("%s %s" % (t.get("hostname") or "", t.get("ip") or "") for t in (j.get("targets") or [])),
    }


if __name__ == "__main__":
    dispatch(R7ScanStatus, sys.argv, sys.stdin, sys.stdout, __name__)
