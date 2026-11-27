#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7rescan cve=... [software=... ranges=...] [env=...] [app=...] [hosts=...] [scope=affected|all]
           [dryrun=true|false] [request_id=...] [reason=...] [launched_from=...]

dryrun=true (default) shows what would be scanned. dryrun=false records a scan
job; the poller (scheduled search, every minute) launches it in Rapid7 with the
scan account, so users never need the Rapid7 password.
"""
from __future__ import absolute_import

import json
import random
import string
import sys

import r7_lib as L
import r7_query as Q
from r7cve import resolve_spec
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


def current_capabilities(svc):
    try:
        body = svc.get("authentication/current-context", output_mode="json").body.read()
        entry = json.loads(body.decode("utf-8"))["entry"][0]["content"]
        return set(entry.get("capabilities") or [])
    except Exception:
        return set()


def new_job_id():
    return "JOB-%s-%s" % (L.utcnow().strftime("%Y%m%d%H%M%S"),
                          "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4)))


@Configuration(type="reporting")
class R7Rescan(GeneratingCommand):
    cve = Option(require=False)
    software = Option(require=False)
    ranges = Option(require=False)
    announced = Option(require=False)
    env = Option(require=False)
    app = Option(require=False)
    hosts = Option(require=False)
    only_hosts = Option(require=False, default="auto")  # true | false (ignore hosts=) | auto
    scope = Option(require=False, default="affected")
    dryrun = Option(require=False, default=True, validate=validators.Boolean())
    detail = Option(require=False, default=False, validate=validators.Boolean())
    request_id = Option(require=False)
    reason = Option(require=False)
    launched_from = Option(require=False, default="Search")

    @L.safe
    def generate(self):
        mode = str(self.only_hosts or "auto").lower()
        if mode in ("false", "0", "no"):
            self.hosts = ""
        elif mode in ("true", "1", "yes") and not L.split_csv(self.hosts):
            raise ValueError("No servers picked: choose servers, or switch to 'All that need a rescan'")
        svc = L.command_service(self)
        settings = L.load_settings(svc)
        max_servers = int(settings["max_servers_per_job"])
        self.include_inactive = True
        self.include_nodata = bool(self.hosts)
        if not (self.cve or self.software) and L.split_csv(self.hosts):
            # plain rescan of named servers (Impacted assets, Asset management): no CVE or software
            spec = {"cve": "", "software": "", "ranges": "", "env": [], "app": ""}
            rows = Q.host_rows(svc, settings, L.split_csv(self.hosts))
            info = {"has_check": False, "vuln_ids": [], "announced": ""}
        else:
            spec = resolve_spec(svc, self)
            spec["include_inactive"] = True
            rows, info = Q.build_rows(svc, settings, spec)

        wanted = set(x.lower() for x in L.split_csv(self.hosts))
        selected, skipped = [], []
        found = set()
        done_ids = set()
        for r in rows:
            if r.get("asset_id") in done_ids:
                continue  # one target per server, whatever the number of matching rows
            done_ids.add(r.get("asset_id"))
            keys = set(x.lower() for x in (r["asset_id"], r["hostname"], r["ip"], r["cmdb_host"]) if x)
            if wanted:
                if not (keys & wanted):
                    continue
                found |= keys & wanted
            reason = None
            if r["cmdb_status"] in L.BLOCKED_STATUSES:
                reason = "%s in CMDB" % r["cmdb_status"]
            elif not r["site_id"]:
                reason = "No Rapid7 site"
            elif (self.scope or "affected") == "affected" and not wanted and not L.needs_rescan(r["verdict"]):
                reason = "Already %s" % r["verdict"].lower()
            (skipped if reason else selected).append(dict(r, skip_reason=reason))
        plain = not (self.cve or self.software)
        typed = dict((x.lower(), x) for x in L.split_csv(self.hosts))
        for missing in sorted(wanted - found):
            skipped.append({"hostname": typed.get(missing, missing), "site_name": "", "site_id": "", "env_label": "",
                            "skip_reason": ("Not found in the latest Rapid7 asset data (software collector, last 3 days)" if plain
                                            else "Not found in Rapid7 data for this CVE/software")})

        groups = L.group_by_site(selected)

        if self.dryrun:
            for row in self._preview(groups, skipped, settings):
                yield row
            return

        if not selected:
            raise ValueError("Nothing to scan: every server was skipped (run with dryrun=true to see why)")
        if len(selected) > max_servers:
            raise ValueError("%d servers selected; the limit is %d per job. Narrow env=/app=/hosts="
                             % (len(selected), max_servers))
        cap = settings["rescan_capability"]
        if cap not in current_capabilities(svc):
            raise PermissionError("You need the '%s' capability (role rapid7_cve_rescan) to launch scans" % cap)

        jobs = L.kv(svc, L.SCAN_JOBS)
        if self.request_id:
            dup = jobs.query(query=json.dumps({"request_id": self.request_id}))
            if dup:
                yield {"job_id": dup[0]["job_id"], "status": dup[0]["status"],
                       "message": "Already requested (same request_id); not launched again"}
                return

        user = L.command_user(self)
        now = L.iso(L.utcnow())
        job_id = new_job_id()
        doc = {
            "_key": job_id, "job_id": job_id, "request_id": self.request_id or job_id, "status": "Requested",
            "cve": spec.get("cve") or "", "software": spec.get("software") or "", "ranges": spec.get("ranges") or "",
            "announced": info.get("announced") or "", "has_check": info["has_check"],
            "vuln_ids": info.get("vuln_ids") or [],
            "reason": self.reason or spec.get("cve") or ("%s %s" % (spec.get("software"), spec.get("ranges"))).strip() or "Rescan of selected servers",
            "launched_by": user, "launched_from": self.launched_from or "Search", "created": now, "updated": now,
            "scope": self.scope, "env": spec.get("env") or [], "app": spec.get("app") or "",
            "template_id": settings.get("scan_template_id") or "",
            "groups": [{"site_id": g["site_id"], "site_name": g["site_name"],
                        "hosts": [L.scan_host(t) for t in g["targets"]], "scan_id": "", "scan_status": "",
                        "error": ""} for g in groups.values()],
            "targets": [{"asset_id": t["asset_id"], "hostname": t["hostname"], "ip": t["ip"],
                         "env_label": t["env_label"], "appname": t["appname"], "site_id": t["site_id"],
                         "before": {"installed": t["installed"], "version": t["version"] if t["installed"] else "",
                                    "r7_vulnerable": t["r7_vulnerable"], "last_scan": t["last_scan"],
                                    "verdict": t["verdict"]}} for t in selected],
            "results": [], "error": "",
        }
        jobs.batch_save(doc)
        yield {"job_id": job_id, "status": "Requested", "servers": len(selected), "rapid7_scans": len(groups),
               "skipped": len(skipped),
               "message": "Recorded. The poller launches it within about a minute. Follow with "
                          "| r7scanstatus job=%s" % job_id}

    def _preview(self, groups, skipped, settings):
        tmpl = settings.get("scan_template_id") or "site default"
        if self.detail:
            for g in groups.values():
                for t in g["targets"]:
                    yield {"action": "scan", "hostname": t["hostname"], "ip": t["ip"], "env_label": t["env_label"],
                           "site_name": g["site_name"], "verdict": t["verdict"], "reason": "", "template": tmpl}
            for s in skipped:
                yield {"action": "skip", "hostname": s.get("hostname"), "ip": s.get("ip", ""),
                       "env_label": s.get("env_label", ""), "site_name": s.get("site_name", ""),
                       "verdict": "" if s.get("verdict") == "Rescan requested" else s.get("verdict", ""), "reason": s.get("skip_reason"), "template": ""}
            return
        by_site = {}
        for s in skipped:
            k = s.get("site_id") or ""
            by_site.setdefault(k, []).append(s)
        sites = set(groups) | set(by_site)
        total = sum(len(g["targets"]) for g in groups.values())
        for sid in sorted(sites):
            g = groups.get(sid, {"site_name": "", "targets": []})
            sk = by_site.get(sid, [])
            reasons = {}
            for s in sk:
                reasons[s["skip_reason"]] = reasons.get(s["skip_reason"], 0) + 1
            yield {"rapid7_site": g["site_name"] or (sk[0].get("site_name") if sk else "") or "(no site)",
                   "site_id": sid, "servers_to_scan": len(g["targets"]), "skipped": len(sk),
                   "skipped_reasons": "; ".join("%d %s" % (n, r) for r, n in sorted(reasons.items())) or "—",
                   "template": tmpl, "total_selected": total,
                   "within_limit": "yes" if total <= int(settings["max_servers_per_job"]) else "no"}


if __name__ == "__main__":
    dispatch(R7Rescan, sys.argv, sys.stdin, sys.stdout, __name__)
