#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7cve cve=CVE-... [software=...] [ranges=...] [announced=...] [env="Prod · DC,Prod · DR"] [app=...]

Read only. Lists servers with the affected software or a Rapid7 finding for the
CVE, with version, scan freshness, Rapid7 result and verdict. Without cve=, use
software= and ranges= for a CVE that is not saved (or has no Rapid7 check).
"""
from __future__ import absolute_import

import sys

import r7_lib as L
import r7_query as Q
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

FIELDS = ["hostname", "ip", "env_label", "env_group", "appname", "app_id", "cmdb_status", "device_category",
          "product", "vendor", "version", "range_status", "last_scan", "freshness", "days_before_announced",
          "r7_result", "verdict", "action", "credentialed", "site_name", "site_id", "asset_id", "os",
          "rescan_blocked"]


@Configuration(type="reporting")
class R7Cve(GeneratingCommand):
    cve = Option(require=False)
    software = Option(require=False)
    ranges = Option(require=False)
    announced = Option(require=False)
    env = Option(require=False)
    app = Option(require=False)
    verdict = Option(require=False)
    include_inactive = Option(require=False, default=False, validate=validators.Boolean())
    include_nodata = Option(require=False, default=False, validate=validators.Boolean())

    @L.safe
    def generate(self):
        svc = L.command_service(self)
        settings = L.load_settings(svc)
        spec = resolve_spec(svc, self)
        rows, info = Q.build_rows(svc, settings, spec)
        wanted = set(L.split_csv(self.verdict))
        if not rows:
            self.write_warning("No servers found. Check that the software collector has run and that "
                               "software=/ranges= match Rapid7 product names.")
        for r in rows:
            if wanted and r["verdict"] not in wanted:
                continue
            out = dict((k, r.get(k)) for k in FIELDS)
            out.update({
                "cve": spec.get("cve") or "", "rapid7_check": "Yes" if info["has_check"] else "Not yet",
                "check_added": info.get("check_added", ""), "vuln_ids": info.get("vuln_ids", []),
                "severity": info.get("severity", ""), "cvss_v3": info.get("cvss_v3", ""),
                "announced": info.get("announced", ""), "software": spec.get("software") or "",
                "ranges": spec.get("ranges") or "",
            })
            yield out


def resolve_spec(svc, cmd):
    """Merge command options with the saved CVE (options win)."""
    cve = (cmd.cve or "").strip().upper()
    saved = {}
    if cve:
        try:
            saved = L.kv(svc, L.SAVED_CVES).query_by_id(cve) or {}
        except Exception:
            saved = {}
    spec = {
        "cve": cve,
        "software": cmd.software or saved.get("software") or "",
        "ranges": cmd.ranges or saved.get("ranges") or "",
        "announced": cmd.announced or saved.get("announced") or "",
        "env": L.split_csv(cmd.env),
        "app": cmd.app or "",
        "include_inactive": bool(getattr(cmd, "include_inactive", False)),
        "include_nodata": bool(getattr(cmd, "include_nodata", False)),
    }
    if not cve and not spec["software"]:
        raise ValueError("Give cve= (a saved CVE or one with a Rapid7 check) or software= with ranges=")
    if spec["ranges"]:
        L.parse_ranges(spec["ranges"])
    return spec


if __name__ == "__main__":
    dispatch(R7Cve, sys.argv, sys.stdin, sys.stdout, __name__)
