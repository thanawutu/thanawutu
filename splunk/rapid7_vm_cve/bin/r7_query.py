# -*- coding: utf-8 -*-
"""Build the per-server CVE / software view from data already in Splunk.

Used by the r7cve, r7rescan and r7cvewatch commands. Reads only indexed
Rapid7 data and the CMDB lookups; never calls the Rapid7 API, so normal
users can run it without access to the Rapid7 credential.
"""
from __future__ import absolute_import

import r7_lib as L


def _like(pattern):
    p = (pattern or "").strip().lower().replace("%", "")
    if "*" in p:
        return p.replace("*", "%")
    return "%" + p + "%"


def latest_run(service, index, sourcetype):
    rows = L.oneshot(service, 'search index=%s sourcetype=%s | stats latest(run_id) as run_id'
                     % (L.spl_quote(index), L.spl_quote(sourcetype)), earliest="-3d")
    return rows[0].get("run_id") if rows and rows[0].get("run_id") else None


def cve_info(service, index, cve):
    """Rapid7 vulnerability checks that reference the CVE."""
    if not cve:
        return {"has_check": False, "vuln_ids": [], "check_added": "", "severity": "", "cvss_v3": "",
                "title": "", "published": ""}
    spl = ('search index=%s sourcetype="rapid7:vm:vuln_content" %s '
           '| where mvfind(\'cves{}\', "^%s$")>=0 '
           '| stats latest(title) as title latest(severity) as severity max(cvss_v3) as cvss_v3 '
           'min(added) as added min(published) as published max(modified) as modified by vuln_id'
           % (L.spl_quote(index), L.spl_quote(cve), cve.replace('"', "")))
    rows = L.oneshot(service, spl, earliest="-400d")
    ids = [r["vuln_id"] for r in rows if r.get("vuln_id")]
    added = sorted([r.get("added") for r in rows if r.get("added")])
    pub = sorted([r.get("published") for r in rows if r.get("published")])
    sev = [r.get("severity") for r in rows if r.get("severity")]
    order = {"Critical": 3, "Severe": 2, "Moderate": 1}
    return {
        "has_check": bool(ids), "vuln_ids": ids, "check_added": added[0] if added else "",
        "published": pub[0] if pub else "",
        "severity": max(sev, key=lambda s: order.get(s, 0)) if sev else "",
        "cvss_v3": max([r.get("cvss_v3") or "" for r in rows] or [""]),
        "title": rows[0].get("title", "") if rows else "",
    }


def asset_table(service, index, run_id):
    """Latest Rapid7 asset/site snapshot enriched with the CMDB."""
    if not run_id:
        return {}
    spl = ('search index=%s sourcetype="rapid7:vm:asset_site" run_id=%s | dedup asset_id '
           '| `r7_cmdb_enrich` '
           '| table asset_id hostname ip os site_id site_name site_names last_scan credentialed software_count '
           'cmdb_host cmdb_status cmdb_class cmdb_env env_label env_group appname app_id device_category'
           % (L.spl_quote(index), L.spl_quote(run_id)))
    return dict((r.get("asset_id"), r) for r in L.oneshot(service, spl, earliest="-3d") if r.get("asset_id"))


def software_hits(service, index, run_id, pattern):
    if not run_id or not pattern:
        return []
    spl = ('search index=%s sourcetype="rapid7:vm:software" run_id=%s '
           '| eval sw=lower(vendor." ".product) | where like(sw, %s) '
           '| stats values(product) as product first(vendor) as vendor values(cpe) as cpe by asset_id version'
           % (L.spl_quote(index), L.spl_quote(run_id), L.spl_quote(_like(pattern))))
    return L.oneshot(service, spl, earliest="-3d")


def finding_assets(service, index, vuln_ids):
    """Return (set of asset_ids with any of the vuln ids, findings_available)."""
    if not vuln_ids:
        return set(), True
    run_id = latest_run(service, index, "rapid7:vm:asset_vuln")
    if not run_id:
        return set(), False
    terms = " OR ".join(L.spl_quote(v) for v in vuln_ids)
    spl = ('search index=%s sourcetype="rapid7:vm:asset_vuln" run_id=%s (%s) | table asset_id vuln_ids{}'
           % (L.spl_quote(index), L.spl_quote(run_id), terms))
    hit = set()
    wanted = set(vuln_ids)
    for r in L.oneshot(service, spl, earliest="-3d"):
        if wanted & set(L.as_list(r.get("vuln_ids{}"))):
            hit.add(r.get("asset_id"))
    return hit, True


def build_rows(service, settings, spec):
    """spec keys: cve, software, ranges, announced, env (list), app, include_inactive (bool),
    include_nodata (bool). Returns (rows, info)."""
    index = settings["index"]
    stale = int(settings.get("stale_days") or 7)
    info = cve_info(service, index, spec.get("cve"))
    run_id = latest_run(service, index, "rapid7:vm:asset_site")
    assets = asset_table(service, index, run_id)
    hits = software_hits(service, index, run_id, spec.get("software"))
    vuln_assets, findings_ok = finding_assets(service, index, info["vuln_ids"])
    announced = spec.get("announced") or info.get("published") or ""

    rows = []
    seen = set()
    for h in hits:
        aid = h.get("asset_id")
        a = assets.get(aid)
        if not a:
            continue
        seen.add(aid)
        rows.append(_row(a, h, spec, info, vuln_assets, findings_ok, announced, stale))
    for aid in vuln_assets:
        if aid in seen or aid not in assets:
            continue
        seen.add(aid)
        rows.append(_row(assets[aid], None, spec, info, vuln_assets, findings_ok, announced, stale))
    if spec.get("include_nodata"):
        for aid, a in assets.items():
            if aid in seen or L.truthy(a.get("credentialed")):
                continue
            rows.append(_row(a, None, spec, info, vuln_assets, findings_ok, announced, stale))

    envs = set(spec.get("env") or [])
    app = (spec.get("app") or "").strip().lower()
    out = []
    for r in rows:
        if not spec.get("include_inactive") and r["cmdb_status"] in L.BLOCKED_STATUSES:
            continue
        if envs and r["env_label"] not in envs and r["env_group"] not in envs:
            continue
        if app and app not in [x.lower() for x in L.as_list(r.get("appname"))]:
            continue
        out.append(r)
    info.update({"announced": announced, "run_id": run_id or "", "findings_available": findings_ok,
                 "assets_in_snapshot": len(assets)})
    return out, info


def _row(a, hit, spec, info, vuln_assets, findings_ok, announced, stale):
    aid = a.get("asset_id")
    version = hit.get("version") if hit else ""
    vendor = hit.get("vendor") if hit else ""
    if info["has_check"]:
        vulnerable = (aid in vuln_assets) if findings_ok else None
    else:
        vulnerable = False
    base = {
        "version": version, "vendor": vendor, "ranges": spec.get("ranges") or "",
        "last_scan": a.get("last_scan"), "credentialed": L.truthy(a.get("credentialed")),
        "r7_vulnerable": vulnerable,
    }
    v = L.verdict(base, announced, info.get("check_added"), info["has_check"], stale)
    status = a.get("cmdb_status") or "NOT_IN_CMDB"
    return {
        "asset_id": aid, "hostname": a.get("hostname") or a.get("cmdb_host") or "", "ip": a.get("ip") or "",
        "cmdb_host": a.get("cmdb_host") or "", "cmdb_status": status,
        "env_label": a.get("env_label") or "UNKNOWN", "env_group": a.get("env_group") or "UNKNOWN",
        "appname": a.get("appname") or "", "app_id": a.get("app_id") or "",
        "device_category": a.get("device_category") or "", "os": a.get("os") or "",
        "site_id": a.get("site_id") or "", "site_name": a.get("site_name") or "",
        "product": ", ".join(L.as_list(hit.get("product"))) if hit else "", "vendor": vendor,
        "version": version or ("no software data" if not base["credentialed"] else ""),
        "installed": bool(hit), "last_scan": a.get("last_scan") or "", "credentialed": base["credentialed"],
        "freshness": v["freshness"], "days_before_announced": v["days_before"],
        "range_status": v["range_status"], "r7_result": v["r7_result"], "r7_vulnerable": vulnerable,
        "verdict": v["verdict"], "action": v["action"],
        "rescan_blocked": status in L.BLOCKED_STATUSES,
    }
