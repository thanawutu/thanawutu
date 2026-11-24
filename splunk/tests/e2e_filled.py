# -*- coding: utf-8 -*-
"""Second pass: every dashboard with all search boxes filled in (on top of the defaults)."""
import os, sys
import splunk_e2e as E
F = {
 "r7_cve_overview.xml": {"f_cve": "CVE-2026", "f_title": "e", "f_sw": "o", "f_plat": "e", "f_os": "Red Hat", "f_cvss": "7",
                         "f_sev": 'severity=*', "f_win": "-30d@d", "f_addfrom": "2026-11-01", "f_addto": "2026-11-24",
                         "f_pubfrom": "2026-10-01", "f_pubto": "2026-11-24", "f_roll": "rollup=*"},
 "r7_cve_response.xml": {"cve": "CVE-2026-150000", "software": "PHP", "ranges": "< 9.9", "announced": "2026-11-18", "env": "Prod",
                         "app": "App 1", "ready": "1", "l_cve": "2026", "l_sw": "o", "l_plat": "e", "l_os": "Linux", "l_cvss": "4",
                         "l_pub": "2026-11-01", "l_add": "2026-11-01", "s_host": "srv", "s_os": "Red", "s_verdict": "Likely affected",
                         "only": "true", "hosts": "10000,10001", "preview_nonce": "x"},
 "r7_impacted_assets.xml": {"f_host": "srv00", "f_app": "App", "f_env": "Prod*", "f_os": "Red Hat", "f_cve": "CVE-2026",
                            "cve_join": '| join type=inner asset_id [search `r7_latest(rapid7:vm:asset_vuln)` [| inputlookup r7_vuln_catalog_lookup | search cves_str="*CVE-2026-15*" | fields vuln_id | rename vuln_id as search | format] | fields asset_id]',
                            "sw_join": '| join type=inner asset_id [search `r7_latest(rapid7:vm:software)` product="*OpenSSH*" | stats count by asset_id | fields asset_id]',
                            "f_sev": "critical>0", "asset": "10000", "asset_name": "SRV0000", "d_cve": "CVE", "d_sw": "o", "d_sev": "Critical",
                            "d_cvss": "7", "r_hosts": "10000,10001", "preview_nonce": "x"},
 "r7_inventory.xml": {"kind": "Software", "product": "OpenSSH", "ranges": "< 9.8", "announced": "2026-11-18", "env": "Prod*",
                      "q_sw": "open", "q_vendor": "vend", "q_os": "Red", "q_ver": "1.", "q_host": "srv", "hosts": "10000", "preview_nonce": "x"},
 "r7_scan_jobs.xml": {"j_cve": "CVE", "j_sw": "PHP", "j_host": "web", "j_status": "Finished", "j_from": "2026-11-01", "job": "JOB-20261124172411-LZ0K"},
 "r7_cmdb_changes.xml": {"range": "-90d", "c_host": "SRV", "c_os": "Linux", "c_from": "2026-11-01", "change": "*"},
 "r7_saved_cves.xml": {"closed": "true", "w_cve": "CVE", "w_sw": "PHP", "w_plat": "", "w_os": "", "w_cvss": "0", "w_pub": "2026-01-01",
                       "w_add": "2026-01-01", "cve": "CVE-2026-150000", "env": "Prod · DC,Prod · DR", "app": "App 1", "scope": "all", "preview_nonce": "x"},
 "r7_asset_management.xml": {"status": "*", "cat": '(device_category="SERVER" OR device_category="NETWORK")', "envc": "PROD",
                             "gap_group": "Network", "am_host": "SRV", "am_os": "Red", "am_app": "App", "issue": "Environment differs",
                             "req_issue": "Environment differs"},
}
views = os.path.join(E.APPDIR, "default", "data", "ui", "views")
tot = {"ok  ": 0, "WARN": 0, "FAIL": 0}
for f, toks in F.items():
    print("--", f)
    for i, (q, e, l) in enumerate(E.dashboard_searches(os.path.join(views, f), toks)):
        if "action=done" in q or "action=request" in q or "dryrun=false" in q or "action=add" in q:
            continue
        r = E.run(q, e, l, label="%s #%d %s" % (f, i, q.strip().splitlines()[0][:80]))
        tot[E.report(r)] += 1
print("== summary", tot)
