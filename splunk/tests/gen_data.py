# -*- coding: utf-8 -*-
"""Generate test data shaped and sized like the production environment (2026-11-24):

- 1,655 Rapid7 assets: Prod-DC 518, DR 77, UAT 236, SIT 49, INFRA 299, UNKNOWN 3,
  not in CMDB 275, DECOMMISSION 196, INACTIVE 2; 70 % with software data
- ~634,000 findings (asset_vuln: one event per asset, up to 9,165 IDs)
- 91,297 Rapid7 checks (vuln_content), incl. rollups with up to 21,960 CVEs and
  46,749 checks re-added in bulk on 2026-11-12
- ~200,000 software rows, v1.0 rapid7:vm:asset events, run events
- CMDB lookups (cmdb_assets.csv, cmdb_ip_map.csv, asset_context.csv, rapid7_host_context.csv)
  in the column layout of the existing dashboards, and index=cmdb mssql_inventory_Asset events

Usage: python3 gen_data.py OUTDIR
"""
import csv
import datetime as dt
import json
import os
import random
import sys

R = random.Random(20261124)
TODAY = dt.date(2026, 11, 24)
OUT = sys.argv[1] if len(sys.argv) > 1 else "testdata"
os.makedirs(OUT, exist_ok=True)
RUN_SW, RUN_AV = "20261124T020000Z", "20261124T034500Z"

PLAT = ["redhat_linux", "oracle_linux", "alma_linux", "debian", "ubuntu", "suse", "msft", "jre-vuln", "apache-httpd",
        "php", "openssl", "cisco-ios-xe", "vmware-esxi", "splunk"]
COMP = ["OpenJDK", "PHP", "OpenSSH", "OpenSSL", "kernel", "sudo", "Apache HTTP Server", "Apache Tomcat", "glibc",
        "curl", "Windows Server", "Cisco IOS XE", "VMware ESXi", "Splunk"]
VENDOR = ["Red Hat", "Oracle Linux", "Alma Linux", "Debian", "Ubuntu", "SUSE", "Microsoft Windows", "Oracle Java",
          "Apache", "PHP Group", "OpenSSL", "Cisco", "VMware", "Splunk"]


def d(date):
    return date.strftime("%Y-%m-%d")


# ----------------------------------------------------------------- checks catalog
checks = []
cve_n = [100000]


def new_cve(year):
    cve_n[0] += 1
    return "CVE-%d-%d" % (year, cve_n[0])


def add_check(added, published, n_cves=None, rollup=False):
    p = R.randrange(len(PLAT))
    year = published.year
    if rollup:
        cves = [new_cve(R.randint(2015, 2026)) for _ in range(n_cves)]
        title = "Vulnerabilities deemed not relevant on Red Hat Enterprise Linux %d" % R.choice([8, 9, 10])
        vid = "linuxrpm-rhsa-rhel%d-family-unaffected-vulns-%d" % (R.choice([8, 9, 10]), len(checks))
        sev = "Moderate"
    else:
        cves = [new_cve(year) for _ in range(n_cves or R.choice([1, 1, 1, 2, 3]))]
        title = "%s: %s: %s: %s" % (VENDOR[p], cves[0], COMP[p], R.choice(["Heap overflow", "Use-after-free",
                                                                           "Privilege escalation", "Denial of service",
                                                                           "Information disclosure"]))
        vid = "%s-%s" % (PLAT[p], cves[0].lower())
        sev = R.choice(["Critical", "Severe", "Severe", "Moderate"])
    modified = added + dt.timedelta(days=R.randint(0, max(0, (TODAY - added).days)))
    checks.append({"vuln_id": vid, "title": title, "severity": sev, "severity_score": {"Critical": 9, "Severe": 6, "Moderate": 3}[sev],
                   "cvss_v3": None if rollup else round(R.uniform(4, 10), 1), "cvss_v2": None, "published": d(published),
                   "added": d(added), "modified": d(min(modified, TODAY)), "risk_score": round(R.uniform(100, 900), 1),
                   "run_id": "20261124T060000Z", "cve_count": len(cves), "categories": [VENDOR[p]], "cves": cves})


# 46,749 checks re-added in bulk on 2026-11-12 for old CVEs (published 2000-2026)
for _ in range(46749):
    pub = dt.date(R.randint(2000, 2026), R.randint(1, 12), R.randint(1, 28))
    pub = min(pub, dt.date(2026, 11, 11))
    add_check(dt.date(2026, 11, 12), pub)
# daily new content over the last 60 days: CVEs published shortly before the check
for back in range(1, 61):
    day = TODAY - dt.timedelta(days=back)
    if day == dt.date(2026, 11, 12):
        continue
    for _ in range(R.randint(150, 900)):
        add_check(day, day - dt.timedelta(days=R.randint(0, 25)))
# older catalog up to 91,297 checks
while len(checks) < 91290:
    added = dt.date(R.randint(2004, 2026), R.randint(1, 12), R.randint(1, 28))
    added = min(added, TODAY - dt.timedelta(days=61))
    add_check(added, added - dt.timedelta(days=R.randint(0, 60)))
# rollups
for n in (21960, 15000, 9000, 4200, 2431, 800, 120):
    add_check(dt.date(2026, 11, 23), dt.date(2026, 11, 20), n_cves=n, rollup=True)
recent = [c for c in checks if c["added"] >= d(TODAY - dt.timedelta(days=30))]
old = [c for c in checks if c["added"] < d(TODAY - dt.timedelta(days=30))]

with open(os.path.join(OUT, "vuln_content.json"), "w") as fh:
    for c in checks:
        fh.write(json.dumps(c) + "\n")

# ----------------------------------------------------------------- assets
groups = ([("PROD", "", "WORKING_ACTIVE", "SERVER")] * 518 + [("DR", "", "WORKING_ACTIVE", "SERVER")] * 77 +
          [("NONPROD", "UAT", "WORKING_ACTIVE", "SERVER")] * 236 + [("NONPROD", "SIT", "WORKING_ACTIVE", "SERVER")] * 49 +
          [("INFRA", "", "WORKING_ACTIVE", "NETWORK")] * 200 + [("INFRA", "", "WORKING_ACTIVE", "HYPERVISOR")] * 99 +
          [("UNKNOWN", "", "WORKING_ACTIVE", "SERVER")] * 3 + [(None, None, None, None)] * 275 +
          [("DECOMMISSIONED", "", "DECOMMISSION", "SERVER")] * 196 + [("INACTIVE", "", "INACTIVE", "SERVER")] * 2)
OSES = ["Red Hat Enterprise Linux 9.6", "Red Hat Enterprise Linux 8.10", "Oracle Linux 8.10", "Ubuntu Linux 22.04",
        "Microsoft Windows Server 2019 Standard Edition 1809", "Microsoft Windows Server 2016 Standard Edition 1607",
        "Microsoft Windows Server 2012 R2 Standard Edition"]
assets = []
for i, g in enumerate(groups):
    cls, env, status, cat = g
    host = ("SRV%04d" % i) if cat != "NETWORK" else ("SW-%04d" % i)
    ip = "10.%d.%d.%d" % (R.choice([10, 20, 30, 35, 50, 190, 200]), R.randint(0, 255), R.randint(1, 254))
    os_ = "Cisco IOS XE 17.9" if cat == "NETWORK" else ("VMware ESXi 8.0" if cat == "HYPERVISOR" else R.choice(OSES))
    cred = (cat == "SERVER" and R.random() < 0.85) or (cat != "SERVER" and R.random() < 0.3)
    site = {"PROD": "DC1-Servers", "DR": "DC2-Servers", "NONPROD": "NONPROD-Servers", "INFRA": "Infra"}.get(cls, "Misc")
    last = TODAY - dt.timedelta(days=R.choice([0, 1, 1, 2, 3, 5, 9, 20, 45, 63]))
    assets.append({"asset_id": str(10000 + i), "host": host, "hostname": host.lower() + ".bank.local", "ip": ip,
                   "os": os_, "cls": cls, "env": env, "status": status, "cat": cat, "cred": cred, "site": site,
                   "last": last})

with open(os.path.join(OUT, "asset_site.json"), "w") as a_fh, open(os.path.join(OUT, "software.json"), "w") as s_fh, \
        open(os.path.join(OUT, "asset_v1.json"), "w") as v_fh:
    n_sw = 0
    for a in assets:
        base = {"asset_id": a["asset_id"], "hostname": a["hostname"], "ip": a["ip"], "last_scan": d(a["last"]) + "T02:00:00Z"}
        a_fh.write(json.dumps(dict(base, run_id=RUN_SW, os=a["os"], os_vendor="", os_family="", os_product=a["os"],
                                   os_version="", site_id=a["site"], site_name=a["site"], site_ids=[a["site"]],
                                   site_names=a["site"], software_count=170 if a["cred"] else 0,
                                   credentialed=a["cred"], mac="", risk_score=1000), sort_keys=True) + "\n")
        s_fh.write(json.dumps(dict(base, run_id=RUN_SW, vendor="", product=a["os"], version="", family="",
                                   type="Operating System", cpe=""), sort_keys=True) + "\n")
        if a["cred"]:
            for k in range(170):
                prod = R.choice(COMP + ["pkg-%d" % R.randint(1, 4000)] * 6)
                ver = "%d.%d.%d" % (R.randint(1, 9), R.randint(0, 20), R.randint(0, 40))
                s_fh.write(json.dumps(dict(base, run_id=RUN_SW, vendor="Vendor", product=prod, version=ver, family="",
                                           type="", cpe=""), sort_keys=True) + "\n")
                n_sw += 1
        v_fh.write(json.dumps({"ip": a["ip"], "hostname": a["hostname"], "os": a["os"],
                               "last_assessed_epoch": int(dt.datetime(a["last"].year, a["last"].month, a["last"].day).timestamp()),
                               "vuln_critical": R.randint(0, 200), "vuln_severe": R.randint(0, 400), "risk_score": R.randint(0, 99999),
                               "site_name": a["site"], "asset_id": a["asset_id"]}) + "\n")

# ----------------------------------------------------------------- findings: ~634k IDs
total = 0
with open(os.path.join(OUT, "asset_vuln.json"), "w") as fh:
    sizes = []
    for i, a in enumerate(assets):
        n = int(R.lognormvariate(5.4, 0.9))
        sizes.append(n)
    sizes[0] = 9165
    scale = 634715.0 / sum(sizes)
    for a, n in zip(assets, sizes):
        n = max(1, min(9165, int(n * scale))) if n != 9165 else 9165
        ids = set()
        for _ in range(n):
            c = R.choice(recent) if R.random() < 0.06 else R.choice(old)
            ids.add(c["vuln_id"])
        total += len(ids)
        fh.write(json.dumps({"asset_id": a["asset_id"], "hostname": a["hostname"], "ip": a["ip"],
                             "last_scan": d(a["last"]) + "T02:00:00Z", "run_id": RUN_AV, "vuln_count": len(ids),
                             "vuln_ids": sorted(ids)}, sort_keys=True) + "\n")

with open(os.path.join(OUT, "run.json"), "w") as fh:
    for col, ev in (("software", n_sw + len(assets) * 2), ("asset_vulns", len(assets)), ("vuln_content", len(checks))):
        fh.write(json.dumps({"collector": col, "status": "success", "events": ev, "run_id": RUN_SW, "api_calls": 100,
                             "duration_s": 100.0, "error": ""}) + "\n")

# ----------------------------------------------------------------- CMDB lookups
cmdb = [a for a in assets if a["status"]]
extra_cmdb = []
for i in range(1900):  # CMDB-only / never scanned / other categories, as in production (3,638 rows)
    st = R.choice(["WORKING_ACTIVE"] * 4 + ["DECOMMISSION"] * 3 + ["INACTIVE"])
    cls = {"WORKING_ACTIVE": R.choice(["PROD", "NONPROD", "DR", "INFRA"]), "DECOMMISSION": "DECOMMISSIONED", "INACTIVE": "INACTIVE"}[st]
    extra_cmdb.append({"host": "CMDB%04d" % i, "ip": "10.99.%d.%d" % (i // 250, i % 250 + 1), "status": st, "cls": cls,
                       "env": "UAT" if cls == "NONPROD" else "", "cat": R.choice(["SERVER", "SERVER", "NETWORK", "VENDOR_APPLIANCE", "CLOUD_EPHEMERAL"])})
with open(os.path.join(OUT, "cmdb_assets.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["host", "ip", "vendor", "app_id", "appname", "device_category", "va_scannable", "cmdb_status", "cmdb_env", "cmdb_class"])
    for a in cmdb:
        w.writerow([a["host"], a["ip"], "VMware, Inc", "APP-%04d" % (int(a["asset_id"]) % 300), "App %d\nShared App" % (int(a["asset_id"]) % 300),
                    a["cat"], "yes", a["status"], a["env"], a["cls"]])
    for e in extra_cmdb:
        w.writerow([e["host"], e["ip"], "VMware, Inc", "APP-9999", "Other app", e["cat"], R.choice(["yes", "agent", "review"]),
                    e["status"], e["env"], e["cls"]])
with open(os.path.join(OUT, "cmdb_ip_map.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["ip", "host"])
    for a in cmdb:
        w.writerow([a["ip"], a["host"]])
    for e in extra_cmdb:
        w.writerow([e["ip"], e["host"]])
with open(os.path.join(OUT, "rapid7_host_context.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["host", "ip", "env"])
    for a in assets:
        w.writerow([a["host"], a["ip"], {"PROD": "PRD", "DR": "DR", "NONPROD": "UAT"}.get(a["cls"], "INFRA")])
with open(os.path.join(OUT, "asset_context.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["host", "in_cmdb", "r7_env", "r7_class", "cmdb_class", "cmdb_status", "va_scannable", "ip", "device_category",
                "cmdb_env", "vendor", "app_id", "appname"])
    for a in assets:
        r7c = {"PROD": "PROD", "DR": "DR", "NONPROD": "NONPROD"}.get(a["cls"], "INFRA")
        if a["status"] == "WORKING_ACTIVE" and R.random() < 0.05:
            r7c = "NONPROD" if a["cls"] == "PROD" else "PROD"
        w.writerow([a["host"], 1 if a["status"] else 0, a["site"], r7c, a["cls"] or "", a["status"] or "", "yes", a["ip"], a["cat"] or "",
                    a["env"] or "", "VMware, Inc", "APP-1", "App"])
    for e in extra_cmdb:
        w.writerow([e["host"], 1, "", "", e["cls"], e["status"], R.choice(["yes", "agent", "review"]),
                    e["ip"] if R.random() > 0.1 else "", e["cat"], e["env"], "VMware, Inc", "APP-9999", "Other app"])
with open(os.path.join(OUT, "mssql_inventory_asset.json"), "w") as fh:
    for a in cmdb[:900]:
        fh.write(json.dumps({"ComputerName": a["host"], "ServerStatus": a["status"], "NetworkAddress": a["ip"]}) + "\n")

print("checks", len(checks), "recent", len(recent), "assets", len(assets), "software", n_sw, "findings", total)
