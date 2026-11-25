# -*- coding: utf-8 -*-
"""End-to-end test of the app on a real Splunk instance loaded with gen_data.py data.

Runs the scheduled searches in production order, every dashboard panel (default tokens,
plus test values for click-through panels) and the search commands. Reports, per search:
errors, warnings (truncation, memory limits, subsearch limits), result count and run time.

Usage: python3 splunk_e2e.py https://localhost:8089 admin PASSWORD /path/to/app
"""
import json
import os
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from urllib import parse, request

BASE, USER, PASSWORD, APPDIR = sys.argv[1:5]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
OPENER = request.build_opener(request.HTTPSHandler(context=CTX), request.ProxyHandler({}))
import base64
AUTH = "Basic " + base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode()
APP = "rapid7_vm_cve"


def call(method, path, data=None):
    url = BASE + path
    body = parse.urlencode(data, doseq=True).encode() if data else None
    req = request.Request(url, data=body, method=method, headers={"Authorization": AUTH})
    with OPENER.open(req, timeout=900) as r:
        return json.loads(r.read().decode() or "{}")


def run(spl, earliest="-24h", latest="now", label=""):
    if not spl.strip().startswith(("search ", "|")):
        spl = "search " + spl.strip()
    t0 = time.time()
    try:
        job = call("POST", "/servicesNS/%s/%s/search/jobs?output_mode=json" % (USER, APP),
                   {"search": spl, "exec_mode": "blocking", "earliest_time": earliest, "latest_time": latest,
                    "max_count": 0})
        sid = job["sid"]
        info = call("GET", "/servicesNS/%s/%s/search/jobs/%s?output_mode=json" % (USER, APP, sid))["entry"][0]["content"]
        res = call("GET", "/servicesNS/%s/%s/search/jobs/%s/results?output_mode=json&count=0" % (USER, APP, sid))
    except Exception as e:
        return {"label": label, "error": ["HTTP: %s" % e], "warn": [], "rows": 0, "secs": round(time.time() - t0, 1), "results": []}
    msgs = info.get("messages") or {}
    errs, warns = [], []
    if isinstance(msgs, dict):
        errs = list(msgs.get("fatal", [])) + list(msgs.get("error", []))
        warns = list(msgs.get("warn", []))
    else:
        for m in msgs:
            t = str(m.get("type", "")).upper()
            (errs if t in ("ERROR", "FATAL") else warns if t == "WARN" else []).append(m.get("text"))
    for m in res.get("messages") or []:
        t = str(m.get("type", "")).upper()
        if t in ("ERROR", "FATAL"):
            errs.append(m.get("text"))
        elif t == "WARN":
            warns.append(m.get("text"))
    return {"label": label, "error": errs, "warn": warns, "rows": len(res.get("results") or []),
            "secs": round(time.time() - t0, 1), "results": res.get("results") or []}


def subst(q, tokens):
    def rep(m):
        name, filt = m.group(1), m.group(2)
        v = tokens.get(name, "")
        if filt == "s":
            return '"%s"' % str(v).replace('"', '\\"')
        return str(v)
    q = re.sub(r"\$([A-Za-z0-9_.]+)(?:\|(\w+))?\$", rep, q)
    return q.replace("$$", "$")


def dashboard_searches(path, extra_tokens):
    root = ET.parse(path).getroot()
    tokens = {}
    for inp in root.iter("input"):
        tok = inp.get("token")
        dflt = inp.find("default")
        val = (dflt.text or "") if dflt is not None else ""
        if inp.get("type") == "multiselect" and inp.find("valuePrefix") is not None and val:
            vp, vs = inp.findtext("valuePrefix") or "", inp.findtext("valueSuffix") or ""
            val = (inp.findtext("prefix") or "") + vp + val + vs + (inp.findtext("suffix") or "")
        tokens[tok] = val
    init = root.find("init")
    if init is not None:
        for st in init.findall("set"):
            tokens[st.get("token")] = st.text or ""
    tokens.update(extra_tokens)
    bases = {}
    out = []
    for s in root.iter("search"):
        q = s.findtext("query")
        if q is None:
            continue
        e, l = s.findtext("earliest") or "-24h", s.findtext("latest") or "now"
        if s.get("id"):
            bases[s.get("id")] = (q, e, l)
    for s in root.iter("search"):
        q = s.findtext("query")
        if q is None:
            continue
        e, l = s.findtext("earliest") or "-24h", s.findtext("latest") or "now"
        if s.get("base"):
            bq, e, l = bases[s.get("base")]
            q = bq.rstrip() + "\n" + q
        out.append((subst(q, tokens), e, l))
    return out


def report(r, show=False):
    flag = "FAIL" if r["error"] else ("WARN" if r["warn"] else "ok  ")
    print("%s %6.1fs %7d rows  %s" % (flag, r["secs"], r["rows"], r["label"]))
    for m in r["error"]:
        print("       ERROR:", str(m)[:300])
    for m in r["warn"]:
        print("       WARN :", str(m)[:300])
    if show and r["results"]:
        print("       first:", json.dumps(r["results"][0])[:400])
    return flag


if __name__ == "__main__":
    summary = {"ok  ": 0, "WARN": 0, "FAIL": 0}
    print("== data")
    r = run('search index=rapid7 OR index=cmdb earliest=0 | stats count by sourcetype', "0", label="events per sourcetype")
    report(r)
    for x in r["results"]:
        print("       %-28s %s" % (x["sourcetype"], x["count"]))

    print("== scheduled searches (production order)")
    order = ["Rapid7 CVE - vuln catalog", "Rapid7 CVE - recent checks lookup", "Rapid7 CVE - recent hits lookup",
             "Rapid7 CVE - asset summary", "Rapid7 CVE - CMDB snapshot", "Rapid7 CVE - CMDB change tracker",
             "Rapid7 CVE - CMDB history backfill (run once)"]
    for name in order:
        r = run('| savedsearch "%s"' % name, "0", label=name)
        r["warn"] = [w for w in r["warn"] if "Found no results to append" not in str(w)]  # nothing changed: expected
        summary[report(r, show=True)] += 1

    print("== commands")
    cmds = [
        '| makeresults count=3 | streamstats count | eval version=case(count=1,"8.1.27",count=2,"8.1.34",count=3,"2.4.6-99.el7") | r7vercheck ranges="8.1 < 8.1.34 ; < 2.4.63"',
        '| r7cve software="OpenSSH" ranges="< 9.8"',
        '| r7cvewatch action=update cve=CVE-2026-150000 announced=2026-11-18 software="PHP" ranges="< 9.9"',
        '| r7cvewatch action=list with_counts=true',
        '| r7cve cve=CVE-2026-150000',
        '| r7rescan cve=CVE-2026-150000 env="Prod" dryrun=true',
        '| r7rescan hosts="SRV0001,SRV0002" only_hosts=true dryrun=true detail=true',
        '| r7assetaction action=request hosts="SRV0001" issue="Environment differs" note="test" request_id=E2E1',
        '| r7assetaction action=list',
        '| r7scanstatus',
    ]
    for c in cmds:
        r = run(c, label=c[:110])
        summary[report(r, show=True)] += 1

    print("== dashboards (every panel, default tokens)")
    extra = {
        "r7_cve_response.xml": {"cve": "CVE-2026-150000", "software": "PHP", "ranges": "< 9.9", "ready": "1",
                                "only": "false", "hosts": "", "preview_nonce": "x", "launch_nonce": "E2E-L1", "job_id": "JOB-20261124172411-LZ0K"},
        "r7_impacted_assets.xml": {"asset": "10000", "asset_name": "SRV0000", "r_hosts": "10000", "preview_nonce": "x", "job_id": "JOB-20261124172411-LZ0K"},
        "r7_inventory.xml": {"product": "OpenSSH", "hosts": "10000", "preview_nonce": "x", "job_id": "JOB-20261124172411-LZ0K"},
        "r7_scan_jobs.xml": {"job": "JOB-20261124172411-LZ0K"},
        "r7_saved_cves.xml": {"cve": "CVE-2026-150000", "env": "Prod · DC", "preview_nonce": "x", "job_id": "JOB-20261124172411-LZ0K"},
        "r7_asset_management.xml": {"issue": "Environment differs", "req_issue": "Environment differs"},
    }
    views = os.path.join(APPDIR, "default", "data", "ui", "views")
    for f in sorted(os.listdir(views)):
        print("--", f)
        for i, (q, e, l) in enumerate(dashboard_searches(os.path.join(views, f), extra.get(f, {}))):
            if "action=done" in q or "action=request" in q or "dryrun=false" in q or "action=add" in q:
                continue  # state-changing panels are covered by the command tests
            first = q.strip().splitlines()[0][:90]
            r = run(q, e, l, label="%s #%d %s" % (f, i, first))
            summary[report(r)] += 1
    print("== summary", summary)
