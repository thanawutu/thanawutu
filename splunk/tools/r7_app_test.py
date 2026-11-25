# -*- coding: utf-8 -*-
"""Read-only test pack for the Rapid7 VM CVE Response app, for a production search head.

It runs, through the Splunk REST API, the same searches the app's pages and buttons run,
and writes a report: errors, warnings (truncation, limits), row counts and run time.

  1. Account, app version, collected data, lookups and KV collections
  2. Scheduled searches: enabled, schedule, last runs (from the scheduler log; nothing is run)
  3. Search commands, read-only forms only (dry runs, lists, status)
  4. Every panel on every page with the default values
  5. Every search box and drop-down, one at a time, filled with a value from your own data
     (a CVE, software, host, OS, application ... picked automatically), and every drop-down choice

READ-ONLY: it never runs a search that saves or changes anything. Any search containing
dryrun=false, r7cvewatch add/update/close/reopen/delete or autoclose=true, r7assetaction
request/done/cancel, r7scanpoll, outputlookup, outputcsv, collect, delete, sendemail or
savedsearch is skipped and listed as "skipped (would change data)".

The report holds counts, timings and Splunk messages, and the sample values used (CVE ID,
software name, Rapid7 asset ID). It does not hold hostnames, IPs or result rows.

Run on a search head (SIEMSHEPR01), with an account that has the rapid7_cve_analyst role:

  /opt/splunk/bin/splunk cmd python3 r7_app_test.py --user <account>

The password is asked at a prompt. Options:
  --url https://localhost:8089   splunkd management URL (default)
  --out r7_app_test_report.txt   report file (default, in the current folder)
  --quick                        skip step 5 (search boxes and drop-downs)
  --slow 60                      seconds after which a search is listed as slow
"""
import argparse
import base64
import datetime as dt
import getpass
import json
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from urllib import error, parse, request

APP = "rapid7_vm_cve"
VERSION = "1.2 (for app 1.1.11)"

WRITE_PATTERNS = [
    r"dryrun\s*=\s*(false|f|0|no)\b",
    r"\br7cvewatch\b[^|]*action\s*=\s*\"?(add|update|close|reopen|delete|remove)",
    r"\bautoclose\s*=\s*\"?(true|t|1|yes)",
    r"\br7assetaction\b[^|]*action\s*=\s*\"?(request|done|cancel)",
    r"\br7scanpoll\b",
    r"\|\s*outputlookup\b", r"\|\s*outputcsv\b", r"\|\s*collect\b", r"\|\s*delete\b",
    r"\|\s*sendemail\b", r"\|\s*savedsearch\b", r"\|\s*tscollect\b", r"\|\s*mcollect\b",
]


def would_write(q):
    return any(re.search(p, q, re.I) for p in WRITE_PATTERNS)


class Splunk(object):
    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        ctx = ssl.create_default_context()
        if self.url.startswith("https://localhost") or self.url.startswith("https://127.0.0.1"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = request.build_opener(request.HTTPSHandler(context=ctx), request.ProxyHandler({}))
        # log in once and reuse the session, as Splunk Web does (a password check per request is slow
        # for LDAP / SSO accounts)
        t0 = time.time()
        body = parse.urlencode({"username": user, "password": password, "output_mode": "json"}).encode()
        with self.opener.open(request.Request(self.url + "/services/auth/login", data=body, method="POST"),
                              timeout=300) as r:
            key = json.loads(r.read().decode())["sessionKey"]
        self.auth = "Splunk " + key
        self.login_secs = round(time.time() - t0, 1)
        self.user = user

    def call(self, method, path, data=None, timeout=1800):
        body = parse.urlencode(data, doseq=True).encode() if data else None
        req = request.Request(self.url + path, data=body, method=method, headers={"Authorization": self.auth})
        with self.opener.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "{}")

    def search(self, spl, earliest="-24h", latest="now"):
        """Blocking search. Returns dict(error=[...], warn=[...], rows=int, secs=float, results=[...])."""
        spl = spl.strip()
        if not spl.startswith(("search ", "|")):
            spl = "search " + spl
        if would_write(spl):
            raise RuntimeError("refused: would change data")
        t0 = time.time()
        try:
            job = self.call("POST", "/servicesNS/%s/%s/search/jobs?output_mode=json" % (parse.quote(self.user), APP),
                            {"search": spl, "exec_mode": "blocking", "earliest_time": earliest or "",
                             "latest_time": latest or "", "max_count": 0, "timeout": 300})
            sid = job["sid"]
            base = "/servicesNS/%s/%s/search/jobs/%s" % (parse.quote(self.user), APP, sid)
            info = self.call("GET", base + "?output_mode=json")["entry"][0]["content"]
            res = self.call("GET", base + "/results?output_mode=json&count=0")
        except error.HTTPError as e:
            msg = e.read().decode(errors="replace")
            try:
                msg = "; ".join(m.get("text", "") for m in json.loads(msg).get("messages", []))
            except Exception:
                pass
            return {"error": ["HTTP %s: %s" % (e.code, msg[:300])], "warn": [], "rows": 0,
                    "secs": round(time.time() - t0, 1), "results": []}
        except Exception as e:
            return {"error": ["%s" % e], "warn": [], "rows": 0, "secs": round(time.time() - t0, 1), "results": []}
        errs, warns = [], []
        msgs = info.get("messages") or {}
        items = []
        if isinstance(msgs, dict):
            for k, v in msgs.items():
                items += [{"type": k, "text": t} for t in (v if isinstance(v, list) else [v])]
        else:
            items = list(msgs)
        items += list(res.get("messages") or [])
        for m in items:
            t, text = str(m.get("type", "")).upper(), m.get("text")
            if t in ("ERROR", "FATAL") and text not in errs:
                errs.append(text)
            elif t == "WARN" and text not in warns:
                warns.append(text)
        rows = res.get("results") or []
        return {"error": errs, "warn": warns, "rows": len(rows), "secs": round(time.time() - t0, 1), "results": rows}


class Report(object):
    def __init__(self, path, slow):
        self.f = open(path, "w")
        self.slow = slow
        self.total = {"ok": 0, "WARN": 0, "FAIL": 0, "skipped": 0}
        self.slow_list = []
        self.cache = {}
        self.mask = []

    def line(self, text=""):
        print(text)
        self.f.write(text + "\n")
        self.f.flush()

    def result(self, label, r):
        for secret in self.mask:
            if secret:
                label = label.replace(secret, "(sample host)")
        notes = [w for w in r["warn"] if "No servers found" in str(w)]  # filter matched nothing: normal
        r = dict(r, warn=[w for w in r["warn"] if w not in notes])
        flag = "FAIL" if r["error"] else ("WARN" if r["warn"] else "ok")
        self.total[flag] += 1
        self.line("%-4s %6.1fs %8d rows  %s" % (flag, r["secs"], r["rows"], label))
        for m in r["error"]:
            self.line("        ERROR: %s" % str(m)[:400])
        for m in r["warn"]:
            self.line("        WARN : %s" % str(m)[:400])
        if notes:
            self.line("        note : nothing matched this filter (normal)")
        if r["secs"] >= self.slow:
            self.slow_list.append((r["secs"], label))
        return r

    def skipped(self, label):
        self.total["skipped"] += 1
        self.line("skip   -       -       -   %s  (would change data)" % label)


# ---------------------------------------------------------------------- dashboards
TOKEN_RE = re.compile(r"\$([A-Za-z0-9_.]+)(?:\|(\w+))?\$")


def subst(q, tokens):
    def rep(m):
        v = tokens.get(m.group(1), "")
        if m.group(2) == "s":
            return '"%s"' % str(v).replace("\\", "\\\\").replace('"', '\\"')
        return str(v)
    return TOKEN_RE.sub(rep, q).replace("$$", "$")


def input_default(inp):
    d = inp.find("default")
    val = (d.text or "") if d is not None else ""
    if inp.get("type") in ("multiselect", "checkbox") and val:
        vp, vs = inp.findtext("valuePrefix") or "", inp.findtext("valueSuffix") or ""
        delim = inp.findtext("delimiter") or " "
        parts = [x.strip() for x in val.split(",")]
        val = (inp.findtext("prefix") or "") + delim.join(vp + x + vs for x in parts) + (inp.findtext("suffix") or "")
    return val


def apply_change(inp, value, tokens):
    """Apply an input's <change> handler for value (sets cve_join etc.)."""
    ch = inp.find("change")
    if ch is None:
        return
    chosen = None
    for c in ch.findall("condition"):
        if c.get("value") is not None:
            if c.get("value") == value:
                chosen = c
                break
        elif c.get("label") is None and c.get("match") is None and chosen is None:
            chosen = c
    for el in (chosen if chosen is not None else ch):
        if el.tag == "set" and el.get("token"):
            tokens[el.get("token")] = (el.text or "").replace("$value$", value).replace("$label$", value)
        elif el.tag == "unset" and el.get("token"):
            tokens.pop(el.get("token"), None)


def parse_view(xml_text):
    root = ET.fromstring(xml_text.encode("utf-8"))
    inputs = list(root.iter("input"))
    tokens = {}
    for inp in inputs:
        if inp.get("token"):
            tokens[inp.get("token")] = input_default(inp)
    init = root.find("init")
    if init is not None:
        for st in init.findall("set"):
            tokens[st.get("token")] = st.text or ""
    bases, searches = {}, []
    for s in root.iter("search"):
        q = s.findtext("query")
        if q is not None and s.get("id"):
            bases[s.get("id")] = (q, s.findtext("earliest"), s.findtext("latest"))
    # panel titles for labels
    titles = {}
    for panel in root.iter("panel"):
        t = panel.findtext("title") or ""
        for el in panel.iter():
            if el.tag == "search":
                ttl = t
                for viz in panel:
                    if viz.find("search") is el or el in list(viz.iter("search")):
                        ttl = viz.findtext("title") or t
                titles[id(el)] = ttl
    for s in root.iter("search"):
        q = s.findtext("query")
        if q is None:
            continue
        e, l = s.findtext("earliest"), s.findtext("latest")
        base_q = None
        if s.get("base"):
            bq, be, bl = bases.get(s.get("base"), ("", None, None))
            base_q = bq
            e, l = e or be, l or bl
        searches.append({"id": s.get("id"), "base": s.get("base"), "base_q": base_q, "q": q,
                         "earliest": e or "-24h", "latest": l or "now", "title": titles.get(id(s), "")})
    return root, inputs, tokens, searches


def composed(s, tokens):
    q = (s["base_q"].rstrip() + "\n" + s["q"]) if s["base_q"] else s["q"]
    return subst(q, tokens), subst(s["earliest"], tokens), subst(s["latest"], tokens)


def uses(s, tok):
    pat = re.compile(r"\$%s(\|\w+)?\$" % re.escape(tok))
    return bool(pat.search(s["q"]) or (s["base_q"] and pat.search(s["base_q"])))


# ---------------------------------------------------------------------- samples
def first(sp, rep, spl, earliest="-24h", label=""):
    r = sp.search(spl, earliest)
    rep.result("sample: " + label, r)
    return (r["results"] or [{}])[0]


def os_word(os_name):
    w = (os_name or "").split()
    return w[0] if w else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="https://localhost:8089")
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", default="r7_app_test_report.txt")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--slow", type=float, default=60)
    a = ap.parse_args()
    pw = getpass.getpass("Splunk password for %s: " % a.user)
    try:
        sp = Splunk(a.url, a.user, pw)
    except Exception as e:
        print("Login failed: %s" % e)
        return 2
    rep = Report(a.out, a.slow)
    t_start = time.time()
    rep.line("Rapid7 VM CVE Response - read-only test pack %s" % VERSION)
    rep.line("Started %s UTC against %s (login took %ss)" % (dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M"), a.url, sp.login_secs))

    # 1 ----------------------------------------------------------------- account and data
    rep.line("\n== 1. Account, app and data")
    try:
        ctx = sp.call("GET", "/services/authentication/current-context?output_mode=json")["entry"][0]["content"]
        caps = ctx.get("capabilities") or []
        rep.line("roles: %s" % ", ".join(ctx.get("roles") or []))
        rep.line("app capabilities: %s" % (", ".join(c for c in caps if c.startswith("rapid7_cve")) or "none"))
        app = sp.call("GET", "/services/apps/local/%s?output_mode=json" % APP)["entry"][0]["content"]
        rep.line("app version on this search head: %s (build %s)" % (app.get("version"), app.get("build")))
    except Exception as e:
        rep.line("FAIL cannot read account or app: %s" % e)
        rep.line("Check the URL, user and password, and that the app is installed.")
        return 2

    r = sp.search(
        '`r7_index` sourcetype="rapid7:vm:*" | eval kb=len(_raw)/1024 | stats count max(kb) as max_kb max(_time) as last by sourcetype '
        '| eval last=strftime(last,"%F %T"), max_kb=round(max_kb,1)', "-3d")
    rep.result("collected data, last 3 days, per sourcetype (index from the app's r7_index macro)", r)
    for x in r["results"]:
        rep.line("        %-26s %9s events  largest %7s KB  latest %s" % (x.get("sourcetype"), x.get("count"), x.get("max_kb"), x.get("last")))
    r = sp.search(
        '`r7_index` sourcetype="rapid7:vm:run" | stats latest(status) as status latest(events) as events '
        'latest(error) as error latest(_time) as t by collector | eval t=strftime(t,"%F %T")', "-3d")
    rep.result("collector runs, last 3 days", r)
    for x in r["results"]:
        rep.line("        %-14s %-8s %8s events  %s  %s" % (x.get("collector"), x.get("status"), x.get("events"), x.get("t"), (x.get("error") or "")[:120]))
    for lk in ["r7_recent_checks.csv", "r7_recent_hits.csv", "r7_asset_summary.csv", "r7_vuln_catalog_lookup",
               "r7_saved_cves_lookup", "r7_scan_jobs_lookup", "r7_asset_actions_lookup", "r7_cmdb_changes_lookup",
               "cmdb_assets.csv", "cmdb_ip_map.csv"]:
        r = sp.search("| inputlookup %s | stats count" % lk)
        rep.result("lookup %-26s %s rows" % (lk, (r["results"] or [{}])[0].get("count", "?")), r)

    # 2 ----------------------------------------------------------------- scheduled searches
    rep.line("\n== 2. Scheduled searches (not run; schedule and last 24 h from the scheduler log)")
    try:
        ss = sp.call("GET", "/servicesNS/-/%s/saved/searches?output_mode=json&count=0&search=%s"
                     % (APP, parse.quote("eai:acl.app=%s" % APP)))["entry"]
        for e in ss:
            c = e["content"]
            if not c.get("is_scheduled"):
                continue
            rep.line("        %-50s %-8s cron %-14s next %s" % (e["name"], "disabled" if c.get("disabled") else "enabled",
                                                              c.get("cron_schedule"), c.get("next_scheduled_time") or "-"))
    except Exception as e:
        rep.line("FAIL cannot list saved searches: %s" % e)
    r = sp.search(
        'index=_internal sourcetype=scheduler app="%s" '
        '| stats count(eval(status="success" OR status="completed")) as success '
        'count(eval(status="skipped")) as skipped count(eval(like(status,"delegated%%"))) as delegated '
        'count(eval(NOT (status="success" OR status="completed" OR status="skipped" OR like(status,"delegated%%")))) as other '
        'values(eval(if(status="skipped", reason, null()))) as skip_reason '
        'max(run_time) as max_run_s latest(result_count) as last_rows by savedsearch_name' % APP, "-24h")
    rep.result("scheduler log, last 24 h (delegated = search head cluster hand-over, normal)", r)
    for x in r["results"]:
        sk, ot = str(x.get("skipped") or "0"), str(x.get("other") or "0")
        flag = "  <-- check" if sk != "0" or ot != "0" else ""
        reason = x.get("skip_reason") or ""
        if isinstance(reason, list):
            reason = "; ".join(reason)
        rep.line("        %-46s success %3s  skipped %3s  delegated %3s  other %3s  max %6ss  rows %s%s%s" % (
            x.get("savedsearch_name"), x.get("success"), sk, x.get("delegated"), ot,
            round(float(x.get("max_run_s") or 0), 1), x.get("last_rows"), flag,
            ("  skip reason: " + str(reason)[:150]) if reason else ""))

    # samples from your data ------------------------------------------------
    rep.line("\n== Sample values picked from your data (used to fill the search boxes)")
    hit = first(sp, rep, '| inputlookup r7_recent_hits.csv | search cmdb_status="WORKING_ACTIVE" | stats dc(asset_id) as n '
                'first(component) as sw first(title) as title first(platform) as plat by cve | sort 0 - n | head 1', label="CVE with most Active servers")
    asset = first(sp, rep, '| inputlookup r7_asset_summary.csv | search cmdb_status="WORKING_ACTIVE" | where open>0 '
                  '| sort 0 - critical - open | head 1 | table asset_id hostname ip os appname env_label', label="server with most open CVEs")
    prod = first(sp, rep, '`r7_latest(rapid7:vm:software)` | stats dc(asset_id) as n first(vendor) as vendor first(version) as version by product '
                 '| sort 0 - n | head 1', "-3d", label="most installed software")
    job = first(sp, rep, "| r7scanstatus limit=1", label="latest rescan job")
    saved = first(sp, rep, "| r7cvewatch action=list | head 1", label="a saved CVE")
    change = first(sp, rep, "| inputlookup r7_cmdb_changes_lookup | head 1 | table host change_type", label="a CMDB change")
    rep.mask = [x for x in (asset.get("hostname"), asset.get("ip")) if x]
    today = dt.date.today()
    d30 = (today - dt.timedelta(days=30)).isoformat()
    cve = hit.get("cve") or "CVE-2026-0001"
    product = prod.get("product") or "OpenSSH"
    host = asset.get("hostname") or ""
    aid = asset.get("asset_id") or ""
    app_name = (asset.get("appname") or "").split("\n")[0]
    sw = product
    title_word = ([w for w in (hit.get("title") or "").replace(":", " ").split() if len(w) > 4] or ["kernel"])[0]
    S = {
        "cve": cve, "software": sw, "host": host, "os": os_word(asset.get("os")), "app": app_name,
        "plat": hit.get("plat") or prod.get("vendor") or "", "title": title_word, "from": d30, "to": today.isoformat(),
        "aid": aid, "product": product, "version": (prod.get("version") or "1").split(".")[0],
        "job": job.get("job_id") or "", "saved": saved.get("cve") or cve,
    }
    rep.line("        CVE %s | software %s | asset_id %s | OS word %s | application %s | platform %s | job %s | saved CVE %s"
             % (S["cve"], S["software"], S["aid"] or "-", S["os"] or "-", "(set)" if S["app"] else "-", S["plat"] or "-",
                S["job"] or "-", S["saved"]))

    # 3 ----------------------------------------------------------------- commands (read-only)
    rep.line("\n== 3. Search commands (read-only forms)")
    cmds = [
        '| makeresults count=3 | streamstats count | eval version=case(count=1,"8.1.27",count=2,"8.1.34",count=3,"2.4.6-99.el7") '
        '| r7vercheck ranges="8.1 < 8.1.34 ; < 2.4.63"',
        '| r7cve cve="%s"' % S["cve"],
        '| r7cve software="%s" ranges="< 999"' % S["software"],
        '| r7cve cve="%s" env="Prod"' % S["cve"],
        '| r7cvewatch action=list with_counts=true',
        '| r7rescan cve="%s" dryrun=true' % S["cve"],
        '| r7rescan cve="%s" dryrun=true detail=true' % S["cve"],
        '| r7assetaction action=list',
        '| r7scanstatus',
    ]
    if S["aid"]:
        cmds.append('| r7rescan hosts="%s" only_hosts=true dryrun=true detail=true' % S["aid"])
    if S["job"]:
        cmds += ['| r7scanstatus job="%s"' % S["job"], '| r7scanstatus job="%s" view=scans' % S["job"]]
    for c in cmds:
        rep.result(c[:130], sp.search(c))

    # 4/5 --------------------------------------------------------------- pages
    views = sp.call("GET", "/servicesNS/-/%s/data/ui/views?output_mode=json&count=0&search=%s"
                    % (APP, parse.quote("eai:acl.app=%s" % APP)))["entry"]
    views = sorted(views, key=lambda e: e["name"])
    # values to fill per token name
    fill = {}
    for t in ["cve", "f_cve", "l_cve", "d_cve", "j_cve", "w_cve"]:
        fill[t] = S["cve"]
    for t in ["software", "f_sw", "l_sw", "d_sw", "j_sw", "w_sw", "q_sw"]:
        fill[t] = S["software"]
    for t in ["f_host", "s_host", "j_host", "q_host", "c_host", "am_host"]:
        fill[t] = S["host"]
    for t in ["f_os", "l_os", "s_os", "q_os", "c_os", "am_os", "w_os"]:
        fill[t] = S["os"]
    for t in ["f_app", "am_app", "app"]:
        fill[t] = S["app"]
    for t in ["f_plat", "l_plat", "w_plat", "q_vendor"]:
        fill[t] = S["plat"]
    for t in ["f_addfrom", "f_pubfrom", "l_pub", "l_add", "w_pub", "w_add", "j_from", "c_from"]:
        fill[t] = S["from"]
    for t in ["f_addto", "f_pubto"]:
        fill[t] = S["to"]
    fill.update({"f_title": S["title"], "ranges": "< 999", "announced": S["from"], "q_ver": S["version"],
                 "product": S["product"]})
    # tokens that panels need to be shown (clicks, buttons) - set on every page
    shown = {"ready": "1", "preview_nonce": "test", "launch_nonce": "", "asset": S["aid"], "asset_name": S["host"],
             "r_hosts": S["aid"], "hosts": S["aid"], "only": "true", "job": S["job"], "job_id": S["job"],
             "product": S["product"], "kind": "Software", "cve_view": S["saved"],
             "issue": "Environment differs", "req_issue": "Environment differs", "change": "*"}
    sec = ["sec_cov", "sec_mis", "sec_decom", "sec_r7", "sec_req", "sec_fresh"]

    rep.line("\n== 4. Every panel, default values (panels behind clicks shown with sample values)")
    parsed = []
    for v in views:
        name = v["name"]
        try:
            root, inputs, tokens, searches = parse_view(v["content"]["eai:data"])
        except Exception as e:
            rep.result("page %s: cannot parse" % name, {"error": [str(e)], "warn": [], "rows": 0, "secs": 0})
            continue
        base_tokens = dict(tokens)
        base_tokens.update(shown)
        for t in sec:
            base_tokens[t] = "1"
        if name == "r7_saved_cves":
            base_tokens["cve"] = S["saved"]
        if name == "r7_cve_response":
            base_tokens["cve"] = S["cve"]  # the page's panels appear once a CVE is entered
        if not S["job"]:
            base_tokens.pop("job_id", None)
            base_tokens.pop("job", None)
        parsed.append((name, inputs, base_tokens, searches))
        rep.line("-- %s (%s)" % (name, v["content"].get("label") or root.findtext("label") or ""))
        for i, s in enumerate(searches):
            if s["id"] and any(x["base"] == s["id"] for x in searches):
                continue  # base searches run through their panels
            if ("$job_id" in s["q"] or "$job$" in s["q"] or "$job|" in s["q"]) and not S["job"]:
                continue  # no rescan jobs yet: the page hides these panels until a job is picked
            q, e, l = composed(s, base_tokens)
            label = "%s #%d %s" % (name, i, (s["title"] or q.strip().splitlines()[0])[:90])
            if would_write(q):
                rep.skipped(label)
                continue
            key = (q, e, l)
            r = rep.cache.get(key) or sp.search(q, e, l)
            rep.cache[key] = r
            rep.result(label, r)

    if not a.quick:
        rep.line("\n== 5. Search boxes and drop-downs, one at a time (rows = what the panel shows)")
        for name, inputs, base_tokens, searches in parsed:
            rep.line("-- %s" % name)
            for inp in inputs:
                tok = inp.get("token")
                if not tok or tok in shown and tok not in fill:
                    continue
                typ = inp.get("type") or "text"
                values = []
                if typ == "text":
                    if fill.get(tok):
                        values = [fill[tok]]
                elif typ in ("dropdown", "radio"):
                    values = [c.get("value") for c in inp.findall("choice") if c.get("value") is not None]
                    if not values and fill.get(tok):
                        values = [fill[tok]]
                if not values:
                    continue
                label_txt = (inp.findtext("label") or tok).strip()
                for val in values:
                    toks = dict(base_tokens)
                    toks[tok] = val
                    apply_change(inp, val, toks)
                    targets = [s for s in searches if uses(s, tok) or
                               any(uses(s, t) for t in toks if t != tok and toks.get(t) != base_tokens.get(t))]
                    seen_bases = set()
                    for s in targets:
                        if s["id"] and any(x["base"] == s["id"] for x in searches):
                            continue
                        if "$job_id" in s["q"] and not S["job"]:
                            continue
                        # a filter in a base search: check the base once (row count) instead of every panel
                        if s["base"] and not uses({"q": s["q"], "base_q": None}, tok):
                            if s["base"] in seen_bases:
                                continue
                            seen_bases.add(s["base"])
                            s = dict(s, q="| stats count as base_rows", title="base '%s'" % s["base"])
                        q, e, l = composed(s, toks)
                        lab = "%s [%s = %s] %s" % (name, label_txt[:40], val[:40] if tok not in ("f_host", "s_host", "j_host", "q_host", "c_host", "am_host", "asset_name") else "(sample host)", (s["title"] or q.strip().splitlines()[-1])[:60])
                        if would_write(q):
                            rep.skipped(lab)
                            continue
                        key = (q, e, l)
                        r = rep.cache.get(key) or sp.search(q, e, l)
                        rep.cache[key] = r
                        if s["q"].startswith("| stats count as base_rows") and r["results"]:
                            r = dict(r, rows=int(r["results"][0].get("base_rows") or 0))
                        rep.result(lab, r)

    # summary -----------------------------------------------------------------
    rep.line("\n== Summary")
    rep.line("ok %(ok)d   WARN %(WARN)d   FAIL %(FAIL)d   skipped (would change data) %(skipped)d" % rep.total)
    if rep.slow_list:
        rep.line("Slow searches (>= %ss):" % a.slow)
        for secs, lab in sorted(rep.slow_list, reverse=True)[:20]:
            rep.line("   %6.1fs  %s" % (secs, lab))
    rep.line("Finished in %.1f minutes. Report: %s" % ((time.time() - t_start) / 60, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
