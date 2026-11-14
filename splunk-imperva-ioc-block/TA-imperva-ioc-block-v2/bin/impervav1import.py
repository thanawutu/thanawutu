"""
Splunk generating command: impervav1import (V2, admin only, run once after installing V2)

Copies the data of V1 (app TA-imperva-ioc-block) into V2 (this app), so V2 starts with the same
history while V1 stays installed and unchanged.

    | impervav1import action=kv
        KV store: imperva_block_registry, imperva_ioc_dismissed, imperva_cache (VirusTotal results)
        -> only documents V2 does not have yet (V2 wins); imperva_ioc_rules -> V1 rules replace the
        default rules V2 created (only while V2 has no rule of its own)
    | impervav1import action=credentials
        storage/passwords realms imperva_waf, splunk_soar, virustotal -> V2 (copied server side, the
        secrets are never output). Needed before V1 is removed: until then V2 also reads V1's.
    | impervav1import action=audit | outputlookup append=true imperva_audit
        rows of V1's audit lookup that V2's audit CSV does not have yet. Both are read with
        "| inputlookup imperva_audit" run in the app's own namespace (search/jobs/export), so it works
        wherever Splunk keeps the CSV file.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402
import splunk.rest as rest       # noqa: E402

from splunk_helpers import APP, V1_APP, get_logger, parse_options  # noqa: E402

COPY_NEW = ("imperva_block_registry", "imperva_ioc_dismissed", "imperva_cache")
RULES = "imperva_ioc_rules"
REALMS = ("imperva_waf", "splunk_soar", "virustotal")
AUDIT_COLS = ("time", "user", "action", "ip", "ticket", "description", "status", "verified", "policy",
              "backend", "soar_container", "detail")


def _get(path, session_key):
    resp, content = rest.simpleRequest(path, sessionKey=session_key, method="GET", raiseAllErrors=True)
    return json.loads(content)


def kv_docs(session_key, app, collection):
    return _get("/servicesNS/nobody/%s/storage/collections/data/%s?output_mode=json" % (app, collection),
                session_key) or []


def kv_save(session_key, app, collection, docs):
    for k in range(0, len(docs), 500):
        rest.simpleRequest("/servicesNS/nobody/%s/storage/collections/data/%s/batch_save" % (app, collection),
                           sessionKey=session_key, method="POST", jsonargs=json.dumps(docs[k:k + 500]),
                           raiseAllErrors=True)


def kv_remove(session_key, app, collection, key):
    rest.simpleRequest("/servicesNS/nobody/%s/storage/collections/data/%s/%s" % (app, collection, key),
                       sessionKey=session_key, method="DELETE", raiseAllErrors=True)


def clean(d):
    return dict((k, v) for k, v in d.items() if k == "_key" or not k.startswith("_"))


def import_kv(session_key):
    out = []
    for c in COPY_NEW:
        try:
            src = kv_docs(session_key, V1_APP, c)
            if c == "imperva_cache":   # VirusTotal results only; the policy cache is refreshed every 5 min
                src = [d for d in src if str(d.get("_key", "")).startswith("vt_")]
            have = set(d.get("_key") for d in kv_docs(session_key, APP, c))
            new = [clean(d) for d in src if d.get("_key") not in have]
            kv_save(session_key, APP, c, new)
            out.append({"what": c, "items": len(new), "status": "copied",
                        "detail": "%d in V1, %d already in V2" % (len(src), len(src) - len(new))})
        except Exception as e:  # noqa: BLE001
            out.append({"what": c, "items": 0, "status": "error", "detail": str(e)})
    try:
        src = [clean(d) for d in kv_docs(session_key, V1_APP, RULES)]
        mine = kv_docs(session_key, APP, RULES)
        import ioc_rules as ir
        defaults = set(ir.rule_key(p, m) for p, m, _n in ir.DEFAULT_RULES) | {ir.SEED_KEY}
        own_rules = [d for d in mine if d.get("_key") not in defaults]   # rules added / changed in V2
        if not src:
            out.append({"what": RULES, "items": 0, "status": "skipped", "detail": "V1 has no rules"})
        elif own_rules:
            out.append({"what": RULES, "items": 0, "status": "skipped",
                        "detail": "V2 already has %d rule(s) of its own - not overwritten" % len(own_rules)})
        else:
            for d in mine:
                kv_remove(session_key, APP, RULES, d["_key"])
            kv_save(session_key, APP, RULES, src)
            out.append({"what": RULES, "items": len(src), "status": "copied",
                        "detail": "V1 rules replace the %d default rule(s) of V2" % len(mine)})
    except Exception as e:  # noqa: BLE001
        out.append({"what": RULES, "items": 0, "status": "error", "detail": str(e)})
    return out


def import_credentials(session_key):
    out = []
    try:
        v1 = _get("/servicesNS/nobody/%s/storage/passwords?output_mode=json&count=0" % V1_APP, session_key)
        v2 = _get("/servicesNS/nobody/%s/storage/passwords?output_mode=json&count=0" % APP, session_key)
    except Exception as e:  # noqa: BLE001
        return [{"what": "credentials", "items": 0, "status": "error", "detail": str(e)}]

    def by_realm(js, app):
        found = {}
        for e in js.get("entry", []):
            c = e.get("content", {})
            if (e.get("acl") or {}).get("app", app) == app and c.get("realm") in REALMS:
                found.setdefault(c["realm"], c)
        return found
    have, src = by_realm(v2, APP), by_realm(v1, V1_APP)
    for realm in REALMS:
        if realm in have:
            out.append({"what": "credential " + realm, "items": 0, "status": "exists", "detail": "already in V2"})
        elif realm not in src:
            out.append({"what": "credential " + realm, "items": 0, "status": "skipped", "detail": "not in V1"})
        else:
            c = src[realm]
            try:
                rest.simpleRequest("/servicesNS/nobody/%s/storage/passwords" % APP, sessionKey=session_key,
                                   method="POST", raiseAllErrors=True,
                                   postargs={"name": c.get("username", ""), "password": c.get("clear_password", ""),
                                             "realm": realm})
                out.append({"what": "credential " + realm, "items": 1, "status": "copied",
                            "detail": "user %s (secret not shown)" % c.get("username", "")})
            except Exception as e:  # noqa: BLE001
                out.append({"what": "credential " + realm, "items": 0, "status": "error", "detail": str(e)})
    return out


def search_rows(session_key, app, spl):
    """Run SPL in the namespace of <app> (so | inputlookup finds that app's lookup) -> (rows, errors)."""
    _resp, content = rest.simpleRequest("/servicesNS/nobody/%s/search/jobs/export" % app, sessionKey=session_key,
                                        method="POST", raiseAllErrors=True, timeout=300,
                                        postargs={"search": spl, "output_mode": "json"})
    if isinstance(content, bytes):
        content = content.decode("utf-8", "replace")
    rows, errors = [], []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("preview"):
            continue
        if isinstance(o.get("result"), dict):
            rows.append(o["result"])
        for m in o.get("messages") or []:
            if str(m.get("type", "")).upper() in ("ERROR", "FATAL"):
                errors.append(m.get("text", ""))
    return rows, errors


def import_audit(session_key):
    """Rows of V1's audit lookup that V2 does not have yet (matched on time, user, action, ip, status).
    Never returns anything but audit rows: the saved search appends the output to V2's audit CSV."""
    v1, err = search_rows(session_key, V1_APP, "| inputlookup imperva_audit")
    if err and not v1:
        raise RuntimeError("cannot read the V1 audit lookup: %s" % "; ".join(err))
    v2, _err2 = search_rows(session_key, APP, "| inputlookup imperva_audit")   # no file yet = nothing in V2
    sig = lambda r: tuple(str(r.get(k, "")) for k in ("time", "user", "action", "ip", "status"))  # noqa: E731
    have = set(sig(r) for r in v2)
    return [dict((k, r.get(k, "-")) for k in AUDIT_COLS) for r in v1 if sig(r) not in have]


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action",))
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    action = (opts.get("action") or "").strip().lower()
    try:
        if APP == V1_APP:
            raise RuntimeError("run this in V2 (%s-v2), not in V1" % V1_APP)
        if action == "kv":
            rows = import_kv(session_key)
        elif action == "credentials":
            rows = import_credentials(session_key)
        elif action == "audit":
            rows = import_audit(session_key)
        else:
            raise ValueError("action must be kv, credentials or audit")
        log.info('user=%s action=v1import_%s rows=%d', user, action, len(rows))
        si.outputResults(rows)
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=v1import_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervav1import: %s" % e)


if __name__ == "__main__":
    main()
