"""
Splunk command: impervapolicycheck

For each row, find every WAF policy of the Imperva account whose IP rules
(block / allow / exceptions; IP, CIDR or range) cover the IP.

Usage:
    ... | impervapolicycheck field=src
    | makeresults | eval src="1.2.3.4" | impervapolicycheck
    | impervapolicycheck action=refresh          (drop the cache, read the policies again)

Added fields:
    waf_policy_verdict  ALLOWLISTED | BLOCKED_ELSEWHERE | BLOCKED_HERE | NONE | UNKNOWN
    waf_policies        "BLOCK in 1364280 Block DDOS Attack 2025 (1.2.3.0/24); ALLOW in ..."

The policy list is read directly or through SOAR (api_mode) and cached for
[settings] policy_cache_minutes (default 10) in
$SPLUNK_HOME/var/run/splunk/ta_imperva_policies_cache.json
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
from backend import get_backend   # noqa: E402
from splunk_helpers import (CACHE, get_logger, kv_get, kv_upsert, load_conf_stanza,  # noqa: E402
                            load_credential, parse_options, policy_cache_path)


def cache_path():
    return policy_cache_path()


def load_entries(session_key, conf, log, force=False):
    ttl = float(conf.get("policy_cache_minutes", 10)) * 60
    path = cache_path()
    if not force:
        try:
            with open(path) as f:
                c = json.load(f)
            if time.time() - c.get("ts", 0) < ttl:
                return c["entries"], c.get("targets", []), "cache"
        except (IOError, OSError, ValueError, KeyError):
            pass
        try:  # shared by the cluster (refreshed every 5 min by "Imperva - WAF policy cache refresh")
            d = kv_get(session_key, "policies", CACHE)
            if d and time.time() - float(d.get("ts") or 0) < ttl:
                c = json.loads(d.get("data") or "{}")
                _save_file(path, float(d["ts"]), c["entries"], c.get("targets", []), log)
                return c["entries"], c.get("targets", []), "shared cache"
        except Exception as e:  # noqa: BLE001
            log.warning("cannot read shared policy cache: %s", e)
    backend = get_backend(conf, load_credential, session_key)
    entries = backend.policy_entries()
    now = time.time()
    _save_file(path, now, entries, backend.targets, log)
    try:
        kv_upsert(session_key, [{"_key": "policies", "ts": now,
                                 "data": json.dumps({"entries": entries, "targets": backend.targets})}], CACHE)
    except Exception as e:  # noqa: BLE001
        log.warning("cannot write shared policy cache: %s", e)
    return entries, backend.targets, getattr(backend, "mode", "-")


def _save_file(path, ts, entries, targets, log):
    try:
        d = os.path.dirname(path)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".policies")
        with os.fdopen(fd, "w") as f:
            json.dump({"ts": ts, "entries": entries, "targets": targets}, f)
        os.replace(tmp, path)
    except (IOError, OSError) as e:
        log.warning("cannot save policy cache: %s", e)


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("field", "action"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_vtcheck", "imperva_vtcheck.log")
    field = opts.get("field", "src")
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        try:
            entries, targets, via = load_entries(session_key, conf, log,
                                                 force=(opts.get("action") == "refresh"))
        except Exception as e:  # noqa: BLE001 - annotate rows instead of failing the dashboard
            log.warning("cannot read WAF policies: %s", e)
            for r in results:
                r["waf_policy_verdict"], r["waf_policies"] = "UNKNOWN", "cannot read WAF policies: %s" % e
            si.outputResults(results)
            return
        if not any((r.get(field) or "").strip() for r in results):  # no IPs: show a summary
            results = [{"policies_ip_rules": len(entries), "read_via": via}]
        for r in results:
            ip = (r.get(field) or "").strip()
            if not ip:
                continue
            verdict, texts = il.policy_verdict(il.match_policies(ip, entries), targets)
            r["waf_policy_verdict"] = verdict
            r["waf_policies"] = "; ".join(texts) if texts else "-"
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        si.generateErrorResults("impervapolicycheck: %s" % e)


if __name__ == "__main__":
    main()
