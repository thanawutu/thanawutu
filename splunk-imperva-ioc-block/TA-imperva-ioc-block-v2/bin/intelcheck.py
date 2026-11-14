"""
Splunk custom search command: intelcheck (V2)

Enrich each row with AbuseIPDB and GreyNoise IP reputation, the same way vtcheck does with
VirusTotal, and adjust the Block suggestion that vtcheck made (intel_lib.intel_adjust).

Usage:
    ... | vtcheck field=src | intelcheck field=src
    | makeresults | eval src="45.95.147.236" | intelcheck

Options:
    field        field holding the IP                              (default: src)
    sources      abuseipdb,greynoise (any of them)                 (default: both)
    cache_only   true -> never call the APIs: cache only, IPs not checked yet get
                 <prefix>_status "pending" (the dashboards use this; the saved search
                 "Imperva V2 - AbuseIPDB / GreyNoise cache warm-up" does the lookups)
    adjust       true -> change suggestion / suggestion_reason of the row   (default: true)
    max_lookups / max_wait   override max_lookups_per_run / rate_limit_max_wait_seconds

Lookups go through SOAR (playbook actions abusecheck / gncheck) when [<source>] via = auto and
[settings] api_mode = soar, else directly (key in storage/passwords realm abuseipdb / greynoise).
Cache: per search head file + KV store collection imperva_cache (keys abuse_<ip> / gn_<ip>).

Added fields:
    abuse_status abuse_score abuse_reports abuse_users abuse_last_reported abuse_country
    abuse_usage abuse_isp abuse_domain abuse_tor abuse_whitelisted abuse_link
    gn_status gn_noise gn_riot gn_classification gn_name gn_last_seen gn_message gn_link
    intel_summary (+ suggestion / suggestion_reason changed when adjust=true)
<prefix>_status: ok | not_found | pending | private_ip | rate_limited | not_checked | error | off
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import intel_lib as il            # noqa: E402
import vt_lib as vt               # noqa: E402  (VTCache: a generic {ip: {ts, data}} file cache)
from backend import get_soar_bridge  # noqa: E402
from splunk_helpers import (CACHE, get_logger, is_true, kv_query, kv_upsert,  # noqa: E402
                            load_conf_stanza, load_credential, parse_options, splunk_home)

DEFAULTS = {   # per source: requests per minute, lookups per run
    "abuseipdb": {"requests_per_minute": 30, "max_lookups_per_run": 40},
    "greynoise": {"requests_per_minute": 10, "max_lookups_per_run": 10},
}


def cache_key(prefix, ip):
    return "%s_%s" % (prefix, ip.replace(":", "-").replace("/", "_"))


def via_of(sconf, iconf):
    via = (sconf.get("via") or "auto").strip().lower()
    if via == "auto":
        via = "soar" if (iconf.get("api_mode") or "").strip().lower() == "soar" else "direct"
    return via


def lookup_source(source, ips, opts, sconf, iconf, session_key, log, now=None):
    """-> {ip: info} for one source (cache, then SOAR / direct lookups for the rest)."""
    meta = il.INTEL_SOURCES[source]
    pre, gui = meta["prefix"], meta["gui"]
    st = pre + "_status"
    now = now or time.time()
    ttl = int(float(sconf.get("cache_ttl_hours", 24)) * 3600)
    cache = vt.VTCache(os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_v2_%s_cache.json" % source),
                       ttl_seconds=ttl)
    out, todo = {}, []
    for ip in ips:
        hit = cache.get(ip)
        if hit is not None:
            out[ip] = dict(hit, **{pre + "_cached": "yes"})
        elif ip not in todo:
            todo.append(ip)
    if todo:   # shared cache (KV store): looked up on another cluster member
        try:
            docs = kv_query(session_key, CACHE, {"_key": {"$in": [cache_key(pre, ip) for ip in todo]}})
            by_key = dict((d.get("_key"), d) for d in docs)
            for ip in list(todo):
                d = by_key.get(cache_key(pre, ip))
                if d and now - float(d.get("ts") or 0) < ttl:
                    info = json.loads(d.get("data") or "{}")
                    out[ip] = dict(info, **{pre + "_cached": "yes"})
                    cache.put(ip, info, now=float(d["ts"]))
                    todo.remove(ip)
        except Exception as e:  # noqa: BLE001 - best effort
            log.warning("cannot read shared %s cache: %s", source, e)
    if todo and is_true(opts.get("cache_only", "false")):
        for ip in todo:
            out[ip] = {st: "pending", pre + "_link": gui + ip,
                       pre + "_error": "not checked yet - the warm-up search runs every hour"}
        todo = []
    fresh = {}
    if todo:
        d = DEFAULTS[source]
        rpm = max(1, int(sconf.get("requests_per_minute") or d["requests_per_minute"]))
        max_lookups = int(opts.get("max_lookups") or sconf.get("max_lookups_per_run") or d["max_lookups_per_run"])
        retry_wait = int(sconf.get("rate_limit_retry_seconds") or 60)
        max_wait = int(opts.get("max_wait") or sconf.get("rate_limit_max_wait_seconds") or 0)
        via = via_of(sconf, iconf)
        try:
            if via == "soar":
                bridge = get_soar_bridge(iconf, load_credential, session_key)
                n = min(len(todo), max_lookups) if max_lookups > 0 else len(todo)
                wait = max(bridge.wait_seconds, int(n * 60.0 / rpm) + max_wait + 45)
                for row in bridge.intel_lookup(meta["action"], todo, wait_seconds=wait, max_lookups=max_lookups,
                                               max_wait=max_wait, retry_wait=retry_wait):
                    ip = row.pop("ip", None)
                    row.pop("soar_container", None)
                    if ip:
                        fresh[ip] = row
            else:
                try:
                    _u, key = load_credential(session_key, source)
                except Exception:  # noqa: BLE001 - GreyNoise Community answers without a key
                    if source != "greynoise":
                        raise
                    key = None
                client = il.intel_client(source, key, base_url=sconf.get("api_base_url") or None,
                                         timeout=int(sconf.get("timeout", 30)),
                                         proxy=sconf.get("proxy") or iconf.get("proxy") or None,
                                         verify_ssl=is_true(sconf.get("verify_ssl", "true")),
                                         max_age_days=sconf.get("max_age_days") or 90)
                fresh = il.intel_lookup_many(client, todo, rpm=rpm, max_lookups=max_lookups,
                                             retry_wait=retry_wait, max_wait=max_wait)
        except Exception as e:  # noqa: BLE001 - show the error per row, keep the table
            log.warning("%s lookup via %s failed: %s", source, via, e)
            fresh = dict((ip, {st: "error", pre + "_error": str(e), pre + "_link": gui + ip}) for ip in todo)
        shared = []
        for ip, info in fresh.items():
            if info.get(st) in ("ok", "not_found"):
                cache.put(ip, info, now=now)
                shared.append({"_key": cache_key(pre, ip), "ts": now, "data": json.dumps(info)})
            out[ip] = dict(info, **{pre + "_cached": "no"})
        if shared:
            try:
                kv_upsert(session_key, shared, CACHE)
            except Exception as e:  # noqa: BLE001
                log.warning("cannot write shared %s cache: %s", source, e)
        log.info("intelcheck source=%s via=%s asked=%d ok=%d rate_limited=%d", source, via, len(todo),
                 sum(1 for i in fresh.values() if i.get(st) in ("ok", "not_found")),
                 sum(1 for i in fresh.values() if i.get(st) == "rate_limited"))
    try:
        cache.save()
    except (IOError, OSError) as e:
        log.warning("cannot save %s cache: %s", source, e)
    return out


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("field", "sources", "cache_only", "adjust", "max_lookups", "max_wait"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_intelcheck", "imperva_intelcheck.log")
    field = opts.get("field", "src")
    wanted = [s.strip().lower() for s in (opts.get("sources") or "abuseipdb,greynoise").split(",") if s.strip()]
    try:
        bad = [s for s in wanted if s not in il.INTEL_SOURCES]
        if bad:
            raise ValueError("unknown source(s) %s - use abuseipdb, greynoise" % ", ".join(bad))
        iconf = load_conf_stanza(session_key, "imperva", "settings")
        ips = []
        for r in results:
            ip = (r.get(field) or "").strip()
            if ip and ip != "-" and ip not in ips:
                ips.append(ip)
        found, thresholds = {}, {}
        for source in il.INTEL_SOURCES:
            pre = il.INTEL_SOURCES[source]["prefix"]
            sconf = load_conf_stanza(session_key, "imperva", source)
            if source not in wanted or not is_true(sconf.get("enabled", "true")):
                found[source] = None          # off: <prefix>_status=off
                continue
            if source == "abuseipdb":
                thresholds = {"abuse_block_score": sconf.get("block_score", ""),
                              "abuse_review_score": sconf.get("review_score", "")}
            found[source] = lookup_source(source, ips, opts, sconf, iconf, session_key, log)
        adjust = is_true(opts.get("adjust", "true"))
        for r in results:
            ip = (r.get(field) or "").strip()
            info = {}
            for source, res in found.items():
                pre = il.INTEL_SOURCES[source]["prefix"]
                if res is None:
                    info[pre + "_status"] = "off"
                elif ip in res:
                    info.update(res[ip])
                else:
                    info[pre + "_status"] = "no_ip"
            r.update(dict((k, str(v)) for k, v in info.items()))
            r["intel_summary"] = il.intel_summary(info) or "-"
            if adjust and r.get("suggestion"):
                r["suggestion"], r["suggestion_reason"] = il.intel_adjust(
                    r.get("suggestion"), r.get("suggestion_reason", ""), info, thresholds)
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        log.error("intelcheck failed: %s", e)
        si.generateErrorResults("intelcheck: %s" % e)


if __name__ == "__main__":
    main()
