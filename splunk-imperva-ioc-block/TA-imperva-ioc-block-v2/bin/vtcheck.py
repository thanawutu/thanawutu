"""
Splunk custom search command: vtcheck

Enrich each row with VirusTotal IP reputation + a block suggestion.

Usage:
    ... | stats count BY src | vtcheck field=src count_field=count
    | makeresults | eval src="45.95.147.236" | vtcheck

Options:
    field        field holding the IP          (default: src)
    count_field  field holding attack count    (default: count)
    check_waf    true -> also mark IPs that are already on the Imperva blacklist (default: true)
    cache_only   true -> never call VirusTotal: use the cache, IPs not checked yet get
                 vt_status "pending" (the dashboards use this; the saved search
                 "Imperva - VT cache warm-up" does the lookups every 10 min)
    max_lookups / max_wait   override [virustotal] limits (warm-up: max_lookups=0 max_wait=1500)

Cache: per search head file + KV store collection imperva_cache (shared by the cluster).

Added fields:
    vt_status vt_malicious vt_suspicious vt_harmless vt_undetected vt_engines vt_reputation
    vt_country vt_continent vt_asn vt_as_owner vt_network vt_link vt_cached
    waf_blocked suggestion suggestion_reason

Settings: imperva.conf [virustotal]. API key: storage/passwords realm "virustotal".
"""

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import vt_lib as vt              # noqa: E402
from backend import get_backend, get_soar_bridge   # noqa: E402
import json                      # noqa: E402
import time                      # noqa: E402

from splunk_helpers import (CACHE, cache_key_ip, get_logger, is_true,  # noqa: E402
                            kv_query, kv_upsert, load_conf_stanza, load_credential,
                            parse_options, protected_networks, splunk_home)

VT_REALM = "virustotal"


def waf_blacklist(session_key, conf):
    """Union of the block lists of all configured targets (best effort, direct or via SOAR)."""
    rows = get_backend(conf, load_credential, session_key).list_blocked()
    return {r["ip"] for r in rows if r.get("in_waf") == "yes"}


def in_networks(ip, networks):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in networks:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("field", "count_field", "check_waf", "max_lookups", "max_wait",
                                        "cache_only"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_vtcheck", "imperva_vtcheck.log")
    field = opts.get("field", "src")
    count_field = opts.get("count_field", "count")

    try:
        vconf = load_conf_stanza(session_key, "imperva", "virustotal")
        iconf = load_conf_stanza(session_key, "imperva", "settings")
        # vt_via: auto (= soar when api_mode = soar) | direct | soar
        vt_via = (vconf.get("vt_via") or "auto").strip().lower()
        if vt_via == "auto":
            vt_via = "soar" if (iconf.get("api_mode") or "").strip().lower() == "soar" else "direct"

        cache = vt.VTCache(os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_vt_cache.json"),
                           ttl_seconds=int(float(vconf.get("cache_ttl_hours", 24)) * 3600))
        rpm = max(1, int(vconf.get("requests_per_minute", 4)))
        # max_lookups=0 / max_wait=<s> options: used by the background warm-up search,
        # which keeps calling VirusTotal (waiting on HTTP 429) until every IP is checked
        max_lookups = int(opts.get("max_lookups") or vconf.get("max_lookups_per_run", 10))
        retry_wait = int(vconf.get("rate_limit_retry_seconds", 60))
        max_wait = int(opts.get("max_wait") or vconf.get("rate_limit_max_wait_seconds", 120))
        thresholds = {k: int(vconf[k]) for k in vt.DEFAULT_THRESHOLDS if vconf.get(k)}
        protected = protected_networks(iconf)

        blocked = set()
        waf_ok = False
        if is_true(opts.get("check_waf", "true")):
            try:
                blocked = waf_blacklist(session_key, iconf)
                waf_ok = True
            except Exception as e:  # noqa: BLE001 - enrichment is best effort
                log.warning("cannot read Imperva blacklist: %s", e)

        # ---- pass 1: which IPs need a fresh VirusTotal lookup -----------------
        todo, cached_info = [], {}
        for r in results:
            ip = (r.get(field) or "").strip()
            if not ip or ip == "-" or ip in cached_info or ip in todo:
                continue
            hit = cache.get(ip)
            if hit is not None:
                cached_info[ip] = hit
            else:
                todo.append(ip)

        # ---- shared cache (KV store): results looked up on another cluster member ----
        ttl = int(float(vconf.get("cache_ttl_hours", 24)) * 3600)
        if todo:
            try:
                docs = kv_query(session_key, CACHE, {"_key": {"$in": [cache_key_ip(ip) for ip in todo]}})
                by_key = dict((d.get("_key"), d) for d in docs)
                for ip in list(todo):
                    d = by_key.get(cache_key_ip(ip))
                    if d and time.time() - float(d.get("ts") or 0) < ttl:
                        info = json.loads(d.get("data") or "{}")
                        cached_info[ip] = info
                        cache.put(ip, info, now=float(d["ts"]))
                        todo.remove(ip)
            except Exception as e:  # noqa: BLE001 - the cache is best effort
                log.warning("cannot read shared VT cache: %s", e)

        # ---- lookups: directly from the Search Head, or through SOAR ----------
        fresh = {}
        if todo and is_true(opts.get("cache_only", "false")):
            # dashboards never wait for VirusTotal: the warm-up saved search looks these up
            fresh = {ip: {"vt_status": "pending", "vt_link": vt.VT_GUI + ip,
                          "vt_error": "not checked yet - VT warm-up runs every 10 min"} for ip in todo}
            todo = []
        if todo:
            try:
                if vt_via == "soar":
                    bridge = get_soar_bridge(iconf, load_credential, session_key)
                    n = min(len(todo), max_lookups) if max_lookups > 0 else len(todo)
                    wait = max(bridge.wait_seconds, int(n * 60.0 / rpm) + max_wait + 45)
                    for row in bridge.vt_lookup(todo, wait_seconds=wait, max_lookups=max_lookups,
                                                max_wait=max_wait, retry_wait=retry_wait):
                        ip = row.pop("ip", None)
                        row.pop("soar_container", None)
                        if ip:
                            fresh[ip] = row
                else:
                    _u, api_key = load_credential(session_key, VT_REALM)
                    client = vt.VTClient(api_key, base_url=vconf.get("api_base_url", vt.VT_BASE),
                                         timeout=int(vconf.get("timeout", 30)),
                                         proxy=vconf.get("proxy") or iconf.get("proxy") or None,
                                         verify_ssl=is_true(vconf.get("verify_ssl", "true")))
                    fresh = vt.lookup_many(client, todo, rpm=rpm, max_lookups=max_lookups,
                                           retry_wait=retry_wait, max_wait=max_wait)
            except Exception as e:  # noqa: BLE001 - show the error per row, keep the table
                log.warning("VirusTotal lookup via %s failed: %s", vt_via, e)
                fresh = {ip: {"vt_status": "error", "vt_error": str(e), "vt_link": vt.VT_GUI + ip}
                         for ip in todo}
            shared = []
            for ip, info in fresh.items():
                if info.get("vt_status") in ("ok", "not_found"):
                    cache.put(ip, info)
                    shared.append({"_key": cache_key_ip(ip), "ts": time.time(), "data": json.dumps(info)})
            try:
                kv_upsert(session_key, shared, CACHE)
            except Exception as e:  # noqa: BLE001
                log.warning("cannot write shared VT cache: %s", e)
        lookups_done = sum(1 for i in fresh.values() if i.get("vt_status") in ("ok", "not_found", "error"))
        rate_limited = any(i.get("vt_status") == "rate_limited" for i in fresh.values())

        # ---- pass 2: enrich rows + suggestion ----------------------------------
        for r in results:
            ip = (r.get(field) or "").strip()
            if ip in cached_info:
                info, r["vt_cached"] = dict(cached_info[ip]), "yes"
            else:
                info = fresh.get(ip) or {"vt_status": "no_ip" if not ip or ip == "-" else "skipped",
                                         "vt_link": vt.VT_GUI + ip}
                r["vt_cached"] = "no"
            r["vt_via"] = "cache" if r["vt_cached"] == "yes" else vt_via

            r.update({k: str(v) for k, v in info.items()})
            r["waf_blocked"] = ("yes" if ip in blocked else "no") if waf_ok else "unknown"
            sug, why = vt.suggest(dict(info, ip=ip), attack_count=_int(r.get(count_field)),
                                  protected=in_networks(ip, protected), thresholds=thresholds)
            if r["waf_blocked"] == "yes":
                sug, why = "ALREADY_BLOCKED", "already on Imperva blacklist; " + why
            r["suggestion"], r["suggestion_reason"] = sug, why

        try:
            cache.save()
        except (IOError, OSError) as e:
            log.warning("cannot save VT cache: %s", e)
        log.info("vtcheck via=%s rows=%d api_lookups=%d rate_limited=%s", vt_via, len(results), lookups_done, rate_limited)
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        log.error("vtcheck failed: %s", e)
        si.generateErrorResults("vtcheck: %s" % e)


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":
    main()
