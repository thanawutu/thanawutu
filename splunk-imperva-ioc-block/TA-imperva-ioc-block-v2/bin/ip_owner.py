"""
Owner of an IP (VirusTotal AS owner) and whether it belongs to a cloud provider.

V2: cloud provider IPs (AWS, Google Cloud, Azure, ...) MAY be blocked; their IPs are shared and
re-assigned to other customers, so Auto unblock removes them after a short quiet period
([auto_unblock] cloud_days, default 7 days without an attack; other IPs default_days = 90).

    imperva.conf [settings]
    cloud_providers = amazon|aws|google|...   words matched in the AS owner (whole words, any case)
    cloud_check_max_lookups = 4               VirusTotal lookups per block for IPs not in the cache

The same word list is in macros.conf [imperva_cloud_providers] for the dashboards.
Owner source: the VirusTotal cache (per search head file + KV store imperva_cache), else a
VirusTotal lookup at block time (directly or through SOAR, like vtcheck), which also fills the
cache that Auto unblock reads later.
"""

import ipaddress
import json
import os
import re
import time

import vt_lib as vt
from backend import get_soar_bridge
from splunk_helpers import (CACHE, cache_key_ip, is_true, kv_query, kv_upsert,
                            load_credential, splunk_home)

CLOUD_NOTE = "cloud provider IP (%s): unblocked automatically after %s days without an attack"


def cloud_regex(words):
    """Compiled whole-word, case-insensitive pattern of the provider words, None when empty."""
    words = (words or "").strip().strip("|").strip()
    if not words:
        return None
    return re.compile(r"\b(?:%s)\b" % words, re.I)


def cloud_owner(owner, rx):
    """The AS owner when it is a cloud provider, else None."""
    if not rx or not owner or owner == "-":
        return None
    return owner if rx.search(owner) else None


def lookup_ip(candidate):
    """IP to ask VirusTotal about: the IP itself, or the first address of a CIDR."""
    try:
        return str(ipaddress.ip_network(candidate.strip(), strict=False).network_address)
    except (ValueError, AttributeError):
        return None


def _owner(info):
    if not info or info.get("vt_status", "ok") != "ok":
        return None
    o = (info.get("vt_as_owner") or "").strip()
    return o if o and o != "-" else None


def _vt_lookup(session_key, iconf, vconf, ips):
    """VirusTotal rows {ip: info} for ips, directly or through SOAR (same rules as vtcheck)."""
    vt_via = (vconf.get("vt_via") or "auto").strip().lower()
    if vt_via == "auto":
        vt_via = "soar" if (iconf.get("api_mode") or "").strip().lower() == "soar" else "direct"
    rpm = max(1, int(vconf.get("requests_per_minute", 4)))
    retry_wait = int(vconf.get("rate_limit_retry_seconds", 60))
    max_wait = 0     # a block must not wait minutes for the VirusTotal quota
    if vt_via == "soar":
        bridge = get_soar_bridge(iconf, load_credential, session_key)
        wait = max(bridge.wait_seconds, int(len(ips) * 60.0 / rpm) + 45)
        out = {}
        for row in bridge.vt_lookup(ips, wait_seconds=wait, max_lookups=len(ips),
                                    max_wait=max_wait, retry_wait=retry_wait):
            ip = row.pop("ip", None)
            row.pop("soar_container", None)
            if ip:
                out[ip] = row
        return out
    _u, api_key = load_credential(session_key, "virustotal")
    client = vt.VTClient(api_key, base_url=vconf.get("api_base_url", vt.VT_BASE),
                         timeout=int(vconf.get("timeout", 30)),
                         proxy=vconf.get("proxy") or iconf.get("proxy") or None,
                         verify_ssl=is_true(vconf.get("verify_ssl", "true")))
    return vt.lookup_many(client, ips, rpm=rpm, max_lookups=len(ips),
                          retry_wait=retry_wait, max_wait=max_wait)


def owners(session_key, iconf, vconf, ips, log, max_lookups=4):
    """{ip: AS owner, or None when unknown}. Cache first, then up to max_lookups VirusTotal lookups."""
    ttl = int(float(vconf.get("cache_ttl_hours", 24)) * 3600)
    cache = vt.VTCache(os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_vt_cache.json"),
                       ttl_seconds=ttl)
    out, todo = {}, []
    for ip in ips:
        hit = cache.get(ip)
        if hit is not None:
            out[ip] = _owner(hit)
        else:
            todo.append(ip)
    if todo:
        try:
            docs = kv_query(session_key, CACHE, {"_key": {"$in": [cache_key_ip(i) for i in todo]}})
            by_key = dict((d.get("_key"), d) for d in docs)
            for ip in list(todo):
                d = by_key.get(cache_key_ip(ip))
                if d and time.time() - float(d.get("ts") or 0) < ttl:
                    out[ip] = _owner(json.loads(d.get("data") or "{}"))
                    todo.remove(ip)
        except Exception as e:  # noqa: BLE001 - the cache is best effort
            log.info("ip_owner: cannot read the shared VirusTotal cache: %s", e)
    ask = todo[:max(0, max_lookups)]
    for ip in todo:
        out.setdefault(ip, None)
    if ask:
        fresh = {}
        try:
            fresh = _vt_lookup(session_key, iconf, vconf, ask)
        except Exception as e:  # noqa: BLE001 - fail-open: the caller warns
            log.info("ip_owner: VirusTotal lookup failed: %s", e)
        shared = []
        for ip in ask:
            info = fresh.get(ip) or {}
            out[ip] = _owner(info)
            if info.get("vt_status") in ("ok", "not_found"):
                cache.put(ip, info)
                shared.append({"_key": cache_key_ip(ip), "ts": time.time(), "data": json.dumps(info)})
        if shared:
            try:
                kv_upsert(session_key, shared, CACHE)
            except Exception as e:  # noqa: BLE001
                log.info("ip_owner: cannot write the shared VirusTotal cache: %s", e)
        try:
            cache.save()
        except (IOError, OSError):
            pass
    return out


def cached_owners(session_key, ips, log):
    """{ip: AS owner or None} from the VirusTotal caches only, whatever their age (an AS owner rarely
    changes) and without any lookup. Used by Auto unblock for every IP rule of every policy."""
    out = dict((ip, None) for ip in ips)
    try:
        cache = vt.VTCache(os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_vt_cache.json"),
                           ttl_seconds=10 ** 10)
        for ip in ips:
            hit = cache.get(ip)
            if hit is not None:
                out[ip] = _owner(hit)
    except Exception as e:  # noqa: BLE001
        log.info("ip_owner: cannot read the VirusTotal file cache: %s", e)
    todo = [ip for ip in ips if not out.get(ip)]
    for k in range(0, len(todo), 200):
        part = todo[k:k + 200]
        try:
            for d in kv_query(session_key, CACHE, {"_key": {"$in": [cache_key_ip(i) for i in part]}}):
                ip = next((i for i in part if cache_key_ip(i) == d.get("_key")), None)
                if ip:
                    out[ip] = _owner(json.loads(d.get("data") or "{}"))
        except Exception as e:  # noqa: BLE001
            log.info("ip_owner: cannot read the shared VirusTotal cache: %s", e)
    return out


def cloud_notes(session_key, iconf, vconf, candidates, log, cloud_days):
    """{ip: note} for the IPs / CIDRs about to be blocked that belong to a cloud provider. Looks the
    owner up now (cache, else up to cloud_check_max_lookups VirusTotal lookups) so Auto unblock
    knows it later. Empty cloud_providers -> {}."""
    rx = cloud_regex(iconf.get("cloud_providers"))
    if not rx or not candidates:
        return {}
    ask = dict((c, lookup_ip(c)) for c in candidates)
    try:
        max_lookups = int(iconf.get("cloud_check_max_lookups", 4))
    except (TypeError, ValueError):
        max_lookups = 4
    own = owners(session_key, iconf, vconf, sorted(set(v for v in ask.values() if v)), log,
                 max_lookups=max_lookups)
    out = {}
    for c in candidates:
        cp = cloud_owner(own.get(ask[c]), rx)
        if cp:
            out[c] = CLOUD_NOTE % (cp, cloud_days)
    return out
