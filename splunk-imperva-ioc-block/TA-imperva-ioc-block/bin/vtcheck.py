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

Added fields:
    vt_status vt_malicious vt_suspicious vt_harmless vt_undetected vt_engines vt_reputation
    vt_country vt_continent vt_asn vt_as_owner vt_network vt_link vt_cached
    waf_blocked suggestion suggestion_reason

Settings: imperva.conf [virustotal]. API key: storage/passwords realm "virustotal".
"""

import ipaddress
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
import vt_lib as vt              # noqa: E402
from backend import get_backend   # noqa: E402
from splunk_helpers import (get_logger, is_true, load_conf_stanza,  # noqa: E402
                            load_credential, splunk_home)

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
    _kw, opts = si.getKeywordsAndOptions()
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_vtcheck", "imperva_vtcheck.log")
    field = opts.get("field", "src")
    count_field = opts.get("count_field", "count")

    try:
        vconf = load_conf_stanza(session_key, "imperva", "virustotal")
        iconf = load_conf_stanza(session_key, "imperva", "settings")
        _u, api_key = load_credential(session_key, VT_REALM)

        client = vt.VTClient(api_key, base_url=vconf.get("api_base_url", vt.VT_BASE),
                             timeout=int(vconf.get("timeout", 30)),
                             proxy=vconf.get("proxy") or iconf.get("proxy") or None,
                             verify_ssl=is_true(vconf.get("verify_ssl", "true")))
        cache = vt.VTCache(os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_vt_cache.json"),
                           ttl_seconds=int(float(vconf.get("cache_ttl_hours", 24)) * 3600))
        rpm = max(1, int(vconf.get("requests_per_minute", 4)))
        max_lookups = int(vconf.get("max_lookups_per_run", 10))
        thresholds = {k: int(vconf[k]) for k in vt.DEFAULT_THRESHOLDS if vconf.get(k)}
        protected = il.parse_ip_list(iconf.get("protected_networks", ""))

        blocked = set()
        waf_ok = False
        if is_true(opts.get("check_waf", "true")):
            try:
                blocked = waf_blacklist(session_key, iconf)
                waf_ok = True
            except Exception as e:  # noqa: BLE001 - enrichment is best effort
                log.warning("cannot read Imperva blacklist: %s", e)

        lookups_done, last_call, rate_limited = 0, 0.0, False
        for r in results:
            ip = (r.get(field) or "").strip()
            info = {"vt_status": "skipped", "vt_link": vt.VT_GUI + ip}
            r["vt_cached"] = "no"
            cached = cache.get(ip)
            if cached is not None:
                info, r["vt_cached"] = dict(cached), "yes"
            elif not ip or ip == "-":
                info["vt_status"] = "no_ip"
            elif rate_limited:
                info["vt_status"] = "rate_limited"
            elif lookups_done >= max_lookups:
                info["vt_status"] = "not_checked (max_lookups_per_run)"
            else:
                try:
                    if not vt_is_public(ip):
                        info["vt_status"] = "private_ip"
                    else:
                        wait = 60.0 / rpm - (time.time() - last_call)
                        if last_call and wait > 0:
                            time.sleep(wait)
                        last_call = time.time()
                        info = client.lookup_ip(ip)
                        lookups_done += 1
                        cache.put(ip, info)
                except vt.VTRateLimited as e:
                    rate_limited, info["vt_status"] = True, "rate_limited"
                    log.warning("ip=%s %s", ip, e)
                except vt.VTError as e:
                    info["vt_status"] = "error"
                    log.warning("ip=%s %s", ip, e)

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
        log.info("vtcheck rows=%d api_lookups=%d rate_limited=%s", len(results), lookups_done, rate_limited)
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        log.error("vtcheck failed: %s", e)
        si.generateErrorResults("vtcheck: %s" % e)


def vt_is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":
    main()
