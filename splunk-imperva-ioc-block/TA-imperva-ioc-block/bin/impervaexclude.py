"""
Splunk generating command: impervaexclude

Manage the exclude list: IPs / CIDRs that are never shown as attackers on the
dashboard and can never be blocked (Splunk and SOAR both refuse them).

Usage:
    | impervaexclude                                   (= action=list)
    | impervaexclude action=add cidr="1.2.3.0/24" description="authorised scanner"
    | impervaexclude action=remove cidr="1.2.3.0/24" reason="contract ended"

Sources:
    dashboard  KV store collection imperva_exclude_list (add/remove here)
    conf       imperva.conf [settings] protected_networks (read-only here)

Every add / remove is written to the audit log (imperva_ioc_block.log).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
from splunk_helpers import (EXCLUDES, exclude_networks, get_logger, kv_delete,  # noqa: E402
                            kv_get, kv_upsert, load_conf_stanza, parse_options)


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "cidr", "ip", "description", "reason"))
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    action = (opts.get("action") or "list").strip().lower()
    now = int(time.time())
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        if action in ("add", "remove"):
            norm, err = il.normalize_cidr(opts.get("cidr") or opts.get("ip"))
            if err:
                raise il.ImpervaError(err)
            key = il.exclude_key(norm)
            existing = kv_get(session_key, key, EXCLUDES)
            if action == "add":
                if existing:
                    status, detail = "no_change", "already in exclude list"
                else:
                    kv_upsert(session_key, [{"_key": key, "cidr": norm,
                                             "description": clean(opts.get("description")) or "-",
                                             "added_by": user, "added_at": now}], EXCLUDES)
                    status, detail = "excluded", "added to exclude list"
            else:
                if not existing:
                    in_conf = norm in il.parse_ip_list(conf.get("protected_networks", ""))
                    status = "not_found"
                    detail = ("defined in imperva.conf protected_networks - change it on the deployer"
                              if in_conf else "not in exclude list")
                else:
                    kv_delete(session_key, key, EXCLUDES)
                    status, detail = "removed", "removed from exclude list"
            log.info('user=%s action=exclude_%s ip=%s site_id=- status=%s verified_in_waf=- dry_run=False '
                     'threat_actor="" incident_no="" comment="%s" reason="%s" detail="%s"',
                     user, action, norm, status, clean(opts.get("description")),
                     clean(opts.get("reason")), detail)
            si.outputResults([{"_time": now, "action": "exclude_" + action, "cidr": norm,
                               "status": status, "detail": detail, "user": user,
                               "description": clean(opts.get("description")),
                               "reason": clean(opts.get("reason"))}])
            return

        if action != "list":
            raise il.ImpervaError("action must be list, add or remove")
        docs = {}
        try:
            from splunk_helpers import kv_list
            docs = {d.get("cidr"): d for d in kv_list(session_key, EXCLUDES)}
        except Exception:  # noqa: BLE001 - conf entries are still listed
            pass
        out = []
        for cidr, desc, source in exclude_networks(session_key, conf):
            d = docs.get(cidr, {})
            out.append({"_time": now, "cidr": cidr, "description": desc or "-", "source": source,
                        "added_by": d.get("added_by", "-"), "added_at": d.get("added_at", "")})
        si.outputResults(out)
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=exclude_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervaexclude: %s" % e)


if __name__ == "__main__":
    main()
