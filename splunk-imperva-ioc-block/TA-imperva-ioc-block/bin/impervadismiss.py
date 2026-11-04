"""
Splunk generating command: impervadismiss

"Not block" decisions from the dashboard. A dismissed IP is hidden from the
detected-IOC table until it is detected again after the dismissal (then it
shows up again). Unlike the exclude list it can still be blocked later.

Usage:
    | impervadismiss                                     (= action=list)
    | impervadismiss action=add ip="1.2.3.4" reason="false positive" incident_no="INC-1"
    | impervadismiss action=remove ip="1.2.3.4"          (restore to the dashboard)

Stored in the KV store collection imperva_ioc_dismissed; every change is
written to the audit log (imperva_ioc_block.log).
"""

import ipaddress
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

from splunk_helpers import (get_logger, kv_delete, kv_get, kv_list,  # noqa: E402
                            kv_upsert, parse_options)

DISMISSED = "imperva_ioc_dismissed"


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def norm_ip(v):
    try:
        return str(ipaddress.ip_address((v or "").strip().strip('"')))
    except ValueError:
        return None


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "ip", "reason", "incident_no"))
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    action = (opts.get("action") or "list").strip().lower()
    now = int(time.time())
    try:
        if action == "list":
            rows = []
            for d in sorted(kv_list(session_key, DISMISSED), key=lambda x: -int(x.get("dismissed_at", 0) or 0)):
                rows.append({"_time": now, "ip": d.get("ip"), "reason": d.get("reason", "-"),
                             "incident_no": d.get("incident_no", "-"), "dismissed_by": d.get("dismissed_by", "-"),
                             "dismissed_at": d.get("dismissed_at", "")})
            si.outputResults(rows)
            return
        if action not in ("add", "remove"):
            raise ValueError("action must be list, add or remove")
        ip = norm_ip(opts.get("ip"))
        if not ip:
            raise ValueError("invalid IP %r" % opts.get("ip"))
        key = ip.replace(":", "-")
        reason, incident = clean(opts.get("reason")) or "-", clean(opts.get("incident_no")) or "-"
        if action == "add":
            kv_upsert(session_key, [{"_key": key, "ip": ip, "reason": reason, "incident_no": incident,
                                     "dismissed_by": user, "dismissed_at": now}], DISMISSED)
            status, detail = "dismissed", "hidden from the dashboard until detected again"
        else:
            if kv_get(session_key, key, DISMISSED):
                kv_delete(session_key, key, DISMISSED)
                status, detail = "restored", "shown on the dashboard again"
            else:
                status, detail = "not_found", "IP was not dismissed"
        log.info('user=%s action=%s ip=%s site_id=- status=%s verified_in_waf=- dry_run=False '
                 'threat_actor="" incident_no="%s" comment="" reason="%s" detail="%s"',
                 user, "dismiss" if action == "add" else "restore", ip, status, incident, reason, detail)
        si.outputResults([{"_time": now, "ip": ip, "status": status, "detail": detail,
                           "reason": reason, "incident_no": incident, "user": user}])
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=dismiss_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervadismiss: %s" % e)


if __name__ == "__main__":
    main()
