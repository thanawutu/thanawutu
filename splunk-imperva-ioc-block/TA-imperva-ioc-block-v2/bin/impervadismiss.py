"""
Splunk generating command: impervadismiss

"Not block" decisions from the Block / Older detections dashboards. A dismissed
IP is hidden from those pages until it is detected again after the decision
(then it shows up again). Nothing is sent to the WAF. It can still be blocked later.

Usage:
    | impervadismiss                                              (= action=list)
    | impervadismiss action=add ip="1.2.3.4, 5.6.7.8" incident_no="ITHM 1" description="quiet"
    | impervadismiss action=remove ip="1.2.3.4"                   (Restore: show it again now)

ip may hold several IPs (comma / space separated); any other words in it are
ignored, so the dashboard can pass the clicked "✖ NOT BLOCK 2 IPs: a, b" cell as is.
`reason` is still accepted as an older name for `description`.

Stored in the KV store collection imperva_ioc_dismissed. add / remove return one row
per IP in the audit format (pipe it to `imperva_audit_write`) and are written to
imperva_ioc_block.log.
"""

import ipaddress
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
from splunk_helpers import (get_logger, kv_delete, kv_get, kv_list,  # noqa: E402
                            kv_upsert, parse_options)

DISMISSED = "imperva_ioc_dismissed"


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def norm_ip(v):
    try:
        return str(ipaddress.ip_address((v or "").strip().strip('"').strip(",")))
    except ValueError:
        return None


def ips_from(raw):
    """Valid single IPs found in `raw` (other words, e.g. a button label, are ignored)."""
    out = []
    for tok in il.parse_ip_list(raw):
        ip = norm_ip(tok)
        if ip and ip not in out:
            out.append(ip)
    return out


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "ip", "reason", "description", "incident_no"))
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
        ips = ips_from(opts.get("ip"))
        if not ips:
            raise ValueError("no IP selected - click rows in the table first")
        reason = clean(opts.get("description")) or clean(opts.get("reason")) or "-"
        incident = clean(opts.get("incident_no")) or "-"
        out, docs = [], []
        for ip in ips:
            key = ip.replace(":", "-")
            if action == "add":
                docs.append({"_key": key, "ip": ip, "reason": reason, "incident_no": incident,
                             "dismissed_by": user, "dismissed_at": now})
                act, status, detail = "not_block", "dismissed", "hidden from the Block pages until detected again"
            elif kv_get(session_key, key, DISMISSED):
                kv_delete(session_key, key, DISMISSED)
                act, status, detail = "restore", "restored", "shown on the Block pages again"
            else:
                act, status, detail = "restore", "not_found", "IP was not dismissed"
            out.append({"_time": now, "user": user, "action": act, "ip": ip, "site_id": "-",
                        "incident_no": incident, "comment": reason, "status": status,
                        "verified_in_waf": "-", "backend": "-", "detail": detail})
        if docs:
            kv_upsert(session_key, docs, DISMISSED)
        for r in out:
            log.info('user=%s action=%s ip=%s site_id=- status=%s verified_in_waf=- dry_run=False '
                     'threat_actor="" incident_no="%s" comment="%s" reason="%s" detail="%s"',
                     user, "dismiss" if r["action"] == "not_block" else "restore", r["ip"], r["status"],
                     incident, reason, reason, r["detail"])
        si.outputResults(out)
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=dismiss_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervadismiss: %s" % e)


if __name__ == "__main__":
    main()
