"""
Splunk generating command: impervarules

Detection rules = which ES correlation searches feed the Block pages
(KV store collection imperva_ioc_rules). Changed from the "Detection rules"
dashboard - no code change or app deploy needed.

Usage:
    | impervarules                                        (= action=list)
    | impervarules action=terms mode=include              (search_name terms for the notables macro)
    | impervarules action=add pattern="*WAF*" mode=include note="all WAF searches"
    | impervarules action=disable key=<key>               (enable / disable / remove)

The first call on an empty collection writes the default rules
(include *WAF*, exclude *WAF Monitor Error code 404*).
add / remove / enable / disable return one row in the audit format
(pipe it to `imperva_audit_write`) and are written to imperva_ioc_block.log.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import ioc_rules as ir           # noqa: E402
from splunk_helpers import (get_logger, kv_delete, kv_list, kv_upsert,  # noqa: E402
                            parse_options)


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def load_rules(session_key, user, now):
    docs = kv_list(session_key, ir.COLLECTION)
    if not any(d.get("_key") == ir.SEED_KEY for d in docs):
        seed = [d for d in ir.default_docs(user, now)
                if d["_key"] == ir.SEED_KEY or d["_key"] not in set(x.get("_key") for x in docs)]
        kv_upsert(session_key, seed, ir.COLLECTION)
        docs = docs + [d for d in seed]
    return ir.real_rules(docs)


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "pattern", "mode", "note", "key"))
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    action = (opts.get("action") or "list").strip().lower()
    now = int(time.time())
    try:
        rules = load_rules(session_key, user, now)

        if action == "list":
            rows = []
            for r in sorted(rules, key=lambda x: (x["mode"] != "include", x["pattern"].lower())):
                rows.append({"_time": now, "key": r["_key"], "pattern": r["pattern"], "mode": r["mode"],
                             "enabled": "on" if ir.is_enabled(r) else "off", "note": r.get("note") or "-",
                             "updated_by": r.get("updated_by") or "-", "updated_at": r.get("updated_at") or ""})
            si.outputResults(rows)
            return

        if action == "terms":
            mode = (opts.get("mode") or "include").strip().lower()
            if mode not in ir.MODES:
                raise ValueError("mode must be include or exclude")
            si.outputResults([{"search_name": p} for p in ir.search_terms(rules, mode)])
            return

        by_key = dict((r["_key"], r) for r in rules)
        if action == "add":
            pattern = ir.clean_pattern(opts.get("pattern"))
            mode = (opts.get("mode") or "include").strip().lower()
            if not pattern or pattern == "-":
                raise ValueError("pattern is empty")
            if mode not in ir.MODES:
                raise ValueError("mode must be include or exclude")
            rule = {"_key": ir.rule_key(pattern, mode), "pattern": pattern, "mode": mode, "enabled": "1",
                    "note": clean(opts.get("note")) or "-", "updated_by": user, "updated_at": now}
            status = "updated" if rule["_key"] in by_key else "added"
            kv_upsert(session_key, [rule], ir.COLLECTION)
        elif action in ("remove", "enable", "disable"):
            rule = by_key.get((opts.get("key") or "").strip())
            if not rule:
                raise ValueError("rule %r not found (already removed?)" % opts.get("key"))
            if action == "remove":
                kv_delete(session_key, rule["_key"], ir.COLLECTION)
                status = "removed"
            else:
                rule = dict(rule, enabled="1" if action == "enable" else "0", updated_by=user, updated_at=now)
                rule.pop("_user", None)
                kv_upsert(session_key, [rule], ir.COLLECTION)
                status = action + "d"
        else:
            raise ValueError("action must be list, terms, add, remove, enable or disable")

        desc = "%s %s" % (rule["mode"], rule["pattern"])
        detail = "detection rule %s - effective on the next dashboard search" % status
        log.info('user=%s action=rule_%s ip=- site_id=- status=%s verified_in_waf=- dry_run=False '
                 'threat_actor="" incident_no="-" comment="%s" reason="%s" detail="%s"',
                 user, action, status, clean(desc), clean(rule.get("note")), detail)
        si.outputResults([{"_time": now, "user": user, "action": "rule_" + action, "ip": "-",
                           "site_id": "-", "incident_no": "-", "comment": desc, "status": status,
                           "verified_in_waf": "-", "backend": "-", "detail": detail}])
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=rule_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervarules: %s" % e)


if __name__ == "__main__":
    main()
