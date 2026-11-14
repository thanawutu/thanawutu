"""
Splunk generating command: impervaautounblock (V2)

Unblock IP rules of the WAF policies after a quiet period (see auto_unblock.py), fixed values:
cloud provider and shared IPs after 7 days without an attack, other IPs after 60 days; every
enabled policy; at most 50 rules per run. The countdown never starts before the day V2 first saw
the rule.

Usage:
    | makeresults | impervaautounblock                  (= action=list: every BLOCK IP rule + plan)
    | makeresults | impervaautounblock action=run | `imperva_audit_write`        (unblock what is due)
    | makeresults | impervaautounblock action=set ip="1.2.3.4" rule=keep reason="C2" | `imperva_audit_write`
          rule = keep (never) | default | <days>; policy_id=<id> to change one policy only
    | makeresults | impervaautounblock action=policies  (policies holding BLOCK IP rules)
    ... | impervaautounblock action=annotate field=ip policy_field=site_id   (add plan columns)
(not a generating command, because annotate needs input rows: start with | makeresults)

Sources: IP rules of every policy (cache of impervapolicycheck, KV imperva_cache), last request
of each source IP (KV imperva_blocked_seen), rule state (KV imperva_auto_unblock),
block date / ticket (KV imperva_block_registry), AS owner (VirusTotal caches).
Unblocking goes through the normal backend (SOAR in production) with the policy ID of the rule;
SOAR must allow that policy ID (IMPERVA_POLICY_IDS).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import auto_unblock as au        # noqa: E402
import imperva_lib as il         # noqa: E402
import ip_owner                  # noqa: E402
from backend import get_backend   # noqa: E402
from soar_bridge import SoarError  # noqa: E402
from splunk_helpers import (REGISTRY, get_logger, kv_delete, kv_get, kv_list,  # noqa: E402
                            kv_upsert, load_conf_stanza, load_credential, parse_options,
                            registry_key)

AUTO_USER = "auto-unblock"


def fmt(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "-"


def load_entries(session_key, conf, log):
    import impervapolicycheck as pc
    entries, targets, _via = pc.load_entries(session_key, conf, log)
    own = targets or il.parse_ip_list(conf.get("policy_ids", ""))
    return entries, [str(x) for x in own]


def refresh_entries(session_key, conf, log):
    try:
        import impervapolicycheck as pc
        pc.load_entries(session_key, conf, log, force=True)
    except Exception as e:  # noqa: BLE001 - next refresh (5 min) will do it
        log.error("auto unblock: policy cache refresh failed: %s", e)


def gather(session_key, conf, log, now):
    entries, own = load_entries(session_key, conf, log)
    states = {}
    for d in kv_list(session_key, au.STATE):
        if d.get("_key") != au.OLD_SETTINGS_KEY:
            states[d["_key"]] = d
    seen, hits = {}, {}
    try:
        for d in kv_list(session_key, au.SEEN):
            if d.get("src"):
                seen[d["src"]] = float(d.get("last_seen") or 0)
                hits[d["src"]] = float(d.get("hits_24h") or 0)
    except Exception as e:  # noqa: BLE001 - no activity data yet
        log.error("auto unblock: cannot read %s: %s", au.SEEN, e)
    registry = {}
    for d in kv_list(session_key, REGISTRY):
        if d.get("status") == "blocked":
            registry[(str(d.get("site_id")), d.get("ip"))] = d
    cands = au.candidate_entries(entries, own)
    owners = ip_owner.cached_owners(session_key, sorted(set(filter(None, (au.first_address(e["cidr"]) for e in cands)))), log)
    rx = ip_owner.cloud_regex(conf.get("cloud_providers"))
    srx = ip_owner.cloud_regex(conf.get("shared_ip_providers"))
    items, new_states = au.plan(now, entries, own, states, seen, registry, owners,
                                lambda o: ip_owner.short_class(o, rx, srx), hits)
    if new_states:
        try:
            kv_upsert(session_key, new_states, au.STATE)
        except Exception as e:  # noqa: BLE001
            log.error("auto unblock: cannot save new rules: %s", e)
    return items, own


STATUS = {"kept": "Kept", "due": "Due · unblock", "attacking": "Attacking · seen today",
          "soon": "Unblock soon", "quiet": "Quiet"}


def row_of(i, now):
    if i["status"] == "quiet":
        st = "Quiet %d d" % int((now - i["base"]) / au.DAY)
    else:
        st = STATUS[i["status"]]
    rule = "Keep" if i["rule"] == "keep" else ("%s d quiet" % i["rule"] if isinstance(i["rule"], int) else
                                               ("%s %s d quiet" % (i["short"], i["days"]) if i["short"] else "%s d quiet" % i["days"]))
    return {"ip": i["cidr"], "policy_id": i["policy_id"], "policy_name": i["policy_name"],
            "own_policy": "yes" if i["own"] else "no",
            "owner": i["owner"] or "-", "cloud_provider": i["cloud"] or "-",
            "short_block": ("%s: %s" % (i["short"], i["owner"])) if i["short"] else "-",
            "blocked_at": fmt(i["blocked_at"]), "listed_since": fmt(i["first_listed"]),
            "ticket": i["ticket"], "description": i["description"], "blocked_by": i["blocked_by"],
            "last_attack": fmt(i["last_seen"]) if i["last_seen"] else "-",
            "attacks_24h": i.get("attacks_24h", 0),
            "unblock_after": rule, "unblock_on": fmt(i["unblock_on"]),
            "days_left": "-" if i["left_days"] is None else ("%.1f" % i["left_days"] if i["left_days"] > 0 else "0"),
            "status": st, "status_code": i["status"], "rule_reason": i["rule_reason"] or "-"}


def audit_row(now, user, action, ip, sid, status, detail, ticket="-", comment="-", verified="-", backend="-", extra=None):
    r = {"_time": now, "user": user, "action": action, "ip": ip, "site_id": sid, "status": status,
         "verified_in_waf": verified, "backend": backend, "detail": detail,
         "incident_no": ticket, "comment": comment}
    r.update(extra or {})
    return r


def do_run(session_key, conf, log, now):
    items, _own = gather(session_key, conf, log, now)
    due = au.due_items(items, au.MAX_PER_RUN)
    out, by_policy = [], {}
    for i in due:
        by_policy.setdefault(i["policy_id"], []).append(i)
    unblocked_keys, reg_docs = [], []
    for pid, group in sorted(by_policy.items()):
        for k in range(0, len(group), 50):
            part = group[k:k + 50]
            ips = [i["cidr"] for i in part]
            meta = {"reason": "auto unblock: no attack for the quiet period", "threat_actor": "",
                    "incident_no": "-", "comment": "auto unblock (V2)"}
            try:
                backend = get_backend(conf, load_credential, session_key, override_ids=pid)
                res = dict((r["ip"], r) for r in backend.execute("unblock", ips, False, meta, AUTO_USER))
                mode = backend.mode
            except (il.ImpervaError, SoarError, Exception) as e:  # noqa: BLE001 - per policy
                hint = " (add the policy ID to IMPERVA_POLICY_IDS on SOAR)" if "not allowed" in str(e) else ""
                for i in part:
                    out.append(audit_row(now, AUTO_USER, "unblock", i["cidr"], pid, "error", str(e) + hint,
                                         i["ticket"], au.reason_text(i)))
                log.error("auto unblock: policy %s failed: %s", pid, e)
                continue
            for i in part:
                r = res.get(i["cidr"]) or {"status": "error", "detail": "no answer for this IP", "verified_in_waf": "unknown"}
                why = au.reason_text(i)
                row = audit_row(now, AUTO_USER, "unblock", i["cidr"], r.get("site_id", pid), r["status"],
                                (r.get("detail") or "") + " | " + why, i["ticket"], why,
                                r.get("verified_in_waf", "-"), mode,
                                {"soar_container": r["soar_container"]} if "soar_container" in r else None)
                out.append(row)
                if r["status"] in ("unblocked", "no_change"):
                    unblocked_keys.append(i["key"])
                    if i["own"]:
                        key = registry_key(pid, i["cidr"])
                        try:
                            existing = kv_get(session_key, key)
                        except Exception:  # noqa: BLE001
                            existing = None
                        doc = il.build_registry_doc(existing, key, pid, i["cidr"], "unblock", r["status"],
                                                    AUTO_USER, int(now), {"reason": why, "incident_no": "-",
                                                                          "comment": why, "threat_actor": ""})
                        if doc:
                            reg_docs.append(doc)
    try:
        kv_upsert(session_key, reg_docs)
    except Exception as e:  # noqa: BLE001 - the WAF change already happened
        log.error("auto unblock: registry write failed: %s", e)
    for k in unblocked_keys:     # a rule added again later starts a new countdown
        try:
            kv_delete(session_key, k, au.STATE)
        except Exception:  # noqa: BLE001
            pass
    for r in out:
        log.info('user=%s action=auto_unblock ip=%s site_id=%s status=%s verified_in_waf=%s dry_run=False '
                 'incident_no="%s" comment="%s" reason="%s" detail="%s"', r["user"], r["ip"], r["site_id"],
                 r["status"], r["verified_in_waf"], r["incident_no"], r["comment"], r["comment"],
                 str(r["detail"]).replace('"', "'"))
    if out:
        refresh_entries(session_key, conf, log)
    return out


def do_set(session_key, conf, log, now, opts, user):
    ips = il.parse_ip_list(opts.get("ip"))
    if not ips:
        raise ValueError("no IP given (ip=...)")
    rule = au.rule_of(opts.get("rule"))
    reason = (opts.get("reason") or opts.get("description") or "-").replace('"', "'").strip() or "-"
    pid = (opts.get("policy_id") or "").strip()
    items, _own = gather(session_key, conf, log, now)
    out, docs = [], []
    for ip in ips:
        hits = [i for i in items if i["cidr"] == ip and (not pid or i["policy_id"] == pid)]
        if not hits:
            out.append(audit_row(now, user, "auto_unblock_rule", ip, pid or "-", "not_found",
                                 "no BLOCK IP rule for this IP in the policies"))
            continue
        for i in hits:
            docs.append({"_key": i["key"], "policy_id": i["policy_id"], "cidr": i["cidr"],
                         "first_listed": int(i["first_listed"]), "rule": str(rule),
                         "rule_by": user, "rule_at": int(now), "rule_reason": reason})
            label = {"keep": "Keep (never unblock)", "default": "default"}.get(rule, "%s days without an attack" % rule)
            out.append(audit_row(now, user, "auto_unblock_rule", ip, i["policy_id"], "saved",
                                 "unblock after: " + label, i["ticket"], reason))
    kv_upsert(session_key, docs, au.STATE)
    for r in out:
        log.info('user=%s action=auto_unblock_rule ip=%s site_id=%s status=%s detail="%s" reason="%s"',
                 user, r["ip"], r["site_id"], r["status"], r["detail"], reason)
    return out


def do_policies(items, own):
    pol = {}
    for i in items:
        p = pol.setdefault(i["policy_id"], {"policy_id": i["policy_id"], "policy_name": i["policy_name"],
                                            "own_policy": "yes" if i["own"] else "no", "block_ip_rules": 0,
                                            "due": 0, "cloud": 0, "shared": 0, "attacks_24h": 0})
        p["block_ip_rules"] += 1
        p["due"] += 1 if i["status"] == "due" else 0
        p["cloud"] += 1 if i["cloud"] else 0
        p["shared"] += 1 if i["shared"] else 0
        p["attacks_24h"] += i.get("attacks_24h", 0)
    return sorted(pol.values(), key=lambda p: (p["own_policy"] != "yes", p["policy_id"]))


def main():
    results, _dummy, settings_ctx = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "ip", "policy_id", "rule", "reason", "description",
                                        "field", "policy_field"))
    session_key = settings_ctx.get("sessionKey")
    user = settings_ctx.get("owner", "unknown")
    log = get_logger("imperva_auto_unblock", "imperva_auto_unblock.log")
    action = (opts.get("action") or "list").strip().lower()
    now = time.time()
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        if action == "run":
            si.outputResults(do_run(session_key, conf, log, now))
        elif action == "set":
            si.outputResults(do_set(session_key, conf, log, now, opts, user))
        elif action in ("list", "policies", "annotate"):
            items, own = gather(session_key, conf, log, now)
            if action == "list":
                si.outputResults([row_of(i, now) for i in items])
            elif action == "policies":
                si.outputResults(do_policies(items, own))
            else:
                field, pfield = opts.get("field", "ip"), opts.get("policy_field", "site_id")
                by = dict(((i["policy_id"], i["cidr"]), row_of(i, now)) for i in items)
                for r in results:
                    p = by.get((str(r.get(pfield, "")), (r.get(field) or "").strip()))
                    if p:
                        for k in ("unblock_after", "last_attack", "attacks_24h", "unblock_on", "days_left", "status", "cloud_provider", "short_block"):
                            r["auto_" + k] = p[k]
                si.outputResults(results)
        else:
            raise ValueError("action must be list, run, set, policies or annotate")
    except Exception as e:  # noqa: BLE001
        log.error('user=%s action=auto_unblock_%s status=failed error="%s"', user, action, e)
        si.generateErrorResults("impervaautounblock: %s" % e)


if __name__ == "__main__":
    main()
