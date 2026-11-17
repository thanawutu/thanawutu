"""
Splunk custom search command: impervaticketfill (V2)

A block made without a Ticket / Incident no. or without a Description keeps waiting for them for
24 hours (window_hours): analysts often add the ITHM number to the ES finding notes after the IP
was blocked. The saved search "Imperva V2 - Ticket / description of new blocks (every 10 min)"
reads the ES findings of the waiting IPs (one row per finding) and this command fills the
registry (Blocked IPs page):

    ticket       an ITHM number written in the finding notes AFTER the block (NEW_NOTE_MARGIN
                 = 1 hour before the block is still taken: a note written while blocking).
                 Numbers in the finding's own comment fields count from the finding time.
                 An older number (a previous incident of the same IP) is never taken.
    description  name of the detection rule that detected the IP: the findings of the 7 days up
                 to the block (the window of the Block page); none -> the latest finding before
                 (blocked from Older detections); none -> the first finding after (IP typed in)

Only an EMPTY ticket / description ("-") is filled, never one an analyst typed.

    `imperva_ioc_notables` [| makeresults | impervaticketfill action=terms]
    | ... | table ip finding_time rule_name ithm_times comment_ithm
    | impervaticketfill action=update | `imperva_audit_write`

    | makeresults | impervaticketfill action=pending
    | makeresults | impervaticketfill action=reset ip="198.51.100.48"   (or ip=all) | `imperva_audit_write`

action=terms    one row, field search = ("1.2.3.4" OR "5.6.7.8") for the waiting IPs, or the term
                "imperva_no_ip_pending" when none waits (never an unfiltered search of the findings)
action=update   input: one row per finding of a waiting IP:
                  ip, finding_time (epoch), rule_name, ithm_times ("1234567@<epoch>, ..." from
                  impervanotes), comment_ithm (ITHM numbers in the finding's comment fields)
                output: one audit row per registry entry changed (user auto-ticket, action ticket_update)
action=rules    rules of the OTHER enabled WAF policies (blocked outside Splunk, no registry):
                input as action=update, from the findings that got a note in the last 7 days
                (saved search "Imperva V2 - Ticket of rules in other policies (every 10 min)").
                Same choice of ticket / description, counted from the day V2 first saw the rule
                (imperva_auto_unblock first_listed: no block date in Imperva). Stored on that rule
                (KV imperva_auto_unblock ticket / description), shown on the Blocked IPs page.
action=pending  the registry entries still waiting (ip, policy, blocked_at, waiting_for, hours_left)
action=reset    clears a ticket / description that THIS command filled (not one an analyst typed)
                for ip="a,b" or ip=all (only blocks still inside the window), so the next run fills
                it again with the current rules; audit status "reset"
Option: window_hours (default 24)
"""

import ipaddress
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import auto_unblock as au         # noqa: E402
from splunk_helpers import (REGISTRY, get_logger, kv_query, kv_upsert, load_conf_stanza,  # noqa: E402
                            parse_options)

USER = "auto-ticket"
WINDOW_HOURS = 24
NEW_NOTE_MARGIN = 3600          # a note written up to 1 h before the block counts as new
RULE_DAYS = 7                   # findings of the 7 days up to the block give the description
NONE_TERM = '"imperva_no_ip_pending"'
NUM_RE = re.compile(r"(?i)(?:ITHM\s*-?\s*)?(\d{5,})")
MAX_DESC = 250
# The Description is set on the card when the analyst selects the IPs (rule names of the rows), so the
# scheduled searches only look for the ITHM ticket in the ES findings. True = also fill an empty
# description with the rule name (the earlier behaviour).
FILL_DESCRIPTION = False


def empty(v):
    return str(v or "").strip() in ("", "-")


def waiting_for(doc):
    out = []
    if empty(doc.get("incident_no")):
        out.append("ticket")
    if FILL_DESCRIPTION and empty(doc.get("comment")):
        out.append("description")
    return out


def is_ip(v):
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def num(v, default=None):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def pending(docs, now, window_hours=WINDOW_HOURS):
    """Registry entries blocked in the last window_hours that still have no ticket or description."""
    since = now - window_hours * 3600
    return [d for d in docs if d.get("status") == "blocked" and num(d.get("blocked_at"), 0) >= since
            and waiting_for(d) and is_ip(d.get("ip"))]


def terms(docs):
    ips = sorted(set(str(d["ip"]).strip() for d in docs))
    if not ips:
        return NONE_TERM
    return "(" + " OR ".join('"%s"' % ip for ip in ips) + ")"


def values(v, sep=r"[,;\n]"):
    """Multivalue field (list) or text with separators -> unique values, in order."""
    items = v if isinstance(v, list) else re.split(sep, str(v or ""))
    out = []
    for x in items:
        x = str(x).strip()
        if x and x != "-" and x not in out:
            out.append(x)
    return out


def finding_of(row):
    """One input row -> {t, rules, notes: [(number, note time)], comment: [numbers]}."""
    notes = []
    for x in values(row.get("ithm_times")):
        n, _sep, t = x.partition("@")
        m = NUM_RE.search(n)
        if m:
            notes.append((m.group(1), num(t)))
    comment = []
    for x in values(row.get("comment_ithm")):
        comment += [n for n in NUM_RE.findall(x) if n not in comment]
    return {"t": num(row.get("finding_time")), "rules": values(row.get("rule_name"), r";\s*|\n"),
            "notes": notes, "comment": comment}


def new_tickets(findings, blocked_at):
    """ITHM numbers written after the block (or up to NEW_NOTE_MARGIN before it)."""
    since, out = blocked_at - NEW_NOTE_MARGIN, []
    for f in findings:
        for n, t in f["notes"]:
            if t is not None and t >= since and n not in out:
                out.append(n)
        if f["t"] is not None and f["t"] >= since:
            out += [n for n in f["comment"] if n not in out]
    return out


def rule_names(findings, blocked_at):
    """Rules of the findings that detected the IP for this block (see the module docstring)."""
    timed = sorted((f for f in findings if f["t"] is not None), key=lambda f: f["t"])
    recent = [f for f in timed if blocked_at - RULE_DAYS * 86400 <= f["t"] <= blocked_at + 600]
    if not recent:
        before = [f for f in timed if f["t"] < blocked_at]
        after = [f for f in timed if f["t"] > blocked_at]
        recent = before[-1:] or after[:1]
    out = []
    for f in recent:
        out += [r for r in f["rules"] if r not in out]
    return out


def fill(docs, findings_by_ip, now):
    """docs: waiting registry entries; findings_by_ip: {ip: [finding]} -> (documents to save, audit rows)"""
    save, audit = [], []
    for d in docs:
        found = findings_by_ip.get(str(d.get("ip")).strip(), [])
        blocked_at = num(d.get("blocked_at"), 0)
        new, what = dict(d), []
        new.pop("_user", None)
        if empty(d.get("incident_no")):
            tk = new_tickets(found, blocked_at)
            if tk:
                new["incident_no"] = ", ".join(tk)
                new["ticket_filled_at"] = int(now)
                what.append("ticket %s from a new note of the ES finding" % new["incident_no"])
        if FILL_DESCRIPTION and empty(d.get("comment")):
            rules = rule_names(found, blocked_at)
            if rules:
                desc = "; ".join(rules)
                if len(desc) > MAX_DESC:
                    desc = desc[:MAX_DESC - 1] + "…"
                new["comment"] = desc
                if empty(d.get("reason")):
                    new["reason"] = desc
                new["comment_filled_at"] = int(now)
                what.append("description = detection rule name")
        if what:
            save.append(new)
            audit.append(audit_row(now, new, "updated", " · ".join(what) + " (filled after the block)"))
    return save, audit


def fill_rules(entries, own, states, findings_by_ip, now, registry=None):
    """Rules blocked outside Splunk V2 with exactly a finding's IP -> (state documents, audit rows):
    every rule of the other enabled policies, and a rule of the own policy that has no V2 registry
    entry (blocked from V1 or directly in Imperva). states: {entry_key: imperva_auto_unblock document};
    registry: {(site_id, ip)} of the V2 registry entries with status blocked."""
    own = set(str(x) for x in own)
    registry = registry or set()
    save, audit = [], []
    for e in entries:
        pid, cidr = str(e.get("policy_id")), str(e.get("cidr") or "")
        if ((pid in own and (pid, cidr) in registry) or cidr not in findings_by_ip or not e.get("enabled", True)
                or e.get("kind") == "exception" or not str(e.get("action", "")).startswith("BLOCK")):
            continue
        st = states.get(au.entry_key(pid, cidr))
        if not st:
            continue                      # not seen by Auto unblock yet: next run
        found, since = findings_by_ip[cidr], num(st.get("first_listed"), now)
        new, what = dict(st), []
        new.pop("_user", None)
        if empty(st.get("ticket")):
            tk = new_tickets(found, since)
            if tk:
                new["ticket"], new["ticket_filled_at"] = ", ".join(tk), int(now)
                what.append("ticket %s from a new note of the ES finding" % new["ticket"])
        if FILL_DESCRIPTION and empty(st.get("description")):
            # the rule of the finding that got the new ticket note (first_listed is only when V2 first
            # saw the rule), else the findings around first_listed
            tk_new = set(new_tickets(found, since))
            rules = []
            for f in found:
                if any(n in tk_new for n, _t in f["notes"]):
                    rules += [x for x in f["rules"] if x not in rules]
            rules = rules or rule_names(found, since)
            if rules:
                desc = "; ".join(rules)
                new["description"] = desc if len(desc) <= MAX_DESC else desc[:MAX_DESC - 1] + "…"
                new["description_filled_at"] = int(now)
                what.append("description = detection rule name")
        if what:
            save.append(new)
            audit.append(audit_row(now, {"ip": cidr, "site_id": pid, "incident_no": new.get("ticket"),
                                         "comment": new.get("description")}, "updated",
                                   " · ".join(what) + (" (own policy, blocked outside Splunk V2)" if pid in own
                                                       else " (rule of another policy, blocked outside Splunk)")))
    return save, audit


def audit_row(now, doc, status, detail):
    return {"_time": now, "user": USER, "action": "ticket_update", "ip": doc.get("ip"),
            "site_id": doc.get("site_id") or "-", "status": status,
            "incident_no": doc.get("incident_no") or "-", "comment": doc.get("comment") or "-",
            "verified_in_waf": "-", "backend": "-", "detail": detail}


def reset(docs, ips, now, window_hours=WINDOW_HOURS):
    """Clear what this command filled (ticket_filled_at / comment_filled_at) -> (documents, audit rows).
    ip=all: only the blocks still inside the window (filled again by the next run); named IPs: any."""
    every = [x.lower() for x in ips] == ["all"]
    since = now - window_hours * 3600
    save, audit = [], []
    for d in docs:
        inside = num(d.get("blocked_at"), 0) >= since
        if d.get("status") != "blocked" or not ((every and inside) or str(d.get("ip")).strip() in ips):
            continue
        new, what = dict(d), []
        new.pop("_user", None)
        if new.pop("ticket_filled_at", None) is not None:
            new["incident_no"] = "-"
            what.append("ticket")
        if new.pop("comment_filled_at", None) is not None:
            if new.get("reason") == new.get("comment"):
                new["reason"] = "-"
            new["comment"] = "-"
            what.append("description")
        if what:
            save.append(new)
            audit.append(audit_row(now, new, "reset", "auto-filled %s cleared - %s" % (
                " and ".join(what), "filled again by the next run" if inside
                else "not filled again (more than %g h after the block)" % window_hours)))
    return save, audit


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "window_hours", "ip"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_ticketfill", "imperva_ticketfill.log")
    action = (opts.get("action") or "update").strip().lower()
    try:
        window = float(opts.get("window_hours") or WINDOW_HOURS)
        now = time.time()
        blocked = kv_query(session_key, REGISTRY, {"status": "blocked"})
        docs = pending(blocked, now, window)
        if action == "terms":
            si.outputResults([{"search": terms(docs)}])
        elif action == "pending":
            si.outputResults([{"ip": d.get("ip"), "policy": d.get("site_id") or "-",
                               "blocked_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(num(d["blocked_at"]))),
                               "blocked_by": d.get("blocked_by") or "-", "waiting_for": ", ".join(waiting_for(d)),
                               "hours_left": round((num(d["blocked_at"]) + window * 3600 - now) / 3600.0, 1)}
                              for d in docs])
        elif action == "update":
            by_ip = {}
            for r in results:
                ip = str(r.get("ip") or "").strip()
                if ip:
                    by_ip.setdefault(ip, []).append(finding_of(r))
            save, audit = fill(docs, by_ip, now)
            if save:
                kv_upsert(session_key, save, REGISTRY)
            for a in audit:
                log.info('user=%s action=ticket_update ip=%s site_id=%s incident_no="%s" comment="%s" detail="%s"',
                         USER, a["ip"], a["site_id"], a["incident_no"], a["comment"], a["detail"])
            log.info("ticketfill waiting=%d finding_rows=%d ips=%d updated=%d", len(docs), len(results),
                     len(by_ip), len(save))
            si.outputResults(audit)
        elif action == "rules":
            by_ip = {}
            for r in results:
                ip = str(r.get("ip") or "").strip()
                if ip:
                    by_ip.setdefault(ip, []).append(finding_of(r))
            save, audit = [], []
            if by_ip:
                import impervapolicycheck as pc
                conf = load_conf_stanza(session_key, "imperva", "settings")
                entries, targets, _via = pc.load_entries(session_key, conf, log)
                own = [str(x) for x in (targets or [p.strip() for p in str(conf.get("policy_ids", "")).split(",") if p.strip()])]
                keys = [au.entry_key(e["policy_id"], e["cidr"]) for e in entries if e.get("cidr") in by_ip]
                states = dict((d["_key"], d) for d in kv_query(session_key, au.STATE, {"_key": {"$in": keys}})) if keys else {}
                reg = set((str(d.get("site_id")), str(d.get("ip"))) for d in blocked)
                save, audit = fill_rules(entries, own, states, by_ip, now, reg)
            if save:
                kv_upsert(session_key, save, au.STATE)
            for a in audit:
                log.info('user=%s action=ticket_update ip=%s site_id=%s incident_no="%s" comment="%s" detail="%s"',
                         USER, a["ip"], a["site_id"], a["incident_no"], a["comment"], a["detail"])
            log.info("ticketfill rules finding_rows=%d ips=%d updated=%d", len(results), len(by_ip), len(save))
            si.outputResults(audit)
        elif action == "reset":
            ips = values(opts.get("ip"))
            if not ips:
                raise ValueError('give ip="1.2.3.4,5.6.7.8" or ip=all')
            save, audit = reset(blocked, ips, now, window)
            if save:
                kv_upsert(session_key, save, REGISTRY)
            for a in audit:
                log.info('user=%s action=ticket_update status=reset ip=%s detail="%s"', USER, a["ip"], a["detail"])
            si.outputResults(audit)
        else:
            raise ValueError("action must be terms, update, rules, pending or reset")
    except Exception as e:  # noqa: BLE001
        log.error("impervaticketfill failed: %s", e)
        si.generateErrorResults("impervaticketfill: %s" % e)


if __name__ == "__main__":
    main()
