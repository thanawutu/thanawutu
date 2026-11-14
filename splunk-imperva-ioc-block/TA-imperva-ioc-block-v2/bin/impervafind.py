"""
Splunk custom search command: impervafind (V2)

"Found" box of the single Search / add box (Block and Older detections pages): where are the IPs
typed in the search box - on the WAF (EVERY policy), blocked from Splunk (registry), in the
Not block list - and can they be blocked?

    | makeresults | eval ip="185.220.101.47" | impervafind field=ip
    | makeresults | eval _text="1000090" | impervafind field=ip text_field=_text

Rows with an IP get:
    find_lines      "<cls>¦<text>" lines joined with " ‖ "   cls: no = already blocked / cannot be blocked,
                    al = allowed by a policy, pg = information, ok = can be blocked
    find_blockable  yes | no     (yes = the Block button includes this IP)
    find_unblockable yes | no    (yes = blocked by a rule of exactly this IP: the Unblock button includes it)
    find_unblock_policy  policy ID(s) the Unblock removes it from, or "-"
    find_cloud      AS owner of a cloud provider / shared IP (short block) or "-"
A blocked IP can only be unblocked, an IP that is not blocked can only be blocked.
A row with text instead (no IP in the search box) gets find_lines with the number of matches in
the registry (Blocked IPs page), in the rules of the other WAF policies and in the Not block list.

Detections (Block / Older pages) are added by the view's search (ES notables of the typed IPs).
Data: policy cache of every policy (impervapolicycheck), KV imperva_block_registry,
imperva_ioc_dismissed, imperva_auto_unblock (first time V2 saw a rule), VirusTotal owner cache.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import auto_unblock as au        # noqa: E402
import imperva_lib as il         # noqa: E402
import ip_owner                  # noqa: E402
from splunk_helpers import (REGISTRY, get_logger, kv_list, kv_query, load_conf_stanza,  # noqa: E402
                            parse_options, protected_networks)

DISMISSED = "imperva_ioc_dismissed"
SEP = "¦"          # between class and text of one line
JOIN = " ‖ "       # between lines


def fmt(t):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t))) if t else "-"
    except (TypeError, ValueError):
        return "-"


def line(cls, text):
    return "%s%s%s" % (cls, SEP, text)


def find_ip(ip, entries, own, registry, dismissed, states, owner, short_of, protected, conf, cloud_days):
    """-> (lines, blockable, cloud_owner, unblock_policies) for one IP / CIDR typed in the search box.
    unblock_policies: policies with a BLOCK rule of exactly this IP (the Unblock button removes it)."""
    lines, stop, unblock = [], False, []
    own = set(str(x) for x in own)
    exact = [m for m in il.match_policies(ip, entries) if m.get("enabled", True) and m["cidr"] == ip
             and str(m["action"]).startswith("BLOCK") and m.get("kind") != "exception"]
    accepted, rejected = il.validate_ips([ip], protected, int(conf.get("max_cidr_prefix_v4", 24)),
                                         int(conf.get("max_cidr_prefix_v6", 48)))
    if rejected and not exact:            # a rule on the WAF can still be removed, whatever the address
        return [line("no", "cannot be blocked: %s" % rejected[0][1])], "no", "-", []
    for m in il.match_policies(ip, entries):
        if not m.get("enabled", True):
            continue
        pid, name = str(m["policy_id"]), m.get("policy_name") or "-"
        if m["action"] == "ALLOW" or m.get("kind") == "exception":
            lines.append(line("al", "ALLOWED by policy %s %s (%s) - cannot be blocked" % (pid, name, m["cidr"])))
            stop = True
        elif str(m["action"]).startswith("BLOCK"):
            reg = registry.get((pid, m["cidr"])) or registry.get((pid, ip))
            if reg:
                lines.append(line("no", "already BLOCKED in policy %s %s · blocked %s by %s · ticket %s" % (
                    pid, name, fmt(reg.get("blocked_at")), reg.get("blocked_by") or "-",
                    reg.get("incident_no") or "-")))
            else:
                st = states.get(au.entry_key(pid, m["cidr"])) or {}
                since = (" · on the policy since %s (block date not kept by Imperva)" % fmt(st["first_listed"])[:10]
                         if st.get("first_listed") else "")
                cover = "" if m["cidr"] == ip else " (rule %s - unblock that rule on the Blocked IPs page)" % m["cidr"]
                lines.append(line("no", "already BLOCKED in policy %s %s%s%s" % (pid, name, cover, since)))
            if m["cidr"] == ip and pid not in unblock:
                unblock.append(pid)
            stop = True
    if not stop:
        for (pid, rip), reg in registry.items():
            if rip == ip and pid in own:      # blocked from Splunk, policy cache not refreshed yet
                lines.append(line("no", "blocked from Splunk %s by %s · ticket %s (policy cache refresh pending)" % (
                    fmt(reg.get("blocked_at")), reg.get("blocked_by") or "-", reg.get("incident_no") or "-")))
                stop = True
                unblock.append(pid)
                break
    d = dismissed.get(ip)
    if d:
        lines.append(line("pg", "hidden by Not block (%s, %s)%s" % (
            d.get("dismissed_by") or "-", fmt(d.get("dismissed_at"))[:10], "" if stop else " - can still be blocked")))
    cloud = "-"
    if not stop and owner:
        short = short_of(owner)
        if short:
            cloud = short[1]
            lines.append(line("pg", "%s (%s) - short block: auto unblock after %d days without an attack" % (
                "cloud provider" if short[0] == "cloud" else "shared IP", short[1], cloud_days)))
    if not stop:
        lines.insert(0, line("ok", "not on the WAF and not blocked from Splunk - can be blocked"))
    if any(x.startswith("al" + SEP) for x in lines):
        unblock = []                      # allowed by a policy: nothing to unblock from the Block page
    return lines, "no" if stop else "yes", cloud, unblock


def find_text(text, entries, own, registry_docs, dismissed_docs):
    t = text.strip().lower()
    own = set(str(x) for x in own)

    def has(*vals):
        return any(t in str(v or "").lower() for v in vals)
    blocked = [d for d in registry_docs if d.get("status") == "blocked" and
               has(d.get("ip"), d.get("incident_no"), d.get("comment"), d.get("blocked_by"))]
    other = set((str(e["policy_id"]), e["cidr"]) for e in entries
                if str(e["policy_id"]) not in own and e.get("enabled", True)
                and str(e.get("action", "")).startswith("BLOCK") and has(e["cidr"], e.get("policy_name")))
    hidden = [d for d in dismissed_docs if has(d.get("ip"), d.get("incident_no"), d.get("reason"))]
    return [line("pg", "%d blocked from Splunk (Blocked IPs page)" % len(blocked)),
            line("pg", "%d IP rules in other WAF policies" % len(other)),
            line("pg", "%d in the Not block list" % len(hidden))]


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("field", "text_field"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_find", "imperva_find.log")
    field, tfield = opts.get("field", "ip"), opts.get("text_field", "_text")
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        import impervapolicycheck as pc
        entries, targets, _via = pc.load_entries(session_key, conf, log)
        own = [str(x) for x in (targets or il.parse_ip_list(conf.get("policy_ids", "")))]
        ips = sorted(set((r.get(field) or "").strip() for r in results if (r.get(field) or "").strip()))
        texts = [r for r in results if not (r.get(field) or "").strip() and (r.get(tfield) or "").strip()]
        registry, dismissed, states, owners = {}, {}, {}, {}
        reg_docs, dis_docs = [], []
        if ips or texts:
            reg_docs = kv_list(session_key, REGISTRY) if texts else kv_query(session_key, REGISTRY, {"ip": {"$in": ips}})
            dis_docs = kv_list(session_key, DISMISSED) if texts else kv_query(session_key, DISMISSED, {"ip": {"$in": ips}})
        for d in reg_docs:
            if d.get("status") == "blocked":
                registry[(str(d.get("site_id")), d.get("ip"))] = d
        for d in dis_docs:
            dismissed[d.get("ip")] = d
        if ips:
            keys = [au.entry_key(m["policy_id"], m["cidr"]) for ip in ips for m in il.match_policies(ip, entries)]
            if keys:
                try:
                    states = dict((d["_key"], d) for d in kv_query(session_key, au.STATE, {"_key": {"$in": keys}}))
                except Exception as e:  # noqa: BLE001 - only the "since" date
                    log.warning("cannot read %s: %s", au.STATE, e)
            owners = ip_owner.cached_owners(session_key, ips, log)
        rx = ip_owner.cloud_regex(conf.get("cloud_providers"))
        srx = ip_owner.cloud_regex(conf.get("shared_ip_providers"))
        protected = protected_networks(conf)
        for r in results:
            ip = (r.get(field) or "").strip()
            if ip:
                lines, ok, cloud, unblock = find_ip(ip, entries, own, registry, dismissed, states, owners.get(ip),
                                                    lambda o: ip_owner.short_class(o, rx, srx), protected, conf,
                                                    au.CLOUD_DAYS)
                r["find_lines"], r["find_blockable"], r["find_cloud"] = JOIN.join(lines), ok, cloud
                r["find_unblockable"] = "yes" if unblock else "no"
                r["find_unblock_policy"] = ",".join(unblock) or "-"
            elif (r.get(tfield) or "").strip():
                r["find_lines"] = JOIN.join(find_text(r[tfield], entries, own, reg_docs, dis_docs))
                r["find_blockable"], r["find_cloud"], r["find_unblockable"], r["find_unblock_policy"] = "-", "-", "-", "-"
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        log.error("impervafind failed: %s", e)
        si.generateErrorResults("impervafind: %s" % e)


if __name__ == "__main__":
    main()
