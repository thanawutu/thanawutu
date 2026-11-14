"""
Auto unblock (V2): which IP rules of the WAF policies to unblock, and when.

An IP rule (IP or CIDR with action BLOCK in an IP setting of a WAF policy) is unblocked when the
IP has sent no request for N days (fixed values, no settings):
    cloud provider IP (imperva.conf cloud_providers)          7 days
    shared IP, e.g. mobile carrier NAT (shared_ip_providers)  7 days
    any other IP                                              60 days
Always on (unblocks, no report-only mode), every enabled policy, no daily limit: due rules are unblocked
in rounds of 10 per policy, and the next round starts only when the WAF confirmed the previous one.
"Request" = an Imperva event "Blocked IP" / act REQ_BLOCKED_ACL from the IP, collected every hour
by the saved search "Imperva V2 - Last attack of blocked IPs (hourly)" into KV imperva_blocked_seen.

The countdown starts at the latest of:
    the last request seen from the IP (or from any IP of the CIDR)
    the block date (KV imperva_block_registry, IPs blocked from Splunk)
    the first time Auto unblock saw the rule (= the day V2 was installed for rules already there)

Per rule (KV imperva_auto_unblock): rule = default | keep (never) | <days>.
Policies: every ENABLED policy, plus the own policy (imperva.conf policy_ids) even when disabled.
Their IDs must be in IMPERVA_POLICY_IDS on SOAR. Range rules ("a-b") and non-BLOCK rules
(ALLOW, exceptions) are never touched.

Pure functions (no Splunk imports) so the decisions can be unit-tested.
"""

import ipaddress

STATE = "imperva_auto_unblock"       # per rule: first_listed, rule
SEEN = "imperva_blocked_seen"        # per source IP: last_seen, hits_24h
OLD_SETTINGS_KEY = "settings"        # settings document of an earlier V2 build: ignored
DAY = 86400
ATTACKING_SECONDS = DAY              # a request in the last 24 h = "attacking now"

DEFAULT_DAYS = 60                    # other IPs
CLOUD_DAYS = 7                       # cloud provider / shared IPs
BATCH_SIZE = 10                      # IP rules per round (one SOAR request, re-read from the WAF)
RUN_TIME_BUDGET = 3 * 3600 + 1800    # no new round after 3.5 h (saved search max time 4 h): rest next run


def entry_key(policy_id, cidr):
    return "e_%s_%s" % (policy_id, str(cidr).replace("/", "_").replace(":", "-"))


def rule_of(value):
    """'default' | 'keep' | int days."""
    v = str(value or "default").strip().lower()
    if v in ("keep", "never", "no"):
        return "keep"
    if v in ("", "default", "-"):
        return "default"
    try:
        d = int(float(v))
    except ValueError:
        raise ValueError("rule must be default, keep or a number of days")
    if d < 1 or d > 3650:
        raise ValueError("days must be 1 - 3650")
    return d


def nets(cidr):
    try:
        return [ipaddress.ip_network(cidr.strip(), strict=False)]
    except ValueError:
        return []


def first_address(cidr):
    n = nets(cidr)
    return str(n[0].network_address) if n else None


def candidate_entries(entries, own_ids):
    """BLOCK IP settings of enabled policies (own policies even when disabled), IP / CIDR only."""
    own = set(str(x) for x in own_ids)
    out, seen = [], set()
    for e in entries or []:
        pid = str(e.get("policy_id"))
        if e.get("kind") != "setting" or not str(e.get("action", "")).upper().startswith("BLOCK"):
            continue
        if not (e.get("enabled", True) or pid in own):
            continue
        cidr = str(e.get("cidr", "")).strip()
        if not cidr or "-" in cidr or not nets(cidr):
            continue
        k = (pid, cidr)
        if k in seen:
            continue
        seen.add(k)
        out.append(dict(e, policy_id=pid, cidr=cidr, own=pid in own))
    return out


def last_seen_for(cidr, seen):
    """Latest request time of the IP, or of any IP inside the CIDR. seen = {src: epoch}."""
    n = nets(cidr)
    if not n:
        return 0
    net = n[0]
    if net.num_addresses == 1:
        return float(seen.get(str(net.network_address), 0) or 0)
    best = 0.0
    for src, t in seen.items():
        try:
            a = ipaddress.ip_address(src)
        except ValueError:
            continue
        if a.version == net.version and a in net and float(t or 0) > best:
            best = float(t)
    return best


def hits_for(cidr, hits):
    """Requests blocked in the last 24 h from the IP, or from all IPs inside the CIDR. hits = {src: n}."""
    n = nets(cidr)
    if not n or not hits:
        return 0
    net = n[0]
    if net.num_addresses == 1:
        return int(float(hits.get(str(net.network_address), 0) or 0))
    total = 0
    for src, c in hits.items():
        try:
            a = ipaddress.ip_address(src)
        except ValueError:
            continue
        if a.version == net.version and a in net:
            total += int(float(c or 0))
    return total


def plan(now, entries, own_ids, states, seen, registry, owners, short_of, hits=None):
    """
    -> (items, new_states)
      entries   policy IP entries (imperva_lib.policy_ip_entries)
      states    {entry_key: {first_listed, rule, ...}}
      seen      {src_ip: last_seen epoch}
      registry  {(site_id, ip): registry doc with status blocked}
      owners    {first address: AS owner or None}
      short_of  function(owner) -> ("cloud" | "shared", owner) or None (= CLOUD_DAYS applies)
      hits      {src_ip: requests blocked in the last 24 h} (optional)
    item status: kept | due | attacking | soon | quiet
    """
    items, new_states = [], []
    for e in candidate_entries(entries, own_ids):
        pid, cidr = e["policy_id"], e["cidr"]
        key = entry_key(pid, cidr)
        st = states.get(key)
        if st is None:
            st = {"_key": key, "policy_id": pid, "cidr": cidr, "first_listed": int(now), "rule": "default"}
            new_states.append(st)
        first = float(st.get("first_listed") or now)
        try:
            rule = rule_of(st.get("rule"))
        except ValueError:
            rule = "default"
        reg = registry.get((pid, cidr)) or {}
        blocked_at = float(reg.get("blocked_at") or 0)
        last = last_seen_for(cidr, seen)
        owner = owners.get(first_address(cidr))
        short = short_of(owner) if owner else None
        cloud = short[1] if short and short[0] == "cloud" else None
        shared = short[1] if short and short[0] == "shared" else None
        item = {"policy_id": pid, "policy_name": e.get("policy_name") or "-", "cidr": cidr,
                "own": e["own"], "owner": owner or "", "cloud": cloud or "",
                "shared": shared or "", "short": short[0] if short else "",
                "blocked_at": blocked_at, "ticket": reg.get("incident_no") or "-",
                "description": reg.get("comment") or "-", "blocked_by": reg.get("blocked_by") or "-",
                "first_listed": first, "last_seen": last, "rule": rule,
                "attacks_24h": hits_for(cidr, hits or {}),
                "rule_reason": st.get("rule_reason") or "", "key": key}
        if rule == "keep":
            item.update(days=None, base=None, unblock_on=None, left_days=None, status="kept")
            items.append(item)
            continue
        days = rule if isinstance(rule, int) else (CLOUD_DAYS if short else DEFAULT_DAYS)
        base = max(last, blocked_at, first)
        unblock_on = base + days * DAY
        left = (unblock_on - now) / DAY
        if left <= 0:
            status = "due"
        elif last and now - last < ATTACKING_SECONDS:
            status = "attacking"
        elif left <= min(7, days * 0.3):
            status = "soon"
        else:
            status = "quiet"
        item.update(days=days, base=base, unblock_on=unblock_on, left_days=left, status=status)
        items.append(item)
    items.sort(key=lambda x: (x["unblock_on"] is None, x["unblock_on"] or 0, x["policy_id"], x["cidr"]))
    return items, new_states


def due_items(items):
    """Rules to unblock now: every due rule, oldest first (no limit: they go in rounds of BATCH_SIZE)."""
    return [i for i in items if i["status"] == "due"]


def reason_text(item, now=None):
    """Human-readable reason written to the audit log, e.g.
    'auto unblock: no attack for 60 days (last attack 2026-08-01)'."""
    import time as _t
    if item.get("last_seen"):
        seen = "last attack " + _t.strftime("%Y-%m-%d", _t.localtime(item["last_seen"]))
    elif item.get("blocked_at"):
        seen = "no attack seen since the block"
    else:
        seen = "no attack seen since Auto unblock started watching this rule"
    who = ("cloud provider IP (%s), " % item["cloud"] if item.get("cloud") else
           "shared IP (%s), " % item["shared"] if item.get("shared") else "")
    return "auto unblock: %sno attack for %s days (%s)" % (who, item.get("days"), seen)

