"""
Auto unblock (V2): which IP rules of the WAF policies to unblock, and when.

An IP rule (IP or CIDR with action BLOCK in an IP setting of a WAF policy) is unblocked when the
IP has sent no request for N days:
    cloud provider IP (imperva.conf cloud_providers)       cloud_days    (default 7)
    shared IP, e.g. mobile carrier NAT (shared_ip_providers) cloud_days   (default 7)
    any other IP                                           default_days  (default 60)
"Request" = an Imperva event "Blocked IP" / act REQ_BLOCKED_ACL from the IP, collected every hour
by the saved search "Imperva V2 - Last attack of blocked IPs (hourly)" into KV imperva_blocked_seen.

The countdown starts at the latest of:
    the last request seen from the IP (or from any IP of the CIDR)
    the block date (KV imperva_block_registry, IPs blocked from Splunk)
    the first time Auto unblock saw the rule (= the day V2 was installed for rules already there)
    [auto_unblock] start_time (optional)

Per rule (KV imperva_auto_unblock): rule = default | keep (never) | <days>.
Scope: own policies (imperva.conf policy_ids) are always handled; scope = all adds every other
ENABLED policy (their IDs must be in IMPERVA_POLICY_IDS on SOAR). Range rules ("a-b") and
non-BLOCK rules (ALLOW, exceptions) are never touched.

Pure functions (no Splunk imports) so the decisions can be unit-tested.
"""

import ipaddress

STATE = "imperva_auto_unblock"       # per rule: first_listed, rule; document "settings"
SEEN = "imperva_blocked_seen"        # per source IP: last_seen, hits_24h
SETTINGS_KEY = "settings"
DAY = 86400
ATTACKING_SECONDS = DAY              # a request in the last 24 h = "attacking now"

DEFAULTS = {"enabled": "on", "default_days": 60, "cloud_days": 7, "scope": "all",
            "max_per_run": 50, "start_time": 0}


def _int(v, default, lo, hi):
    try:
        return max(lo, min(hi, int(float(v))))
    except (TypeError, ValueError):
        return default


def normalize_settings(raw):
    """Typed settings from imperva.conf [auto_unblock] values and / or the KV document."""
    raw = raw or {}
    out = dict(DEFAULTS)
    en = str(raw.get("enabled", out["enabled"])).strip().lower()
    out["enabled"] = "off" if en in ("off", "0", "false", "no", "disabled") else "on"
    out["default_days"] = _int(raw.get("default_days"), DEFAULTS["default_days"], 1, 3650)
    out["cloud_days"] = _int(raw.get("cloud_days"), DEFAULTS["cloud_days"], 1, 3650)
    out["scope"] = "own" if str(raw.get("scope", "all")).strip().lower() in ("own", "splunk", "policy_ids") else "all"
    out["max_per_run"] = _int(raw.get("max_per_run"), DEFAULTS["max_per_run"], 1, 500)
    out["start_time"] = _int(raw.get("start_time"), 0, 0, 10 ** 11) if str(raw.get("start_time", "")).strip() else 0
    for k in ("updated_by", "updated_at"):
        if raw.get(k):
            out[k] = raw[k]
    return out


def merge_settings(conf_stanza, kv_doc):
    """imperva.conf [auto_unblock] defaults, overridden by the KV document saved from the page."""
    raw = dict(conf_stanza or {})
    for k, v in (kv_doc or {}).items():
        if not k.startswith("_") and v not in (None, ""):
            raw[k] = v
    return normalize_settings(raw)


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


def plan(now, entries, own_ids, settings, states, seen, registry, owners, short_of, hits=None):
    """
    -> (items, new_states)
      entries   policy IP entries (imperva_lib.policy_ip_entries)
      states    {entry_key: {first_listed, rule, ...}}
      seen      {src_ip: last_seen epoch}
      registry  {(site_id, ip): registry doc with status blocked}
      owners    {first address: AS owner or None}
      short_of  function(owner) -> ("cloud" | "shared", owner) or None (= cloud_days applies)
      hits      {src_ip: requests blocked in the last 24 h} (optional)
    item status: kept | due | attacking | soon | quiet | due_not_managed
    """
    s = settings
    items, new_states = [], []
    for e in candidate_entries(entries, own_ids):
        pid, cidr = e["policy_id"], e["cidr"]
        key = entry_key(pid, cidr)
        st = states.get(key)
        if st is None:
            st = {"_key": key, "policy_id": pid, "cidr": cidr,
                  "first_listed": int(max(now, s.get("start_time") or 0)), "rule": "default"}
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
        managed = e["own"] or s["scope"] == "all"
        item = {"policy_id": pid, "policy_name": e.get("policy_name") or "-", "cidr": cidr,
                "own": e["own"], "managed": managed, "owner": owner or "", "cloud": cloud or "",
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
        days = rule if isinstance(rule, int) else (s["cloud_days"] if short else s["default_days"])
        base = max(last, blocked_at, first, float(s.get("start_time") or 0))
        unblock_on = base + days * DAY
        left = (unblock_on - now) / DAY
        if left <= 0:
            status = "due" if managed else "due_not_managed"
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


def due_items(items, max_per_run):
    """Rules to unblock now: managed and due, oldest first, at most max_per_run."""
    return [i for i in items if i["status"] == "due"][:max(0, int(max_per_run))]


def reason_text(item, now=None):
    """Human-readable reason written to the audit log, e.g.
    'auto unblock: no attack for 90 days (last seen 2026-08-01)'."""
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


def load_settings(session_key, conf=None):
    """Settings in force: imperva.conf [auto_unblock] + the KV document saved from the page."""
    from splunk_helpers import kv_get, load_conf_stanza
    try:
        stanza = load_conf_stanza(session_key, "imperva", "auto_unblock")
    except Exception:  # noqa: BLE001 - defaults
        stanza = {}
    try:
        doc = kv_get(session_key, SETTINGS_KEY, STATE)
    except Exception:  # noqa: BLE001
        doc = None
    return merge_settings(stanza, doc)
