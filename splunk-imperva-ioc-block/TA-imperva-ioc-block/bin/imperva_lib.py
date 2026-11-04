"""
Pure-Python helpers for blocking / unblocking IP IOCs on Imperva Cloud WAF.

No Splunk imports here, so the logic can be unit-tested outside Splunk.

Imperva Cloud WAF API (v1) endpoints used:
  POST {base}/api/prov/v1/sites/status         -> read current ACL rules of a site
  POST {base}/api/prov/v1/sites/configure/acl  -> set the ACL rule "api.acl.blacklisted_ips"

NOTE: configure/acl REPLACES the whole blacklist, so we always
read -> merge -> write, never write only the new IPs.
"""

import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

BLACKLIST_RULE_ID = "api.acl.blacklisted_ips"
DEFAULT_BASE_URL = "https://my.imperva.com"


class ImpervaError(Exception):
    pass


# --------------------------------------------------------------------------- #
# IP validation / safety guards
# --------------------------------------------------------------------------- #
def parse_ip_list(raw):
    """Split a comma / space / newline separated string into unique tokens (order kept)."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        raw = ",".join(str(x) for x in raw)
    seen, out = set(), []
    for tok in raw.replace("\n", ",").replace(" ", ",").replace(";", ",").split(","):
        tok = tok.strip().strip('"').strip("'")
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _as_network(value):
    """Return an ip_network for an IP or CIDR string, or raise ValueError."""
    return ipaddress.ip_network(value, strict=False)


def validate_ips(candidates, protected_networks=(), max_prefix_v4=24, max_prefix_v6=48):
    """
    Split candidate IPs/CIDRs into (accepted, rejected).

    accepted : list[str]  normalised IP / CIDR strings that are safe to block
    rejected : list[(str, reason)]

    Rules:
      * must parse as IPv4/IPv6 address or CIDR
      * must be a public (global) address - private/loopback/reserved/multicast refused
      * CIDR not wider than /max_prefix_v4 (IPv4) or /max_prefix_v6 (IPv6)
      * must not overlap any protected network (own egress IPs, partners, CDN, ...)
    """
    protected = []
    for p in protected_networks:
        try:
            protected.append(_as_network(p))
        except ValueError:
            continue

    accepted, rejected = [], []
    for c in candidates:
        try:
            net = _as_network(c)
        except ValueError:
            rejected.append((c, "invalid IP/CIDR"))
            continue

        addr = net.network_address
        if not addr.is_global or addr.is_multicast:
            rejected.append((c, "non-public address (private/reserved/loopback/multicast)"))
            continue

        limit = max_prefix_v4 if net.version == 4 else max_prefix_v6
        if net.prefixlen < limit:
            rejected.append((c, "CIDR wider than /%d not allowed" % limit))
            continue

        hit = next((p for p in protected if p.version == net.version and p.overlaps(net)), None)
        if hit is not None:
            rejected.append((c, "overlaps protected network %s" % hit))
            continue

        norm = str(net.network_address) if net.num_addresses == 1 else str(net)
        accepted.append(norm)
    return accepted, rejected


def merge_blacklist(current, to_add=(), to_remove=()):
    """Return (new_list, added, removed, already_present, not_present)."""
    current = list(dict.fromkeys(current))  # dedupe, keep order
    cur_set = set(current)
    added = [ip for ip in dict.fromkeys(to_add) if ip not in cur_set]
    already = [ip for ip in dict.fromkeys(to_add) if ip in cur_set]
    rm_set = set(to_remove)
    removed = [ip for ip in current if ip in rm_set]
    not_present = [ip for ip in dict.fromkeys(to_remove) if ip not in cur_set]
    new_list = [ip for ip in current if ip not in rm_set] + added
    return new_list, added, removed, already, not_present


# --------------------------------------------------------------------------- #
# Imperva API client
# --------------------------------------------------------------------------- #
class ImpervaClient(object):
    def __init__(self, api_id, api_key, base_url=DEFAULT_BASE_URL, timeout=30,
                 proxy=None, verify_ssl=True):
        if not api_id or not api_key:
            raise ImpervaError("Imperva API ID / API Key not configured")
        self.api_id = api_id
        self.api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def _post(self, path, params):
        url = self.base_url + path
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("x-API-Id", self.api_id)
        req.add_header("x-API-Key", self.api_key)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Accept", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise ImpervaError("HTTP %s from %s: %s" % (e.code, path, e.read()[:300]))
        except urllib.error.URLError as e:
            raise ImpervaError("Cannot reach Imperva API (%s): %s" % (path, e.reason))
        try:
            js = json.loads(body)
        except ValueError:
            raise ImpervaError("Non-JSON response from %s: %s" % (path, body[:300]))
        if str(js.get("res", "")) not in ("0", ""):
            raise ImpervaError("Imperva API error res=%s: %s" % (
                js.get("res"), js.get("res_message") or js.get("debug_info")))
        return js

    def get_blacklist(self, site_id):
        js = self._post("/api/prov/v1/sites/status", {"site_id": site_id, "tests": ""})
        rules = (js.get("security") or {}).get("acls", {}).get("rules", []) or []
        for r in rules:
            if r.get("id") == BLACKLIST_RULE_ID:
                return list(r.get("ips") or [])
        return []

    def set_blacklist(self, site_id, ips):
        return self._post("/api/prov/v1/sites/configure/acl", {
            "site_id": site_id,
            "rule_id": BLACKLIST_RULE_ID,
            "ips": ",".join(ips),
        })


def apply_action(client, site_id, ips, action="block", dry_run=False):
    """
    Read current blacklist of site_id, merge, and write it back.
    Returns a dict summarising what happened.
    """
    current = client.get_blacklist(site_id)
    if action == "block":
        new_list, changed, _, unchanged, _ = merge_blacklist(current, to_add=ips)
    elif action == "unblock":
        new_list, _, changed, _, unchanged = merge_blacklist(current, to_remove=ips)
    else:
        raise ImpervaError("unknown action %r (use block|unblock)" % action)

    if changed and not dry_run:
        client.set_blacklist(site_id, new_list)
    return {
        "site_id": site_id,
        "changed": changed,
        "unchanged": unchanged,
        "blacklist_size_before": len(current),
        "blacklist_size_after": len(new_list) if not dry_run else len(current),
    }
