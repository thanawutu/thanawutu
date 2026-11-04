# GENERATED FILE - do not edit. Source: imperva_lib.py + imperva_soar_handler.py
# Rebuild with: python3 soar/build_global_code.py
# Paste ALL of this into the SOAR playbook > Global Custom Code.

# ==========================================================================
# imperva_lib
# ==========================================================================
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

    def get_site_acl(self, site_id):
        """Return (site_domain, [blacklisted ips]) read live from Imperva."""
        js = self._post("/api/prov/v1/sites/status", {"site_id": site_id, "tests": ""})
        rules = (js.get("security") or {}).get("acls", {}).get("rules", []) or []
        ips = []
        for r in rules:
            if r.get("id") == BLACKLIST_RULE_ID:
                ips = list(r.get("ips") or [])
                break
        return js.get("domain") or "-", ips

    def get_blacklist(self, site_id):
        return self.get_site_acl(site_id)[1]

    def set_blacklist(self, site_id, ips):
        return self._post("/api/prov/v1/sites/configure/acl", {
            "site_id": site_id,
            "rule_id": BLACKLIST_RULE_ID,
            "ips": ",".join(ips),
        })


# --------------------------------------------------------------------------- #
# Imperva Policies API v2 client (ACL policy, IP BLOCK setting)
#   GET  {base}/policies/v2/policies/{id}?extended=true  -> {"value": {...}, "isError": false}
#   PUT  {base}/policies/v2/policies/{id}                -> full policy body (overwrite)
# Same interface as ImpervaClient, but the target id is a POLICY id, so one
# write updates every site/account the policy is applied to.
# --------------------------------------------------------------------------- #
DEFAULT_V2_BASE_URL = "https://api.imperva.com"
_SUBMIT_KEYS = ("name", "description", "enabled", "accountId", "policyType",
                "policySettings", "defaultPolicyConfig")


def find_ip_block_setting(policy):
    for st in policy.get("policySettings") or []:
        if st.get("policySettingType") == "IP" and st.get("settingsAction") == "BLOCK":
            return st
    return None


def policy_with_blocked_ips(policy, ips):
    """
    Return the PUT body for `policy` with its IP/BLOCK setting set to `ips`.
    Every other setting, exception and field is kept as it is.
    """
    if policy.get("policyType") != "ACL":
        raise ImpervaError("policy %s is type %r, not ACL - refusing to modify"
                           % (policy.get("id"), policy.get("policyType")))
    body = {k: policy[k] for k in _SUBMIT_KEYS if k in policy}
    settings = [dict(st) for st in (policy.get("policySettings") or [])]
    idx = next((i for i, st in enumerate(settings)
                if st.get("policySettingType") == "IP" and st.get("settingsAction") == "BLOCK"), None)
    if idx is None:
        if ips:
            settings.append({"settingsAction": "BLOCK", "policySettingType": "IP",
                             "data": {"ips": list(ips)}})
    elif ips:
        st = settings[idx]
        st["data"] = dict(st.get("data") or {}, ips=list(ips))
    else:
        # an IP setting with an empty list is not valid - drop it
        settings.pop(idx)
    body["policySettings"] = settings
    body.setdefault("defaultPolicyConfig", [])
    return body


class ImpervaPolicyClient(object):
    def __init__(self, api_id, api_key, base_url=DEFAULT_V2_BASE_URL, timeout=30,
                 proxy=None, verify_ssl=True, caid=None):
        if not api_id or not api_key:
            raise ImpervaError("Imperva API ID / API Key not configured")
        self.api_id, self.api_key = api_id, api_key
        self.base_url = (base_url or DEFAULT_V2_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.caid = caid
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def _request(self, method, path, query=None, body=None):
        q = dict(query or {})
        if self.caid:
            q["caid"] = self.caid
        url = self.base_url + path + ("?" + urllib.parse.urlencode(q) if q else "")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("x-API-Id", self.api_id)
        req.add_header("x-API-Key", self.api_key)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise ImpervaError("HTTP %s %s %s: %s" % (e.code, method, path, e.read()[:300]))
        except urllib.error.URLError as e:
            raise ImpervaError("Cannot reach Imperva API (%s): %s" % (path, e.reason))
        try:
            js = json.loads(raw)
        except ValueError:
            raise ImpervaError("Non-JSON response from %s: %s" % (path, raw[:300]))
        if js.get("isError"):
            raise ImpervaError("Imperva API error on %s: %s" % (path, raw[:300]))
        return js

    def get_policy(self, policy_id):
        pol = self._request("GET", "/policies/v2/policies/%s" % policy_id,
                            {"extended": "true"}).get("value") or {}
        self.last_enabled = pol.get("enabled", True)
        return pol

    def is_enabled(self, policy_id):
        return bool(self.get_policy(policy_id).get("enabled", True))

    def get_site_acl(self, policy_id):
        """Return (policy_name, [blocked ips]) read live from Imperva."""
        pol = self.get_policy(policy_id)
        st = find_ip_block_setting(pol)
        ips = list(((st or {}).get("data") or {}).get("ips") or [])
        name = pol.get("name") or "-"
        if not pol.get("enabled", True):
            name += " [POLICY DISABLED]"
        return name, ips

    def get_blacklist(self, policy_id):
        return self.get_site_acl(policy_id)[1]

    def set_blacklist(self, policy_id, ips):
        pol = self.get_policy(policy_id)
        return self._request("PUT", "/policies/v2/policies/%s" % policy_id,
                             body=policy_with_blocked_ips(pol, ips))

    def modify_ips(self, policy_id, add=(), remove=()):
        """
        Re-read the policy immediately before the PUT and apply only our delta,
        so IPs that someone else added/removed in the console in the meantime
        are not lost (minimises the read-modify-write race).
        """
        pol = self.get_policy(policy_id)
        st = find_ip_block_setting(pol)
        live = list(((st or {}).get("data") or {}).get("ips") or [])
        new_list, _, _, _, _ = merge_blacklist(live, to_add=add, to_remove=remove)
        return self._request("PUT", "/policies/v2/policies/%s" % policy_id,
                             body=policy_with_blocked_ips(pol, new_list))


def make_client(conf, api_id, api_key, override_ids=None):
    """
    Build the client and target ids from imperva.conf [settings].
      api_mode = v2_policy (default) -> ImpervaPolicyClient, targets = policy_ids
      api_mode = v1_site             -> ImpervaClient,       targets = site_ids
    """
    def truthy(v):
        return str(v).strip().lower() in ("1", "t", "true", "y", "yes")

    mode = (conf.get("api_mode") or "v2_policy").strip().lower()
    common = dict(timeout=int(conf.get("timeout", 30)), proxy=conf.get("proxy") or None,
                  verify_ssl=truthy(conf.get("verify_ssl", "true")))
    if mode == "v1_site":
        client = ImpervaClient(api_id, api_key,
                               base_url=conf.get("api_base_url") or DEFAULT_BASE_URL, **common)
        ids = parse_ip_list(override_ids or conf.get("site_ids", ""))
        what = "site_ids"
    elif mode == "v2_policy":
        client = ImpervaPolicyClient(api_id, api_key,
                                     base_url=conf.get("api_v2_base_url") or DEFAULT_V2_BASE_URL,
                                     caid=conf.get("caid") or None, **common)
        ids = parse_ip_list(override_ids or conf.get("policy_ids", ""))
        what = "policy_ids"
    else:
        raise ImpervaError("api_mode must be v2_policy or v1_site, not %r" % mode)
    if not ids:
        raise ImpervaError("No %s configured in imperva.conf [settings]" % what)
    return client, ids, mode


def apply_action(client, site_id, ips, action="block", dry_run=False, verify=True):
    """
    Read current blacklist of site_id, merge, write it back and (optionally)
    re-read it to VERIFY the change really landed on the WAF.

    Returns dict:
      changed      IPs added (block) / removed (unblock) and verified
      unchanged    already blocked (block) / not in list (unblock)
      not_applied  written but NOT found as expected on re-read (verification failed)
    """
    current = client.get_blacklist(site_id)
    if action == "block":
        new_list, changed, _, unchanged, _ = merge_blacklist(current, to_add=ips)
    elif action == "unblock":
        new_list, _, changed, _, unchanged = merge_blacklist(current, to_remove=ips)
    else:
        raise ImpervaError("unknown action %r (use block|unblock)" % action)

    not_applied = []
    after = current
    if changed and not dry_run:
        if hasattr(client, "modify_ips"):  # v2 policy: delta on a fresh read
            client.modify_ips(site_id, add=changed if action == "block" else (),
                              remove=changed if action == "unblock" else ())
        else:
            client.set_blacklist(site_id, new_list)
        after = new_list
        if verify:
            after = client.get_blacklist(site_id)
            live = set(after)
            if action == "block":
                not_applied = [ip for ip in changed if ip not in live]
            else:
                not_applied = [ip for ip in changed if ip in live]
            changed = [ip for ip in changed if ip not in not_applied]
    return {
        "site_id": site_id,
        "changed": changed,
        "unchanged": unchanged,
        "not_applied": not_applied,
        "blacklist_size_before": len(current),
        "blacklist_size_after": len(after) if not dry_run else len(current),
    }


def build_registry_doc(existing, key, site_id, ip, action, status, user, now, meta):
    """
    Decide what to store in the KV store registry for one (site, ip) result.
    meta: dict(threat_actor, incident_no, comment, reason)
    Returns the full document to save, or None (nothing to store).
    """
    meta = dict((k, (v or "").strip()) for k, v in (meta or {}).items())
    if action == "block" and status == "blocked":
        doc = {"_key": key, "site_id": site_id, "ip": ip, "status": "blocked",
               "blocked_at": now, "blocked_by": user, "source": "splunk"}
        doc.update(meta)
        return doc
    if action == "block" and status == "no_change":
        if existing and existing.get("status") == "blocked":
            return None  # keep the original description / time
        doc = {"_key": key, "site_id": site_id, "ip": ip, "status": "blocked",
               "blocked_at": now, "blocked_by": user,
               "source": "already in WAF - registered from splunk"}
        doc.update(meta)
        return doc
    if action == "unblock" and status == "unblocked":
        doc = dict(existing or {"_key": key, "site_id": site_id, "ip": ip})
        doc.pop("_user", None)
        doc.update({"_key": key, "status": "unblocked", "unblocked_at": now,
                    "unblocked_by": user, "unblock_reason": meta.get("reason", ""),
                    "unblock_incident_no": meta.get("incident_no", "")})
        return doc
    return None


# --------------------------------------------------------------------------- #
# High-level operations shared by the Splunk commands (direct mode) and the
# SOAR playbook (soar mode). They return plain row dicts.
# --------------------------------------------------------------------------- #
def run_action(client, targets, ips, action="block", dry_run=False):
    """Block/unblock already-validated `ips` on every target. Returns rows:
    {ip, site_id, status, verified_in_waf, detail}"""
    rows = []
    ok = "blocked" if action == "block" else "unblocked"

    def row(ip, sid, status, detail, verified="-"):
        rows.append({"ip": ip, "site_id": sid, "status": status,
                     "verified_in_waf": verified, "detail": detail})

    for sid in targets:
        if not ips:
            break
        try:
            res = apply_action(client, sid, ips, action=action, dry_run=dry_run)
            size = "blacklist size %d -> %d" % (res["blacklist_size_before"], res["blacklist_size_after"])
            if getattr(client, "last_enabled", True) is False:
                size += (" | WARNING: policy %s is DISABLED in Imperva - "
                         "the block has NO effect until it is enabled" % sid)
            for ip in res["changed"]:
                if dry_run:
                    row(ip, sid, "would_be_" + ok, size)
                else:
                    row(ip, sid, ok, size + " (re-read from WAF)", "yes" if action == "block" else "removed")
            for ip in res["not_applied"]:
                row(ip, sid, "error", "write accepted but NOT confirmed on re-read from WAF", "no")
            for ip in res["unchanged"]:
                row(ip, sid, "no_change",
                    "already blocked" if action == "block" else "not in blacklist",
                    "yes" if action == "block" else "-")
        except ImpervaError as e:
            for ip in ips:
                row(ip, sid, "error", str(e), "unknown")
    return rows


def list_targets(client, targets):
    """Read the live block list of every target. Returns rows:
    {site_id, site_name, ip, in_waf[, detail]}"""
    rows = []
    for sid in targets:
        try:
            name, ips = client.get_site_acl(sid)
            for ip in ips:
                rows.append({"site_id": sid, "site_name": name, "ip": ip, "in_waf": "yes"})
            if not ips:
                rows.append({"site_id": sid, "site_name": name, "ip": "-", "in_waf": "empty"})
        except ImpervaError as e:
            rows.append({"site_id": sid, "site_name": "-", "ip": "-", "in_waf": "error", "detail": str(e)})
    return rows


# ==========================================================================
# SOAR handler
# ==========================================================================
"""
Splunk SOAR side of api_mode = soar.

The SOAR playbook "imperva_ioc_block" (label imperva_ioc_block) runs this
code. It reads the "imperva_request" artifact that Splunk created, performs
the action on Imperva (Policies API v2) and adds an "imperva_result" artifact
that Splunk polls for.

SOAR re-validates every request itself (allowed policy IDs, public IPs,
protected networks, max IPs) - it never trusts Splunk blindly.

Settings come from SOAR environment variables
(Administration > Administration Settings > Environment Variables; mark keys secret):
  IMPERVA_API_ID, IMPERVA_API_KEY        required
  IMPERVA_POLICY_IDS                     required, allow-list e.g. "2169031"
  IMPERVA_PROTECTED_NETWORKS             optional, comma separated IP/CIDR
  IMPERVA_MAX_IPS                        optional, default 50
  IMPERVA_API_BASE                       optional, default https://api.imperva.com
  IMPERVA_CAID                           optional, sub-account id
  HTTPS_PROXY                            optional, honoured automatically

Do not edit soar/imperva_ioc_block_global_code.py by hand - it is generated
by soar/build_global_code.py from this file + TA-imperva-ioc-block/bin/imperva_lib.py
"""
import json
import os

REQUEST_NAME = "imperva_request"
RESULT_NAME = "imperva_result"


def process_request(cef, env=None, client_factory=None):
    """
    Pure function: request cef dict -> result cef dict
      {request_id, status: ok|error, error, result_json}
    """
    env = os.environ if env is None else env
    rid = cef.get("request_id", "")
    try:
        action = (cef.get("action") or "").strip().lower()
        if action not in ("block", "unblock", "list"):
            raise ImpervaError("unknown action %r" % action)

        allowed = parse_ip_list(env.get("IMPERVA_POLICY_IDS", ""))
        if not allowed:
            raise ImpervaError("IMPERVA_POLICY_IDS is not set on SOAR")
        requested = parse_ip_list(cef.get("policy_ids", "")) or allowed
        denied = [p for p in requested if p not in allowed]
        if denied:
            raise ImpervaError("policy ids %s are not allowed on SOAR (IMPERVA_POLICY_IDS)" % denied)

        if client_factory is None:
            client = ImpervaPolicyClient(env.get("IMPERVA_API_ID"), env.get("IMPERVA_API_KEY"),
                                         base_url=env.get("IMPERVA_API_BASE") or DEFAULT_V2_BASE_URL,
                                         caid=env.get("IMPERVA_CAID") or None)
        else:
            client = client_factory()

        if action == "list":
            rows = list_targets(client, requested)
        else:
            ips = parse_ip_list(cef.get("ips", ""))
            if not ips:
                raise ImpervaError("no IPs in request")
            max_ips = int(env.get("IMPERVA_MAX_IPS") or 50)
            if len(ips) > max_ips:
                raise ImpervaError("%d IPs requested, SOAR limit is %d" % (len(ips), max_ips))
            if action == "block":
                accepted, rejected = validate_ips(
                    ips, parse_ip_list(env.get("IMPERVA_PROTECTED_NETWORKS", "")))
            else:
                accepted, rejected = validate_ips(ips, (), 0, 0)
            rows = [{"ip": ip, "site_id": "-", "status": "rejected", "verified_in_waf": "-",
                     "detail": "SOAR: " + why} for ip, why in rejected]
            rows += run_action(client, requested, accepted, action=action,
                               dry_run=str(cef.get("dry_run")).lower() == "true")
        return {"request_id": rid, "status": "ok", "error": "", "result_json": json.dumps(rows)}
    except Exception as e:  # noqa: BLE001 - always answer Splunk
        return {"request_id": rid, "status": "error", "error": str(e), "result_json": "[]"}


def imperva_soar_handle(container, phantom):
    """
    Entry point called from the playbook's custom code block:
        imperva_soar_handle(container, phantom)
    Processes every request artifact in the container that has no result yet.
    """
    url = phantom.build_phantom_rest_url("container", container["id"], "artifacts")
    resp = phantom.requests.get(url, params={"page_size": 0}, verify=False)
    artifacts = resp.json().get("data", [])
    answered = {(a.get("cef") or {}).get("request_id") for a in artifacts if a.get("name") == RESULT_NAME}
    handled = 0
    for a in artifacts:
        cef = a.get("cef") or {}
        if a.get("name") != REQUEST_NAME or cef.get("request_id") in answered:
            continue
        result = process_request(cef)
        phantom.debug("imperva %s request %s -> %s %s" % (
            cef.get("action"), cef.get("request_id"), result["status"], result["error"]))
        phantom.add_artifact(container=container, raw_data={}, cef_data=result,
                             label=container.get("label") or "imperva_ioc_block",
                             name=RESULT_NAME, severity="low",
                             identifier=cef.get("request_id", "") + "-result",
                             artifact_type="imperva_result", run_automation=False)
        handled += 1
    if handled:
        phantom.set_status(container=container, status="closed")
    return handled
