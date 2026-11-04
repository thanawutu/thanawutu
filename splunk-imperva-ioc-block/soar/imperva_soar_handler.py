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
  VT_API_KEY                             required for VirusTotal lookups (action vtcheck)
  VT_REQUESTS_PER_MINUTE                 optional, default 4 (public API); raise for premium
  VT_MAX_LOOKUPS                         optional, default 10 per request
  VT_API_BASE                            optional, default https://www.virustotal.com/api/v3
  IMPERVA_PROXY                          optional, proxy used ONLY by this playbook for Imperva
                                         and VirusTotal, e.g. http://10.12.30.100:8080
                                         (no global HTTPS_PROXY needed, so other SOAR apps are not affected)
  VT_PROXY                               optional, VirusTotal-only proxy (default: IMPERVA_PROXY)

Do not edit soar/imperva_ioc_block_global_code.py by hand - it is generated
by soar/build_global_code.py from this file + TA-imperva-ioc-block/bin/imperva_lib.py + vt_lib.py
"""
# --- BEGIN LIB IMPORT (removed in the generated SOAR file, where the library is inlined) ---
import json
import os

from imperva_lib import (DEFAULT_V2_BASE_URL, ImpervaError, ImpervaPolicyClient,  # noqa: F401
                         list_targets, parse_ip_list, run_action, validate_ips)
from vt_lib import VT_BASE, VTClient, lookup_many  # noqa: F401
# --- END LIB IMPORT ---

REQUEST_NAME = "imperva_request"
RESULT_NAME = "imperva_result"


def process_vtcheck(cef, env, vt_client_factory=None):
    """VirusTotal lookups for Splunk's vtcheck command. Returns rows {ip, vt_status, ...}."""
    if vt_client_factory is None:
        key = env.get("VT_API_KEY")
        if not key:
            raise ImpervaError("VT_API_KEY is not set on SOAR")
        client = VTClient(key, base_url=env.get("VT_API_BASE") or VT_BASE,
                          proxy=env.get("VT_PROXY") or env.get("IMPERVA_PROXY") or None)
    else:
        client = vt_client_factory()
    ips = parse_ip_list(cef.get("ips", ""))
    res = lookup_many(client, ips, rpm=int(env.get("VT_REQUESTS_PER_MINUTE") or 4),
                      max_lookups=int(env.get("VT_MAX_LOOKUPS") or 10))
    return [dict(info, ip=ip) for ip, info in res.items()]


def process_request(cef, env=None, client_factory=None, vt_client_factory=None):
    """
    Pure function: request cef dict -> result cef dict
      {request_id, status: ok|error, error, result_json}
    """
    env = os.environ if env is None else env
    rid = cef.get("request_id", "")
    try:
        action = (cef.get("action") or "").strip().lower()
        if action == "vtcheck":  # read-only, no Imperva policy involved
            rows = process_vtcheck(cef, env, vt_client_factory)
            return {"request_id": rid, "status": "ok", "error": "", "result_json": json.dumps(rows)}
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
                                         caid=env.get("IMPERVA_CAID") or None,
                                         proxy=env.get("IMPERVA_PROXY") or None)
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


def request_from_artifact(a):
    """
    Turn an artifact into a request cef, or None if it is not a request.
      * "imperva_request" artifacts created by the Splunk app (impervablock / impervalist / vtcheck)
      * artifacts created by `| sendalert sendtophantom` or the "Send to SOAR" adaptive response
        of a detection rule: cef needs imperva_action (or action) = block|unblock and
        ips / ip / src / src_ip with the address(es)
    """
    cef = dict(a.get("cef") or {})
    if a.get("name") == REQUEST_NAME:
        return cef
    if a.get("name") == RESULT_NAME:
        return None
    act = str(cef.get("imperva_action") or cef.get("action") or "").strip().lower()
    ips = cef.get("ips") or cef.get("ip") or cef.get("src") or cef.get("src_ip") or cef.get("sourceAddress")
    if act not in ("block", "unblock") or not ips:
        return None
    return {
        "request_id": cef.get("request_id") or "artifact-%s" % a.get("id"),
        "action": act,
        "ips": ",".join(ips) if isinstance(ips, list) else str(ips),
        "policy_ids": cef.get("policy_ids", ""),            # empty -> all allowed policies
        "dry_run": cef.get("dry_run", "false"),
        "requested_by": cef.get("requested_by") or "splunk-sendalert",
        "requested_from": "sendalert",
    }


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
        cef = request_from_artifact(a)
        if cef is None or cef.get("request_id") in answered:
            continue
        answered.add(cef.get("request_id"))
        result = process_request(cef)
        result["requested_from"] = cef.get("requested_from", "splunk")
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
