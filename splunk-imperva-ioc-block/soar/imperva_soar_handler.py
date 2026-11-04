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
# --- BEGIN LIB IMPORT (removed in the generated SOAR file, where the library is inlined) ---
import json
import os

from imperva_lib import (DEFAULT_V2_BASE_URL, ImpervaError, ImpervaPolicyClient,  # noqa: F401
                         list_targets, parse_ip_list, run_action, validate_ips)
# --- END LIB IMPORT ---

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
