"""
Splunk custom search command: impervablock

Usage (SPL):
    | makeresults | impervablock action=block ip="198.51.100.7,192.0.2.0/24" reason="IOC TI-1234"
    | inputlookup malicious_ip_iocs.csv | impervablock action=block field=ip
    | makeresults | impervablock action=unblock ip="198.51.100.7"
    ... | impervablock action=block field=src_ip dry_run=true

Options:
    action   block | unblock                       (default: block)
    ip       comma separated IPs / CIDRs           (optional if field= is used)
    field    take IPs from this field of input rows (default: none)
    site_id  override site id(s) from imperva.conf (comma separated)
    dry_run  true -> read & compute only, do not write to Imperva
    reason   free text, written to the audit log

Credentials are read from Splunk storage/passwords (realm = imperva_waf,
username = <Imperva API ID>, password = <Imperva API Key>).
"""

import datetime
import json
import logging
import logging.handlers
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402
import splunk.rest as rest       # noqa: E402

import imperva_lib as il         # noqa: E402

APP = "TA-imperva-ioc-block"
REALM = "imperva_waf"
CONF = "imperva"
TRUE = ("1", "t", "true", "y", "yes")


def get_logger():
    log = logging.getLogger("imperva_ioc_block")
    if not log.handlers:
        home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
        path = os.path.join(home, "var", "log", "splunk", "imperva_ioc_block.log")
        h = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
    return log


def rest_json(path, session_key):
    sep = "&" if "?" in path else "?"
    resp, content = rest.simpleRequest(path + sep + "output_mode=json&count=0",
                                       sessionKey=session_key, method="GET", raiseAllErrors=True)
    return json.loads(content)


def load_settings(session_key):
    js = rest_json("/servicesNS/nobody/%s/configs/conf-%s/settings" % (APP, CONF), session_key)
    return js["entry"][0]["content"]


def load_credentials(session_key):
    js = rest_json("/servicesNS/nobody/%s/storage/passwords" % APP, session_key)
    for e in js.get("entry", []):
        c = e.get("content", {})
        if c.get("realm") == REALM:
            return c.get("username"), c.get("clear_password")
    raise il.ImpervaError("No credential with realm '%s' in storage/passwords "
                          "(user needs list_storage_passwords capability)" % REALM)


def main():
    results, _dummy, settings = si.getOrganizedResults()
    _kw, opts = si.getKeywordsAndOptions()
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger()

    action = opts.get("action", "block").lower()
    dry_run = str(opts.get("dry_run", "false")).lower() in TRUE
    reason = opts.get("reason", "")

    if not session_key:
        si.generateErrorResults("No session key - set passauth = true in commands.conf")
        return

    try:
        conf = load_settings(session_key)
        api_id, api_key = load_credentials(session_key)

        # ---- collect candidate IPs ------------------------------------------------
        candidates = il.parse_ip_list(opts.get("ip"))
        field = opts.get("field")
        if field:
            for r in results:
                candidates += il.parse_ip_list(r.get(field))
        candidates = il.parse_ip_list(candidates)  # dedupe
        if not candidates:
            raise il.ImpervaError("No IP supplied (use ip=... or field=...)")

        max_ips = int(conf.get("max_ips_per_action", 50))
        if len(candidates) > max_ips:
            raise il.ImpervaError("%d IPs requested, max_ips_per_action is %d"
                                  % (len(candidates), max_ips))

        protected = il.parse_ip_list(conf.get("protected_networks", ""))
        if action == "block":
            accepted, rejected = il.validate_ips(
                candidates, protected,
                max_prefix_v4=int(conf.get("max_cidr_prefix_v4", 24)),
                max_prefix_v6=int(conf.get("max_cidr_prefix_v6", 48)))
        else:  # unblocking is always allowed for anything that parses
            accepted, rejected = il.validate_ips(candidates, (), 0, 0)

        site_ids = il.parse_ip_list(opts.get("site_id") or conf.get("site_ids", ""))
        if not site_ids:
            raise il.ImpervaError("No site_ids configured in imperva.conf [settings]")

        client = il.ImpervaClient(
            api_id, api_key,
            base_url=conf.get("api_base_url", il.DEFAULT_BASE_URL),
            timeout=int(conf.get("timeout", 30)),
            proxy=conf.get("proxy") or None,
            verify_ssl=str(conf.get("verify_ssl", "true")).lower() in TRUE)

        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        out = []
        for ip, why in rejected:
            out.append({"_time": now, "ip": ip, "site_id": "-", "action": action,
                        "status": "rejected", "detail": why, "user": user,
                        "dry_run": dry_run, "reason": reason})

        for sid in site_ids:
            if not accepted:
                break
            try:
                res = il.apply_action(client, sid, accepted, action=action, dry_run=dry_run)
                ok = "blocked" if action == "block" else "unblocked"
                for ip in res["changed"]:
                    out.append({"_time": now, "ip": ip, "site_id": sid, "action": action,
                                "status": ("would_be_" + ok) if dry_run else ok,
                                "detail": "blacklist size %d -> %d" % (
                                    res["blacklist_size_before"], res["blacklist_size_after"]),
                                "user": user, "dry_run": dry_run, "reason": reason})
                for ip in res["unchanged"]:
                    out.append({"_time": now, "ip": ip, "site_id": sid, "action": action,
                                "status": "no_change",
                                "detail": "already blocked" if action == "block" else "not in blacklist",
                                "user": user, "dry_run": dry_run, "reason": reason})
            except il.ImpervaError as e:
                for ip in accepted:
                    out.append({"_time": now, "ip": ip, "site_id": sid, "action": action,
                                "status": "error", "detail": str(e), "user": user,
                                "dry_run": dry_run, "reason": reason})

        for row in out:
            log.info("user=%s action=%s ip=%s site_id=%s status=%s dry_run=%s reason=\"%s\" detail=\"%s\"",
                     row["user"], row["action"], row["ip"], row["site_id"], row["status"],
                     row["dry_run"], reason.replace('"', "'"), row["detail"].replace('"', "'"))
        si.outputResults(out)

    except Exception as e:  # noqa: BLE001 - surface any failure to the dashboard
        log.error("user=%s action=%s status=failed error=\"%s\"", user, action, e)
        si.generateErrorResults("impervablock: %s" % e)


if __name__ == "__main__":
    main()
