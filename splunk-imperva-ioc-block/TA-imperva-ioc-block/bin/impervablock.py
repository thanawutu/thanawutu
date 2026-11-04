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
    reason        free text, written to the audit log and registry
    threat_actor  threat actor name                 (stored in KV store registry)
    incident_no   incident / ticket number          (stored in KV store registry)
    comment       any other comment                 (stored in KV store registry)

After writing, the blacklist is re-read from Imperva to VERIFY the change
(column verified_in_waf). Successful blocks are recorded in the KV store
collection imperva_block_registry with date/time, user and description.

Credentials are read from Splunk storage/passwords (realm = imperva_waf,
username = <Imperva API ID>, password = <Imperva API Key>).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
from splunk_helpers import (get_logger, is_true, kv_get, kv_upsert,  # noqa: E402
                            load_conf_stanza, load_credential, registry_key)

REALM = "imperva_waf"


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def main():
    results, _dummy, settings = si.getOrganizedResults()
    _kw, opts = si.getKeywordsAndOptions()
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")

    action = opts.get("action", "block").lower()
    dry_run = is_true(opts.get("dry_run", "false"))
    meta = {
        "reason": clean(opts.get("reason")),
        "threat_actor": clean(opts.get("threat_actor")),
        "incident_no": clean(opts.get("incident_no")),
        "comment": clean(opts.get("comment")),
    }

    if not session_key:
        si.generateErrorResults("No session key - set passauth = true in commands.conf")
        return

    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        api_id, api_key = load_credential(session_key, REALM)

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
            verify_ssl=is_true(conf.get("verify_ssl", "true")))

        now = int(time.time())
        out = []

        def row(ip, sid, status, detail, verified="-"):
            r = {"_time": now, "ip": ip, "site_id": sid, "action": action, "status": status,
                 "verified_in_waf": verified, "detail": detail, "user": user, "dry_run": dry_run}
            r.update(meta)
            out.append(r)

        for ip, why in rejected:
            row(ip, "-", "rejected", why)

        ok = "blocked" if action == "block" else "unblocked"
        for sid in site_ids:
            if not accepted:
                break
            try:
                res = il.apply_action(client, sid, accepted, action=action, dry_run=dry_run)
                size = "blacklist size %d -> %d" % (res["blacklist_size_before"], res["blacklist_size_after"])
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
            except il.ImpervaError as e:
                for ip in accepted:
                    row(ip, sid, "error", str(e), "unknown")

        # ---- registry (description / threat actor / incident) in KV store ------------
        if not dry_run:
            docs = []
            for r in out:
                if r["status"] not in ("blocked", "unblocked", "no_change"):
                    continue
                key = registry_key(r["site_id"], r["ip"])
                existing = kv_get(session_key, key) if r["status"] != "blocked" else None
                doc = il.build_registry_doc(existing, key, r["site_id"], r["ip"], action,
                                            r["status"], user, now, meta)
                if doc:
                    docs.append(doc)
            try:
                kv_upsert(session_key, docs)
            except Exception as e:  # noqa: BLE001 - the WAF change already happened
                log.error("registry write failed: %s", e)
                for r in out:
                    r["detail"] += " | WARNING: description not saved to registry: %s" % e

        for r in out:
            log.info('user=%s action=%s ip=%s site_id=%s status=%s verified_in_waf=%s dry_run=%s '
                     'threat_actor="%s" incident_no="%s" comment="%s" reason="%s" detail="%s"',
                     r["user"], r["action"], r["ip"], r["site_id"], r["status"], r["verified_in_waf"],
                     r["dry_run"], meta["threat_actor"], meta["incident_no"], meta["comment"],
                     meta["reason"], clean(r["detail"]))
        si.outputResults(out)

    except Exception as e:  # noqa: BLE001 - surface any failure to the dashboard
        log.error("user=%s action=%s status=failed error=\"%s\"", user, action, e)
        si.generateErrorResults("impervablock: %s" % e)


if __name__ == "__main__":
    main()
