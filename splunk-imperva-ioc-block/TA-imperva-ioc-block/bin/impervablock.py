"""
Splunk custom search command: impervablock

Usage (SPL):
    | makeresults | impervablock action=block ip="198.51.100.7,192.0.2.0/24" reason="IOC TI-1234"
    | inputlookup malicious_ip_iocs.csv | impervablock action=block field=ip
    | makeresults | impervablock action=unblock ip="198.51.100.7" incident_no="ITHM 1234567" description="false positive"
    ... | impervablock action=block field=src_ip dry_run=true

Options:
    action   block | unblock                       (default: block)
    ip       comma separated IPs / CIDRs           (optional if field= is used)
    field    take IPs from this field of input rows (default: none)
    site_id  override site id(s) from imperva.conf (comma separated)
    dry_run  true -> read & compute only, do not write to Imperva
    incident_no   Ticket / Incident no.             (stored in KV store registry)
    description   free text description             (stored in KV store registry as comment;
                                                     for unblock also as the unblock reason)
    reason, threat_actor, comment                   (older options, still accepted)

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
import ip_owner                  # noqa: E402
from backend import get_backend   # noqa: E402
from soar_bridge import SoarError  # noqa: E402
from splunk_helpers import (get_logger, is_true, kv_get,  # noqa: E402
                            kv_upsert, load_conf_stanza, load_credential, parse_options,
                            protected_networks, registry_key)


def clean(v):
    return (v or "").replace('"', "'").replace("\n", " ").strip()


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("action", "ip", "field", "site_id", "policy_id", "dry_run",
                                        "reason", "threat_actor", "incident_no", "comment",
                                        "description"))
    session_key = settings.get("sessionKey")
    user = settings.get("owner", "unknown")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")

    action = opts.get("action", "block").lower()
    dry_run = is_true(opts.get("dry_run", "false"))
    meta = {
        "reason": clean(opts.get("reason")),
        "threat_actor": clean(opts.get("threat_actor")),
        "incident_no": clean(opts.get("incident_no")),
        "comment": clean(opts.get("description")) or clean(opts.get("comment")),
    }
    if not meta["reason"]:
        meta["reason"] = meta["comment"]

    if not session_key:
        si.generateErrorResults("No session key - set passauth = true in commands.conf")
        return

    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")

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

        # never block: imperva.conf protected_networks (also sent to SOAR, which adds its own list)
        protected = protected_networks(conf)
        if action == "block":
            accepted, rejected = il.validate_ips(
                candidates, protected,
                max_prefix_v4=int(conf.get("max_cidr_prefix_v4", 24)),
                max_prefix_v6=int(conf.get("max_cidr_prefix_v6", 48)))
            # never block cloud provider IPs (imperva.conf cloud_providers): Not block only.
            # Owner unknown (no VirusTotal data) -> blocked anyway, with a warning (fail-open)
            vconf = load_conf_stanza(session_key, "imperva", "virustotal") if conf.get("cloud_providers") else {}
            accepted, cloud_rejected, owner_unknown = ip_owner.split_cloud(session_key, conf, vconf, accepted, log)
            rejected += cloud_rejected
        else:  # unblocking is always allowed for anything that parses
            accepted, rejected = il.validate_ips(candidates, (), 0, 0)
            owner_unknown = set()

        # direct (v2_policy / v1_site) or via Splunk SOAR (soar) - same rows either way
        backend = get_backend(conf, load_credential, session_key,
                              override_ids=opts.get("policy_id") or opts.get("site_id"))

        now = int(time.time())
        out = []

        def row(ip, sid, status, detail, verified="-", extra=None):
            r = {"_time": now, "ip": ip, "site_id": sid, "action": action, "status": status,
                 "verified_in_waf": verified, "detail": detail, "user": user, "dry_run": dry_run,
                 "backend": backend.mode}
            r.update(meta)
            r.update(extra or {})
            out.append(r)

        for ip, why in rejected:
            row(ip, "-", "rejected", why)

        if accepted:
            try:
                for r in backend.execute(action, accepted, dry_run, meta, user, protected=protected):
                    extra = {"soar_container": r["soar_container"]} if "soar_container" in r else None
                    detail = r.get("detail", "")
                    if r["ip"] in owner_unknown:
                        detail = (detail + " | " if detail else "") + ip_owner.UNKNOWN_WARNING
                    row(r["ip"], r["site_id"], r["status"], detail,
                        r.get("verified_in_waf", "-"), extra)
            except (il.ImpervaError, SoarError) as e:
                for ip in accepted:
                    row(ip, "-", "error", str(e), "unknown")

        # ---- registry (description / threat actor / incident) in KV store ------------
        # The WAF-policy cache is NOT dropped here: IPs blocked from Splunk are filtered by the
        # registry, and "Imperva - WAF policy cache refresh" re-reads every policy every 5 min,
        # so the dashboards never have to wait for SOAR after a block.
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
            log.info('backend=%s soar_container=%s '
                     'user=%s action=%s ip=%s site_id=%s status=%s verified_in_waf=%s dry_run=%s '
                     'threat_actor="%s" incident_no="%s" comment="%s" reason="%s" detail="%s"',
                     r.get("backend", "-"), r.get("soar_container", "-"),
                     r["user"], r["action"], r["ip"], r["site_id"], r["status"], r["verified_in_waf"],
                     r["dry_run"], meta["threat_actor"], meta["incident_no"], meta["comment"],
                     meta["reason"], clean(r["detail"]))
        si.outputResults(out)

    except Exception as e:  # noqa: BLE001 - surface any failure to the dashboard
        log.error("user=%s action=%s status=failed error=\"%s\"", user, action, e)
        si.generateErrorResults("impervablock: %s" % e)


if __name__ == "__main__":
    main()
