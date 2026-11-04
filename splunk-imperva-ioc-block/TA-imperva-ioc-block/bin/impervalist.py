"""
Splunk generating command: impervalist

Reads the Blacklisted IPs ACL rule LIVE from Imperva Cloud WAF (no Splunk data
involved), one row per (site, ip).

Usage:
    | impervalist
    | impervalist site_id="12345678"

Output fields: _time site_id site_name ip in_waf checked_at  (or status=error + detail)
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import imperva_lib as il         # noqa: E402
from splunk_helpers import get_logger, is_true, load_conf_stanza, load_credential  # noqa: E402


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    _kw, opts = si.getKeywordsAndOptions()
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        api_id, api_key = load_credential(session_key, "imperva_waf")
        client = il.ImpervaClient(api_id, api_key,
                                  base_url=conf.get("api_base_url", il.DEFAULT_BASE_URL),
                                  timeout=int(conf.get("timeout", 30)),
                                  proxy=conf.get("proxy") or None,
                                  verify_ssl=is_true(conf.get("verify_ssl", "true")))
        site_ids = il.parse_ip_list(opts.get("site_id") or conf.get("site_ids", ""))
        now = int(time.time())
        out = []
        for sid in site_ids:
            try:
                domain, ips = client.get_site_acl(sid)
                for ip in ips:
                    out.append({"_time": now, "site_id": sid, "site_name": domain, "ip": ip,
                                "in_waf": "yes", "checked_at": now})
                if not ips:
                    out.append({"_time": now, "site_id": sid, "site_name": domain, "ip": "-",
                                "in_waf": "empty", "checked_at": now})
            except il.ImpervaError as e:
                log.error("impervalist site_id=%s error=\"%s\"", sid, e)
                out.append({"_time": now, "site_id": sid, "site_name": "-", "ip": "-",
                            "in_waf": "error", "detail": str(e), "checked_at": now})
        si.outputResults(out)
    except Exception as e:  # noqa: BLE001
        si.generateErrorResults("impervalist: %s" % e)


if __name__ == "__main__":
    main()
