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
from backend import get_backend   # noqa: E402
from soar_bridge import SoarError  # noqa: E402
from splunk_helpers import get_logger, load_conf_stanza, load_credential, parse_options  # noqa: E402


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("site_id", "policy_id"))
    session_key = settings.get("sessionKey")
    log = get_logger("imperva_ioc_block", "imperva_ioc_block.log")
    try:
        conf = load_conf_stanza(session_key, "imperva", "settings")
        backend = get_backend(conf, load_credential, session_key,
                              override_ids=opts.get("policy_id") or opts.get("site_id"))
        now = int(time.time())
        out = []
        try:
            rows = backend.list_blocked()
        except (il.ImpervaError, SoarError) as e:
            rows = [{"site_id": t, "site_name": "-", "ip": "-", "in_waf": "error", "detail": str(e)}
                    for t in backend.targets]
        for r in rows:
            if r.get("in_waf") == "error":
                log.error("impervalist site_id=%s error=\"%s\"", r.get("site_id"), r.get("detail"))
            r.update({"_time": now, "checked_at": now, "backend": backend.mode})
            out.append(r)
        si.outputResults(out)
    except Exception as e:  # noqa: BLE001
        si.generateErrorResults("impervalist: %s" % e)


if __name__ == "__main__":
    main()
