"""
Splunk command: impervarulecheck

Annotates each row with whether its correlation search name is used by the
detection rules (KV store imperva_ioc_rules). Used for the preview on the
"Detection rules" dashboard.

Usage:
    index=notable | stats count BY search_name | impervarulecheck field=search_name

Added fields:
    rule_used    yes | no
    matched_by   "included by *WAF*" / "excluded by ..." / "no include rule"
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402

import ioc_rules as ir           # noqa: E402
from splunk_helpers import kv_list, parse_options  # noqa: E402


def main():
    results, _dummy, settings = si.getOrganizedResults()
    opts = parse_options(sys.argv[1:], ("field",))
    field = opts.get("field", "search_name")
    try:
        rules = ir.real_rules(kv_list(settings.get("sessionKey"), ir.COLLECTION))
        if not rules:  # nothing saved yet -> show what the defaults would do
            rules = ir.real_rules(ir.default_docs("-", 0))
        for r in results:
            used, why = ir.verdict(r.get(field, ""), rules)
            r["rule_used"], r["matched_by"] = ("yes" if used else "no"), why
        si.outputResults(results)
    except Exception as e:  # noqa: BLE001
        si.generateErrorResults("impervarulecheck: %s" % e)


if __name__ == "__main__":
    main()
