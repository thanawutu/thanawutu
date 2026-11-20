"""
Detection rules: which ES correlation searches (search_name) feed the Block pages.

Stored in the KV store collection imperva_ioc_rules, one document per rule:
    pattern   correlation search name, '*' = wildcard (case-insensitive)
    mode      include | exclude
    enabled   1 | 0
    note, updated_by, updated_at

A search_name is used when it matches at least one enabled include rule and
no enabled exclude rule. No Splunk imports here (unit-testable).
"""

import hashlib
import re

COLLECTION = "imperva_ioc_rules"
MODES = ("include", "exclude")
SEED_KEY = "__seeded__"          # marker doc: defaults are written only once
NO_RULE = "__no_rule__"          # search term that matches nothing

DEFAULT_RULES = (
    ("*WAF*", "include", "all WAF correlation searches"),
    ("*WAF Monitor Error code 404*", "exclude", "monitoring only, not an attack"),
)


def clean_pattern(p):
    # quotes / newlines would break the generated search terms
    return re.sub(r'["\r\n\t]', "", p or "").strip()


def rule_key(pattern, mode):
    return hashlib.sha1(("%s|%s" % (mode, pattern.lower())).encode("utf-8")).hexdigest()[:16]


def is_enabled(rule):
    return str(rule.get("enabled", "1")).strip().lower() in ("1", "true", "yes", "on")


def wildcard_match(pattern, name):
    rx = "^" + ".*".join(re.escape(x) for x in (pattern or "").split("*")) + "$"
    return re.match(rx, name or "", re.I | re.S) is not None


def real_rules(docs):
    """Drop the seed marker and anything that is not a valid rule."""
    return [d for d in docs if d.get("_key") != SEED_KEY and d.get("mode") in MODES and d.get("pattern")]


def verdict(name, rules):
    """-> (used: bool, matched_by: str)"""
    inc = [r for r in rules if is_enabled(r) and r["mode"] == "include" and wildcard_match(r["pattern"], name)]
    exc = [r for r in rules if is_enabled(r) and r["mode"] == "exclude" and wildcard_match(r["pattern"], name)]
    if exc:
        return False, "excluded by " + exc[0]["pattern"]
    if inc:
        return True, "included by " + inc[0]["pattern"]
    return False, "no include rule"


def search_terms(rules, mode):
    """Enabled patterns of one mode, for `index=notable [..include..] NOT [..exclude..]`.
    Never empty: an empty subsearch would turn into a broken search."""
    pats = sorted(set(r["pattern"] for r in rules if is_enabled(r) and r["mode"] == mode))
    return pats or [NO_RULE]


def default_docs(user, now):
    docs = [{"_key": rule_key(p, m), "pattern": p, "mode": m, "enabled": "1", "note": n,
             "updated_by": user, "updated_at": now} for p, m, n in DEFAULT_RULES]
    docs.append({"_key": SEED_KEY, "pattern": "", "mode": "meta", "enabled": "0",
                 "note": "defaults written", "updated_by": user, "updated_at": now})
    return docs
