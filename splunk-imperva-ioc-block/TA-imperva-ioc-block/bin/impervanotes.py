"""
Splunk generating command: impervanotes

Incident numbers that analysts type into Enterprise Security 8 finding notes
(KV store collection mc_notes of the missioncontrol app), e.g.
    "ITHM 1234567 | Sev 3 | <team> | <title> | <date> [xxxxxx]"
One row per finding:
    finding_guid  uuid of the finding (= source_guid of the event in index=notable)
    notable_id    full id "<uuid>@@notable@@..."
    ithm          "ITHM 1234567" (several, comma separated, if more than one)
    note_time     latest note time

Usage (the dashboard joins it on source_guid):
    | impervanotes
"""

import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunk.Intersplunk as si  # noqa: E402
import splunk.rest as rest       # noqa: E402

from splunk_helpers import get_logger  # noqa: E402

NOTES_PATH = "/servicesNS/nobody/missioncontrol/storage/collections/data/mc_notes"
ITHM_RE = re.compile(r"(?i)ITHM\s*-?\s*(\d+)")


def ithm_numbers(content):
    """URL-encoded note content -> ['ITHM 1234567', ...] (unique, in order)."""
    text = urllib.parse.unquote(content or "")
    out = []
    for n in ITHM_RE.findall(text):
        v = "ITHM " + n
        if v not in out:
            out.append(v)
    return out


def finding_guid(notable_id):
    return (notable_id or "").split("@@", 1)[0].strip().lower()


def notes_to_rows(notes):
    by = {}
    for n in notes:
        guid = finding_guid(n.get("notable_id"))
        nums = ithm_numbers(n.get("content"))
        if not guid or not nums:
            continue
        r = by.setdefault(guid, {"finding_guid": guid, "notable_id": n.get("notable_id"),
                                 "ithm": [], "note_time": 0})
        for x in nums:
            if x not in r["ithm"]:
                r["ithm"].append(x)
        r["note_time"] = max(r["note_time"], float(n.get("create_time") or 0))
    rows = []
    for r in by.values():
        r["ithm"] = ", ".join(r["ithm"])
        rows.append(r)
    return rows


def fetch_notes(session_key):
    fields = "notable_id,content,create_time"
    query = json.dumps({"content": {"$regex": "ITHM"}})
    for params in ({"query": query, "fields": fields, "output_mode": "json"},
                   {"fields": fields, "output_mode": "json"}):     # fallback without the filter
        try:
            _resp, content = rest.simpleRequest(NOTES_PATH + "?" + urllib.parse.urlencode(params),
                                                sessionKey=session_key, method="GET", raiseAllErrors=True)
            return json.loads(content) or []
        except Exception as e:  # noqa: BLE001
            last = e
    raise last


def main():
    _results, _dummy, settings = si.getOrganizedResults()
    log = get_logger("imperva_vtcheck", "imperva_vtcheck.log")
    try:
        rows = notes_to_rows(fetch_notes(settings.get("sessionKey")))
        now = time.time()
        for r in rows:
            r["_time"] = now
        si.outputResults(rows)
    except Exception as e:  # noqa: BLE001
        log.warning("cannot read mc_notes: %s", e)
        si.generateErrorResults("impervanotes: cannot read ES finding notes (mc_notes): %s" % e)


if __name__ == "__main__":
    main()
