#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7cvewatch action=add|list|update|close|reopen|delete cve=... announced=... software=... ranges=..."""
from __future__ import absolute_import

import json
import re
import sys

import r7_lib as L
import r7_query as Q
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration(type="reporting")
class R7CveWatch(GeneratingCommand):
    action = Option(require=False, default="list")
    cve = Option(require=False)
    announced = Option(require=False)
    software = Option(require=False)
    ranges = Option(require=False)
    notes = Option(require=False, default="")
    with_counts = Option(require=False, default=False, validate=validators.Boolean())
    include_closed = Option(require=False, default=False, validate=validators.Boolean())
    autoclose = Option(require=False, default=False, validate=validators.Boolean())

    @L.safe
    def generate(self):
        svc = L.command_service(self)
        settings = L.load_settings(svc)
        data = L.kv(svc, L.SAVED_CVES)
        action = (self.action or "list").lower()
        user = L.command_user(self)
        now = L.iso(L.utcnow())

        if action == "list":
            for row in self._list(svc, settings, data):
                yield row
            return

        cve = (self.cve or "").strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            raise ValueError("cve= must look like CVE-2026-12345")
        existing = self._get(data, cve)

        if action in ("add", "update"):
            if action == "add" and existing:
                raise ValueError("%s is already saved; use action=update" % cve)
            if action == "update" and not existing:
                raise ValueError("%s is not saved; use action=add" % cve)
            doc = dict(existing or {})
            doc.update({"_key": cve, "cve": cve})
            for f in ("announced", "software", "ranges", "notes"):
                v = getattr(self, f)
                if v is not None and v != "":
                    doc[f] = v
            if doc.get("ranges"):
                L.parse_ranges(doc["ranges"])  # raises on bad input
            if doc.get("announced") and not L.parse_date(doc["announced"]):
                raise ValueError("announced= must be a date like 2026-11-18 or 2026-11-18 14:00")
            if action == "add":
                doc.update({"status": "Open", "saved_by": user, "saved_at": now, "closed_at": ""})
            doc["updated_by"], doc["updated_at"] = user, now
            data.batch_save(L.clean_doc(doc))
            yield self._out(doc, "saved")
        elif action in ("close", "reopen"):
            if not existing:
                raise ValueError("%s is not saved" % cve)
            existing["status"] = "Closed" if action == "close" else "Open"
            existing["closed_at"] = now if action == "close" else ""
            existing["updated_by"], existing["updated_at"] = user, now
            data.batch_save(L.clean_doc(existing))
            yield self._out(existing, action + "d" if action == "close" else "reopened")
        elif action == "delete":
            if existing:
                data.delete_by_id(cve)
            yield {"_time": 0, "cve": cve, "result": "deleted" if existing else "not found"}
        else:
            raise ValueError("action= must be add, list, update, close, reopen or delete")

    @staticmethod
    def _get(data, cve):
        try:
            return data.query_by_id(cve)
        except Exception:
            return None

    @staticmethod
    def _out(doc, result):
        row = dict((k, v) for k, v in doc.items() if not k.startswith("_") or k == "_key")
        row.pop("_key", None)
        row["result"] = result
        return row

    def _list(self, svc, settings, data):
        docs = data.query(sort="saved_at:-1")
        fixed = self._fixed_counts(svc) if self.with_counts else {}
        for d in docs:
            if not self.include_closed and d.get("status") == "Closed":
                continue
            row = self._out(d, "listed")
            if self.with_counts:
                rows, info = Q.build_rows(svc, settings, {
                    "cve": d.get("cve"), "software": d.get("software"), "ranges": d.get("ranges"),
                    "announced": d.get("announced")})
                open_rows = [r for r in rows if r["verdict"] != "Not affected" and r["verdict"] != "Likely not affected"]
                row.update({
                    "rapid7_check": ("Yes (%s)" % info["check_added"][:10]) if info["has_check"] else "Not yet",
                    "affected_now": len(open_rows),
                    "prod_dc": sum(1 for r in open_rows if r["env_label"] == "Prod · DC"),
                    "prod_dr": sum(1 for r in open_rows if r["env_label"] == "Prod · DR"),
                    "non_prod": sum(1 for r in open_rows if r["env_group"] == "Non-prod"),
                    "confirmed_affected": sum(1 for r in open_rows if r["verdict"] == "Affected"),
                    "unknown": sum(1 for r in open_rows if r["verdict"] == "Unknown"),
                    "fixed_since_saved": fixed.get(d.get("cve"), 0),
                    "severity": info.get("severity", ""), "cvss_v3": info.get("cvss_v3", ""),
                    "published": (info.get("published") or "")[:10], "added": (info.get("check_added") or "")[:10],
                    "platform": info.get("platform", ""),
                    "os_list": "; ".join(sorted(set(r["os"] for r in open_rows if r.get("os")))[:5]),
                })
                if self.autoclose and d.get("status") == "Open" and not open_rows and info["has_check"]:
                    d["status"], d["closed_at"] = "Closed", L.iso(L.utcnow())
                    d["updated_by"] = "autoclose"
                    data.batch_save(L.clean_doc(d))
                    row["status"], row["result"] = "Closed", "autoclosed"
            yield row

    @staticmethod
    def _fixed_counts(svc):
        counts = {}
        try:
            for j in L.kv(svc, L.SCAN_JOBS).query(query=json.dumps({"status": "Finished"})):
                cve = j.get("cve")
                if not cve:
                    continue
                s = counts.setdefault(cve, set())
                for r in j.get("results") or []:
                    if r.get("cve_result") == "CVE fixed":
                        s.add(r.get("asset_id"))
        except Exception:
            pass
        return dict((k, len(v)) for k, v in counts.items())


if __name__ == "__main__":
    dispatch(R7CveWatch, sys.argv, sys.stdin, sys.stdout, __name__)
