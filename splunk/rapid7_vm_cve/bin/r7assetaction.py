#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""| r7assetaction action=request|list|done|cancel [hosts=...] [issue=...] [note=...] [id=ACT-...] [request_id=...]

Asset management requests (1.1.6): "Request fix in Rapid7" records which assets the
Rapid7 team must fix (for example move to the site matching the CMDB environment).
The app never changes Rapid7 sites or the CMDB itself. Delete / tag with a second
approver are added in 1.1.7.
"""
from __future__ import absolute_import

import json
import random
import string
import sys

import r7_lib as L
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

ACTIONS = "r7_asset_actions"


def new_id():
    return "ACT-%s-%s" % (L.utcnow().strftime("%Y%m%d%H%M%S"),
                          "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(3)))


@Configuration(type="reporting")
class R7AssetAction(GeneratingCommand):
    action = Option(require=False, default="list")
    hosts = Option(require=False)
    issue = Option(require=False, default="")
    note = Option(require=False, default="")
    id = Option(require=False)
    request_id = Option(require=False)
    include_done = Option(require=False, default=True, validate=validators.Boolean())
    limit = Option(require=False, default=200, validate=validators.Integer(1, 5000))

    @L.safe
    def generate(self):
        svc = L.command_service(self)
        kv = L.kv(svc, ACTIONS)
        user = L.command_user(self)
        now = L.iso(L.utcnow())
        act = (self.action or "list").lower()

        if act == "list":
            for d in kv.query(sort="requested_at:-1", limit=int(self.limit)):
                if not self.include_done and d.get("status") in ("Done", "Cancelled"):
                    continue
                yield self._row(d)
            return

        if act == "request":
            hosts = L.split_csv(self.hosts)
            if not hosts:
                raise ValueError("Pick at least one asset (hosts=)")
            if len(hosts) > 500:
                raise ValueError("At most 500 assets per request")
            if self.request_id:
                dup = kv.query(query=json.dumps({"request_id": self.request_id}))
                if dup:
                    yield dict(self._row(dup[0]), message="Already recorded (same request_id)")
                    return
            doc = {"_key": new_id(), "action": "Request fix in Rapid7", "hosts": hosts, "issue": self.issue or "",
                   "note": self.note or "", "status": "Open", "requested_by": user, "requested_at": now,
                   "request_id": self.request_id or "", "done_by": "", "done_at": "", "result": ""}
            doc["id"] = doc["_key"]
            kv.batch_save(doc)
            yield dict(self._row(doc), message="Fix request recorded for the Rapid7 team")
            return

        if act in ("done", "cancel"):
            if not self.id:
                raise ValueError("id= is required")
            d = kv.query_by_id(self.id)
            if not d:
                raise ValueError("Request %s not found" % self.id)
            if d.get("status") in ("Done", "Cancelled"):
                yield dict(self._row(d), message="Already %s" % d.get("status").lower())
                return
            if act == "cancel" and d.get("requested_by") != user:
                raise PermissionError("Only the requester (%s) can cancel this request" % d.get("requested_by"))
            d.update({"status": "Done" if act == "done" else "Cancelled", "done_by": user, "done_at": now,
                      "result": self.note or d.get("result", "")})
            kv.batch_save(L.clean_doc(d))
            yield dict(self._row(d), message="Marked %s" % d["status"].lower())
            return

        raise ValueError("action= must be request, list, done or cancel")

    @staticmethod
    def _row(d):
        hosts = d.get("hosts") or []
        return {"id": d.get("id") or d.get("_key"), "action": d.get("action"), "assets": len(hosts),
                "hosts": ", ".join(hosts[:20]) + (" …" if len(hosts) > 20 else ""), "issue": d.get("issue"),
                "note": d.get("note"), "status": d.get("status"), "requested_by": d.get("requested_by"),
                "requested_at": d.get("requested_at"), "done_by": d.get("done_by"), "done_at": d.get("done_at"),
                "result": d.get("result")}


if __name__ == "__main__":
    dispatch(R7AssetAction, sys.argv, sys.stdin, sys.stdout, __name__)
