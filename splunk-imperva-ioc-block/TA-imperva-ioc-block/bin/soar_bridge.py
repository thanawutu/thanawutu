"""
Splunk -> Splunk SOAR bridge (api_mode = soar).

Used when the Search Head has no route to Imperva but can reach SOAR.
No Splunk imports here (unit-testable).

Flow
  1. POST {soar}/rest/container   with one artifact "imperva_request"
     (label = soar_label, run_automation = true) -> starts the active
     playbook "imperva_ioc_block" on SOAR.
  2. The playbook talks to Imperva and adds an artifact "imperva_result"
     whose cef.result_json holds the rows (same format as direct mode).
  3. Splunk polls GET {soar}/rest/container/{id}/artifacts until that
     result appears (or the playbook run fails / the wait times out).

Auth: header ph-auth-token (SOAR automation user token).
"""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REQUEST_NAME = "imperva_request"
RESULT_NAME = "imperva_result"


class SoarError(Exception):
    pass


class SoarBridge(object):
    def __init__(self, base_url, token, label="imperva_ioc_block", verify_ssl=True, proxy=None,
                 timeout=30, wait_seconds=90, poll_interval=2.0, delete_list_containers=True,
                 ca_file=None, _sleep=time.sleep, _now=time.time):
        if not base_url or not token:
            raise SoarError("SOAR URL / automation token not configured")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.label = label
        self.timeout = timeout
        self.wait_seconds = wait_seconds
        self.poll_interval = poll_interval
        self.delete_list_containers = delete_list_containers
        self._sleep, self._now = _sleep, _now
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        # ca_file: PEM bundle of the internal CA that signed the SOAR certificate
        ctx = ssl.create_default_context(cafile=ca_file or None)
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------------ REST
    def _req(self, method, path, query=None, body=None):
        url = self.base_url + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("ph-auth-token", self.token)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise SoarError("SOAR HTTP %s on %s %s: %s" % (e.code, method, path, e.read()[:300]))
        except urllib.error.URLError as e:
            raise SoarError("Cannot reach SOAR (%s): %s" % (path, e.reason))
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise SoarError("Non-JSON response from SOAR %s: %s" % (path, raw[:300]))

    # ------------------------------------------------------------------ steps
    def submit(self, request):
        """Create the container + request artifact. Returns container id."""
        rid = request["request_id"]
        cef = {k: ("" if v is None else str(v)) for k, v in request.items()}
        ips = request.get("ips", "")
        short = ips if len(ips) <= 60 else ips[:57] + "..."
        body = {
            "name": "Splunk Imperva %s %s" % (request["action"], short or request.get("policy_ids", "")),
            "label": self.label,
            "severity": "low",
            "status": "new",
            "source_data_identifier": rid,
            "description": "Requested from Splunk by %s" % request.get("requested_by", "-"),
            "artifacts": [{
                "name": REQUEST_NAME,
                "label": self.label,
                "severity": "low",
                "source_data_identifier": rid,
                "cef": cef,
                "run_automation": True,
            }],
        }
        js = self._req("POST", "/rest/container", body=body)
        if not js.get("success") or not js.get("id"):
            raise SoarError("SOAR did not create the container: %s" % json.dumps(js)[:300])
        return js["id"]

    def _find_result(self, cid, rid):
        js = self._req("GET", "/rest/container/%s/artifacts" % cid,
                       {"_filter_name": '"%s"' % RESULT_NAME, "page_size": 0})
        for a in js.get("data") or []:
            cef = a.get("cef") or {}
            if cef.get("request_id") == rid:
                return cef
        return None

    def _playbook_failed(self, cid):
        js = self._req("GET", "/rest/playbook_run", {"_filter_container": cid, "page_size": 0})
        for run in js.get("data") or []:
            if str(run.get("status")).lower() == "failed":
                return run.get("message") or "playbook run %s failed" % run.get("id")
        return None

    def wait_result(self, cid, rid, wait_seconds=None):
        wait_seconds = self.wait_seconds if wait_seconds is None else wait_seconds
        deadline = self._now() + wait_seconds
        while True:
            cef = self._find_result(cid, rid)
            if cef is not None:
                if cef.get("status") != "ok":
                    raise SoarError("SOAR playbook error: %s" % (cef.get("error") or "unknown"))
                try:
                    return json.loads(cef.get("result_json") or "[]")
                except ValueError:
                    raise SoarError("SOAR result is not valid JSON")
            failed = self._playbook_failed(cid)
            if failed:
                raise SoarError("SOAR playbook failed on container %s: %s" % (cid, failed))
            if self._now() >= deadline:
                raise SoarError("No result from SOAR within %ss (container %s). Is the playbook "
                                "active for label '%s'?" % (wait_seconds, cid, self.label))
            self._sleep(self.poll_interval)

    def delete_container(self, cid):
        try:
            self._req("DELETE", "/rest/container/%s" % cid)
        except SoarError:
            pass  # cleanup is best effort

    # ------------------------------------------------------------------ API
    def call(self, action, ips=(), policy_ids=(), dry_run=False, meta=None, requested_by="-",
             wait_seconds=None, protected=(), extra=None):
        # `meta` (threat actor / incident no. / comment / reason) is deliberately NOT sent:
        # the WAF has no field for it. It is kept only in Splunk (KV store registry,
        # audit log, dashboard). SOAR receives just what it needs to act.
        req = {
            "request_id": uuid.uuid4().hex,
            "action": action,
            "ips": ",".join(ips),
            "policy_ids": ",".join(policy_ids),
            "dry_run": "true" if dry_run else "false",
            "requested_by": requested_by,
            "requested_from": "splunk",
        }
        for k, v in (extra or {}).items():
            req[k] = str(v)
        if protected:
            # Splunk's protected_networks (CIDRs only). SOAR unions it with its own
            # IMPERVA_PROTECTED_NETWORKS, so Splunk can only make SOAR stricter, never looser.
            req["protected_networks"] = ",".join(protected)
        cid = self.submit(req)
        try:
            rows = self.wait_result(cid, req["request_id"], wait_seconds)
        finally:
            # list / vtcheck are read-only and frequent: do not keep their containers
            if action in ("list", "vtcheck", "policy_entries") and self.delete_list_containers:
                self.delete_container(cid)
        for r in rows:
            r.setdefault("soar_container", cid)
        return rows

    def execute(self, action, ips, policy_ids, dry_run, meta, requested_by, protected=()):
        return self.call(action, ips, policy_ids, dry_run, meta, requested_by, protected=protected)

    def list_blocked(self, policy_ids):
        return self.call("list", (), policy_ids)

    def policy_entries(self):
        """IP rules of every WAF policy in the account (read by SOAR)."""
        return self.call("policy_entries")

    def vt_lookup(self, ips, wait_seconds=None, max_lookups=None, max_wait=None, retry_wait=None):
        """VirusTotal lookups done by SOAR. Returns rows {ip, vt_status, vt_malicious, ...}.
        max_lookups / max_wait / retry_wait override SOAR's VT_* env (rate-limit retry)."""
        extra = dict((k, v) for k, v in (("vt_max_lookups", max_lookups), ("vt_max_wait", max_wait),
                                         ("vt_retry_wait", retry_wait)) if v is not None)
        return self.call("vtcheck", ips, wait_seconds=wait_seconds, extra=extra)
