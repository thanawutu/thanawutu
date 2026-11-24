# -*- coding: utf-8 -*-
"""Shared code for the Rapid7 VM CVE Response app.

Pure logic (version ranges, verdicts, before/after comparison) has no Splunk
dependency so it can be unit tested. The Rapid7 client uses only the standard
library. Splunk helpers use the vendored splunklib in bin/lib.
"""
from __future__ import absolute_import

import base64
import datetime
import json
import os
import re
import ssl
import sys
import time

try:  # Python 3
    from urllib import request as urlrequest
    from urllib import parse as urlparse
    from urllib import error as urlerror
except ImportError:  # pragma: no cover
    raise

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(BIN_DIR, "lib")
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

APP = "rapid7_vm_cve"
CONF = "rapid7_cve"
REALM = "rapid7_vm_cve"

SAVED_CVES = "r7_saved_cves"
SCAN_JOBS = "r7_scan_jobs"

ENV_LABELS = ["Prod · DC", "Prod · DR", "Non-prod · UAT", "Non-prod · SIT", "Non-prod · DEV"]
ACTIVE_STATUS = "WORKING_ACTIVE"
BLOCKED_STATUSES = ("INACTIVE", "DECOMMISSION")

TERMINAL_SCAN_STATES = ("finished", "stopped", "error", "aborted")


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------

def parse_date(value):
    """Return a UTC datetime for ISO strings ('2026-11-18', '2026-11-18T14:00:00Z',
    '2026-11-18 14:00', '2026-11-18T14:00:00.123Z') or epoch numbers. None if empty."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.datetime.utcfromtimestamp(float(value))
    s = str(value).strip()
    if re.match(r"^\d+(\.\d+)?$", s):
        return datetime.datetime.utcfromtimestamp(float(s))
    s = s.replace("Z", "").replace("T", " ")
    s = re.sub(r"[+-]\d{2}:?\d{2}$", "", s)
    s = s.split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def utcnow():
    return datetime.datetime.utcnow()


# --------------------------------------------------------------------------
# Versions and ranges
# --------------------------------------------------------------------------

_DISTRO_RE = re.compile(r"(\.el\d|el\d_|\.module\+el|ubuntu|deb\d|\+deb|\.amzn|\.fc\d|\.sles|~)", re.I)


def upstream_version(version):
    """'2.4.62-1.el9' -> '2.4.62', '8.7p1' -> '8.7p1', 'v1.2' -> '1.2'."""
    if version is None:
        return ""
    s = str(version).strip()
    m = re.search(r"\d+(?:\.\d+)*(?:[a-z]\d+)?", s, re.I)
    return m.group(0) if m else ""


def version_parts(version):
    """Numeric segments for comparison: '8.7p1' -> [8, 7, 1]; '2.4.10' -> [2, 4, 10]."""
    return [int(x) for x in re.findall(r"\d+", upstream_version(version))]


def compare_versions(a, b):
    x, y = version_parts(a), version_parts(b)
    for i in range(max(len(x), len(y))):
        p = x[i] if i < len(x) else 0
        q = y[i] if i < len(y) else 0
        if p != q:
            return -1 if p < q else 1
    return 0


_DISTROS = ("red hat", "redhat", "rhel", "canonical", "ubuntu", "debian", "oracle linux", "centos", "rocky",
            "alma", "suse", "amazon linux", "fedora")


def is_distro_build(version, vendor=""):
    """True for distro-packaged builds, where fixes are often back-ported under an older
    version number. vendor may also carry the server's OS name."""
    s = "%s %s" % (version or "", vendor or "")
    low = s.lower()
    return bool(_DISTRO_RE.search(s)) or any(d in low for d in _DISTROS)


_OPS = {
    "<": lambda c: c < 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    ">=": lambda c: c >= 0,
    "=": lambda c: c == 0,
    "==": lambda c: c == 0,
}

_COND_RE = re.compile(r"(<=|>=|==|<|>|=)\s*(\d[\w.\-]*)")


def parse_ranges(ranges):
    """Parse '8.1 < 8.1.34 ; 8.2 < 8.2.29', '< 2.4.63', '>= 7.2.0 <= 7.2.10',
    '7.2.0 - 7.2.10' or '9.0.*' into a list of (branch, [(op, version), ...])."""
    out = []
    if not ranges:
        return out
    for part in re.split(r"[;\n|]+", str(ranges)):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(\d[\d.]*)\s*-\s*(\d[\d.]*)$", part)
        if m:
            out.append(("", [(">=", m.group(1)), ("<=", m.group(2))]))
            continue
        m = re.match(r"^(\d[\d.]*)\.\*$", part)
        if m:
            out.append((m.group(1), []))
            continue
        conds = _COND_RE.findall(part)
        if not conds:
            raise ValueError("Cannot read version range: %r" % part)
        first = _COND_RE.search(part)
        prefix = part[:first.start()].strip()
        branch = prefix if re.match(r"^\d+(\.\d+)*$", prefix) else ""
        out.append((branch, conds))
    return out


def in_range(version, ranges):
    """True when the version is inside any of the ranges."""
    v = upstream_version(version)
    if not v:
        return False
    for branch, conds in parse_ranges(ranges):
        if branch and not (v == branch or v.startswith(branch + ".")):
            continue
        if all(_OPS[op](compare_versions(v, ref)) for op, ref in conds):
            return True
    return False


def range_status(version, ranges, vendor=""):
    """'In range', 'Check advisory' (distro build in range), 'Not in range' or 'Unknown'."""
    if not version or not upstream_version(version):
        return "Unknown"
    hit = in_range(version, ranges)
    if hit and is_distro_build(version, vendor):
        return "Check advisory"
    return "In range" if hit else "Not in range"


def software_matches(pattern, vendor, product):
    """Case-insensitive wildcard match of 'Apache*HTTP*' or plain 'php' against 'vendor product'."""
    if not pattern:
        return False
    text = ("%s %s" % (vendor or "", product or "")).lower()
    pat = pattern.strip().lower()
    if "*" not in pat:
        return pat in text
    rx = "^.*" + ".*".join(re.escape(p) for p in pat.split("*")) + ".*$"
    return re.match(rx, text) is not None


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------

def freshness(last_scan, announced, stale_days=7):
    """Return (label, days_before_announcement). Labels: Fresh, OK, Stale, None."""
    ls, an = parse_date(last_scan), parse_date(announced)
    if ls is None:
        return "None", None
    if an is None:
        return "OK", None
    days = (an - ls).total_seconds() / 86400.0
    if days <= 0:
        return "Fresh", round(days, 1)
    if days <= stale_days:
        return "OK", round(days, 1)
    return "Stale", round(days, 1)


def verdict(row, announced, check_added, has_check, stale_days=7):
    """Decide the verdict for one server.

    row keys: version, vendor, ranges, last_scan, credentialed (bool), r7_vulnerable (bool).
    Returns dict: freshness, days_before, range_status, r7_result, verdict, action.
    """
    fresh, days = freshness(row.get("last_scan"), announced, stale_days)
    rs = range_status(row.get("version"), row.get("ranges"), row.get("vendor")) if row.get("ranges") else "Unknown"
    ls = parse_date(row.get("last_scan"))
    ca = parse_date(check_added)
    credentialed = bool(row.get("credentialed"))
    vulnerable = row.get("r7_vulnerable")  # True / False / None (finding data not collected)

    if not has_check:
        r7 = "No Rapid7 check yet"
    elif vulnerable is None:
        r7 = "Finding data not collected"
    elif vulnerable:
        r7 = "Vulnerable"
    elif ls is not None and ca is not None and ls.date() > ca.date() and credentialed:
        r7 = "Not vulnerable"
    elif ls is not None and ca is not None and ls.date() == ca.date():
        r7 = "Not run: scanned same day check was added"
    else:
        r7 = "Not run: scan before check added"

    if r7 == "Vulnerable":
        v, action = "Affected", "Patch"
    elif r7 == "Not vulnerable":
        v, action = "Not affected", "None"
    elif not credentialed or fresh == "None":
        v, action = "Unknown", "Fix scan credentials or install the Insight Agent, then rescan"
    elif fresh == "Stale":
        v, action = "Unknown", "Rescan: version data is older than the announcement window"
    elif rs == "In range":
        v, action = "Likely affected", "Rescan to confirm" if has_check else "Rescan once Rapid7 adds the check"
    elif rs == "Check advisory":
        v, action = "Likely affected", "Distro build: check the vendor advisory, then rescan"
    elif rs == "Not in range":
        v, action = "Likely not affected", "Rescan to confirm" if has_check else "None until Rapid7 adds the check"
    else:
        v, action = "Unknown", "Rescan"
    return {"freshness": fresh, "days_before": days, "range_status": rs, "r7_result": r7,
            "verdict": v, "action": action}


def needs_rescan(verdict_value):
    return verdict_value not in ("Not affected",)


def compare_result(before, after, has_check):
    """Before/after comparison after a rescan.

    before/after keys: installed (bool|None), version, r7_vulnerable (bool|None)
    after extra keys: assessed (bool, the asset was assessed by this job's scan),
                      credentialed (bool)
    Returns dict: installed, version_change, cve_before, cve_after, cve_result.
    """
    b_ver, a_ver = before.get("version") or "", after.get("version") or ""
    assessed = bool(after.get("assessed"))
    cred = bool(after.get("credentialed"))

    if not assessed:
        installed = "Unknown"
        change = "Unknown"
    elif not cred:
        installed = "Unknown"
        change = "Unknown"
    elif after.get("installed"):
        installed = "Yes"
        if not b_ver:
            change = "New"
        else:
            c = compare_versions(a_ver, b_ver)
            change = "No change" if (c == 0 and a_ver == b_ver) else ("Updated" if c >= 0 else "Downgraded")
    else:
        installed = "Removed" if before.get("installed") else "Not installed"
        change = "Removed" if before.get("installed") else "No change"

    def cve_state(v):
        if v is None:
            return "Not checked"
        return "Vulnerable" if v else "Not found"

    cb = cve_state(before.get("r7_vulnerable")) if has_check else "—"
    ca = cve_state(after.get("r7_vulnerable")) if (has_check and assessed) else ("—" if not has_check else "Not checked")

    if not has_check:
        result = "No Rapid7 check yet"
    elif not assessed:
        result = "Not verified"
    elif after.get("r7_vulnerable"):
        result = "Still vulnerable" if before.get("r7_vulnerable") else "Newly found"
    elif not cred:
        result = "Not verified"
    elif before.get("r7_vulnerable"):
        result = "CVE fixed"
    else:
        result = "Not vulnerable"
    return {"installed": installed, "version_change": change, "cve_before": cb, "cve_after": ca,
            "cve_result": result}


def group_by_site(targets):
    """targets: list of dicts with site_id, site_name, ip, hostname. Returns {site_id: {...}}."""
    groups = {}
    for t in targets:
        sid = str(t.get("site_id") or "")
        g = groups.setdefault(sid, {"site_id": sid, "site_name": t.get("site_name") or "", "targets": []})
        g["targets"].append(t)
    return groups


def scan_host(target):
    return target.get("ip") or target.get("hostname")


# --------------------------------------------------------------------------
# Rapid7 InsightVM API client (stdlib only)
# --------------------------------------------------------------------------

class Rapid7Error(Exception):
    def __init__(self, msg, status=None):
        Exception.__init__(self, msg)
        self.status = status


class Rapid7Client(object):
    def __init__(self, base_url, username, password, verify_ssl=True, ca_bundle="",
                 timeout=60, use_system_proxy=False, retries=4, logger=None):
        if not base_url:
            raise Rapid7Error("console_url is not set in rapid7_cve.conf [settings]")
        self.base = base_url.rstrip("/")
        token = base64.b64encode(("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
        self.headers = {"Authorization": "Basic " + token, "Accept": "application/json",
                        "Content-Type": "application/json"}
        if verify_ssl:
            ctx = ssl.create_default_context(cafile=ca_bundle or None)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [urlrequest.HTTPSHandler(context=ctx)]
        if not use_system_proxy:
            handlers.append(urlrequest.ProxyHandler({}))
        self.opener = urlrequest.build_opener(*handlers)
        self.timeout = timeout
        self.retries = retries
        self.log = logger
        self.calls = 0

    def request(self, method, path, params=None, body=None, allow_404=False):
        url = self.base + path
        if params:
            url += ("&" if "?" in url else "?") + urlparse.urlencode(params, doseq=True)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        delay = 2
        for attempt in range(self.retries + 1):
            req = urlrequest.Request(url, data=data, headers=self.headers, method=method)
            try:
                self.calls += 1
                resp = self.opener.open(req, timeout=self.timeout)
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
            except urlerror.HTTPError as e:
                if e.code == 404 and allow_404:
                    return None
                if e.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                detail = ""
                try:
                    detail = e.read().decode("utf-8")[:500]
                except Exception:
                    pass
                raise Rapid7Error("%s %s -> HTTP %s %s" % (method, path, e.code, detail), e.code)
            except (urlerror.URLError, ssl.SSLError, OSError) as e:
                if attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise Rapid7Error("%s %s -> %s" % (method, path, e))
        raise Rapid7Error("%s %s -> retries exhausted" % (method, path))

    def get(self, path, params=None, allow_404=False):
        return self.request("GET", path, params=params, allow_404=allow_404)

    def post(self, path, body):
        return self.request("POST", path, body=body)

    def paged(self, path, params=None, size=500, max_pages=None):
        """Yield resources across pages."""
        page = 0
        params = dict(params or {})
        while True:
            params.update({"page": page, "size": size})
            data = self.get(path, params) or {}
            for r in data.get("resources", []) or []:
                yield r
            info = data.get("page") or {}
            total = info.get("totalPages")
            page += 1
            if total is None or page >= total:
                break
            if max_pages is not None and page >= max_pages:
                break

    # -- convenience wrappers --------------------------------------------
    def sites(self):
        return list(self.paged("/api/3/sites"))

    def site_assets(self, site_id):
        return self.paged("/api/3/sites/%s/assets" % site_id)

    def asset(self, asset_id):
        return self.get("/api/3/assets/%s" % asset_id, allow_404=True)

    def asset_software(self, asset_id):
        data = self.get("/api/3/assets/%s/software" % asset_id, allow_404=True) or {}
        return data.get("resources", []) or []

    def asset_vuln_ids(self, asset_id):
        return [r.get("id") for r in self.paged("/api/3/assets/%s/vulnerabilities" % asset_id) if r.get("id")]

    def asset_has_vuln(self, asset_id, vuln_id):
        r = self.get("/api/3/assets/%s/vulnerabilities/%s" % (asset_id, urlparse.quote(vuln_id, safe="")),
                     allow_404=True)
        if r is None:
            return False
        status = str(r.get("status", "")).lower()
        return status.startswith("vulnerable") or status == ""

    def start_site_scan(self, site_id, hosts, name, template_id=""):
        body = {"name": name, "hosts": hosts}
        if template_id:
            body["templateId"] = template_id
        r = self.post("/api/3/sites/%s/scans" % site_id, body) or {}
        return r.get("id")

    def scan(self, scan_id):
        return self.get("/api/3/scans/%s" % scan_id) or {}


def asset_last_scan(asset):
    """Latest scan date from an Asset resource's history, else None."""
    best = None
    for h in asset.get("history", []) or []:
        if str(h.get("type", "")).upper() in ("SCAN", "AGENT-IMPORT", "ACTIVE-SYNC", "ACTIVE_SYNC"):
            d = parse_date(h.get("date"))
            if d and (best is None or d > best):
                best = d
    return best


def asset_scan_ids(asset):
    return set(str(h.get("scanId")) for h in asset.get("history", []) or [] if h.get("scanId") is not None)


def asset_hostname(asset):
    hn = asset.get("hostName")
    if not hn:
        for h in asset.get("hostNames", []) or []:
            if h.get("name"):
                hn = h["name"]
                break
    return hn or ""


def software_row(sw):
    cpe = sw.get("cpe") or {}
    return {
        "vendor": sw.get("vendor") or "",
        "product": sw.get("product") or sw.get("description") or "",
        "version": sw.get("version") or "",
        "family": sw.get("family") or "",
        "type": sw.get("type") or "",
        "cpe": cpe.get("v2.3") or cpe.get("v2.2") or "",
    }


# --------------------------------------------------------------------------
# Splunk helpers
# --------------------------------------------------------------------------

def app_service(splunkd_uri, session_key):
    """Service bound to this app's namespace (owner nobody)."""
    from splunklib import client
    u = urlparse.urlsplit(splunkd_uri)
    return client.Service(scheme=u.scheme, host=u.hostname, port=u.port, token=session_key,
                          owner="nobody", app=APP, autologin=False)


def command_service(cmd):
    si = cmd._metadata.searchinfo
    return app_service(si.splunkd_uri, si.session_key)


def command_user(cmd):
    return cmd._metadata.searchinfo.username


def load_settings(service):
    defaults = {
        "console_url": "", "verify_ssl": "true", "ca_bundle": "", "use_system_proxy": "false",
        "collector_username": "", "scan_username": "", "index": "rapid7", "request_timeout": "60",
        "page_size": "500", "threads": "4", "scan_template_id": "", "max_servers_per_job": "50",
        "max_job_hours": "12", "stale_days": "7", "rescan_capability": "rapid7_cve_rescan",
        "vuln_content_first_days": "30", "vuln_content_overlap_days": "2", "vuln_content_max_pages": "400",
        "credential_app": "", "credential_realm": "",
    }
    try:
        stanza = service.confs[CONF]["settings"]
        for k, v in stanza.content.items():
            if k in defaults and v is not None:
                defaults[k] = v
    except Exception:
        pass
    return defaults


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "t", "y", "on")


def get_password(service, username, cred_app="", cred_realm=""):
    """Clear password from Splunk's password store.

    By default the credential stored in this app under realm rapid7_vm_cve.
    With cred_app/cred_realm set, reuse a credential another app already stores
    (e.g. the existing Rapid7 InsightVM app) without copying it.
    """
    if not username:
        raise Rapid7Error("Rapid7 username is not set in rapid7_cve.conf [settings]")
    app = cred_app or APP
    realm = cred_realm if cred_app else (cred_realm or REALM)
    resp = service.get("storage/passwords", owner="-", app=app, output_mode="json", count=0)
    raw = resp.body.read()
    data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    for e in data.get("entry") or []:
        c = e.get("content") or {}
        if c.get("username") != username:
            continue
        if realm and c.get("realm") != realm:
            continue
        acl = e.get("acl") or {}
        if cred_app and acl.get("app") not in (None, app) and acl.get("sharing") != "global":
            continue
        return c.get("clear_password")
    raise Rapid7Error("No password stored for app=%s realm=%s username=%s (see README, step 3)"
                      % (app, realm or "(any)", username))


def make_client(service, settings, role="collector"):
    user = settings["scan_username"] if role == "scan" else settings["collector_username"]
    if role == "scan" and not user:
        user = settings["collector_username"]
    return Rapid7Client(
        settings["console_url"], user,
        get_password(service, user, settings.get("credential_app", ""), settings.get("credential_realm", "")),
        verify_ssl=truthy(settings["verify_ssl"]), ca_bundle=settings["ca_bundle"],
        timeout=int(settings["request_timeout"]), use_system_proxy=truthy(settings["use_system_proxy"]))


def oneshot(service, spl, earliest="-3d", latest="now", count=0):
    """Run a search and return a list of result dicts."""
    if not spl.lstrip().startswith(("search ", "|")):
        spl = "search " + spl
    stream = service.jobs.oneshot(spl, output_mode="json", count=count,
                                  earliest_time=earliest, latest_time=latest)
    raw = stream.read()
    if not raw:
        return []
    data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    for m in data.get("messages") or []:
        if str(m.get("type", "")).upper() in ("FATAL", "ERROR"):
            raise RuntimeError("Search failed: %s :: %s" % (m.get("text"), spl[:200]))
    return [r for r in data.get("results") or [] if isinstance(r, dict)]


def spl_quote(value):
    return '"%s"' % str(value).replace("\\", "\\\\").replace('"', '\\"')


def user_capabilities(service, username):
    try:
        u = service.users[username]
        caps = u.content.get("capabilities") or []
        return set(caps if isinstance(caps, list) else [caps])
    except Exception:
        return set()


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def split_csv(v):
    if not v:
        return []
    return [x.strip() for x in re.split(r"[,\n]+", str(v)) if x.strip()]


def clean_doc(doc):
    """Drop KV store system fields (except _key) before saving a document back."""
    return dict((k, v) for k, v in doc.items() if not k.startswith("_") or k == "_key")


class KV(object):
    """Minimal KV store data client for one collection in this app (owner nobody)."""

    def __init__(self, service, collection):
        self.service = service
        self.path = "storage/collections/data/%s/" % collection

    def _json(self, resp):
        raw = resp.body.read()
        return json.loads(raw.decode("utf-8")) if raw else None

    def query(self, **params):
        for k, v in list(params.items()):
            if isinstance(v, (dict, list)):
                params[k] = json.dumps(v)
        return self._json(self.service.get(self.path, owner="nobody", app=APP, output_mode="json", **params)) or []

    def query_by_id(self, key):
        from splunklib.binding import HTTPError
        try:
            return self._json(self.service.get(self.path + urlparse.quote(str(key), safe=""), owner="nobody",
                                               app=APP, output_mode="json"))
        except HTTPError as e:
            if e.status == 404:
                return None
            raise

    def batch_save(self, *docs):
        return self._json(self.service.post(self.path + "batch_save", owner="nobody", app=APP,
                                            headers=[("Content-Type", "application/json")],
                                            body=json.dumps(list(docs))))

    def delete_by_id(self, key):
        return self.service.delete(self.path + urlparse.quote(str(key), safe=""), owner="nobody", app=APP)


def kv(service, collection):
    return KV(service, collection)


def safe(fn):
    """Wrap a generate()/stream() method: report errors as a clean Splunk error message.

    splunklib formats error text with str.format, so braces in a message would
    break error reporting; they are replaced here.
    """
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        try:
            for row in fn(self, *args, **kwargs):
                yield row
        except Exception as e:
            known = (ValueError, PermissionError, RuntimeError, Rapid7Error)
            msg = str(e) if isinstance(e, known) else "%s: %s" % (type(e).__name__, e)
            self.write_error(msg.replace("{", "(").replace("}", ")"))
    return wrapper
