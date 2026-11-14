"""
AbuseIPDB and GreyNoise IP reputation lookups (V2) + how they adjust the Block suggestion.
No Splunk imports here (unit-testable). Used by the Splunk command intelcheck (direct mode) and
by the SOAR playbook (actions abusecheck / gncheck), exactly like vt_lib for VirusTotal.

AbuseIPDB  APIv2  GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=<n>
                  headers  Key: <api key>   Accept: application/json
                  -> data.abuseConfidenceScore (0-100), totalReports, numDistinctUsers, ...
GreyNoise  Community API v3  GET https://api.greynoise.io/v3/community/<ip>   header key: <api key>
                  -> noise, riot, classification (benign | malicious | unknown), name, last_seen
                  HTTP 404 = IP not observed scanning the internet and not in RIOT

Every top-level name here is prefixed (intel_ / abuse / gn / INTEL_): the SOAR playbook inlines
imperva_lib + vt_lib + intel_lib into ONE namespace, so a generic name (lookup_many, _opener ...)
would replace the VirusTotal one.
"""

import ipaddress
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
ABUSE_GUI = "https://www.abuseipdb.com/check/"
GN_BASE = "https://api.greynoise.io/v3"
GN_GUI = "https://viz.greynoise.io/ip/"

# source name -> field prefix, SOAR action, link to the web page of an IP
INTEL_SOURCES = {
    "abuseipdb": {"prefix": "abuse", "action": "abusecheck", "gui": ABUSE_GUI, "title": "AbuseIPDB"},
    "greynoise": {"prefix": "gn", "action": "gncheck", "gui": GN_GUI, "title": "GreyNoise"},
}

INTEL_THRESHOLDS = {
    "abuse_block_score": 75,    # AbuseIPDB confidence >= N %  -> BLOCK
    "abuse_review_score": 25,   # AbuseIPDB confidence >= N %  -> at least REVIEW
}


class IntelError(Exception):
    pass


class IntelRateLimited(IntelError):
    pass


def _intel_opener(proxy=None, verify_ssl=True):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _intel_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _intel_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _intel_body(e):
    try:
        return e.read()[:300].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- AbuseIPDB
def parse_abuse_response(ip, js):
    """Flatten the AbuseIPDB /check JSON into Splunk-friendly fields (abuse_*)."""
    d = (js or {}).get("data") or {}
    last = str(d.get("lastReportedAt") or "")
    return {
        "abuse_status": "ok",
        "abuse_score": _intel_int(d.get("abuseConfidenceScore")),
        "abuse_reports": _intel_int(d.get("totalReports")),
        "abuse_users": _intel_int(d.get("numDistinctUsers")),
        "abuse_last_reported": last[:16].replace("T", " ") if last else "-",
        "abuse_country": d.get("countryCode") or "-",
        "abuse_usage": d.get("usageType") or "-",
        "abuse_isp": d.get("isp") or "-",
        "abuse_domain": d.get("domain") or "-",
        "abuse_tor": "yes" if d.get("isTor") else "no",
        "abuse_whitelisted": "yes" if d.get("isWhitelisted") else "no",
        "abuse_link": ABUSE_GUI + ip,
    }


class AbuseIPDBClient(object):
    prefix, gui = "abuse", ABUSE_GUI

    def __init__(self, api_key, base_url=ABUSE_BASE, max_age_days=90, timeout=30, proxy=None,
                 verify_ssl=True):
        if not api_key:
            raise IntelError("AbuseIPDB API key not configured")
        self.api_key = api_key
        self.base_url = (base_url or ABUSE_BASE).rstrip("/")
        self.max_age_days = max(1, min(365, _intel_int(max_age_days) or 90))
        self.timeout = timeout
        self._opener = _intel_opener(proxy, verify_ssl)

    def lookup_ip(self, ip):
        q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        req = urllib.request.Request("%s/check?%s" % (self.base_url, q), method="GET")
        req.add_header("Key", self.api_key)
        req.add_header("Accept", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                js = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise IntelRateLimited("AbuseIPDB quota exceeded (HTTP 429)")
            raise IntelError("AbuseIPDB HTTP %s: %s" % (e.code, _intel_body(e)))
        except urllib.error.URLError as e:
            raise IntelError("Cannot reach AbuseIPDB: %s" % e.reason)
        return parse_abuse_response(ip, js)


# --------------------------------------------------------------------------- GreyNoise
def parse_gn_response(ip, js, status="ok"):
    """Flatten the GreyNoise Community JSON into gn_* fields. status not_found = HTTP 404
    (not observed scanning the internet and not a known benign service)."""
    js = js or {}
    cls = str(js.get("classification") or "").strip().lower()
    return {
        "gn_status": status,
        "gn_noise": "yes" if js.get("noise") else "no",
        "gn_riot": "yes" if js.get("riot") else "no",
        "gn_classification": cls or "-",
        "gn_name": js.get("name") or "-",
        "gn_last_seen": str(js.get("last_seen") or "-"),
        "gn_message": js.get("message") or "-",
        "gn_link": js.get("link") or (GN_GUI + ip),
    }


class GreyNoiseClient(object):
    prefix, gui = "gn", GN_GUI

    def __init__(self, api_key=None, base_url=GN_BASE, timeout=30, proxy=None, verify_ssl=True):
        self.api_key = api_key or ""          # the Community API also answers without a key (lower limit)
        self.base_url = (base_url or GN_BASE).rstrip("/")
        self.timeout = timeout
        self._opener = _intel_opener(proxy, verify_ssl)

    def lookup_ip(self, ip):
        req = urllib.request.Request("%s/community/%s" % (self.base_url, urllib.parse.quote(ip)), method="GET")
        if self.api_key:
            req.add_header("key", self.api_key)
        req.add_header("Accept", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                js = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:                 # not observed + not in RIOT: still an answer
                try:
                    js = json.loads(e.read().decode("utf-8"))
                except Exception:  # noqa: BLE001
                    js = {}
                return parse_gn_response(ip, js, status="not_found")
            if e.code == 429:
                raise IntelRateLimited("GreyNoise quota exceeded (HTTP 429)")
            raise IntelError("GreyNoise HTTP %s: %s" % (e.code, _intel_body(e)))
        except urllib.error.URLError as e:
            raise IntelError("Cannot reach GreyNoise: %s" % e.reason)
        return parse_gn_response(ip, js)


def intel_client(source, api_key, base_url=None, timeout=30, proxy=None, verify_ssl=True, max_age_days=90):
    if source == "abuseipdb":
        return AbuseIPDBClient(api_key, base_url or ABUSE_BASE, max_age_days, timeout, proxy, verify_ssl)
    if source == "greynoise":
        return GreyNoiseClient(api_key, base_url or GN_BASE, timeout, proxy, verify_ssl)
    raise IntelError("unknown intel source %r" % source)


# --------------------------------------------------------------------------- batch lookup
def intel_lookup_many(client, ips, rpm=10, max_lookups=10, retry_wait=60, max_wait=0,
                      _sleep=time.sleep, _now=time.time):
    """
    Same rules as vt_lib.lookup_many, for any intel client (field prefix = client.prefix):
    each IP once, at most max_lookups calls (0 = no limit), spaced 60/rpm seconds.
    <prefix>_status: ok | not_found | private_ip | error | rate_limited |
    not_checked (max_lookups_per_run). HTTP 429: wait retry_wait and call again while the
    max_wait budget lasts, then the rest are rate_limited (not cached: retried next run).
    """
    pre, gui = client.prefix, client.gui
    st = pre + "_status"
    out, calls, last, limited, waited = {}, 0, None, False, 0.0
    gap = 60.0 / max(1, int(rpm))
    max_lookups = int(max_lookups or 0)
    for ip in ips:
        if ip in out:
            continue
        base = {pre + "_link": gui + ip}
        if not _intel_public(ip):
            out[ip] = dict(base, **{st: "private_ip"})
            continue
        if limited:
            out[ip] = dict(base, **{st: "rate_limited"})
            continue
        if max_lookups > 0 and calls >= max_lookups:
            out[ip] = dict(base, **{st: "not_checked (max_lookups_per_run)"})
            continue
        while True:
            if last is not None:
                wait = gap - (_now() - last)
                if wait > 0:
                    _sleep(wait)
            last = _now()
            calls += 1
            try:
                out[ip] = client.lookup_ip(ip)
            except IntelRateLimited:
                if waited + retry_wait <= max_wait:
                    _sleep(retry_wait)
                    waited += retry_wait
                    last = _now()
                    continue
                limited = True
                out[ip] = dict(base, **{st: "rate_limited"})
            except IntelError as e:
                out[ip] = dict(base, **{st: "error", pre + "_error": str(e)})
            break
    return out


# --------------------------------------------------------------------------- suggestion
_INTEL_RANK = {"BLOCK": 1, "REVIEW": 2, "MONITOR": 3}


def intel_summary(info):
    """Short text for the table, e.g. 'AbuseIPDB 92% (310 reports)' / 'GreyNoise malicious'."""
    parts = []
    if info.get("abuse_status") == "ok":
        parts.append("AbuseIPDB %s%% (%s reports)" % (info.get("abuse_score", 0), info.get("abuse_reports", 0)))
    gs = info.get("gn_status")
    if gs == "ok":
        if str(info.get("gn_riot")) == "yes":
            parts.append("GreyNoise RIOT (%s)" % info.get("gn_name", "-"))
        else:
            parts.append("GreyNoise %s" % info.get("gn_classification", "-"))
    elif gs == "not_found":
        parts.append("GreyNoise not observed")
    return " · ".join(parts)


def intel_adjust(suggestion, reason, info, thresholds=None):
    """
    VirusTotal suggestion (vt_lib.suggest) + AbuseIPDB / GreyNoise -> (suggestion, reason).
      AbuseIPDB score >= abuse_block_score              -> BLOCK
      AbuseIPDB score >= abuse_review_score             -> at least REVIEW
      GreyNoise classification malicious                -> at least REVIEW
      GreyNoise RIOT / benign, AbuseIPDB whitelisted    -> at most REVIEW (known service:
                                                           the analyst decides)
    DO_NOT_BLOCK / ALREADY_BLOCKED and missing data never change anything.
    """
    if suggestion not in _INTEL_RANK:
        return suggestion, reason
    t = dict(INTEL_THRESHOLDS)
    t.update(dict((k, int(v)) for k, v in (thresholds or {}).items() if str(v).strip() != ""))
    s, notes = suggestion, []
    if info.get("abuse_status") == "ok":
        score = _intel_int(info.get("abuse_score"))
        txt = "AbuseIPDB %d%% (%d reports)" % (score, _intel_int(info.get("abuse_reports")))
        if score >= t["abuse_block_score"]:
            s = "BLOCK"
            notes.append(txt)
        elif score >= t["abuse_review_score"]:
            if _INTEL_RANK[s] > _INTEL_RANK["REVIEW"]:
                s = "REVIEW"
            notes.append(txt)
    gn_ok = info.get("gn_status") == "ok"
    if gn_ok and str(info.get("gn_classification")) == "malicious" and str(info.get("gn_riot")) != "yes":
        if _INTEL_RANK[s] > _INTEL_RANK["REVIEW"]:
            s = "REVIEW"
        notes.append("GreyNoise malicious scanner")
    benign = []
    if gn_ok and (str(info.get("gn_riot")) == "yes" or str(info.get("gn_classification")) == "benign"):
        benign.append("GreyNoise %s (%s)" % ("RIOT known service" if str(info.get("gn_riot")) == "yes" else "benign",
                                             info.get("gn_name", "-")))
    if info.get("abuse_status") == "ok" and str(info.get("abuse_whitelisted")) == "yes":
        benign.append("AbuseIPDB whitelisted")
    if benign:
        if s == "BLOCK":
            s = "REVIEW"
        notes.append(" + ".join(benign) + " - check before blocking")
    if not notes:
        return suggestion, reason
    return s, (reason + "; " if reason else "") + "; ".join(notes)
