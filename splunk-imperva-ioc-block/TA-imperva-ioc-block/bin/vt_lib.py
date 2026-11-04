"""
VirusTotal v3 IP reputation lookup + block suggestion logic.
No Splunk imports here (unit-testable).

API: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}   header: x-apikey
Free (public) API limits: 4 requests/minute, 500/day  -> results are cached on disk.
"""

import ipaddress
import json
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request

VT_BASE = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui/ip-address/"


class VTError(Exception):
    pass


class VTRateLimited(VTError):
    pass


def _opener(proxy=None, verify_ssl=True):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def parse_vt_response(ip, js):
    """Flatten the VT JSON for one IP into Splunk-friendly fields."""
    a = (js.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    total = sum(int(v or 0) for v in st.values())
    return {
        "vt_status": "ok",
        "vt_malicious": int(st.get("malicious", 0) or 0),
        "vt_suspicious": int(st.get("suspicious", 0) or 0),
        "vt_harmless": int(st.get("harmless", 0) or 0),
        "vt_undetected": int(st.get("undetected", 0) or 0),
        "vt_engines": total,
        "vt_reputation": int(a.get("reputation", 0) or 0),
        "vt_country": a.get("country") or "-",
        "vt_continent": a.get("continent") or "-",
        "vt_asn": a.get("asn") or "-",
        "vt_as_owner": a.get("as_owner") or "-",
        "vt_network": a.get("network") or "-",
        "vt_last_analysis": a.get("last_analysis_date") or 0,
        "vt_link": VT_GUI + ip,
    }


class VTClient(object):
    def __init__(self, api_key, base_url=VT_BASE, timeout=30, proxy=None, verify_ssl=True):
        if not api_key:
            raise VTError("VirusTotal API key not configured")
        self.api_key = api_key
        self.base_url = (base_url or VT_BASE).rstrip("/")
        self.timeout = timeout
        self._opener = _opener(proxy, verify_ssl)

    def lookup_ip(self, ip):
        req = urllib.request.Request("%s/ip_addresses/%s" % (self.base_url, ip), method="GET")
        req.add_header("x-apikey", self.api_key)
        req.add_header("Accept", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                js = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise VTRateLimited("VirusTotal quota exceeded (HTTP 429)")
            if e.code == 404:
                r = {"vt_status": "not_found", "vt_link": VT_GUI + ip}
                return r
            raise VTError("VirusTotal HTTP %s: %s" % (e.code, e.read()[:200]))
        except urllib.error.URLError as e:
            raise VTError("Cannot reach VirusTotal: %s" % e.reason)
        return parse_vt_response(ip, js)


# --------------------------------------------------------------------------- #
# Disk cache  {ip: {"ts": epoch, "data": {...}}}
# --------------------------------------------------------------------------- #
class VTCache(object):
    def __init__(self, path, ttl_seconds=86400):
        self.path = path
        self.ttl = ttl_seconds
        self.data = {}
        try:
            with open(path) as f:
                self.data = json.load(f)
        except (IOError, OSError, ValueError):
            self.data = {}

    def get(self, ip, now=None):
        e = self.data.get(ip)
        now = now or time.time()
        if e and now - e.get("ts", 0) < self.ttl:
            return e["data"]
        return None

    def put(self, ip, data, now=None):
        self.data[ip] = {"ts": now or time.time(), "data": data}

    def save(self):
        d = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".vtcache")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------- #
# Suggestion
# --------------------------------------------------------------------------- #
DEFAULT_THRESHOLDS = {
    "block_malicious": 3,       # >= N engines say malicious      -> BLOCK
    "review_malicious": 1,      # >= N engines malicious          -> REVIEW (or BLOCK if high volume)
    "review_suspicious": 2,     # >= N engines suspicious         -> REVIEW
    "high_volume_count": 1000,  # WAF attack events in time range -> treat as strong signal
}


def suggest(vt, attack_count=0, protected=False, thresholds=None):
    """
    Return (suggestion, reason). suggestion is one of:
      BLOCK          strong evidence - block it
      REVIEW         some evidence - analyst should decide
      MONITOR        VT clean and moderate volume - do not block yet
      DO_NOT_BLOCK   private / protected / reserved address
    """
    t = dict(DEFAULT_THRESHOLDS)
    t.update(thresholds or {})
    ip = vt.get("ip")
    try:
        if ip and not ipaddress.ip_address(ip).is_global:
            return "DO_NOT_BLOCK", "non-public address"
    except ValueError:
        return "DO_NOT_BLOCK", "invalid IP"
    if protected:
        return "DO_NOT_BLOCK", "in protected_networks"

    count = int(attack_count or 0)
    high_volume = count >= t["high_volume_count"]
    status = vt.get("vt_status", "ok")
    if status != "ok":
        if high_volume:
            return "BLOCK", "VT %s, but very high attack volume (%d events)" % (status, count)
        return "REVIEW", "VT %s - verify manually" % status

    mal = int(vt.get("vt_malicious", 0))
    sus = int(vt.get("vt_suspicious", 0))
    rep = int(vt.get("vt_reputation", 0))

    if mal >= t["block_malicious"]:
        return "BLOCK", "%d VT engines flag malicious" % mal
    if mal >= t["review_malicious"] or sus >= t["review_suspicious"] or rep < 0:
        if high_volume:
            return "BLOCK", "VT mal=%d sus=%d rep=%d + high attack volume (%d)" % (mal, sus, rep, count)
        return "REVIEW", "VT mal=%d sus=%d rep=%d" % (mal, sus, rep)
    if high_volume:
        return "REVIEW", "VT clean but very high attack volume (%d events)" % count
    return "MONITOR", "VT clean (0 malicious), moderate volume (%d events)" % count
