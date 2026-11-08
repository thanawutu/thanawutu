#!/usr/bin/env python3
"""
preflight.py — ทดสอบการเชื่อมต่อและความพร้อมทั้งหมด *ก่อน* ติดตั้งแอป TA-tbcert-misp
เพื่อไม่ต้องติดตั้ง/ถอนแอปซ้ำ ๆ ระหว่างแก้ปัญหา

ทุกการทดสอบเป็นแบบอ่านอย่างเดียว ยกเว้นใส่ --allow-write (ส่ง HEC test event 1 รายการ)

  misp        : เชื่อมต่อ, API key, user/role/org ที่ key ผูกอยู่, ค้น attribute ได้
  splunk      : REST API, เวอร์ชัน (ต้อง 8.0+), user/roles, KV store, index ปลายทาง,
                แอปที่ติดตั้งอยู่ (TA-tbcert-misp / misp42splunk)
  data        : sourcetype=misp_events มีข้อมูลและมี field ที่แอปต้องใช้
  spl         : รัน SPL ของแอป (macro ขยายจาก splunk_app/.../macros.conf) กับข้อมูลจริง
                โดยไม่ต้องติดตั้งแอป และไม่เขียนอะไรลง Splunk -> เจอ SPL error ก่อนติดตั้ง
  misp42splunk: อ่าน config instance ในแอป MISP42Splunk (URL, ตรวจ certificate, proxy)
                แล้วรัน | mispgetioc จากฝั่ง Splunk (ทดสอบเส้นทาง Splunk → proxy → MISP)
  hec         : HEC health และ token (เขียนจริงเฉพาะ --allow-write)
  sentinelone : อ่าน Blocklist ได้ (สิทธิ์ของ API token)
  imperva     : อ่านสถานะ site และ ACL blacklisted IPs ได้
  proofpoint  : mode=ptr อ่าน list ได้ / mode=csv เขียนโฟลเดอร์ได้

ตัวอย่าง
  python3 preflight.py -c config.ini
  python3 preflight.py -c config.ini --only misp,splunk,spl
  python3 preflight.py -c config.ini --json preflight.json
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import sys
import tempfile
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(HERE, "splunk_app", "TA-tbcert-misp")
REQUIRED_FIELDS = ["attr_uuid", "attr_type", "value", "to_ids", "event_id", "threat_level_id",
                   "attr_timestamp", "event_tags{}", "org", "info", "uuid"]
RESULTS: list[dict] = []


# --------------------------------------------------------------------------- helpers
def record(check: str, status: str, msg: str, hint: str = "") -> None:
    RESULTS.append({"check": check, "status": status, "message": msg, "hint": hint})
    mark = {"PASS": "✔", "WARN": "!", "FAIL": "✘", "SKIP": "–"}[status]
    print(f"  [{mark} {status}] {check}: {msg}")
    if hint and status in ("FAIL", "WARN"):
        print(f"           ↳ {hint}")


def explain(e: Exception, what: str) -> str:
    if isinstance(e, requests.exceptions.SSLError):
        return f"TLS ไม่ผ่าน — ใส่ path CA bundle ขององค์กรใน verify_tls ของ [{what}] (อย่าปิด verify)"
    if isinstance(e, requests.exceptions.ProxyError):
        return "proxy ปฏิเสธ — ตรวจค่า proxy / ขออนุญาต proxy ให้ไปยังปลายทางนี้"
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "เชื่อมต่อไม่ได้ (timeout) — firewall/route ยังไม่เปิด หรือปลายทาง whitelist IP ต้นทาง"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "เชื่อมต่อไม่ได้ — ตรวจ DNS / firewall / proxy / พอร์ต"
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "ปลายทางตอบช้าเกินไป — ลองใหม่ หรือลดช่วงเวลาที่ค้น"
    return str(e)


def http_hint(code: int, what: str) -> str:
    return {401: f"{what}: key/token ไม่ถูกต้องหรือหมดอายุ",
            403: f"{what}: key/token ไม่มีสิทธิ์ (role/permission) หรือ IP ต้นทางไม่ได้รับอนุญาต",
            404: f"{what}: ไม่พบ endpoint/object — ตรวจ URL หรือ id",
            405: f"{what}: method ไม่รองรับ — อาจเป็นเวอร์ชัน API ต่างกัน",
            429: f"{what}: ถูกจำกัดอัตราการเรียก (rate limit)"}.get(code, f"{what}: HTTP {code}")


def verify_of(v: str):
    v = (v or "true").strip()
    if v.lower() in ("true", "1", "yes"):
        return True
    if v.lower() in ("false", "0", "no"):
        return False
    return v


def secret(sec, key: str, env: str) -> str:
    return os.environ.get(env) or sec.get(key, "").strip()


def call(check, what, method, url, **kw):
    """คืน response หรือ None (บันทึก FAIL ให้แล้ว)"""
    kw.setdefault("timeout", 30)
    try:
        r = requests.request(method, url, **kw)
    except requests.RequestException as e:
        record(check, "FAIL", type(e).__name__, explain(e, what))
        return None
    if r.status_code >= 400:
        record(check, "FAIL", f"HTTP {r.status_code}", http_hint(r.status_code, what))
        return None
    return r


# --------------------------------------------------------------------------- macro expansion
def load_macros(path: str) -> dict[str, str]:
    macros, name, buf = {}, None, []
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            name = m.group(1)
        elif name and line.startswith("definition"):
            val = line.split("=", 1)[1].strip()
            while val.endswith("\\") and i + 1 < len(lines):
                i += 1
                val = val[:-1] + "\n" + lines[i]
            macros[name] = val.strip()
        i += 1
    return macros


def expand(spl: str, macros: dict[str, str], depth: int = 0) -> str:
    if depth > 10:
        raise RuntimeError("macro ซ้อนกันลึกเกินไป")
    def rep(m):
        n = m.group(1)
        if n not in macros:
            raise KeyError(f"ไม่พบ macro `{n}` ใน macros.conf")
        return expand(macros[n], macros, depth + 1)
    return re.sub(r"`([A-Za-z0-9_]+)`", rep, spl)


def strip_app_lookups(spl: str) -> str:
    """lookup ของแอปยังไม่มีก่อนติดตั้ง -> ตัดออก (field จาก lookup จะเป็น null = ไม่มี allowlist/trust)"""
    return re.sub(r"\|\s*lookup\s+tbcert_[A-Za-z0-9_]+[^|]*", "", spl)


# --------------------------------------------------------------------------- checks
def check_misp(cp) -> None:
    print("\n▶ MISP")
    if not cp.has_section("misp"):
        return record("misp", "SKIP", "ไม่มี [misp] ใน config")
    m = cp["misp"]
    url, key = m.get("url", "").rstrip("/"), secret(m, "api_key", "MISP_API_KEY")
    if not key:
        return record("misp.key", "FAIL", "ไม่มี API key", "ใส่ env MISP_API_KEY หรือ [misp] api_key")
    proxy = m.get("proxy", "").strip()
    kw = {"headers": {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
          "verify": verify_of(m.get("verify_tls")), "proxies": {"https": proxy, "http": proxy} if proxy else None}
    t = time.time()
    r = call("misp.connect", "misp", "GET", f"{url}/servers/getVersion", **kw)
    if not r:
        return
    ver = r.json().get("version", "?")
    record("misp.connect", "PASS", f"MISP {ver} ({(time.time() - t) * 1000:.0f} ms)")
    r = call("misp.user", "misp", "GET", f"{url}/users/view/me", **kw)
    if r:
        b = r.json()
        role = (b.get("Role") or {})
        record("misp.user", "PASS", f"{(b.get('User') or {}).get('email', '?')} · org {(b.get('Organisation') or {}).get('name', '?')}"
               f" · role {role.get('name', '?')}")
        if not role.get("perm_auth", True):
            record("misp.role", "WARN", "role ไม่มี perm_auth", "ขอ role ที่ใช้ API ได้จาก TB-CERT")
    body = {"returnFormat": "json", "limit": 1, "page": 1, "publish_timestamp": "30d", "to_ids": True}
    r = call("misp.search", "misp", "POST", f"{url}/attributes/restSearch", data=json.dumps(body), timeout=120, **kw)
    if r:
        n = len(r.json().get("response", {}).get("Attribute", []))
        record("misp.search", "PASS" if n else "WARN",
               "ค้น attribute ได้" if n else "ค้นได้แต่ไม่พบ attribute ใน 30 วัน",
               "key อาจเห็นเฉพาะบาง event — ตรวจ sharing group / สิทธิ์ org กับ TB-CERT")


def splunk_kw(cp):
    s = cp["splunk"]
    tok = secret(s, "token", "SPLUNK_TOKEN")
    return s["url"].rstrip("/"), {"headers": {"Authorization": f"Bearer {tok}"},
                                  "verify": verify_of(s.get("verify_tls"))}, tok


def splunk_search(cp, check, spl, earliest="-24h", timeout=300):
    url, kw, _ = splunk_kw(cp)
    r = call(check, "splunk", "POST", f"{url}/services/search/jobs/export", stream=True, timeout=timeout,
             data={"search": spl, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"}, **kw)
    if not r:
        return None
    rows, errors = [], []
    for line in r.iter_lines():
        if not line:
            continue
        obj = json.loads(line)
        for msg in obj.get("messages", []) or []:
            if msg.get("type") in ("ERROR", "FATAL"):
                errors.append(msg.get("text", ""))
        if "result" in obj and not obj.get("preview"):
            rows.append(obj["result"])
    if errors:
        record(check, "FAIL", "SPL error: " + " | ".join(errors)[:400], "แก้ SPL/macro ก่อนติดตั้งแอป แล้วรัน preflight ใหม่")
        return None
    return rows


def check_splunk(cp) -> None:
    print("\n▶ Splunk REST")
    if not cp.has_section("splunk"):
        return record("splunk", "SKIP", "ไม่มี [splunk] ใน config")
    url, kw, tok = splunk_kw(cp)
    if not tok:
        return record("splunk.token", "FAIL", "ไม่มี token", "ใส่ env SPLUNK_TOKEN หรือ [splunk] token")
    q = {"output_mode": "json"}
    r = call("splunk.connect", "splunk", "GET", f"{url}/services/server/info", params=q, **kw)
    if not r:
        return
    info = r.json()["entry"][0]["content"]
    ver = info.get("version", "0")
    major = int(re.match(r"(\d+)", ver).group(1)) if re.match(r"(\d+)", ver) else 0
    record("splunk.version", "PASS" if major >= 8 else "FAIL", f"Splunk {ver} · {info.get('serverName', '')}",
           "แอปใช้ mvmap / outputlookup key_field ต้อง Splunk 8.0 ขึ้นไป")
    if info.get("instance_type") == "cloud":
        record("splunk.cloud", "WARN", "Splunk Cloud", "แอปต้องผ่าน AppInspect/private app vetting ก่อนติดตั้ง")
    r = call("splunk.user", "splunk", "GET", f"{url}/services/authentication/current-context", params=q, **kw)
    if r:
        c = r.json()["entry"][0]["content"]
        caps = set(c.get("capabilities", []))
        record("splunk.user", "PASS", f"{c.get('username')} · roles {', '.join(c.get('roles', []))}")
        need = {"install_apps": "ติดตั้งแอปจากไฟล์", "edit_token_http": "จัดการ HEC token",
                "schedule_search": "ตั้ง schedule saved search"}
        missing = [f"{k} ({v})" for k, v in need.items() if k not in caps]
        if missing:
            record("splunk.capabilities", "WARN", "ไม่มี " + ", ".join(missing),
                   "ไม่จำเป็นสำหรับสคริปต์ แต่ต้องมีคนที่มีสิทธิ์นี้ทำขั้นตอนติดตั้ง")
    r = call("splunk.kvstore", "splunk", "GET", f"{url}/services/kvstore/status", params=q, **kw)
    if r:
        st = r.json()["entry"][0]["content"].get("current", {}).get("status", "?")
        record("splunk.kvstore", "PASS" if st == "ready" else "FAIL", f"KV store {st}",
               "KV store ต้อง ready — ตรวจ splunkd.log / mongod.log")
    idx = cp["splunk"].get("hec_index", "threat_intel")
    try:
        r = requests.get(f"{url}/services/data/indexes/{idx}", params=q, timeout=30, **kw)
        if r.status_code == 200:
            record("splunk.index", "PASS", f"index {idx} มีอยู่")
        elif r.status_code == 404:
            record("splunk.index", "FAIL", f"ไม่พบ index {idx}", "สร้าง index (indexes.conf บน indexer) หรือแก้ hec_index ให้ตรง")
        else:
            record("splunk.index", "WARN", f"ตรวจ index ไม่ได้ (HTTP {r.status_code})", "token อาจไม่มีสิทธิ์ดู index — ให้ admin ยืนยัน")
    except requests.RequestException as e:
        record("splunk.index", "FAIL", type(e).__name__, explain(e, "splunk"))
    r = call("splunk.apps", "splunk", "GET", f"{url}/services/apps/local", params={**q, "count": 0}, **kw)
    if r:
        apps = {e["name"]: e["content"].get("version", "?") for e in r.json().get("entry", [])}
        ta = apps.get("TA-tbcert-misp")
        local = configparser.ConfigParser()
        local.read(os.path.join(APP_DIR, "default", "app.conf"))
        pkg = local.get("launcher", "version", fallback="?")
        record("splunk.app", "PASS", f"TA-tbcert-misp ติดตั้งอยู่ v{ta} (แพ็กเกจในเครื่อง v{pkg})" if ta
               else f"ยังไม่ได้ติดตั้ง TA-tbcert-misp (แพ็กเกจในเครื่อง v{pkg})")
        record("splunk.misp42splunk", "PASS", f"misp42splunk v{apps['misp42splunk']}" if "misp42splunk" in apps
               else "ไม่มี misp42splunk (ไม่จำเป็นสำหรับวิธี A)")


def check_data(cp) -> None:
    print("\n▶ ข้อมูล sourcetype=misp_events")
    macros = load_macros(os.path.join(APP_DIR, "default", "macros.conf"))
    src = expand("`tbcert_misp_src`", macros)
    rows = splunk_search(cp, "data.volume", f"search {src} | stats count dc(attr_uuid) as uniq latest(_time) as last",
                         earliest="-7d")
    if rows is None:
        return
    if not rows or int(rows[0].get("count", 0)) == 0:
        return record("data.volume", "FAIL", f"ไม่มีข้อมูลใน 7 วัน ({src})",
                      "ตรวจ macro tbcert_misp_src ให้ตรง index/sourcetype จริง หรือ token ไม่มีสิทธิ์อ่าน index")
    row = rows[0]
    age_h = (time.time() - float(row.get("last", 0))) / 3600
    record("data.volume", "PASS", f"7 วัน: {int(row['count']):,} event / {int(row['uniq']):,} attr_uuid · ล่าสุด {age_h:.1f} ชม.ที่แล้ว")
    if age_h > 24:
        record("data.fresh", "WARN", "ไม่มีข้อมูลใหม่เกิน 24 ชม.", "ตรวจตัวดึงข้อมูล MISP → Splunk")
    rows = splunk_search(cp, "data.origin", f"search {src} | stats count by source host | sort - count | head 5", earliest="-7d")
    if rows:
        record("data.origin", "PASS", "มาจาก " + " · ".join(f"{r.get('source')} @ {r.get('host')} ({int(r['count']):,})" for r in rows))
    rows = splunk_search(cp, "data.fields", f"search {src} | head 200 | fieldsummary | fields field count", earliest="-7d")
    if rows is None:
        return
    have = {r["field"]: int(r.get("count", 0)) for r in rows}
    miss = [f for f in REQUIRED_FIELDS if have.get(f, 0) == 0]
    if miss:
        record("data.fields", "FAIL" if set(miss) & {"attr_uuid", "attr_type", "value"} else "WARN",
               "ไม่พบ field: " + ", ".join(miss),
               "event_tags{} ต้องใช้ KV_MODE=json ใน props.conf ของ sourcetype misp_events; ถ้าชื่อ field ต่าง ให้แก้ macro tbcert_misp_events_normalize")
    else:
        record("data.fields", "PASS", "มี field ที่แอปต้องใช้ครบ")


def check_spl(cp) -> None:
    print("\n▶ SPL ของแอป (ไม่ต้องติดตั้ง ไม่เขียนข้อมูล)")
    macros = load_macros(os.path.join(APP_DIR, "default", "macros.conf"))
    try:
        base = expand("`tbcert_misp_src` `tbcert_misp_severity_filter`", macros)
        norm = strip_app_lookups(expand("`tbcert_misp_events_normalize`", macros))
    except (KeyError, RuntimeError) as e:
        return record("spl.expand", "FAIL", str(e))
    record("spl.expand", "PASS", f"ขยาย macro ได้ ({len(norm):,} ตัวอักษร, ตัด lookup ของแอปออกชั่วคราว)")
    spl = f"search {base} | head 2000 | {norm} | stats count by indicator_type status action"
    t = time.time()
    rows = splunk_search(cp, "spl.normalize", spl, earliest="-7d", timeout=600)
    if rows is None:
        return
    if not rows:
        return record("spl.normalize", "WARN", "SPL รันได้แต่ไม่มีผล", "ตรวจว่า 7 วันล่าสุดมีข้อมูลตาม tbcert_misp_severity_filter")
    total = sum(int(r["count"]) for r in rows)
    record("spl.normalize", "PASS", f"รันได้ใน {time.time() - t:.0f} วินาที · ตัวอย่าง 2,000 event → {total:,} indicator")
    agg: dict[str, int] = {}
    for r in rows:
        k = f"{r.get('indicator_type')}/{r.get('action')}"
        agg[k] = agg.get(k, 0) + int(r["count"])
    print("           " + " · ".join(f"{k} {v}" for k, v in sorted(agg.items(), key=lambda x: -x[1])[:12]))
    revoked = {}
    for r in rows:
        if str(r.get("status", "")).startswith("revoked"):
            revoked[r["status"]] = revoked.get(r["status"], 0) + int(r["count"])
    if revoked:
        print("           ถูกตัด: " + " · ".join(f"{k} {v}" for k, v in revoked.items()))

def check_misp42splunk(cp) -> None:
    print("\n▶ MISP42Splunk (จากฝั่ง Splunk)")
    sec = cp["misp42splunk"] if cp.has_section("misp42splunk") else {}
    name = sec.get("instance", "MISP_TBCERT").strip() if sec else "MISP_TBCERT"
    app = sec.get("app", "misp42splunk").strip() if sec else "misp42splunk"
    url, kw, _ = splunk_kw(cp)
    q = {"output_mode": "json"}
    try:
        r = requests.get(f"{url}/servicesNS/nobody/{app}/misp42splunk_instances/{name}", params=q, timeout=30, **kw)
    except requests.RequestException as e:
        return record("misp42splunk.instance", "FAIL", type(e).__name__, explain(e, "splunk"))
    if r.status_code == 404:
        return record("misp42splunk.instance", "FAIL", f"ไม่พบ instance {name} หรือไม่ได้ติดตั้งแอป {app}",
                      "ตรวจชื่อใน MISP42Splunk > Configuration และ [misp42splunk] instance / macro tbcert_misp_instance")
    if r.status_code == 403:
        record("misp42splunk.instance", "WARN", "token ไม่มีสิทธิ์อ่าน config ของ MISP42Splunk", "ข้ามการตรวจ config — ทดสอบ mispgetioc ต่อ")
    elif r.status_code >= 400:
        record("misp42splunk.instance", "FAIL", f"HTTP {r.status_code}", http_hint(r.status_code, "splunk"))
    else:
        c = r.json()["entry"][0]["content"]
        verify = str(c.get("misp_verifycert", "0")).lower() in ("1", "true")
        proxy = str(c.get("misp_use_proxy", "0")).lower() in ("1", "true")
        record("misp42splunk.instance", "PASS", f"{name} → {c.get('misp_url', '?')} · proxy {'เปิด' if proxy else 'ปิด'}")
        if not verify:
            record("misp42splunk.tls", "WARN", "ปิด Check MISP certificate อยู่",
                   "เปิด Check MISP certificate (ถ้าใช้ CA ภายในหรือ proxy ที่ถอด TLS ให้ใส่ MISP CA path) เพื่อกัน MITM ขโมย API key")
        else:
            record("misp42splunk.tls", "PASS", "ตรวจ certificate ของ MISP")
        mu = cp.get("misp", "url", fallback="").rstrip("/")
        if mu and c.get("misp_url", "").rstrip("/") != mu:
            record("misp42splunk.url", "WARN", f"URL ไม่ตรงกับ [misp] url ({mu})", "สคริปต์และ MISP42Splunk ควรชี้ MISP เดียวกัน")
        if proxy:
            try:
                pr = requests.get(f"{url}/servicesNS/nobody/{app}/misp42splunk_settings/proxy", params=q, timeout=30, **kw)
                if pr.ok:
                    pc = pr.json()["entry"][0]["content"]
                    on = str(pc.get("proxy_enabled", "0")).lower() in ("1", "true")
                    record("misp42splunk.proxy", "PASS" if on else "WARN",
                           f"proxy {pc.get('proxy_type', '')}://{pc.get('proxy_hostname', '?')}:{pc.get('proxy_port', '?')}" + ("" if on else " (ยังไม่ได้เปิด Enable)"),
                           "instance ใช้ proxy แต่ tab Proxy ยังไม่เปิด" if not on else "")
                    if not cp.get("misp", "proxy", fallback="").strip():
                        record("misp.proxy", "WARN", "[misp] proxy ของสคริปต์ว่าง แต่ Splunk ออกผ่าน proxy",
                               "ถ้าสคริปต์รันบนเครื่องที่ต้องผ่าน proxy เดียวกัน ให้ตั้ง [misp] proxy")
            except requests.RequestException:
                pass
    rows = splunk_search(cp, "misp42splunk.mispgetioc",
                         f"| mispgetioc misp_instance={name} last=1d to_ids=t limit=5 page=1 | stats count",
                         earliest="-1h", timeout=300)
    if rows is not None:
        n = int(rows[0].get("count", 0)) if rows else 0
        record("misp42splunk.mispgetioc", "PASS" if n else "WARN",
               f"mispgetioc จาก Splunk ได้ {n} รายการ (ตัวอย่างสูงสุด 5)" if n else "mispgetioc รันได้แต่ไม่มี IOC ใน 1 วัน",
               "ลอง last=7d หรือตรวจสิทธิ์ของ API key")
    spl = (f'| makeresults | eval misp_instance="{name}", misp_restsearch="attributes", publish_timestamp="7d", '
           'threat_level_id=split("1,2,3,4", ","), to_ids="true" '
           '| tojson publish_timestamp threat_level_id to_ids output_field=misp_http_body '
           '| mispfetch pipesplit=f expand_object=t limit=5 page=1 '
           '| where isnotnull(misp_attribute_uuid) | stats count dc(misp_type) as types')
    rows = splunk_search(cp, "misp42splunk.mispfetch", spl, earliest="-1h", timeout=300)
    if rows is not None:
        n = int(rows[0].get("count", 0)) if rows else 0
        record("misp42splunk.mispfetch", "PASS" if n else "WARN",
               f"mispfetch (tojson, หลาย threat level) ได้ {n} รายการ" if n else "mispfetch รันได้แต่ไม่มีผลใน 7 วัน",
               "ตรวจสิทธิ์ของ API key หรือขยาย publish_timestamp")


def check_hec(cp, allow_write: bool) -> None:
    print("\n▶ Splunk HEC")
    s = cp["splunk"] if cp.has_section("splunk") else {}
    hec = s.get("hec_url", "").strip() if s else ""
    tok = secret(s, "hec_token", "SPLUNK_HEC_TOKEN") if s else ""
    if not hec:
        return record("hec", "SKIP", "ไม่ได้ตั้ง hec_url (จำเป็นสำหรับ dashboard reconcile และ audit)")
    verify = verify_of(s.get("verify_tls"))
    base = hec.split("/services/collector")[0]
    r = call("hec.health", "splunk", "GET", f"{base}/services/collector/health", verify=verify)
    if r:
        record("hec.health", "PASS", "HEC เปิดใช้งาน")
    if not tok:
        return record("hec.token", "FAIL", "ไม่มี hec_token", "ใส่ env SPLUNK_HEC_TOKEN หรือ [splunk] hec_token")
    if not allow_write:
        return record("hec.token", "SKIP", "ไม่ได้ทดสอบ token (ใส่ --allow-write เพื่อส่ง test event 1 รายการ)")
    ev = {"event": {"action": "preflight", "at": int(time.time())}, "sourcetype": "tbcert:preflight",
          "index": s.get("hec_index", "threat_intel")}
    r = call("hec.token", "splunk HEC", "POST", hec, data=json.dumps(ev), verify=verify,
             headers={"Authorization": f"Splunk {tok}"})
    if r:
        record("hec.token", "PASS", f"ส่ง test event เข้า index {ev['index']} ได้ (sourcetype=tbcert:preflight)")


def check_s1(cp) -> None:
    print("\n▶ SentinelOne")
    if not cp.has_section("sentinelone") or not cp["sentinelone"].getboolean("enabled", False):
        return record("sentinelone", "SKIP", "ไม่ได้เปิดใช้ (enabled = false)")
    sec = cp["sentinelone"]
    tok = secret(sec, "api_token", "S1_API_TOKEN")
    if not tok:
        return record("sentinelone.token", "FAIL", "ไม่มี API token", "ใส่ env S1_API_TOKEN")
    r = call("sentinelone.blocklist", "sentinelone", "GET", f"{sec['url'].rstrip('/')}/web/api/v2.1/restrictions",
             params={"type": "black_hash", "limit": 1},
             headers={"Authorization": f"ApiToken {tok}"}, verify=verify_of(cp.get("push", "verify_tls", fallback="true")))
    if r:
        total = (r.json().get("pagination") or {}).get("totalItems", "?")
        record("sentinelone.blocklist", "PASS", f"อ่าน Blocklist ได้ (ปัจจุบัน {total} รายการ)")
        record("sentinelone.write", "SKIP", "ไม่ได้ทดสอบสิทธิ์เขียน — ใช้ push_blocklists.py --target sentinelone (dry-run) แล้วทดสอบ --apply กับ site ทดสอบ")


def check_imperva(cp) -> None:
    print("\n▶ Imperva WAF")
    if not cp.has_section("imperva") or not cp["imperva"].getboolean("enabled", False):
        return record("imperva", "SKIP", "ไม่ได้เปิดใช้ (enabled = false)")
    sec = cp["imperva"]
    api = sec.get("api_url", "https://my.imperva.com").rstrip("/")
    hdr = {"x-API-Id": secret(sec, "api_id", "IMPERVA_API_ID"), "x-API-Key": secret(sec, "api_key", "IMPERVA_API_KEY")}
    if not all(hdr.values()):
        return record("imperva.key", "FAIL", "ไม่มี api_id/api_key", "ใส่ env IMPERVA_API_ID / IMPERVA_API_KEY")
    for site in [x.strip() for x in sec.get("site_ids", "").split(",") if x.strip()]:
        r = call(f"imperva.site.{site}", "imperva", "POST", f"{api}/api/prov/v1/sites/status", data={"site_id": site},
                 headers=hdr, verify=verify_of(cp.get("push", "verify_tls", fallback="true")))
        if not r:
            continue
        b = r.json()
        if int(b.get("res", -1)) != 0:
            record(f"imperva.site.{site}", "FAIL", str(b.get("res_message")), "ตรวจ site_id และสิทธิ์ของ API key กับ site นี้")
            continue
        ips = next((len(x.get("ips", [])) for x in b.get("security", {}).get("acls", {}).get("rules", [])
                    if x.get("id") == "api.acl.blacklisted_ips"), 0)
        cap = sec.getint("max_entries", 1000)
        record(f"imperva.site.{site}", "PASS", f"{b.get('domain', site)} · blacklisted IPs ปัจจุบัน {ips} (max_entries {cap})")


def check_proofpoint(cp) -> None:
    print("\n▶ Proofpoint")
    if not cp.has_section("proofpoint") or not cp["proofpoint"].getboolean("enabled", False):
        return record("proofpoint", "SKIP", "ไม่ได้เปิดใช้ (enabled = false)")
    sec = cp["proofpoint"]
    if sec.get("mode", "csv").strip() == "csv":
        d = sec.get("csv_dir", "proofpoint_out")
        try:
            os.makedirs(d, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=d):
                pass
            record("proofpoint.csv", "PASS", f"เขียนโฟลเดอร์ {os.path.abspath(d)} ได้")
        except OSError as e:
            record("proofpoint.csv", "FAIL", str(e), "ตรวจสิทธิ์โฟลเดอร์ csv_dir")
        return
    key = secret(sec, "ptr_api_key", "PTR_API_KEY")
    if not key:
        return record("proofpoint.key", "FAIL", "ไม่มี PTR API key", "ใส่ env PTR_API_KEY")
    for t in ("email", "domain"):
        lid = sec.get(f"ptr_list_{t}", "").strip()
        if not lid:
            record(f"proofpoint.list.{t}", "WARN", f"ไม่ได้ตั้ง ptr_list_{t}")
            continue
        r = call(f"proofpoint.list.{t}", "proofpoint", "GET", f"{sec['ptr_url'].rstrip('/')}/api/lists/{lid}/members.json",
                 headers={"Authorization": key}, verify=verify_of(cp.get("push", "verify_tls", fallback="true")))
        if r:
            n = len(r.json()) if isinstance(r.json(), list) else "?"
            record(f"proofpoint.list.{t}", "PASS", f"อ่าน list {lid} ได้ ({n} รายการ)")


# --------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description="Pre-install connectivity and readiness checks for TA-tbcert-misp")
    ap.add_argument("-c", "--config", default="config.ini")
    ap.add_argument("--only", help="เลือก: misp,splunk,misp42splunk,data,spl,hec,sentinelone,imperva,proofpoint")
    ap.add_argument("--allow-write", action="store_true", help="อนุญาตส่ง HEC test event 1 รายการ")
    ap.add_argument("--json", help="บันทึกผลเป็น JSON")
    a = ap.parse_args()
    cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
    if not cp.read(a.config, encoding="utf-8"):
        sys.exit(f"อ่านไฟล์ config ไม่ได้: {a.config}")
    only = set(a.only.split(",")) if a.only else None

    def want(n):
        return only is None or n in only

    print(f"TA-tbcert-misp preflight · config {os.path.abspath(a.config)}")
    if want("misp"):
        check_misp(cp)
    if want("splunk"):
        check_splunk(cp)
    if cp.has_section("splunk"):
        if want("misp42splunk"):
            check_misp42splunk(cp)
        if want("data"):
            check_data(cp)
        if want("spl"):
            check_spl(cp)
        if want("hec"):
            check_hec(cp, a.allow_write)
    if want("sentinelone"):
        check_s1(cp)
    if want("imperva"):
        check_imperva(cp)
    if want("proofpoint"):
        check_proofpoint(cp)

    c = {k: sum(1 for r in RESULTS if r["status"] == k) for k in ("PASS", "WARN", "FAIL", "SKIP")}
    print(f"\nสรุป: PASS {c['PASS']} · WARN {c['WARN']} · FAIL {c['FAIL']} · SKIP {c['SKIP']}")
    print("พร้อมติดตั้งแอป" if c["FAIL"] == 0 else "ยังไม่พร้อม — แก้รายการ FAIL ก่อนติดตั้งแอป")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"at": int(time.time()), "summary": c, "results": RESULTS}, fh, ensure_ascii=False, indent=2)
    sys.exit(1 if c["FAIL"] else 0)


if __name__ == "__main__":
    main()
