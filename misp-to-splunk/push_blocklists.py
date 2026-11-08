#!/usr/bin/env python3
"""
push_blocklists.py — ส่ง IOC ที่ action=block จาก Splunk KV store ไปยังเครื่องมือ block ของธนาคาร

  hash  (sha1/sha256 ตามที่ตั้ง)  -> SentinelOne  Blocklist           (/web/api/v2.1/restrictions)
  ip                              -> Imperva Cloud WAF  ACL Blacklisted IPs (/api/prov/v1/sites/configure/acl)
  email / domain                  -> Proofpoint  (ไฟล์ CSV สำหรับ import หรือ Proofpoint Threat Response list API)

หลักการ
  * ค่าเริ่มต้นเป็น dry-run — แสดงแผน (เพิ่ม/ลบ) และเขียนรายงาน CSV; ต้องใส่ --apply จึงจะเปลี่ยนค่าจริง
  * ทำงานแบบ diff กับ state file: เพิ่มเฉพาะของใหม่ และลบเฉพาะรายการที่สคริปต์นี้เคยเพิ่มเอง
    (รายการที่ทีม SOC ใส่เองในเครื่องมือจะไม่ถูกแตะ)
  * มี safety limit: จำนวนเพิ่ม/ลบต่อรอบ และขนาดสูงสุดของแต่ละปลายทาง
  * ข้อมูล API ของแต่ละ vendor ต่างกันตามรุ่น/สัญญา — ทดสอบกับ console จริงด้วย --target <ชื่อ> ทีละตัวก่อน

ตัวอย่าง
  python3 push_blocklists.py -c config.ini                       # dry-run ทุกปลายทาง
  python3 push_blocklists.py -c config.ini --target sentinelone  # dry-run เฉพาะ S1
  python3 push_blocklists.py -c config.ini --apply               # ส่งจริง
"""
from __future__ import annotations

import argparse
import configparser
import csv
import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field

import requests

from export_edl import load_splunk

LOG = logging.getLogger("push_blocklists")


# --------------------------------------------------------------------------- data
@dataclass
class Ioc:
    value: str
    itype: str
    event_id: str = ""
    event_info: str = ""
    expires: int = 0

    def description(self, prefix: str) -> str:
        return f"{prefix} event {self.event_id}: {self.event_info}"[:180]


@dataclass
class Plan:
    target: str
    add: list[Ioc] = field(default_factory=list)
    remove: list[str] = field(default_factory=list)      # ค่าที่จะลบ (เคยเพิ่มโดยสคริปต์นี้)
    keep: int = 0
    dropped_over_cap: int = 0


def fetch_block_iocs(scfg) -> list[Ioc]:
    base = (f"{scfg.splunk_url}/servicesNS/nobody/{scfg.splunk_app}"
            f"/storage/collections/data/{scfg.collection}")
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {scfg.splunk_token}"
    s.verify = scfg.splunk_verify
    now, out, skip = int(time.time()), [], 0
    while True:
        r = s.get(base, timeout=120, params={
            "query": json.dumps({"expires": {"$gt": now}, "action": {"$ne": "detect"}}),
            "fields": "indicator,indicator_type,event_id,event_info,expires,last_seen",
            "sort": "last_seen:-1", "limit": 10000, "skip": skip})
        r.raise_for_status()
        rows = r.json()
        for row in rows:
            if str(row.get("status", "active")).startswith("revoked"):
                continue
            out.append(Ioc(str(row.get("indicator", "")).strip(), row.get("indicator_type", ""),
                           str(row.get("event_id", "")), row.get("event_info", ""),
                           int(float(row.get("expires", 0) or 0))))
        if len(rows) < 10000:
            return [i for i in out if i.value]
        skip += 10000


# --------------------------------------------------------------------------- state
class State:
    """จำว่าสคริปต์เพิ่มอะไรไว้ที่ปลายทางไหน (และ id ฝั่ง vendor) เพื่อให้ลบได้ถูกตัว"""

    def __init__(self, path: str):
        self.path = path
        self.data: dict[str, dict[str, dict]] = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self.data = json.load(fh)

    def owned(self, target: str) -> dict[str, dict]:
        return self.data.setdefault(target, {})

    def save(self) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".state_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)


def make_plan(target: str, wanted: list[Ioc], owned: dict[str, dict], cap: int) -> Plan:
    """wanted เรียงจากใหม่ไปเก่า; ถ้าเกิน cap จะตัดตัวเก่าทิ้ง"""
    plan = Plan(target)
    seen: dict[str, Ioc] = {}
    for ioc in wanted:
        seen.setdefault(ioc.value.lower(), ioc)
    items = list(seen.values())
    if cap and len(items) > cap:
        plan.dropped_over_cap = len(items) - cap
        items = items[:cap]
    want_keys = {i.value.lower() for i in items}
    plan.add = [i for i in items if i.value.lower() not in owned]
    plan.remove = sorted(k for k in owned if k not in want_keys)
    plan.keep = len(want_keys) - len(plan.add)
    return plan


# --------------------------------------------------------------------------- adapters
class SentinelOne:
    """Blocklist (restrictions) — 1 รายการต่อ hash ต่อ OS
    ตรวจในคอนโซลของคุณว่ารองรับ SHA256 ใน Blocklist หรือไม่ (เวอร์ชันเก่ารองรับเฉพาะ SHA1)"""
    name = "sentinelone"

    def __init__(self, sec, verify):
        self.url = sec["url"].rstrip("/")
        self.hash_types = {x.strip() for x in sec.get("hash_types", "sha1,sha256").split(",")}
        self.os_types = [x.strip() for x in sec.get("os_types", "windows,macos,linux").split(",")]
        scope = sec.get("scope", "tenant").strip()          # tenant | account:<id> | site:<id>
        if scope.startswith("site:"):
            self.filter = {"siteIds": [scope[5:]]}
        elif scope.startswith("account:"):
            self.filter = {"accountIds": [scope[8:]]}
        else:
            self.filter = {"tenant": True}
        self.prefix = sec.get("description_prefix", "TB-CERT MISP")
        self.cap = sec.getint("max_entries", 20000)
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"Authorization": f"ApiToken {os.environ.get('S1_API_TOKEN') or sec.get('api_token', '')}",
                               "Content-Type": "application/json"})

    def wants(self, ioc: Ioc) -> bool:
        return ioc.itype in self.hash_types

    def add(self, ioc: Ioc) -> dict:
        ids = []
        for os_type in self.os_types:
            r = self.s.post(f"{self.url}/web/api/v2.1/restrictions", timeout=60, data=json.dumps({
                "data": {"type": "black_hash", "value": ioc.value, "osType": os_type,
                         "description": ioc.description(self.prefix)},
                "filter": self.filter}))
            if r.status_code == 409:        # มีอยู่แล้ว (เช่น SOC ใส่เอง) — ไม่ถือเป็นของเรา
                LOG.info("S1: %s (%s) มีอยู่แล้ว ข้าม", ioc.value, os_type)
                continue
            r.raise_for_status()
            for item in (r.json().get("data") or []):
                if item.get("id"):
                    ids.append(item["id"])
        return {"ids": ids}

    def remove_many(self, entries: dict[str, dict]) -> None:
        ids = [i for e in entries.values() for i in e.get("ids", [])]
        for n in range(0, len(ids), 500):
            r = self.s.delete(f"{self.url}/web/api/v2.1/restrictions", timeout=60,
                              data=json.dumps({"data": {"type": "black_hash", "ids": ids[n:n + 500]}}))
            r.raise_for_status()


class ImpervaWaf:
    """Imperva Cloud WAF — ACL 'Blacklisted IPs' ต่อ site (API นี้แทนที่ทั้งรายการ)
    สคริปต์จะอ่านรายการปัจจุบันก่อน แล้ว รวม (รายการเดิมที่ไม่ใช่ของเรา + ของเรา) เพื่อไม่ทับ IP ที่ SOC ใส่เอง"""
    name = "imperva"

    def __init__(self, sec, verify):
        self.api = sec.get("api_url", "https://my.imperva.com").rstrip("/")
        self.sites = [x.strip() for x in sec["site_ids"].split(",") if x.strip()]
        self.cap = sec.getint("max_entries", 1000)
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"x-API-Id": os.environ.get("IMPERVA_API_ID") or sec.get("api_id", ""),
                               "x-API-Key": os.environ.get("IMPERVA_API_KEY") or sec.get("api_key", "")})
        self._pending: dict[str, set[str]] = {}

    def wants(self, ioc: Ioc) -> bool:
        return ioc.itype == "ip"

    def _current(self, site: str) -> set[str]:
        r = self.s.post(f"{self.api}/api/prov/v1/sites/status", data={"site_id": site}, timeout=60)
        r.raise_for_status()
        body = r.json()
        if int(body.get("res", 0)) != 0:
            raise RuntimeError(f"Imperva site {site}: {body.get('res_message')}")
        for rule in body.get("security", {}).get("acls", {}).get("rules", []):
            if rule.get("id") == "api.acl.blacklisted_ips":
                return {str(x) for x in rule.get("ips", [])}
        return set()

    def apply(self, plan: Plan, owned: dict[str, dict]) -> None:
        ours = (set(owned) - set(plan.remove)) | {i.value.lower() for i in plan.add}
        for site in self.sites:
            current = {x.lower() for x in self._current(site)}
            manual = current - set(owned)                 # IP ที่ไม่ได้มาจากสคริปต์นี้
            final = sorted(manual | ours)
            r = self.s.post(f"{self.api}/api/prov/v1/sites/configure/acl", timeout=120, data={
                "site_id": site, "rule_id": "api.acl.blacklisted_ips", "ips": ",".join(final)})
            r.raise_for_status()
            body = r.json()
            if int(body.get("res", 0)) != 0:
                raise RuntimeError(f"Imperva site {site}: {body.get('res_message')}")
            LOG.info("Imperva site %s: blacklisted_ips = %d (manual %d + MISP %d)",
                     site, len(final), len(manual), len(ours))


class Proofpoint:
    """mode=csv : เขียนไฟล์ sender/domain blocklist สำหรับ import ใน Proofpoint (PoD/PPS) — ใช้ได้ทุกรุ่น
       mode=ptr : เพิ่ม/ลบสมาชิกใน list ของ Proofpoint Threat Response (PTR/TRAP)
                  ที่ผูกกับ blocklist ของ PPS/PoD ไว้แล้ว (ตรวจ endpoint กับเวอร์ชัน PTR ของคุณ)"""
    name = "proofpoint"

    def __init__(self, sec, verify):
        self.mode = sec.get("mode", "csv").strip()
        self.types = {x.strip() for x in sec.get("types", "email,domain").split(",")}
        self.cap = sec.getint("max_entries", 50000)
        self.prefix = sec.get("description_prefix", "TB-CERT MISP")
        self.csv_dir = sec.get("csv_dir", "proofpoint_out")
        if self.mode == "ptr":
            self.url = sec["ptr_url"].rstrip("/")
            self.lists = {"email": sec.get("ptr_list_email", ""), "domain": sec.get("ptr_list_domain", "")}
            self.s = requests.Session()
            self.s.verify = verify
            self.s.headers.update({"Authorization": os.environ.get("PTR_API_KEY") or sec.get("ptr_api_key", ""),
                                   "Content-Type": "application/json"})

    def wants(self, ioc: Ioc) -> bool:
        return ioc.itype in self.types

    def write_csv(self, iocs: list[Ioc]) -> None:
        os.makedirs(self.csv_dir, exist_ok=True)
        for t in sorted(self.types):
            path = os.path.join(self.csv_dir, f"proofpoint_block_{t}.csv")
            rows = sorted({i.value.lower(): i for i in iocs if i.itype == t}.values(), key=lambda i: i.value)
            fd, tmp = tempfile.mkstemp(dir=self.csv_dir, prefix=".tmp_")
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["value", "type", "comment"])
                for i in rows:
                    w.writerow([i.value, t, i.description(self.prefix)])
            os.replace(tmp, path)
            LOG.info("Proofpoint CSV: %s (%d รายการ)", path, len(rows))

    def add(self, ioc: Ioc) -> dict:
        list_id = self.lists.get(ioc.itype)
        if not list_id:
            raise RuntimeError(f"ไม่ได้ตั้ง ptr_list_{ioc.itype}")
        r = self.s.post(f"{self.url}/api/lists/{list_id}/members.json", timeout=60, data=json.dumps({
            "member": ioc.value, "description": ioc.description(self.prefix)}))
        r.raise_for_status()
        body = r.json() if r.content else {}
        if isinstance(body, list):
            body = body[0] if body else {}
        return {"list": list_id, "id": body.get("id")}

    def remove_many(self, entries: dict[str, dict]) -> None:
        for value, e in entries.items():
            if not e.get("id"):
                LOG.warning("PTR: ไม่มี id ของ %s — ลบเองในคอนโซล", value)
                continue
            r = self.s.delete(f"{self.url}/api/lists/{e['list']}/members/{e['id']}.json", timeout=60)
            if r.status_code != 404:
                r.raise_for_status()


# --------------------------------------------------------------------------- main
def write_report(path: str, plans: list[Plan]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target", "change", "value", "type", "event_id", "event_info"])
        for p in plans:
            for i in p.add:
                w.writerow([p.target, "add", i.value, i.itype, i.event_id, i.event_info])
            for v in p.remove:
                w.writerow([p.target, "remove", v, "", "", ""])


def main() -> None:
    ap = argparse.ArgumentParser(description="Push TB-CERT MISP block IOCs to SentinelOne / Imperva / Proofpoint")
    ap.add_argument("-c", "--config", default="config.ini")
    ap.add_argument("--target", choices=["sentinelone", "imperva", "proofpoint"], action="append")
    ap.add_argument("--apply", action="store_true", help="ส่งจริง (ไม่ใส่ = dry-run)")
    ap.add_argument("--report", default="push_plan.csv")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
    cp.read(a.config, encoding="utf-8")
    push = cp["push"] if cp.has_section("push") else cp["DEFAULT"]
    verify_raw = push.get("verify_tls", "true").strip()
    verify = verify_raw.lower() not in ("false", "0", "no") and (verify_raw if os.path.exists(verify_raw) else True)
    max_add = push.getint("max_add_per_run", 2000)
    max_remove = push.getint("max_remove_per_run", 500)
    state = State(push.get("state_file", "push_state.json"))

    adapters = []
    for cls in (SentinelOne, ImpervaWaf, Proofpoint):
        if (a.target and cls.name not in a.target) or not cp.has_section(cls.name):
            continue
        if not cp[cls.name].getboolean("enabled", False):
            LOG.info("%s: ปิดอยู่ (enabled = false)", cls.name)
            continue
        adapters.append(cls(cp[cls.name], verify))
    if not adapters:
        sys.exit("ไม่มีปลายทางที่เปิดใช้ — ตั้ง enabled = true ใน [sentinelone] / [imperva] / [proofpoint]")

    iocs = fetch_block_iocs(load_splunk(a.config))
    LOG.info("IOC action=block จาก Splunk: %d", len(iocs))

    plans = []
    for ad in adapters:
        wanted = [i for i in iocs if ad.wants(i)]
        if isinstance(ad, Proofpoint) and ad.mode == "csv":
            plan = make_plan(ad.name, wanted, {}, ad.cap)
            LOG.info("[proofpoint/csv] %d รายการ%s", len(plan.add),
                     f" (ตัดเกิน cap {plan.dropped_over_cap})" if plan.dropped_over_cap else "")
            if a.apply:
                ad.write_csv(plan.add)
            continue
        owned = state.owned(ad.name)
        plan = make_plan(ad.name, wanted, owned, ad.cap)
        plans.append(plan)
        LOG.info("[%s] เพิ่ม %d · ลบ %d · คงเดิม %d%s", ad.name, len(plan.add), len(plan.remove), plan.keep,
                 f" · ตัดเกิน cap {plan.dropped_over_cap}" if plan.dropped_over_cap else "")
        if len(plan.add) > max_add or len(plan.remove) > max_remove:
            LOG.error("[%s] เปลี่ยนแปลงเกิน safety limit (เพิ่ม ≤ %d, ลบ ≤ %d) — ข้าม ตรวจรายงานแล้วปรับ [push]",
                      ad.name, max_add, max_remove)
            continue
        if not a.apply:
            continue
        try:
            if isinstance(ad, ImpervaWaf):
                ad.apply(plan, owned)
                for v in plan.remove:
                    owned.pop(v, None)
                for i in plan.add:
                    owned[i.value.lower()] = {"event_id": i.event_id, "added": int(time.time())}
            else:
                if plan.remove:
                    ad.remove_many({v: owned[v] for v in plan.remove})
                    for v in plan.remove:
                        owned.pop(v, None)
                for i in plan.add:
                    meta = ad.add(i)
                    meta.update({"event_id": i.event_id, "added": int(time.time())})
                    owned[i.value.lower()] = meta
        finally:
            state.save()                                  # บันทึกความคืบหน้าแม้ล้มกลางทาง

    write_report(a.report, plans)
    LOG.info("%s — รายงาน: %s", "ส่งจริงแล้ว" if a.apply else "DRY-RUN (ยังไม่เปลี่ยนอะไร ใส่ --apply เพื่อส่งจริง)",
             a.report)


if __name__ == "__main__":
    main()
