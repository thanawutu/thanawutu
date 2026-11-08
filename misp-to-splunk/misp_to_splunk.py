#!/usr/bin/env python3
"""
misp_to_splunk.py — ดึง IOC จาก MISP ของ TB-CERT เข้า Splunk KV Store
เพื่อใช้ (1) detect/correlate กับ log ใน Splunk และ (2) ส่งออกเป็น blocklist
ให้ Firewall / Proxy / EDR / Email Gateway / DNS ของธนาคาร

Flow:
  MISP /attributes/restSearch  ->  normalize + filter (TLP, tag, allowlist, TTL)
  -> Splunk KV Store (upsert ด้วย _key = attribute uuid [+ส่วนประกอบ])
  -> ลบ IOC ที่หมดอายุ / ถูกลบ / ถูกปลด to_ids ใน MISP
  -> (option) ส่ง audit log เข้า Splunk HEC

ใช้ได้ทั้ง cron/Task Scheduler บนเครื่อง jump host หรือรันเป็น scripted input ใน Splunk
ต้องการเพียง Python 3.8+ และ requests

ตัวอย่าง:
  python3 misp_to_splunk.py -c config.ini --initial      # ครั้งแรก ดึงย้อนหลังเต็ม
  python3 misp_to_splunk.py -c config.ini                # รอบปกติ (incremental)
  python3 misp_to_splunk.py -c config.ini --dry-run -v   # ทดสอบ ไม่เขียน Splunk
"""
from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable, Iterator

import requests

LOG = logging.getLogger("misp_to_splunk")

# MISP attribute type -> (indicator_type ใน Splunk, ส่วนของ value ที่จะใช้)
# composite type ใน MISP ใช้ "|" คั่น เช่น "ip-dst|port" = "1.2.3.4|443"
TYPE_MAP: dict[str, list[tuple[str, int]]] = {
    "ip-dst": [("ip", 0)],
    "ip-src": [("ip", 0)],
    "ip-dst|port": [("ip", 0)],
    "ip-src|port": [("ip", 0)],
    "domain": [("domain", 0)],
    "hostname": [("domain", 0)],
    "domain|ip": [("domain", 0), ("ip", 1)],
    "url": [("url", 0)],
    "md5": [("md5", 0)],
    "sha1": [("sha1", 0)],
    "sha256": [("sha256", 0)],
    "filename|md5": [("md5", 1)],
    "filename|sha1": [("sha1", 1)],
    "filename|sha256": [("sha256", 1)],
    "email-src": [("email", 0)],
}
TTL_GROUP = {"ip": "ip", "domain": "domain", "url": "url", "md5": "hash",
             "sha1": "hash", "sha256": "hash", "email": "email"}


# --------------------------------------------------------------------------- config
@dataclass
class Settings:
    misp_url: str
    misp_key: str
    misp_verify: bool | str
    proxy: str | None
    types: list[str]
    lookback: str
    initial_lookback: str
    page_size: int
    published_only: bool
    to_ids_only: bool
    enforce_warninglist: bool
    allowed_tlp: set[str]
    exclude_tags: set[str]
    allowlist_file: str | None
    ttl_days: dict[str, int]
    splunk_url: str
    splunk_token: str
    splunk_app: str
    collection: str
    splunk_verify: bool | str
    hec_url: str | None = None
    hec_token: str | None = None
    hec_index: str = "threat_intel"


def _verify(val: str) -> bool | str:
    v = val.strip()
    if v.lower() in ("true", "yes", "1"):
        return True
    if v.lower() in ("false", "no", "0"):
        return False
    return v  # path ไปยัง CA bundle


def _csv(val: str) -> list[str]:
    return [x.strip() for x in val.split(",") if x.strip()]


def load_settings(path: str) -> Settings:
    cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
    if not cp.read(path, encoding="utf-8"):
        sys.exit(f"อ่านไฟล์ config ไม่ได้: {path}")
    m, f, t, s = cp["misp"], cp["filter"], cp["ttl"], cp["splunk"]
    misp_key = os.environ.get("MISP_API_KEY") or m.get("api_key", "")
    splunk_token = os.environ.get("SPLUNK_TOKEN") or s.get("token", "")
    if not misp_key:
        sys.exit("ไม่พบ MISP API key (config [misp] api_key หรือ env MISP_API_KEY)")
    base = os.path.dirname(os.path.abspath(path))
    allow = f.get("allowlist_file", "").strip()
    return Settings(
        misp_url=m["url"].rstrip("/"),
        misp_key=misp_key,
        misp_verify=_verify(m.get("verify_tls", "true")),
        proxy=m.get("proxy", "").strip() or None,
        types=_csv(m.get("types", ",".join(TYPE_MAP))),
        lookback=m.get("lookback", "1h"),
        initial_lookback=m.get("initial_lookback", "90d"),
        page_size=m.getint("page_size", 1000),
        published_only=f.getboolean("published_only", True),
        to_ids_only=f.getboolean("to_ids_only", True),
        enforce_warninglist=f.getboolean("enforce_warninglist", True),
        allowed_tlp={x.lower() for x in _csv(f.get("allowed_tlp", ""))},
        exclude_tags={x.lower() for x in _csv(f.get("exclude_tags", ""))},
        allowlist_file=os.path.join(base, allow) if allow else None,
        ttl_days={k: t.getint(k) for k in ("ip", "domain", "url", "hash", "email")},
        splunk_url=s["url"].rstrip("/"),
        splunk_token=splunk_token,
        splunk_app=s.get("app", "TA-tbcert-misp"),
        collection=s.get("collection", "tbcert_misp_ioc"),
        splunk_verify=_verify(s.get("verify_tls", "true")),
        hec_url=s.get("hec_url", "").strip() or None,
        hec_token=os.environ.get("SPLUNK_HEC_TOKEN") or s.get("hec_token", "").strip() or None,
        hec_index=s.get("hec_index", "threat_intel"),
    )


# --------------------------------------------------------------------------- allowlist
class Allowlist:
    def __init__(self, path: str | None):
        self.nets: list[ipaddress._BaseNetwork] = []
        self.domains: set[str] = set()
        self.values: set[str] = set()
        if not path or not os.path.exists(path):
            if path:
                LOG.warning("ไม่พบ allowlist file %s — แนะนำให้มีเพื่อกันการ block ระบบสำคัญ", path)
            return
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                try:
                    self.nets.append(ipaddress.ip_network(line, strict=False))
                    continue
                except ValueError:
                    pass
                if "/" in line or ":" in line:
                    self.values.add(line)
                else:
                    self.domains.add(line.lstrip("."))
        LOG.info("allowlist: %d network, %d domain, %d value",
                 len(self.nets), len(self.domains), len(self.values))

    def hit(self, itype: str, value: str) -> bool:
        v = value.lower()
        if v in self.values:
            return True
        if itype == "ip":
            try:
                ip = ipaddress.ip_address(v)
            except ValueError:
                return False
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                return True  # ไม่ block private/reserved IP จาก feed ภายนอก
            return any(ip in n for n in self.nets)
        host = v
        if itype == "url":
            host = v.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        elif itype == "email":
            host = v.rsplit("@", 1)[-1]
        elif itype != "domain":
            return False
        parts = host.split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))


# --------------------------------------------------------------------------- MISP
class MispClient:
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": cfg.misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "tbcert-misp-to-splunk/1.0",
        })
        self.s.verify = cfg.misp_verify
        if cfg.proxy:
            self.s.proxies = {"https": cfg.proxy, "http": cfg.proxy}

    def attributes(self, since: str, include_revoked: bool) -> Iterator[dict]:
        """ดึง attribute ที่ถูกแก้ไขภายในช่วง since (เช่น '1h', '90d')
        include_revoked=True: ดึง attribute ที่ถูกลบ/ปลด to_ids มาด้วย เพื่อเอาออกจาก blocklist"""
        body: dict = {
            "returnFormat": "json",
            "type": self.cfg.types,
            "timestamp": since,
            "includeEventTags": True,
            "includeEventUuid": True,
            "enforceWarninglist": self.cfg.enforce_warninglist,
            "limit": self.cfg.page_size,
        }
        if self.cfg.published_only:
            body["published"] = True
        if include_revoked:
            body["deleted"] = [0, 1]
        else:
            body["deleted"] = 0
            if self.cfg.to_ids_only:
                body["to_ids"] = True
        page = 1
        while True:
            body["page"] = page
            for attempt in range(4):
                try:
                    r = self.s.post(f"{self.cfg.misp_url}/attributes/restSearch",
                                    data=json.dumps(body), timeout=300)
                    r.raise_for_status()
                    break
                except requests.RequestException as e:
                    if attempt == 3:
                        raise
                    wait = 2 ** (attempt + 1)
                    LOG.warning("MISP error (%s) — retry ใน %ss", e, wait)
                    time.sleep(wait)
            attrs = r.json().get("response", {}).get("Attribute", [])
            LOG.debug("MISP page %d: %d attributes", page, len(attrs))
            yield from attrs
            if len(attrs) < self.cfg.page_size:
                return
            page += 1


# --------------------------------------------------------------------------- normalize
@dataclass
class Stats:
    fetched: int = 0
    upserts: int = 0
    revoked: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1


def _tags(attr: dict) -> list[str]:
    tags = [t.get("name", "") for t in attr.get("Tag", []) or []]
    tags += [t.get("name", "") for t in (attr.get("Event", {}) or {}).get("Tag", []) or []]
    return sorted({t for t in tags if t})


def _epoch(val) -> int | None:
    if val in (None, ""):
        return None
    if isinstance(val, (int, float)) or str(val).isdigit():
        return int(val)
    # MISP first_seen/last_seen เป็น ISO8601 เช่น 2026-11-01T10:00:00.000000+07:00
    from datetime import datetime
    try:
        return int(datetime.fromisoformat(str(val).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def normalize(attr: dict, cfg: Settings, allow: Allowlist, stats: Stats,
              now: int) -> tuple[list[dict], list[str]]:
    """คืน (records ที่จะ upsert, _key ที่ต้องลบออก)"""
    atype = attr.get("type", "")
    mapping = TYPE_MAP.get(atype)
    uuid = attr.get("uuid", "")
    if not mapping or not uuid:
        stats.skip("unsupported_type")
        return [], []
    keys = [f"{uuid}:{i}" for i in range(len(mapping))]

    # ถูกลบหรือปลด to_ids ใน MISP -> เอาออกจาก blocklist
    if str(attr.get("deleted", False)).lower() in ("true", "1") or \
            (cfg.to_ids_only and str(attr.get("to_ids", True)).lower() in ("false", "0")):
        return [], keys

    tags = _tags(attr)
    ltags = {t.lower() for t in tags}
    if ltags & cfg.exclude_tags:
        stats.skip("excluded_tag")
        return [], keys
    tlp = next((t for t in ltags if t.startswith("tlp:")), "")
    if cfg.allowed_tlp and tlp and tlp not in cfg.allowed_tlp:
        stats.skip(f"tlp_not_allowed:{tlp}")
        return [], keys

    ts = _epoch(attr.get("last_seen")) or _epoch(attr.get("timestamp")) or now
    event = attr.get("Event", {}) or {}
    parts = str(attr.get("value", "")).split("|")
    recs, drop = [], []
    for (itype, idx), key in zip(mapping, keys):
        if idx >= len(parts) or not parts[idx].strip():
            stats.skip("empty_value")
            continue
        value = parts[idx].strip()
        if itype in ("domain", "email", "md5", "sha1", "sha256"):
            value = value.lower().rstrip(".")
        if allow.hit(itype, value):
            stats.skip("allowlisted")
            drop.append(key)
            continue
        expires = ts + cfg.ttl_days[TTL_GROUP[itype]] * 86400
        if expires < now:
            stats.skip("expired")
            drop.append(key)
            continue
        recs.append({
            "_key": key,
            "indicator": value,
            "indicator_type": itype,
            "misp_type": atype,
            "category": attr.get("category", ""),
            "event_id": str(attr.get("event_id", "")),
            "event_uuid": event.get("uuid", ""),
            "event_info": event.get("info", ""),
            "attribute_uuid": uuid,
            "comment": attr.get("comment", ""),
            "tags": tags,
            "tlp": tlp,
            "source": "TB-CERT MISP",
            "first_seen": _epoch(attr.get("first_seen")) or "",
            "last_seen": ts,
            "updated": now,
            "expires": expires,
        })
    return recs, drop


# --------------------------------------------------------------------------- Splunk
class SplunkKV:
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.base = (f"{cfg.splunk_url}/servicesNS/nobody/{cfg.splunk_app}"
                     f"/storage/collections/data/{cfg.collection}")
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {cfg.splunk_token}",
                               "Content-Type": "application/json"})
        self.s.verify = cfg.splunk_verify

    def upsert(self, recs: list[dict]) -> None:
        for i in range(0, len(recs), 500):  # batch_save รับได้สูงสุด 1000 ต่อครั้ง (default)
            r = self.s.post(f"{self.base}/batch_save", data=json.dumps(recs[i:i + 500]),
                            timeout=120)
            r.raise_for_status()

    def delete_keys(self, keys: Iterable[str]) -> None:
        keys = list(keys)
        for i in range(0, len(keys), 200):
            q = json.dumps({"$or": [{"_key": k} for k in keys[i:i + 200]]})
            r = self.s.delete(self.base, params={"query": q}, timeout=120)
            r.raise_for_status()

    def purge_expired(self, now: int) -> None:
        r = self.s.delete(self.base, params={"query": json.dumps({"expires": {"$lt": now}})},
                          timeout=120)
        r.raise_for_status()


def send_hec(cfg: Settings, event: dict) -> None:
    if not (cfg.hec_url and cfg.hec_token):
        return
    try:
        requests.post(cfg.hec_url, timeout=30, verify=cfg.splunk_verify,
                      headers={"Authorization": f"Splunk {cfg.hec_token}"},
                      data=json.dumps({"event": event, "index": cfg.hec_index,
                                       "sourcetype": "tbcert:misp:sync"})).raise_for_status()
    except requests.RequestException as e:
        LOG.warning("ส่ง HEC ไม่สำเร็จ: %s", e)


# --------------------------------------------------------------------------- main
def run(cfg: Settings, initial: bool, dry_run: bool) -> Stats:
    now = int(time.time())
    allow = Allowlist(cfg.allowlist_file)
    misp = MispClient(cfg)
    stats = Stats()
    upserts: dict[str, dict] = {}
    drops: set[str] = set()

    since = cfg.initial_lookback if initial else cfg.lookback
    # initial: ดึงเฉพาะที่ใช้งานได้ / incremental: ดึงรวมที่ถูกลบหรือปลด to_ids เพื่อเอาออก
    for attr in misp.attributes(since, include_revoked=not initial):
        stats.fetched += 1
        recs, drop = normalize(attr, cfg, allow, stats, now)
        for rec in recs:
            upserts[rec["_key"]] = rec
            drops.discard(rec["_key"])
        for k in drop:
            if k not in upserts:
                drops.add(k)
    stats.upserts, stats.revoked = len(upserts), len(drops)

    LOG.info("fetched=%d upsert=%d revoke=%d skipped=%s",
             stats.fetched, stats.upserts, stats.revoked, stats.skipped)
    if dry_run:
        for rec in list(upserts.values())[:20]:
            LOG.info("[dry-run] %s %s (%s)", rec["indicator_type"], rec["indicator"],
                     rec["event_info"][:60])
        return stats

    if not cfg.splunk_token:
        sys.exit("ไม่พบ Splunk token (config [splunk] token หรือ env SPLUNK_TOKEN)")
    kv = SplunkKV(cfg)
    if upserts:
        kv.upsert(list(upserts.values()))
    if drops:
        kv.delete_keys(drops)
    kv.purge_expired(now)
    send_hec(cfg, {"action": "sync", "mode": "initial" if initial else "incremental",
                   "since": since, "fetched": stats.fetched, "upserted": stats.upserts,
                   "revoked": stats.revoked, "skipped": stats.skipped})
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Sync TB-CERT MISP IOCs to Splunk KV Store")
    ap.add_argument("-c", "--config", default="config.ini")
    ap.add_argument("--initial", action="store_true", help="ดึงย้อนหลังตาม initial_lookback")
    ap.add_argument("--dry-run", action="store_true", help="ไม่เขียนเข้า Splunk")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    run(load_settings(a.config), a.initial, a.dry_run)


if __name__ == "__main__":
    main()
