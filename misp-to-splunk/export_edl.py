#!/usr/bin/env python3
"""
export_edl.py — อ่าน IOC จาก Splunk KV Store แล้วเขียนเป็นไฟล์ text แยกตามชนิด
สำหรับให้เครื่องมือของธนาคารดึงไปใช้ block:

  ip.txt      -> Palo Alto EDL (IP List), FortiGate External Threat Feed (IP), Check Point
  domain.txt  -> Palo Alto EDL (Domain List), FortiGuard DNS filter, DNS RPZ, Proxy
  url.txt     -> Palo Alto EDL (URL List, ตัด scheme ออกแล้ว), Proxy / Secure Web Gateway
  sha256.txt / md5.txt / sha1.txt -> EDR / Sandbox / Email gateway (custom IOC import)
  email.txt   -> Email Security Gateway (sender blocklist)
  rpz.zone    -> DNS Response Policy Zone (BIND/Infoblox)

นำไฟล์ไปวางบน web server ภายใน (HTTPS + จำกัด IP ที่เข้าถึงได้) ให้ firewall poll ตามรอบ
หรือใช้ไฟล์เป็น input ของ SOAR playbook ที่เรียก API ของแต่ละ vendor

ตัวอย่าง:  python3 export_edl.py -c config.ini -o /var/www/edl
"""
from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import tempfile
import time

import requests

LOG = logging.getLogger("export_edl")
# ค่าเริ่มต้นแบบระวัง — ตรวจขีดจำกัด EDL ของรุ่น firewall จริงแล้วปรับด้วย --max ip=... domain=...
MAX_PER_LIST = {"ip": 150000, "domain": 150000, "url": 100000}
# ส่งออกเฉพาะชนิดที่เครื่องมือ block รองรับ (ชนิดอื่นเช่น filename, mutex ใช้ detect ใน Splunk)
BLOCKABLE = {"ip", "domain", "url", "md5", "sha1", "sha256", "sha512", "email"}


def load_splunk(path: str) -> argparse.Namespace:
    """อ่านเฉพาะ [splunk] — ใช้ได้ทั้งกับวิธี script, index เดิม และ MISP42Splunk"""
    cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
    if not cp.read(path, encoding="utf-8"):
        raise SystemExit(f"อ่านไฟล์ config ไม่ได้: {path}")
    s = cp["splunk"]
    v = s.get("verify_tls", "true").strip()
    verify = True if v.lower() in ("true", "yes", "1") else False if v.lower() in ("false", "no", "0") else v
    token = os.environ.get("SPLUNK_TOKEN") or s.get("token", "")
    if not token:
        raise SystemExit("ไม่พบ Splunk token (config [splunk] token หรือ env SPLUNK_TOKEN)")
    return argparse.Namespace(splunk_url=s["url"].rstrip("/"), splunk_token=token,
                              splunk_app=s.get("app", "TA-tbcert-misp"),
                              collection=s.get("collection", "tbcert_misp_ioc"),
                              splunk_verify=verify)


def fetch_all(cfg) -> list[dict]:
    base = (f"{cfg.splunk_url}/servicesNS/nobody/{cfg.splunk_app}"
            f"/storage/collections/data/{cfg.collection}")
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {cfg.splunk_token}"
    s.verify = cfg.splunk_verify
    now, out, skip = int(time.time()), [], 0
    while True:
        r = s.get(base, timeout=120, params={
            # action=detect = เก็บไว้ detect เท่านั้น ไม่ส่งไป block
            "query": json.dumps({"expires": {"$gt": now}, "action": {"$ne": "detect"}}),
            "fields": "indicator,indicator_type,last_seen",
            "sort": "last_seen:-1", "limit": 10000, "skip": skip})
        r.raise_for_status()
        rows = r.json()
        out.extend(rows)
        if len(rows) < 10000:
            return out
        skip += 10000


def atomic_write(path: str, lines: list[str]) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)  # firewall จะไม่เห็นไฟล์ครึ่ง ๆ ระหว่างเขียน


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default="config.ini")
    ap.add_argument("-o", "--outdir", default="edl_out")
    ap.add_argument("--max", nargs="*", default=[], metavar="TYPE=N",
                    help="ขีดจำกัดต่อไฟล์ เช่น --max domain=500000 url=0 (0 = ไม่จำกัด)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for item in a.max:
        t, _, n = item.partition("=")
        MAX_PER_LIST[t.strip()] = int(n)
    cfg = load_splunk(a.config)
    os.makedirs(a.outdir, exist_ok=True)

    lists: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for row in fetch_all(cfg):  # เรียงจากใหม่ไปเก่า -> ถ้าเกินขีดจำกัด จะตัดตัวเก่าทิ้ง
        t, v = row.get("indicator_type", ""), row.get("indicator", "")
        if t == "url":
            v = v.split("://", 1)[-1]  # PAN-OS URL list ไม่รับ http:// / https://
        if t not in BLOCKABLE or not v or (t, v) in seen:
            continue
        seen.add((t, v))
        lists.setdefault(t, []).append(v)

    for t, vals in lists.items():
        limit = MAX_PER_LIST.get(t)
        if limit and len(vals) > limit:
            LOG.warning("%s มี %d รายการ เกิน %d — ตัดรายการเก่าออก", t, len(vals), limit)
            vals = vals[:limit]
        atomic_write(os.path.join(a.outdir, f"{t}.txt"), sorted(vals))
        LOG.info("เขียน %s.txt: %d รายการ", t, len(vals))

    # DNS RPZ: ตอบ NXDOMAIN ทั้งโดเมนและ sub-domain
    rpz = [f"$TTL 300", f"@ SOA localhost. root.localhost. {int(time.time())} 3600 600 86400 300",
           "@ NS localhost."]
    for d in sorted(lists.get("domain", [])):
        rpz += [f"{d} CNAME .", f"*.{d} CNAME ."]
    atomic_write(os.path.join(a.outdir, "rpz.zone"), rpz)


if __name__ == "__main__":
    main()
