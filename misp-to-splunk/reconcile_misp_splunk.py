#!/usr/bin/env python3
"""
reconcile_misp_splunk.py — ตรวจว่า IOC ใน MISP ของ TB-CERT ถูกนำเข้า Splunk (sourcetype=misp_events) ครบหรือไม่

ขั้นตอน
  1. ดึง attribute จาก MISP API (/attributes/restSearch) ในช่วงเวลาที่กำหนด
     แยกดึงตาม threat_level_id ทีละระดับ เพื่อรู้ว่า IOC ที่ขาดอยู่ระดับไหน
  2. ดึงข้อมูลจาก Splunk ผ่าน REST (/services/search/jobs/export) สรุป 1 แถวต่อ attr_uuid
  3. เทียบด้วย attribute uuid แล้วรายงาน
       - missing_in_splunk : มีใน MISP แต่ไม่มีใน Splunk
       - extra_in_splunk   : มีใน Splunk แต่ไม่พบใน MISP ช่วงเดียวกัน (ถูกลบ/ปลด to_ids/อยู่นอกช่วงเวลา)
       - mismatched        : uuid ตรงกันแต่ value / type / to_ids / timestamp ต่างกัน (Splunk ยังเป็นค่าเก่า)
     พร้อมสรุปตาม threat level, type, event และ duplicate ใน Splunk

ผลลัพธ์อยู่ในโฟลเดอร์ --outdir: summary.json, missing_in_splunk.csv, extra_in_splunk.csv,
mismatched.csv, missing_by_event.csv  และ exit code 2 ถ้าสัดส่วนที่ขาดเกิน max_missing_pct (ใช้ทำ alert ได้)

ตัวอย่าง
  python3 reconcile_misp_splunk.py -c config.ini
  python3 reconcile_misp_splunk.py -c config.ini --window 7d --levels 1,2 --to-ids true
"""
from __future__ import annotations

import argparse
import configparser
import csv
import json
import logging
import os
import sys
import time
from collections import Counter, defaultdict

import requests

LOG = logging.getLogger("reconcile")
LEVEL_NAME = {"1": "high", "2": "medium", "3": "low", "4": "undefined"}


def _verify(v: str):
    v = (v or "true").strip()
    if v.lower() in ("true", "1", "yes"):
        return True
    if v.lower() in ("false", "0", "no"):
        return False
    return v


def _bool(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


# --------------------------------------------------------------------------- MISP
def fetch_misp(cfg: dict) -> dict[str, dict]:
    s = requests.Session()
    s.headers.update({"Authorization": cfg["misp_key"], "Accept": "application/json",
                      "Content-Type": "application/json", "User-Agent": "tbcert-reconcile/1.0"})
    s.verify = cfg["misp_verify"]
    if cfg["proxy"]:
        s.proxies = {"https": cfg["proxy"], "http": cfg["proxy"]}
    out: dict[str, dict] = {}
    for level in cfg["levels"]:
        body = {"returnFormat": "json", cfg["time_field"]: cfg["window"], "threat_level_id": level,
                "deleted": 0, "limit": cfg["page_size"], "includeEventUuid": True}
        if cfg["published_only"]:
            body["published"] = True
        if cfg["to_ids"] in ("true", "false"):
            body["to_ids"] = cfg["to_ids"] == "true"
        if cfg["types"]:
            body["type"] = cfg["types"]
        if cfg["enforce_warninglist"]:
            body["enforceWarninglist"] = True
        page, n = 1, 0
        while True:
            body["page"] = page
            for attempt in range(4):
                try:
                    r = s.post(f"{cfg['misp_url']}/attributes/restSearch", data=json.dumps(body), timeout=300)
                    r.raise_for_status()
                    break
                except requests.RequestException as e:
                    if attempt == 3:
                        raise
                    LOG.warning("MISP error (%s) — retry", e)
                    time.sleep(2 ** (attempt + 1))
            attrs = r.json().get("response", {}).get("Attribute", [])
            for a in attrs:
                ev = a.get("Event") or {}
                out[a["uuid"]] = {
                    "attr_uuid": a["uuid"], "event_id": str(a.get("event_id", "")),
                    "event_info": ev.get("info", ""), "orgc_id": str(ev.get("orgc_id", "")),
                    "attr_type": a.get("type", ""), "value": str(a.get("value", "")),
                    "to_ids": _bool(a.get("to_ids")), "attr_timestamp": int(a.get("timestamp") or 0),
                    "threat_level_id": level, "object": "object" if str(a.get("object_id", "0")) != "0" else "attribute",
                }
            n += len(attrs)
            if len(attrs) < cfg["page_size"]:
                break
            page += 1
        LOG.info("MISP threat_level %s (%s): %d attributes", level, LEVEL_NAME.get(level, level), n)
    return out


# --------------------------------------------------------------------------- Splunk
def fetch_splunk(cfg: dict) -> dict[str, dict]:
    spl = (f"search {cfg['splunk_base']} "
           "| stats count as copies latest(attr_type) as attr_type latest(value) as value "
           "latest(event_id) as event_id latest(to_ids) as to_ids max(attr_timestamp) as attr_timestamp "
           "latest(threat_level_id) as threat_level_id latest(org) as org by attr_uuid")
    r = requests.post(f"{cfg['splunk_url']}/services/search/jobs/export", timeout=1800, stream=True,
                      verify=cfg["splunk_verify"], headers={"Authorization": f"Bearer {cfg['splunk_token']}"},
                      data={"search": spl, "output_mode": "json", "earliest_time": cfg["splunk_earliest"],
                            "latest_time": "now"})
    r.raise_for_status()
    out: dict[str, dict] = {}
    for line in r.iter_lines():
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("preview") or "result" not in obj:
            if "messages" in obj:
                for m in obj["messages"]:
                    if m.get("type") in ("ERROR", "FATAL"):
                        raise RuntimeError(f"Splunk: {m.get('text')}")
            continue
        row = obj["result"]
        uuid = row.get("attr_uuid")
        if not uuid:
            continue
        out[uuid] = {
            "attr_uuid": uuid, "attr_type": row.get("attr_type", ""), "value": str(row.get("value", "")),
            "event_id": str(row.get("event_id", "")), "to_ids": _bool(row.get("to_ids")),
            "attr_timestamp": int(float(row.get("attr_timestamp") or 0)),
            "threat_level_id": str(row.get("threat_level_id", "")), "org": row.get("org", ""),
            "copies": int(row.get("copies", 1)),
        }
    LOG.info("Splunk: %d attr_uuid ไม่ซ้ำ", len(out))
    return out


# --------------------------------------------------------------------------- compare
def compare(misp: dict[str, dict], splunk: dict[str, dict]) -> dict:
    missing = [misp[u] for u in misp if u not in splunk]
    extra = [splunk[u] for u in splunk if u not in misp]
    mismatched = []
    for u in misp.keys() & splunk.keys():
        m, s = misp[u], splunk[u]
        diffs = []
        if m["attr_type"] != s["attr_type"]:
            diffs.append("attr_type")
        if m["value"].strip().lower() != s["value"].strip().lower():
            diffs.append("value")
        if m["to_ids"] != s["to_ids"]:
            diffs.append("to_ids")
        if m["attr_timestamp"] > s["attr_timestamp"]:
            diffs.append("stale")                      # MISP แก้ไขหลังจากที่ Splunk นำเข้า
        if diffs:
            mismatched.append({"attr_uuid": u, "event_id": m["event_id"], "diff": "+".join(diffs),
                               "misp_type": m["attr_type"], "splunk_type": s["attr_type"],
                               "misp_value": m["value"], "splunk_value": s["value"],
                               "misp_to_ids": m["to_ids"], "splunk_to_ids": s["to_ids"],
                               "misp_ts": m["attr_timestamp"], "splunk_ts": s["attr_timestamp"]})

    by_event: dict[str, dict] = defaultdict(lambda: {"missing": 0, "total": 0})
    for m in misp.values():
        e = by_event[m["event_id"]]
        e["total"] += 1
        e["event_info"] = m["event_info"]
        e["threat_level_id"] = m["threat_level_id"]
        if m["attr_uuid"] not in splunk:
            e["missing"] += 1

    def per(rows, key):
        return dict(Counter(r[key] for r in rows).most_common())

    total_misp = len(misp)
    copies = sum(s["copies"] for s in splunk.values())
    return {
        "missing": missing, "extra": extra, "mismatched": mismatched, "by_event": by_event,
        "summary": {
            "misp_attributes": total_misp,
            "splunk_unique_attr_uuid": len(splunk),
            "splunk_events": copies,
            "splunk_duplicate_factor": round(copies / len(splunk), 2) if splunk else 0,
            "matched": total_misp - len(missing),
            "missing_in_splunk": len(missing),
            "missing_pct": round(len(missing) / total_misp * 100, 2) if total_misp else 0.0,
            "extra_in_splunk": len(extra),
            "mismatched": len(mismatched),
            "events_fully_missing": sum(1 for e in by_event.values() if e["missing"] == e["total"]),
            "events_partially_missing": sum(1 for e in by_event.values() if 0 < e["missing"] < e["total"]),
            "missing_by_threat_level": {LEVEL_NAME.get(k, k): v for k, v in per(missing, "threat_level_id").items()},
            "misp_by_threat_level": {LEVEL_NAME.get(k, k): v for k, v in per(misp.values(), "threat_level_id").items()},
            "missing_by_type": per(missing, "attr_type"),
            "missing_by_to_ids": {str(k).lower(): v for k, v in per(missing, "to_ids").items()},
            "mismatch_by_diff": per(mismatched, "diff"),
        },
    }


def write_outputs(outdir: str, res: dict, meta: dict) -> None:
    os.makedirs(outdir, exist_ok=True)

    def dump(name, rows, fields):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    dump("missing_in_splunk.csv", sorted(res["missing"], key=lambda r: (r["event_id"], r["attr_type"])),
         ["attr_uuid", "event_id", "event_info", "threat_level_id", "attr_type", "value", "to_ids",
          "attr_timestamp", "object", "orgc_id"])
    dump("extra_in_splunk.csv", res["extra"],
         ["attr_uuid", "event_id", "org", "attr_type", "value", "to_ids", "attr_timestamp", "threat_level_id", "copies"])
    dump("mismatched.csv", res["mismatched"],
         ["attr_uuid", "event_id", "diff", "misp_type", "splunk_type", "misp_value", "splunk_value",
          "misp_to_ids", "splunk_to_ids", "misp_ts", "splunk_ts"])
    ev_rows = [{"event_id": k, **v, "missing_pct": round(v["missing"] / v["total"] * 100, 1)}
               for k, v in res["by_event"].items() if v["missing"]]
    dump("missing_by_event.csv", sorted(ev_rows, key=lambda r: -r["missing"]),
         ["event_id", "event_info", "threat_level_id", "missing", "total", "missing_pct"])
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"run": meta, **res["summary"]}, fh, ensure_ascii=False, indent=2)


def send_hec(cfg: dict, res: dict, meta: dict) -> None:
    """ส่งผลเข้า Splunk ผ่าน HEC สำหรับ dashboard
       sourcetype=tbcert:misp:reconcile       1 event สรุปต่อรอบ
       sourcetype=tbcert:misp:reconcile:item  รายละเอียด kind=missing|extra|mismatched|event (จำกัดจำนวนตาม hec_max_items)"""
    if not (cfg.get("hec_url") and cfg.get("hec_token")):
        return
    t = meta["run_at"]

    def ev(body, st):
        return json.dumps({"time": t, "event": body, "index": cfg["hec_index"], "sourcetype": st})

    lines = [ev({"action": "reconcile", **meta, **res["summary"]}, "tbcert:misp:reconcile")]
    items = []
    for kind in ("missing", "mismatched", "extra"):
        items += [{"kind": kind, **row} for row in res[kind]]
    items += [{"kind": "event", "event_id": k, **v} for k, v in res["by_event"].items() if v["missing"]]
    cap = cfg.get("hec_max_items", 20000)
    if len(items) > cap:
        LOG.warning("รายละเอียด %d รายการ ส่งเข้า HEC เพียง %d (hec_max_items)", len(items), cap)
        items = items[:cap]
    lines += [ev({"run_at": t, **i}, "tbcert:misp:reconcile:item") for i in items]
    sess = requests.Session()
    sess.headers["Authorization"] = f"Splunk {cfg['hec_token']}"
    sess.verify = cfg["splunk_verify"]
    try:
        for n in range(0, len(lines), 500):
            sess.post(cfg["hec_url"], data="\n".join(lines[n:n + 500]), timeout=60).raise_for_status()
        LOG.info("ส่ง HEC: สรุป 1 + รายละเอียด %d event", len(items))
    except requests.RequestException as e:
        LOG.warning("ส่ง HEC ไม่สำเร็จ: %s", e)


# --------------------------------------------------------------------------- main
def load(path: str, a) -> dict:
    cp = configparser.ConfigParser(inline_comment_prefixes=(";",), interpolation=None)
    if not cp.read(path, encoding="utf-8"):
        sys.exit(f"อ่านไฟล์ config ไม่ได้: {path}")
    m, s = cp["misp"], cp["splunk"]
    r = cp["reconcile"] if cp.has_section("reconcile") else cp["DEFAULT"]
    cfg = {
        "misp_url": m["url"].rstrip("/"), "misp_key": os.environ.get("MISP_API_KEY") or m.get("api_key", ""),
        "misp_verify": _verify(m.get("verify_tls")), "proxy": m.get("proxy", "").strip() or None,
        "splunk_url": s["url"].rstrip("/"), "splunk_token": os.environ.get("SPLUNK_TOKEN") or s.get("token", ""),
        "splunk_verify": _verify(s.get("verify_tls")),
        "hec_url": s.get("hec_url", "").strip(), "hec_token": os.environ.get("SPLUNK_HEC_TOKEN") or s.get("hec_token", "").strip(),
        "hec_index": s.get("hec_index", "threat_intel"),
        "window": a.window or r.get("window", "30d"),
        "time_field": r.get("time_field", "publish_timestamp"),
        "levels": [x.strip() for x in (a.levels or r.get("threat_levels", "1,2,3,4")).split(",") if x.strip()],
        "to_ids": (a.to_ids or r.get("to_ids", "any")).strip().lower(),
        "published_only": r.getboolean("published_only", True),
        "enforce_warninglist": r.getboolean("enforce_warninglist", False),
        "types": [x.strip() for x in r.get("types", "").split(",") if x.strip()],
        "page_size": r.getint("page_size", 1000),
        "splunk_base": r.get("splunk_base", "index=main sourcetype=misp_events"),
        "splunk_earliest": a.splunk_earliest or r.get("splunk_earliest", "-35d"),
        "max_missing_pct": r.getfloat("max_missing_pct", 1.0),
        "hec_max_items": r.getint("hec_max_items", 20000),
    }
    if not cfg["misp_key"] or not cfg["splunk_token"]:
        sys.exit("ต้องมี MISP_API_KEY และ SPLUNK_TOKEN (env หรือ config)")
    return cfg


def main() -> None:
    ap = argparse.ArgumentParser(description="Reconcile TB-CERT MISP attributes against Splunk sourcetype=misp_events")
    ap.add_argument("-c", "--config", default="config.ini")
    ap.add_argument("--window", help="ช่วงเวลาฝั่ง MISP เช่น 7d, 30d (ทับค่าใน config)")
    ap.add_argument("--levels", help="threat_level_id เช่น 1,2")
    ap.add_argument("--to-ids", choices=["any", "true", "false"])
    ap.add_argument("--splunk-earliest", help="earliest ของ search ฝั่ง Splunk เช่น -35d")
    ap.add_argument("-o", "--outdir", default="reconcile_out")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load(a.config, a)
    meta = {"window": cfg["window"], "time_field": cfg["time_field"], "threat_levels": cfg["levels"],
            "to_ids": cfg["to_ids"], "splunk_base": cfg["splunk_base"], "splunk_earliest": cfg["splunk_earliest"],
            "run_at": int(time.time())}

    misp = fetch_misp(cfg)
    splunk = fetch_splunk(cfg)
    res = compare(misp, splunk)
    write_outputs(a.outdir, res, meta)
    send_hec(cfg, res, meta)

    s = res["summary"]
    print(f"\nMISP {s['misp_attributes']:,} attribute  |  Splunk {s['splunk_unique_attr_uuid']:,} uuid "
          f"({s['splunk_events']:,} event, ซ้ำเฉลี่ย {s['splunk_duplicate_factor']}x)")
    print(f"ตรงกัน {s['matched']:,}  ·  ขาดใน Splunk {s['missing_in_splunk']:,} ({s['missing_pct']}%)  ·  "
          f"เกินใน Splunk {s['extra_in_splunk']:,}  ·  ค่าไม่ตรง {s['mismatched']:,}")
    print(f"ขาดตามระดับ: {s['missing_by_threat_level']}  (MISP ทั้งหมด: {s['misp_by_threat_level']})")
    print(f"ขาดตาม to_ids: {s['missing_by_to_ids']}")
    print(f"ขาดตามชนิด (10 อันดับ): {dict(list(s['missing_by_type'].items())[:10])}")
    print(f"event ที่ขาดทั้ง event: {s['events_fully_missing']}  ·  ขาดบางส่วน: {s['events_partially_missing']}")
    print(f"รายละเอียด: {os.path.abspath(a.outdir)}/")
    if s["missing_pct"] > cfg["max_missing_pct"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
