#!/usr/bin/env python3
"""
build_no_app.py — สร้างชุดไฟล์สำหรับใช้งานแบบ "ไม่ติดตั้งแอปใหม่" (ใช้ MISP42Splunk + knowledge object ใน UI)
จากไฟล์ของแอป TA-tbcert-misp (แหล่งเดียวกัน เพื่อไม่ให้ logic สองชุดไม่ตรงกัน)

ผลลัพธ์ใน no_app/generated/
  macro_tbcert_misp_events_normalize.txt : นิยาม macro สำหรับข้อมูล index (sourcetype=misp_events) — macro ย่อยถูกแทนค่าแล้ว
  macro_tbcert_misp_normalize.txt        : นิยาม macro สำหรับผลของ mispgetioc / mispfetch
  lookups/*.csv                          : allowlist และ org trust สำหรับอัปโหลดใน Settings > Lookups

ใช้:  python3 build_no_app.py
"""
import os
import shutil

from preflight import APP_DIR, expand, load_macros

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "no_app", "generated")


def main() -> None:
    macros = load_macros(os.path.join(APP_DIR, "default", "macros.conf"))
    os.makedirs(os.path.join(OUT, "lookups"), exist_ok=True)
    for name in ("tbcert_misp_events_normalize", "tbcert_misp_normalize"):
        body = expand(f"`{name}`", macros)
        # ชื่อ macro ที่เหลืออยู่ = ชื่อที่ผู้ใช้ต้องสร้างเอง (ไม่ควรมี)
        assert "`" not in body, name
        with open(os.path.join(OUT, f"macro_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write(body.strip() + "\n")
        print(f"macro_{name}.txt  ({len(body):,} ตัวอักษร)")
    for f in ("tbcert_allowlist_ip.csv", "tbcert_allowlist_domain.csv", "tbcert_org_trust.csv"):
        shutil.copy(os.path.join(APP_DIR, "lookups", f), os.path.join(OUT, "lookups", f))
        print(f"lookups/{f}")


if __name__ == "__main__":
    main()
