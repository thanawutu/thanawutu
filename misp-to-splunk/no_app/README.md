# ใช้ MISP42Splunk ที่มีอยู่ — ไม่ติดตั้งแอปใหม่

ทุกอย่างสร้างเป็น **knowledge object ใน Splunk UI** (lookup, macro, saved search, dashboard) ในแอป `misp42splunk`
ไม่มีการติดตั้งแอปเพิ่ม — ใช้ feature ของ MISP42Splunk (`mispgetioc`, `mispfetch`, alert action sighting) ร่วมกับ SPL ปกติ

| ความต้องการ | ใช้อะไร |
|---|---|
| ดึง IOC ทุกชนิด / ตาม threat level / ตาม event ID | ข้อมูลเดิมใน `sourcetype=misp_events` หรือ `mispfetch` |
| คัดกรอง (to_ids, TLP, allowlist, อายุ IOC) และแยก block / detect | macro 2 ตัว + lookup 3 ไฟล์ |
| เก็บรายการ IOC | CSV lookup `tbcert_misp_ioc.csv` (ไม่ต้องสร้าง KV store) |
| ตรวจความครบถ้วน MISP ↔ Splunk + dashboard | `mispgetioc` + CSV lookup — **ไม่ต้องใช้สคริปต์ Python หรือ HEC** |
| ส่ง sighting กลับ TB-CERT | alert action ของ MISP42Splunk |
| ส่งไป SentinelOne / Imperva / Proofpoint | **MISP42Splunk ทำไม่ได้** (คุยกับ MISP เท่านั้น) → `push_blocklists.py` ตั้ง `ioc_source = csv` หรือ Splunk SOAR |

> **ตรวจเวอร์ชัน MISP42Splunk ก่อน** — `| rest /services/apps/local/misp42splunk splunk_server=local | table title version`
> `mispgetioc` ต้องมีอาร์กิวเมนต์ช่วงเวลา/ event อย่างใดอย่างหนึ่งเสมอ: `last=` / `date=` / `eventid=` / `json_request=`
> (5.x เพิ่ม `publish_timestamp=` และ `timestamp=`) เช่น `| mispgetioc misp_instance=MISP_TBCERT last=1d to_ids=t getuuid=t limit=0`
>
> **MISP42Splunk 4.x:** ไม่มี `threat_level_id` (ใช้ `json_request` หรือ mispfetch), ต้องใส่ `getuuid=t` เพื่อให้มี attribute uuid,
> `geteventtag=t` เพื่อให้มี tag ของ event และ `limit=0` เพื่อดึงครบ (ค่าเริ่มต้น limit 1000 + page 1 = ได้แค่ 1,000 รายการแรก)

ทุกขั้นตอนทำใน app context **misp42splunk** (เลือกแอปจากเมนู Apps ก่อน) และตั้ง Permissions เป็น *This app only* หรือ *All apps* ตามที่ต้องการ

---

## 1. Lookup (Settings → Lookups)

**Lookup table files → New Lookup Table File** อัปโหลด 3 ไฟล์จาก `generated/lookups/` (แก้ค่าให้เป็นของธนาคารก่อน)

| ไฟล์ | เนื้อหา |
|---|---|
| `tbcert_allowlist_ip.csv` | `cidr,note` — IP/CIDR ที่ห้าม block |
| `tbcert_allowlist_domain.csv` | `domain,note` — โดเมนที่ห้าม block (match sub-domain ด้วย) |
| `tbcert_org_trust.csv` | `org,trust,note` — trust = `block` / `recent` / `detect` |

**Lookup definitions → New Lookup Definition** (Type: File-based)

| Name | Lookup file | Advanced options |
|---|---|---|
| `tbcert_allowlist_ip` | `tbcert_allowlist_ip.csv` | Match type: `CIDR(cidr)` · Max matches: 1 |
| `tbcert_allowlist_domain` | `tbcert_allowlist_domain.csv` | Case sensitive match: ไม่ติ๊ก · Max matches: 1 |
| `tbcert_org_trust` | `tbcert_org_trust.csv` | Case sensitive match: ไม่ติ๊ก · Max matches: 1 |

## 2. Macro (Settings → Advanced search → Search macros → New)

| Name | Definition |
|---|---|
| `tbcert_misp_events_normalize` | คัดลอกทั้งไฟล์ `generated/macro_tbcert_misp_events_normalize.txt` |
| `tbcert_misp_normalize` | คัดลอกทั้งไฟล์ `generated/macro_tbcert_misp_normalize.txt` |

ค่าในไฟล์ (อายุ IOC, TLP, tag ที่ห้าม block, จำนวนวันของ `recent`) แก้ใน `splunk_app/TA-tbcert-misp/default/macros.conf`
แล้วรัน `python3 build_no_app.py` เพื่อสร้างไฟล์ใหม่ — logic ชุดเดียวกับแอป จึงตรวจด้วย `preflight.py --only spl` ได้

ทดสอบ (ยังไม่เขียนอะไร):
```spl
index=main sourcetype=misp_events published=true earliest=-24h
| `tbcert_misp_events_normalize`
| stats count by indicator_type status action
```

## 3. Saved search สร้างรายการ IOC (Search → Save As → Report แล้วตั้ง Schedule)

กรองความรุนแรงด้วย `threat_level_id IN (...)` (1=High 2=Medium 3=Low 4=Undefined)

**TBCERT IOC - Rebuild** · ทุกวัน 02:17 · Time range: Last 400 days
```spl
index=main sourcetype=misp_events published=true threat_level_id IN (1,2,3,4)
| `tbcert_misp_events_normalize`
| where status="active"
| rename _key AS ioc_key
| append [| inputlookup tbcert_misp_ioc.csv where source="TB-CERT MISP (manual event)" | where expires > now()]
| dedup ioc_key
| eventstats count(eval(source="TB-CERT MISP")) as total
| where total >= 50
| fields - total
| outputlookup override_if_empty=false tbcert_misp_ioc.csv
```

**TBCERT IOC - Incremental** · ทุก 15 นาที (`*/15 * * * *`)
```spl
| inputlookup tbcert_misp_ioc.csv
| append [search index=main sourcetype=misp_events published=true threat_level_id IN (1,2,3,4) earliest=-20m
    | `tbcert_misp_events_normalize` | rename _key AS ioc_key]
| sort 0 - updated
| dedup ioc_key
| where expires > now()
| outputlookup override_if_empty=false tbcert_misp_ioc.csv
```
IOC ที่ถูกลบ/ปลด to_ids/เข้า allowlist จะได้ `expires` เป็นอดีต และหลุดจากรายการในรอบนี้

**TBCERT IOC - Pull Event IDs (mispfetch)** · ไม่ตั้ง schedule — แก้เลข event แล้ว Run
```spl
| makeresults
| eval misp_instance="MISP_TBCERT", misp_restsearch="attributes", eventid=split("558822,558900", ","), to_ids="true", includeEventTags="true"
| tojson eventid to_ids includeEventTags output_field=misp_http_body
| mispfetch pipesplit=f expand_object=t limit=1000
| `tbcert_misp_normalize`
| rename _key AS ioc_key
| eval source="TB-CERT MISP (manual event)"
| inputlookup append=true tbcert_misp_ioc.csv
| sort 0 - updated
| dedup ioc_key
| where expires > now()
| outputlookup tbcert_misp_ioc.csv
```
ดึงตาม threat level จาก MISP โดยตรง (เช่น High + Medium 7 วัน): เปลี่ยน `eval` เป็น
`publish_timestamp="7d", threat_level_id=split("1,2", ","), to_ids="true", published="true"` และ `tojson publish_timestamp threat_level_id to_ids published ...`

> ต้องใช้ `pipesplit=f expand_object=t` เสมอ ไม่อย่างนั้น `domain|ip` และ object จะถูกรวมเป็นแถวเดียว

ดูรายการ:
```spl
| inputlookup tbcert_misp_ioc.csv | stats count by indicator_type action severity
```

## 4. Detection (alert ทุก 15 นาที)

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| lookup tbcert_misp_ioc.csv indicator AS dest OUTPUTNEW event_info indicator_type expires
| where isnotnull(event_info) AND indicator_type="ip" AND expires > now()
```
แบบเดียวกันกับ `Web.url_domain`, `Network_Resolution.DNS.query`, `Endpoint.Processes.process_hash`

## 5. ตรวจความครบถ้วน (reconcile) — ใช้ mispgetioc ไม่ต้องใช้สคริปต์

3 saved search เรียงกัน (ใช้ CSV แทน join เพื่อไม่ติดขีดจำกัด subsearch 50,000 แถว)
ตั้งเงื่อนไขฝั่ง MISP ให้ตรงกับตัวดึงข้อมูลเดิม (ปัจจุบัน High + to_ids)

**TBCERT Recon 1 - MISP** · ทุกวัน 07:05
```spl
| mispgetioc misp_instance=MISP_TBCERT json_request="{\"returnFormat\":\"json\",\"last\":\"30d\",\"threat_level_id\":\"1\",\"to_ids\":true,\"published\":true}" getuuid=t geteventtag=t pipesplit=f expand_object=t limit=0
| rename misp_attribute_uuid AS attr_uuid
| table attr_uuid misp_event_id misp_event_info misp_type misp_value misp_to_ids misp_timestamp
| outputlookup tbcert_recon_misp.csv
```

MISP42Splunk 4.x ไม่มีอาร์กิวเมนต์ `threat_level_id` จึงใส่เงื่อนไขทั้งหมดใน `json_request` (body ของ MISP API โดยตรง)
`getuuid=t` จำเป็น (ไม่ใส่จะไม่มี `misp_attribute_uuid`) และ `limit=0` เพื่อดึงครบทุกรายการ (ค่าเริ่มต้นได้แค่ 1,000)
หรือใช้ mispfetch แทน:
```spl
| makeresults
| eval misp_instance="MISP_TBCERT", misp_restsearch="attributes", publish_timestamp="30d", threat_level_id="1", to_ids="true", published="true"
| tojson publish_timestamp threat_level_id to_ids published output_field=misp_http_body
| mispfetch pipesplit=f expand_object=t limit=1000
| where isnotnull(misp_attribute_uuid)
| rename misp_attribute_uuid AS attr_uuid
| table attr_uuid misp_event_id misp_event_info misp_type misp_value misp_to_ids misp_timestamp
| outputlookup tbcert_recon_misp.csv
```

**TBCERT Recon 2 - Splunk** · ทุกวัน 07:10 · Time range: Last 35 days
```spl
index=main sourcetype=misp_events
| stats count as copies latest(value) as s_value latest(attr_type) as s_type max(attr_timestamp) as s_ts by attr_uuid
| outputlookup tbcert_recon_splunk.csv
```

**TBCERT Recon 3 - Result** · ทุกวัน 07:15 · ตั้งเป็น **Alert** (Trigger: Number of results > 0)
```spl
| inputlookup tbcert_recon_misp.csv
| lookup tbcert_recon_splunk.csv attr_uuid OUTPUT copies s_ts s_value
| eval state=case(isnull(copies),"missing", misp_timestamp>s_ts,"stale", lower(misp_value)!=lower(s_value),"value", true(),"ok")
| stats count as misp_attributes count(eval(state="missing")) as missing count(eval(state="stale")) as stale count(eval(state="value")) as value_diff
| eval missing_pct=round(missing/misp_attributes*100,2), run_at=now()
| outputlookup append=true tbcert_recon_history.csv
| where missing_pct > 1
```

**Dashboard:** Dashboards → Create New Dashboard → Classic Dashboards → Source → วางเนื้อหา `reconcile_dashboard.xml`

## 6. ส่ง sighting กลับ TB-CERT (option)
alert ที่จบด้วย `| table sight_ts indicator` แล้วเลือก action *Alert for sighting MISP attribute(s)*:
instance `MISP_TBCERT`, mode `byvalue`, type `0`, timestamp field `sight_ts` — ต้องได้รับอนุมัติก่อนเปิด

## 7. ส่งไปเครื่องมือ block
MISP42Splunk ไม่มีส่วนนี้ ใช้ `push_blocklists.py` (รันนอก Splunk ไม่ใช่แอป) โดยตั้งใน `config.ini`:
```ini
[splunk]
ioc_source = csv
ioc_csv = tbcert_misp_ioc.csv
ioc_csv_app = misp42splunk
```

---

### เทียบกับการติดตั้งแอป TA-tbcert-misp

| | ไม่ติดตั้งแอป (ไฟล์นี้) | ติดตั้งแอป |
|---|---|---|
| change request | สร้าง knowledge object ใน UI | ติดตั้งแอป 1 ครั้ง |
| ที่เก็บ IOC | CSV lookup (เขียนทับทั้งไฟล์ทุกรอบ) | KV store (upsert ทีละรายการ) |
| reconcile | mispgetioc + CSV ทั้งหมดใน Splunk | สคริปต์ Python + HEC |
| การอัปเดต logic | แก้ macro ใน UI (สร้างใหม่จาก `build_no_app.py`) | ติดตั้งแอปเวอร์ชันใหม่ |
| ความเสี่ยงตอนอัปเกรด MISP42Splunk | knowledge object ที่สร้างใน UI อยู่ใน `local/` จึงไม่หายเมื่ออัปเกรด | ไม่เกี่ยว |

ขนาดที่เหมาะกับ CSV: หลักแสนแถวยังทำงานได้ดี ถ้าเกินหลายแสน หรือหลายคนแก้พร้อมกัน ค่อยย้ายไปใช้แอป (KV store)
