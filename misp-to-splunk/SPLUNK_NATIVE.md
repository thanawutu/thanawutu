# ทำทั้งหมดใน Splunk (ไม่ต้องใช้สคริปต์ Python สำหรับดึงข้อมูล)

มี 2 วิธี ใช้ **KV store, lookup, detection search และ `export_edl.py` ชุดเดียวกัน** — เปิดใช้ทีละวิธี

| | วิธี A: ใช้ index เดิม (ค่าเริ่มต้น) | วิธี B: MISP42Splunk |
|---|---|---|
| แหล่งข้อมูล | `index=main sourcetype=misp_events` ที่ดึงเข้ามาอยู่แล้ว | `\| mispgetioc` ยิง API ไป MISP ตรง |
| กรองความรุนแรง | `threat_level_id` อยู่ในทุก event → กรองใน SPL ได้ทุกแบบ | `threat_level_id=` รับได้ค่าเดียว ถ้าหลายค่าต้องใช้ `json_request` |
| ระบุ event | `event_id IN (...)` | `eventid="id1,id2"` (ใช้ร่วมกับช่วงเวลาไม่ได้) |
| ถอด IOC ที่ถูกลบใน MISP | ได้เมื่อ ingestion ส่ง `to_ids=false` มา หรือรอบ rebuild ทุกคืน | ได้ทันที (`include_deleted=t`) |
| สิ่งที่ต้องติดตั้งเพิ่ม | ไม่มี | แอป MISP42Splunk (v5.x) + API key |

## ทำไมตอนนี้ได้แค่ IP

จาก event ตัวอย่างใน `sourcetype=misp_events` มี `attr_type` = `md5`, `sha1`, `sha256` อยู่แล้ว แปลว่า**ข้อมูลเข้ามาครบ แต่ search/lookup ที่นำไปใช้กรองเอาเฉพาะ IP** ตรวจได้ด้วย

```spl
index=main sourcetype=misp_events earliest=-30d
| stats count dc(value) as unique_ioc by attr_type threat_level_id
| sort - count
```
ถ้าในนี้มีแค่ `ip-dst`/`ip-src` แสดงว่าตัวดึงข้อมูล (ingestion) ใส่ filter `type` ไว้ ต้องแก้ที่ตัวดึง หรือเปลี่ยนไปใช้วิธี B

## ติดตั้ง (ทั้ง 2 วิธี)

ถ้าเจอ error `macro 'tbcert_misp_src' cannot be found` แปลว่ายังไม่ได้ติดตั้งแอปบน Search Head นั้น

**ทางที่ 1 — หน้าเว็บ:** Apps → Manage Apps → Install app from file → เลือก `dist/TA-tbcert-misp-1.1.0.tgz` → restart
(Splunk Cloud ต้องผ่าน AppInspect / private app vetting)

**ทางที่ 2 — บนเครื่อง Search Head:**
```bash
tar xzf TA-tbcert-misp-1.1.0.tgz -C $SPLUNK_HOME/etc/apps/
```
```bash
$SPLUNK_HOME/bin/splunk restart
```
Search Head Cluster: วางใน `$SPLUNK_HOME/etc/shcluster/apps/` บน deployer แล้ว `splunk apply shcluster-bundle`

**ทุก saved search ปิด schedule ไว้** — ทดสอบก่อน แล้วค่อยเปิดใน Settings → Searches, reports, and alerts

แก้ allowlist ที่ `lookups/tbcert_allowlist_ip.csv` (CIDR) และ `lookups/tbcert_allowlist_domain.csv` (match sub-domain ด้วย)

## นโยบาย block vs detect

ถ้าทุก event เป็น `threat_level_id=1` และ `to_ids=true` แสดงว่าตัวดึงข้อมูลกรองมาแล้ว — **ถ้าต้องการ Medium/Low ต้องแก้ที่ตัวดึง**
และ IOC จาก feed ชุมชนต่างประเทศจำนวนมากไม่ได้เจาะจงภาคการเงินไทย จึงไม่ควรส่งไป block ทั้งหมด

KV store จึงมี field **`action`**

| action | เงื่อนไข (ปรับใน macro) |
|---|---|
| `block` | hash ทุกตัว / IOC จาก org ที่เชื่อถือ (`tbcert_block_org_regex`) / ip-domain-url-email ที่อายุไม่เกิน `tbcert_block_max_age_days` (14 วัน) |
| `detect` | ที่เหลือ — ใช้หา hit ใน log แต่ไม่ส่งไป firewall |

`export_edl.py` และ `TBCERT - Build Blocklist` ส่งออกเฉพาะ `action=block`

ทดสอบหลังติดตั้ง (ยังไม่เขียนลง KV store)
```spl
`tbcert_misp_src` earliest=-30d | `tbcert_misp_events_normalize` | stats count by indicator_type status action
```
```spl
index=main sourcetype=misp_events earliest=-30d | stats dc(value) as ioc dc(event_id) as events by org | sort - ioc
```
แล้วเลือก org ที่ไว้ใจใส่ใน `tbcert_block_org_regex` (ค่าเริ่มต้นเป็นตัวอย่าง: TB-CERT, NCSA, ThaiCERT, ชื่อที่มี bank)

## วิธี A — ใช้ index เดิม

ตั้งค่าใน **Settings → Advanced search → Search macros** (app `TA-tbcert-misp`)

| macro | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `tbcert_misp_src` | `index=main sourcetype=misp_events published=true` | แหล่งข้อมูล |
| `tbcert_misp_severity_filter` | `threat_level_id IN (1,2,3,4)` | ระดับที่นำเข้า blocklist: 1=High 2=Medium 3=Low 4=Undefined |
| `tbcert_exclude_tag_regex` | `tlp:red`, `false-positive` | tag ที่ห้าม block |
| `tbcert_ttl_*` | ip 30 / domain 90 / url 90 / hash 365 / อื่น ๆ 90 วัน | อายุ IOC |

Saved search ที่ทำงานอัตโนมัติ
- `TBCERT - Sync From Index - Incremental` ทุก 15 นาที — upsert IOC **ทุกชนิด** เข้า KV store
- `TBCERT - Sync From Index - Rebuild Nightly` ตี 2 — สร้างใหม่ทั้งหมด ล้างของหมดอายุ (ถ้าได้ IOC น้อยกว่า `tbcert_min_rebuild_count` จะไม่เขียนทับ)

### ดึงตามความรุนแรง (ตัวอย่าง)

```spl
`tbcert_misp_src` threat_level_id=1
| `tbcert_misp_events_normalize`
| where status="active"
| stats count by indicator_type
```
นำเข้า blocklist เฉพาะ High + Medium: แก้ macro `tbcert_misp_severity_filter` เป็น `threat_level_id IN (1,2)`

หรือเก็บทุกระดับไว้ detect แต่ส่ง block เฉพาะ High (KV store มี field `severity` / `threat_level_id`)
```spl
| inputlookup tbcert_misp_ioc_lookup where severity="high" | where expires > now()
```

### ดึงตาม Event ID ที่ระบุ

เปิด saved search `TBCERT - Pull Specific Event IDs` แก้เลขในวงเล็บแล้ว Run หรือพิมพ์เอง
```spl
`tbcert_misp_src` event_id IN (558822, 558900)
| `tbcert_misp_events_normalize`
| eval source="TB-CERT MISP (manual event)"
| outputlookup append=true key_field=_key tbcert_misp_ioc_lookup
```
IOC ที่ใส่แบบนี้ **ไม่ผ่านตัวกรองความรุนแรง** และรอบ rebuild จะเก็บไว้จนกว่าจะหมดอายุ

ดูก่อนว่าจะได้อะไร (ไม่เขียน KV store) — ตัดบรรทัด `outputlookup` ออก แล้วดูคอลัมน์ `status`
(`active` = จะถูก block, `revoked:allowlist` / `revoked:tlp` / `revoked:to_ids_off` ฯลฯ = ไม่ถูก block พร้อมเหตุผล)

## วิธี B — MISP42Splunk

1. ติดตั้ง **MISP42Splunk** จาก Splunkbase บน Search Head
2. **MISP42Splunk → Configuration → MISP instances → Add**
   - Name: `tbcert` (ต้องตรงกับ macro `tbcert_misp_instance`)
   - URL: `https://<misp ของ TB-CERT>` (ต้องเป็น https)
   - Auth key: key ของ service account ธนาคาร (แอปเก็บแบบเข้ารหัสใน passwords.conf)
   - Check certificate: เปิด และใส่ CA path ถ้าใช้ CA ภายใน / Proxy: ตั้งใน tab Proxy ถ้าออกเน็ตผ่าน proxy
3. ทดสอบ
   ```spl
   | mispgetioc misp_instance=tbcert last=1d to_ids=t limit=20
   ```
4. **ปิด** saved search ของวิธี A แล้ว **เปิด** `TBCERT - MISP42Splunk Pull - Incremental` และ `... - Rebuild Nightly`

### ทุกชนิด / ความรุนแรง / Event ID ด้วย mispgetioc

```spl
| mispgetioc misp_instance=tbcert last=7d to_ids=t pipesplit=f expand_object=t
| `tbcert_misp_normalize`
```
ไม่ใส่ `type=` = ได้ทุกชนิด (หรือใช้ `type=`tbcert_misp_types`` ซึ่งรวม IOC หลักไว้แล้ว)

```spl
| mispgetioc misp_instance=tbcert last=7d threat_level_id=1 to_ids=t pipesplit=f expand_object=t
```
`threat_level_id=` รับได้ค่าเดียว ถ้าต้องการหลายระดับใช้ `json_request` (ใส่ช่วงเวลาไว้ใน JSON เพราะใช้คู่กับ `last=` ไม่ได้)
```spl
| mispgetioc misp_instance=tbcert json_request="{\"publish_timestamp\":\"7d\",\"threat_level_id\":[\"1\",\"2\"]}" to_ids=t pipesplit=f expand_object=t
```
ระบุ event (ID หรือ UUID คั่นด้วย `,`)
```spl
| mispgetioc misp_instance=tbcert eventid="558822,2b4aa4c6-896e-4a3f-bb9f-5b76ebc05b9d" to_ids=t pipesplit=f expand_object=t
```

> ต้องใช้ `pipesplit=f expand_object=t` กับ macro `tbcert_misp_normalize` เสมอ — เพราะถ้า `pipesplit=t` แอปจะรวม attribute แบบ `domain|ip` หรือ object ไว้แถวเดียว และ `misp_value` จะเหลือค่าเดียว

### ส่ง Sighting กลับ TB-CERT (option)
`TBCERT - Sighting to TB-CERT` ใช้ alert action `misp_alert_sighting` (mode `byvalue`) — ปิดไว้ ต้องได้รับอนุมัติก่อนเปิด
เพราะเป็นการบอกสมาชิกอื่นว่าธนาคารพบ IOC นั้น search ต้องจบด้วย `table sight_ts indicator` เท่านั้น
(แอปจะส่ง**ทุก field**ในแถวเป็นค่า sighting)

## ส่งต่อไปเครื่องมือ block
เหมือนเดิม — `export_edl.py` อ่าน KV store แล้วเขียน `ip.txt`, `domain.txt`, `url.txt`, `md5/sha1/sha256/sha512.txt`, `email.txt`, `rpz.zone`
(ชนิดอื่น เช่น `filename`, `mutex`, `user-agent` อยู่ใน KV store สำหรับ detect แต่ไม่ถูกส่งออก) ใช้แค่ส่วน `[splunk]` ใน `config.ini`

## หมายเหตุ
- ทดสอบ SPL นี้กับ Splunk จริงก่อนเปิด schedule — รัน search แต่ละตัวโดยตัด `outputlookup` ออกก่อน
- ต้องใช้ Splunk 8.0+ (`mvmap`, `outputlookup key_field`, `override_if_empty`)
- `event_tags{}` ต้องถูก extract เป็น multivalue (sourcetype `misp_events` ต้องใช้ `KV_MODE=json` หรือ `INDEXED_EXTRACTIONS=json`)
