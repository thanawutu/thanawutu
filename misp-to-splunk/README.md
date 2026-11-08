# TB-CERT MISP → Splunk → Blocking Tools

ดึง IOC ที่สมาชิกแชร์ใน MISP ของ **TB-CERT** เข้า **Splunk** เพื่อ
1. **Detect** — ดูว่ามีเครื่องในธนาคารติดต่อ IOC เหล่านั้นไปแล้วหรือยัง (retro-hunt + alert)
2. **Block** — ส่งออกเป็น blocklist ให้ Firewall / Proxy / DNS / EDR / Email Gateway

```
 ┌──────────────┐  REST API (HTTPS, API key)   ┌─────────────────┐   KV Store REST   ┌──────────────────────┐
 │ TB-CERT MISP │ ───────────────────────────▶ │ misp_to_splunk  │ ────────────────▶ │ Splunk (KV: tbcert_  │
 │  (สมาชิกแชร์)  │  /attributes/restSearch      │ filter TLP/tag/ │                   │  misp_ioc + lookup)  │
 └──────────────┘  to_ids + published +        │ allowlist / TTL │                   └─────────┬────────────┘
                   warninglist                 └─────────────────┘                             │
                                        ┌──────────────────────────────────────────────┬───────┴────────┐
                                        ▼                                              ▼                ▼
                               Saved searches (Detect)                       export_edl.py        SOAR playbook
                               Network/Web/DNS/Endpoint                     ip/domain/url/hash   (เรียก API vendor)
                                                                                   │
                                          ┌───────────────┬──────────────┬─────────┴──────┬───────────────┐
                                          ▼               ▼              ▼                ▼               ▼
                                   Palo Alto EDL   FortiGate Feed   DNS RPZ/Infoblox   Proxy/SWG    EDR/Email GW
```

## ทางเลือกในการเชื่อม MISP กับ Splunk

| วิธี | เหมาะกับ | ข้อดี | ข้อจำกัด |
|---|---|---|---|
| **MISP42Splunk** (Splunkbase app ทางการของชุมชน MISP) | ต้องการเริ่มเร็ว ใช้ใน SPL | มี custom command `mispgetioc`, `mispcollect`, `mispsearch`, alert action สร้าง event กลับเข้า MISP | ต้องเขียน saved search เองเพื่อเก็บลง lookup, logic allowlist/TTL ต้องทำใน SPL |
| **Splunk ES Threat Intelligence Framework** | มี Enterprise Security | ES จะ match กับ data model อัตโนมัติ (Threat Activity) | ต้องแปลงรูปแบบให้ตรง (STIX/TAXII หรือ CSV) |
| **สคริปต์ในโฟลเดอร์นี้** (REST → KV Store) | ต้องการควบคุม filter/allowlist/อายุ IOC และ export ไป block | ควบคุมได้ทุกขั้น, ลบ IOC ที่ถูกเพิกถอนอัตโนมัติ, ใช้แค่ Python + requests | ต้องดูแลสคริปต์เอง |

> **ไม่อยากติดตั้งแอปใหม่ → ใช้ MISP42Splunk ที่มีอยู่ + knowledge object ใน UI: [no_app/README.md](no_app/README.md)**
>
> **ถ้ามีข้อมูล MISP อยู่ใน Splunk แล้ว หรืออยากใช้ MISP42Splunk แทนสคริปต์ → ดู [SPLUNK_NATIVE.md](SPLUNK_NATIVE.md)** (รองรับกรองตามความรุนแรงและ Event ID)
>
> สามารถใช้ร่วมกันได้ เช่น ใช้สคริปต์นี้ทำ blocklist และใช้ MISP42Splunk สำหรับ analyst ค้นหา/ส่ง sighting กลับไป TB-CERT

## สิ่งที่ต้องขอจาก TB-CERT / ทีมภายใน
1. **บัญชี MISP ขององค์กร** + Auth key (role *User* หรือ *Read Only* ก็พอสำหรับดึง) — ขอให้ผูกกับ service account ไม่ใช่บุคคล
2. **Whitelist IP** ขาออกของเครื่องที่รันสคริปต์ (หาก MISP ของ TB-CERT จำกัด source IP) และเปิด firewall/proxy ไปยัง MISP ทาง 443
3. **Splunk token** ของ service account ที่มี role เขียน KV store ของ app `TA-tbcert-misp` (role `tbcert_ti_writer` ใน `metadata/default.meta`)
4. ข้อตกลงเรื่อง **TLP** — ใช้ IOC TLP:AMBER ภายในได้ แต่ห้ามส่งต่อนอกองค์กร (เช่น อัปโหลดขึ้น cloud ของ vendor ที่แชร์ข้อมูลข้ามลูกค้า)

## ทดสอบก่อนติดตั้ง (preflight.py) — ทำก่อนทุกครั้ง

ทดสอบการเชื่อมต่อและความพร้อมทั้งหมดโดยไม่ต้องติดตั้งแอป จะได้ไม่ต้องติดตั้งซ้ำระหว่างแก้ปัญหา
ทุกการทดสอบอ่านอย่างเดียว (ยกเว้น `--allow-write` ที่ส่ง HEC test event 1 รายการ)

```bash
python3 preflight.py -c config.ini
```
```bash
python3 preflight.py -c config.ini --only misp,splunk,spl --json preflight.json
```

| กลุ่ม | ตรวจอะไร |
|---|---|
| misp | เชื่อมต่อ, API key, user/org/role ที่ key ผูกอยู่, ค้น attribute ได้ |
| splunk | REST API, เวอร์ชัน 8.0+, roles/capabilities, KV store, index ปลายทาง, แอปที่ติดตั้งอยู่ |
| data | `sourcetype=misp_events` มีข้อมูลล่าสุด มาจาก source/host ไหน และมี field ที่แอปต้องใช้ (รวม `event_tags{}`) |
| spl | **รัน SPL ของแอปกับข้อมูลจริงโดยไม่ต้องติดตั้ง** — ขยาย macro จาก `macros.conf` ในเครื่อง ตัด lookup ของแอปออกชั่วคราว ไม่เขียนข้อมูล แสดงจำนวน block/detect/revoked |
| misp42splunk | config instance ใน MISP42Splunk (URL, ตรวจ certificate, proxy) และรัน `mispgetioc` / `mispfetch` จากฝั่ง Splunk |
| hec | HEC health และ token |
| sentinelone / imperva / proofpoint | อ่าน Blocklist / สถานะ site และ ACL / list ของ PTR หรือสิทธิ์เขียนโฟลเดอร์ CSV (เฉพาะที่ `enabled = true`) |

แต่ละรายการเป็น PASS / WARN / FAIL / SKIP พร้อมคำแนะนำ (เช่น TLS ต้องใส่ CA bundle, 403 = สิทธิ์หรือ IP ไม่ได้รับอนุญาต)
exit code 1 เมื่อมี FAIL — ติดตั้งแอปเมื่อไม่มี FAIL แล้ว
ถ้าแก้ `macros.conf` ในเครื่อง ให้รัน `--only spl` ซ้ำได้ทันทีโดยไม่ต้องติดตั้งแอปใหม่

## ติดตั้ง

```bash
# 1) ติดตั้ง Splunk app (KV store, lookup, saved searches) บน Search Head
cp -r splunk_app/TA-tbcert-misp $SPLUNK_HOME/etc/apps/ && $SPLUNK_HOME/bin/splunk restart

# 2) เตรียมสคริปต์บน jump host / heavy forwarder
pip install requests
cp config.example.ini config.ini          # แก้ URL, key, token
cp allowlist.example.txt allowlist.txt    # ใส่ IP/โดเมนของธนาคารและ partner ที่ห้าม block
export MISP_API_KEY='...' SPLUNK_TOKEN='...'

# 3) ทดสอบ (ไม่เขียนเข้า Splunk)
python3 misp_to_splunk.py -c config.ini --initial --dry-run -v

# 4) ดึงครั้งแรกแบบเต็ม แล้วตั้งรอบ incremental
python3 misp_to_splunk.py -c config.ini --initial
```

crontab ตัวอย่าง:
```
*/15 * * * *  cd /opt/tbcert-misp && python3 misp_to_splunk.py -c config.ini >> sync.log 2>&1
0 3 * * *     cd /opt/tbcert-misp && python3 misp_to_splunk.py -c config.ini --initial >> sync.log 2>&1
*/15 * * * *  cd /opt/tbcert-misp && python3 export_edl.py -c config.ini -o /var/www/edl >> edl.log 2>&1
```
(รอบ `--initial` ทุกคืนช่วยซ่อมข้อมูลกรณีพลาดบางรอบ)

ทดสอบ logic: `python3 -m unittest -v test_normalize`

## ใช้งานใน Splunk

```spl
| inputlookup tbcert_misp_ioc_lookup | where expires > now() | stats count by indicator_type tlp

index=firewall action=allowed
| lookup tbcert_misp_ioc_lookup indicator AS dest_ip OUTPUT event_info tlp
| where isnotnull(event_info)
```
saved search ที่ให้มา: `TBCERT - IOC Match - Network Traffic / Web Proxy / DNS Query / Endpoint File Hash`,
`TBCERT - Build Blocklist`, `TBCERT - MISP Sync Health` (ปรับชื่อ data model / field ตาม CIM ของธนาคาร)

## ส่งไป block บนเครื่องมือต่างๆ

| เครื่องมือ | วิธีรับ IOC | ไฟล์ |
|---|---|---|
| Palo Alto NGFW / Panorama | External Dynamic List (IP / Domain / URL) poll ทุก 5–15 นาที → ใช้ใน Security policy (deny) + Anti-Spyware DNS sinkhole | `ip.txt`, `domain.txt`, `url.txt` |
| FortiGate | Security Fabric → External Connectors → Threat Feeds | `ip.txt`, `domain.txt`, `url.txt` |
| Check Point | Custom Intelligence Feeds / Generic Data Center objects | `ip.txt` |
| DNS (BIND/Infoblox/Windows) | Response Policy Zone | `rpz.zone`, `domain.txt` |
| Proxy / SWG (Zscaler, Bluecoat, Squid) | URL category ผ่าน API หรือ feed | `url.txt`, `domain.txt` |
| EDR (CrowdStrike, Defender, Trend, SentinelOne) | Custom IOC API — แนะนำทำผ่าน SOAR | `sha256.txt`, `md5.txt` |
| Email Security Gateway | Sender/URL blocklist | `email.txt`, `url.txt` |

วาง `edl_out/` บน web server ภายใน (HTTPS, จำกัด IP เฉพาะอุปกรณ์ security, มี basic auth/cert) — อย่าเปิดสู่อินเทอร์เน็ต

## ส่งตรงเข้าเครื่องมือของธนาคาร (push_blocklists.py)

| IOC | ปลายทาง | วิธี |
|---|---|---|
| hash (sha1, sha256) | **SentinelOne** Blocklist | API `/web/api/v2.1/restrictions` (type `black_hash`) 1 รายการต่อ OS — md5 ใช้ blocklist ไม่ได้ |
| ip | **Imperva Cloud WAF** ACL *Blacklisted IPs* | API `/api/prov/v1/sites/configure/acl` — อ่านรายการเดิมก่อนแล้วรวม จึงไม่ทับ IP ที่ SOC ใส่เอง |
| email, domain | **Proofpoint** | `mode=csv` ไฟล์สำหรับ import (ใช้ได้ทุกรุ่น) หรือ `mode=ptr` ผ่าน list ของ Proofpoint Threat Response |

```bash
python3 push_blocklists.py -c config.ini                        # dry-run ทุกปลายทาง → push_plan.csv
python3 push_blocklists.py -c config.ini --target sentinelone   # ทดสอบทีละปลายทาง
python3 push_blocklists.py -c config.ini --apply                # ส่งจริง
```
- ค่าเริ่มต้นทุกปลายทาง `enabled = false` และทุกครั้งเป็น dry-run จนกว่าจะใส่ `--apply`
- ลบเฉพาะรายการที่สคริปต์เพิ่มเอง (จำไว้ใน `push_state.json` — ห้ามลบไฟล์นี้)
- safety limit `max_add_per_run` / `max_remove_per_run` และขนาดสูงสุดต่อปลายทาง `max_entries` (เก็บตัวใหม่สุด)
- API ของแต่ละ vendor ต่างกันตามรุ่นและ license — **ทดสอบกับ site/tenant ทดสอบก่อน**: S1 ตรวจว่ารองรับ SHA256 ใน Blocklist,
  Imperva ตรวจขีดจำกัดจำนวน IP ใน ACL, Proofpoint ตรวจว่าใช้ PoD/PPS และมี PTR หรือไม่
- ถ้ามี Splunk SOAR ใช้แอป SentinelOne / Imperva / Proofpoint ของ SOAR แทนสคริปต์นี้ได้ โดยใช้ lookup เดียวกันเป็น input

## ตรวจความครบถ้วน MISP เทียบ Splunk (reconcile_misp_splunk.py)

ดึง attribute จาก MISP API โดยตรง แล้วเทียบกับ `sourcetype=misp_events` ด้วย `attr_uuid`

```bash
python3 reconcile_misp_splunk.py -c config.ini                       # 30 วัน ทุกระดับ
python3 reconcile_misp_splunk.py -c config.ini --window 7d --levels 1 --to-ids true
```

| ผลลัพธ์ | ความหมาย |
|---|---|
| `missing_in_splunk.csv` | มีใน MISP แต่ไม่มีใน Splunk |
| `missing_by_event.csv` | event ที่ขาด เรียงตามจำนวนที่ขาด |
| `extra_in_splunk.csv` | มีใน Splunk แต่ไม่พบใน MISP ช่วงเดียวกัน (ถูกลบ/ปลด to_ids/อยู่นอกช่วง) |
| `mismatched.csv` | uuid ตรงแต่ value/type/to_ids ต่าง หรือ MISP แก้ไขหลัง Splunk นำเข้า (`stale`) |
| `summary.json` | สรุป รวม `missing_by_threat_level`, `missing_by_to_ids`, `splunk_duplicate_factor` |

อ่านผล
- ขาดเฉพาะ medium/low หรือ `to_ids=false` → ตัวดึงข้อมูลเดิมกรองไว้ (ตั้งใจ) ถ้าต้องการให้ตรง ใช้ `--levels 1 --to-ids true`
- ขาดทั้ง event → ตัวดึงข้อมูลพลาด event นั้น (เช่น ดึงตาม publish time แต่ event ถูก publish ซ้ำ)
- ขาดบางส่วนของ event → มักเป็น attribute ใน object หรือ attribute ที่เพิ่มหลัง publish
- `splunk_duplicate_factor` สูง → ตัวดึงข้อมูล index ซ้ำทุกรอบ (เปลืองไลเซนส์ Splunk)
- ตั้ง `hec_url` ใน `[splunk]` แล้วเปิด alert `TBCERT - MISP Reconcile - Missing IOC` เพื่อแจ้งเตือนรายวัน; exit code 2 เมื่อขาดเกิน `max_missing_pct`

**Dashboard:** แอป `TA-tbcert-misp` มีหน้า *TB-CERT MISP ↔ Splunk Reconcile* (เป็นหน้าแรกของแอป)
- ต้องตั้ง `hec_url` / `hec_token` ใน `[splunk]` — สคริปต์ส่ง `sourcetype=tbcert:misp:reconcile` (สรุป) และ
  `tbcert:misp:reconcile:item` (รายละเอียด kind=missing/mismatched/extra/event, สูงสุด `hec_max_items` ต่อรอบ)
- index ปลายทางตั้งที่ `hec_index` (ค่าเริ่มต้น `threat_intel` ต้องสร้าง index นี้ก่อน) และ macro `tbcert_reconcile_index` ต้องตรงกัน
- เลือกรอบที่ตรวจ, threat level, คลิก event เพื่อดู IOC ที่ขาดของ event นั้น

## ข้อควรระวังสำหรับธนาคาร (สำคัญกว่าโค้ด)
- **กัน False positive ก่อน block จริง**: เปิด `enforce_warninglist`, ใช้ `to_ids_only`, มี allowlist (IP ของธนาคารเอง, ITMX/NITMX, SWIFT, BOT, ผู้ให้บริการ cloud/CDN ที่ใช้งาน) และตัด private/reserved IP อัตโนมัติ
- **เริ่มจาก monitor → block**: ช่วงแรกใช้ saved search อย่างเดียว 2–4 สัปดาห์ ดูปริมาณ hit และ FP แล้วจึงเปิด policy deny
- **IOC มีอายุ**: IP เปลี่ยนเจ้าของเร็ว (ค่าเริ่มต้น 30 วัน), domain/URL 90 วัน, hash 365 วัน — ปรับได้ใน `[ttl]`; IOC ที่ถูกลบหรือปลด `to_ids` ใน MISP จะถูกถอดออกในรอบถัดไป
- **Change management / audit**: เปิด HEC audit (`sourcetype=tbcert:misp:sync`) เก็บประวัติว่า IOC ใดเข้า/ออก blocklist เมื่อใด สอดคล้องกับแนวทาง Cyber Resilience ของ ธปท.
- **Fail-safe**: ถ้าดึงไม่สำเร็จ สคริปต์จะไม่ล้างลิสต์เดิม (เพียงหยุดอัปเดต) และมี alert `MISP Sync Health`
- **ส่ง Sighting กลับ** ไปยัง TB-CERT เมื่อพบ hit จริง (ผ่าน MISP42Splunk alert action หรือ MISP API `/sightings/add`) เพื่อช่วยสมาชิกอื่นประเมินความน่าเชื่อถือของ IOC
- **เก็บ secret** (MISP key, Splunk token) ใน vault/env ไม่ commit ลง git (`config.ini` อยู่ใน `.gitignore` แล้ว)

## ไฟล์
```
misp_to_splunk.py      ดึงจาก MISP → กรอง → upsert/ลบใน Splunk KV store
export_edl.py          อ่าน KV store → ip/domain/url/hash/email .txt + rpz.zone
push_blocklists.py     ส่ง IOC action=block → SentinelOne / Imperva WAF / Proofpoint
reconcile_misp_splunk.py  เทียบ MISP API กับ sourcetype=misp_events ว่าครบหรือไม่
build_no_app.py        สร้างไฟล์สำหรับโหมดไม่ติดตั้งแอป (macro/lookup) จากไฟล์ของแอป → no_app/generated/
no_app/                คู่มือ + dashboard สำหรับใช้ MISP42Splunk โดยไม่ติดตั้งแอปใหม่
preflight.py           ทดสอบการเชื่อมต่อ MISP / Splunk / HEC / S1 / Imperva / Proofpoint และ SPL ก่อนติดตั้ง
config.example.ini     ตัวอย่าง config
allowlist.example.txt  ตัวอย่าง allowlist
test_normalize.py      unit test ของ logic การกรอง
splunk_app/TA-tbcert-misp/   collections.conf, transforms.conf, savedsearches.conf
```
