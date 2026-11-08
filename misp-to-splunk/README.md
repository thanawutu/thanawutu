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

> **ถ้ามีข้อมูล MISP อยู่ใน Splunk แล้ว หรืออยากใช้ MISP42Splunk แทนสคริปต์ → ดู [SPLUNK_NATIVE.md](SPLUNK_NATIVE.md)** (รองรับกรองตามความรุนแรงและ Event ID)
>
> สามารถใช้ร่วมกันได้ เช่น ใช้สคริปต์นี้ทำ blocklist และใช้ MISP42Splunk สำหรับ analyst ค้นหา/ส่ง sighting กลับไป TB-CERT

## สิ่งที่ต้องขอจาก TB-CERT / ทีมภายใน
1. **บัญชี MISP ขององค์กร** + Auth key (role *User* หรือ *Read Only* ก็พอสำหรับดึง) — ขอให้ผูกกับ service account ไม่ใช่บุคคล
2. **Whitelist IP** ขาออกของเครื่องที่รันสคริปต์ (หาก MISP ของ TB-CERT จำกัด source IP) และเปิด firewall/proxy ไปยัง MISP ทาง 443
3. **Splunk token** ของ service account ที่มี role เขียน KV store ของ app `TA-tbcert-misp` (role `tbcert_ti_writer` ใน `metadata/default.meta`)
4. ข้อตกลงเรื่อง **TLP** — ใช้ IOC TLP:AMBER ภายในได้ แต่ห้ามส่งต่อนอกองค์กร (เช่น อัปโหลดขึ้น cloud ของ vendor ที่แชร์ข้อมูลข้ามลูกค้า)

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
config.example.ini     ตัวอย่าง config
allowlist.example.txt  ตัวอย่าง allowlist
test_normalize.py      unit test ของ logic การกรอง
splunk_app/TA-tbcert-misp/   collections.conf, transforms.conf, savedsearches.conf
```
