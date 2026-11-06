# 📣 Email Notifier — ส่งอีเมลแจ้งเตือนพนักงานผ่าน Splunk

หน้าเว็บ HTML สำหรับส่งอีเมลแจ้งเตือนถึงพนักงานหลายคน: **อัปโหลดรายชื่อ → เขียนข้อความ → ดูตัวอย่าง → กดส่ง**
ส่งผ่านคำสั่ง [`sendemail`](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sendemail) ของ Splunk ซึ่งเชื่อมกับ SMTP ภายในอยู่แล้ว

```
Browser (index.html) ──POST /api/send──▶ server.js ──REST :8089──▶ Splunk ──▶ internal SMTP
                                         (เก็บ Splunk token)   | makeresults | sendemail to=... 
```

ใช้ `server.js` เป็นตัวกลางเพื่อไม่ให้ Splunk token อยู่ในเบราว์เซอร์ และเลี่ยงปัญหา CORS/ใบรับรองของพอร์ต 8089 (ไม่ต้องติดตั้งแพ็กเกจเพิ่ม ใช้ Node.js 18 ขึ้นไป)

## ความสามารถ
- อัปโหลด CSV/TXT (ลากวางได้) หรือวางรายชื่อเอง; ตรวจอีเมลผิดรูปแบบและอีเมลซ้ำ
- ตัวแปรในหัวเรื่องและเนื้อหา เช่น `{{name}}`, `{{department}}` (ใช้ได้ทุกคอลัมน์ในไฟล์)
- ดูตัวอย่างแยกรายคน และเตือนเมื่อตัวแปรไม่มีคอลัมน์รองรับหรือข้อมูลว่าง
- ส่งแยกทีละคน (1 search ต่อ 1 ฉบับ) มีหน้าต่างยืนยัน แถบความคืบหน้า ปุ่มหยุด ส่งซ้ำรายการที่ล้มเหลว และ export ผลเป็น CSV
- โหมด 🧪 ทดสอบ (จำลองการส่ง ไม่มีอีเมลออกจริง)

## ติดตั้ง
1. ใน Splunk: ตั้งค่า SMTP ไว้แล้วที่ *Settings → Server settings → Email settings*
2. สร้าง user/role สำหรับเครื่องมือนี้ ให้สิทธิ์รัน search ใน app `search` และสร้าง token (*Settings → Tokens*)
3. ตั้งค่าและรัน:
   ```bash
   cp .env.example .env    # แล้วแก้ SPLUNK_URL, SPLUNK_TOKEN, MAIL_FROM
   node server.js
   ```
4. เปิด http://localhost:3000 → กด “ทดสอบการเชื่อมต่อ” → ลองโหมดทดสอบก่อน แล้วค่อยเลือก “ส่งจริง”

## รูปแบบไฟล์รายชื่อ
```csv
email,name,department
somchai@example.com,สมชาย ใจดี,IT
```
ดู `sample-recipients.csv` — ถ้าเป็น Excel ให้ Save As เป็น **CSV UTF-8**

## หมายเหตุ
- `sendemail` ไม่รองรับ header Reply-To จึงต่อท้ายไว้ในเนื้อหาแทน
- `MAIL_CONTENT_TYPE=plain` (ค่าเริ่มต้น) ส่งเป็นข้อความธรรมดา; ตั้งเป็น `html` เพื่อส่งตามรูปแบบในหน้าตัวอย่าง
- ค่าที่ใส่ใน SPL ถูก escape (`\` และ `"`) และตรวจรูปแบบอีเมลฝั่ง server เพื่อป้องกัน SPL injection
- ตั้ง `API_TOKEN` ถ้าเปิดให้เครื่องอื่นเข้าถึง server นี้ได้
- ทุกการส่งจะเห็นใน Splunk `_audit` / `_internal` (sendemail logs) ใช้ตรวจสอบย้อนหลังได้
