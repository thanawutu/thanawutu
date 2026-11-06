/*
 * email_notifier.js — companion script for email_notifier_dashboard.xml
 *   1) turns the single-line "body" input into a large email-compose textarea (Enter = new line)
 *   2) adds a "📧 Test" button next to the test-email box: one click sends the first
 *      recipient's personalised email (subject prefixed [TEST]) to that address right away.
 *
 * Install: copy to $SPLUNK_HOME/etc/apps/<app of the dashboard>/appserver/static/
 *          then open https://<splunk>/en-US/_bump and click "Bump version" (or restart Splunk).
 * The dashboard loads it with script="email_notifier.js".
 *
 * The textarea keeps the token format the searches expect: line breaks are stored as \n.
 */
require([
  'splunkjs/mvc',
  'jquery',
  'splunkjs/mvc/simplexml/ready!'
], function (mvc, $) {
  'use strict';

  var EMAIL_RE = /^[^\s@<>(),;:"\\|]+@[^\s@<>(),;:"\\|]+\.[^\s@<>(),;:"\\|]+$/;
  var defaultTokens = mvc.Components.get('default');
  var submittedTokens = mvc.Components.get('submitted');

  $('<style>').text([
    '#in_body { width: 100% !important; max-width: 1100px; }',
    '#in_body input[type=text] { display: none !important; }',
    '.notifier-compose { width: 100%; min-height: 380px; resize: vertical; box-sizing: border-box;',
    '  padding: 12px 14px; border: 1px solid #c3cbd4; border-radius: 3px; background: #fff; color: #2b3033;',
    '  font: 14px/1.6 Tahoma, "Segoe UI", "Noto Sans Thai", sans-serif; }',
    '.notifier-compose:focus { outline: none; border-color: #0877a6; box-shadow: 0 0 0 2px rgba(8,119,166,.25); }',
    '.notifier-compose-meta { font-size: 12px; color: #6b7480; margin-top: 4px; }',
    '#in_test { width: auto !important; }',
    '.notifier-test-row { display: flex; gap: 6px; align-items: center; }',
    '.notifier-test-btn { white-space: nowrap; }',
    '.notifier-test-msg { font-size: 12px; margin-top: 4px; max-width: 360px; }',
    '.notifier-test-msg.ok { color: #1a9035; } .notifier-test-msg.err { color: #d6402e; } .notifier-test-msg.run { color: #0877a6; }'
  ].join('\n')).appendTo('head');

  // ---------- 1) compose textarea ----------
  var toText = function (v) { return String(v == null ? '' : v).replace(/\\n/g, '\n'); };
  var toToken = function (v) { return String(v).replace(/\r\n?/g, '\n').replace(/\n/g, '\\n'); };

  function attachTextarea() {
    var input = mvc.Components.get('in_body');
    var $wrap = $('#in_body');
    if (!input || !$wrap.length) { return false; }
    if ($wrap.find('.notifier-compose').length) { return true; }

    var $ta = $('<textarea class="notifier-compose" spellcheck="false" aria-label="เนื้อหาอีเมล"></textarea>');
    var $meta = $('<div class="notifier-compose-meta"></div>');
    var updateMeta = function () {
      var text = $ta.val();
      $meta.text(text.split('\n').length + ' บรรทัด · ' + text.length + ' ตัวอักษร · ตัวแปรที่ใช้ได้: {{name}}, {{email}} และชื่อคอลัมน์อื่นในไฟล์');
    };
    $ta.val(toText(input.val()));
    updateMeta();
    $ta.on('input', function () { input.val(toToken($ta.val())); updateMeta(); });
    input.on('change', function (value) {
      if (toToken($ta.val()) !== value) { $ta.val(toText(value)); updateMeta(); }
    });
    var $field = $wrap.find('input[type=text]').first();
    ($field.length ? $field.parent() : $wrap).append($ta, $meta);
    return true;
  }

  // ---------- 2) Test button ----------
  function attachTestButton() {
    var $wrap = $('#in_test');
    var manager = mvc.Components.get('test_search');
    if (!$wrap.length || !manager) { return false; }
    if ($wrap.find('.notifier-test-btn').length) { return true; }

    var $field = $wrap.find('input[type=text]').first();
    var $btn = $('<button type="button" class="btn btn-primary notifier-test-btn">📧 Test</button>');
    var $msg = $('<div class="notifier-test-msg" role="status"></div>');
    var $row = $('<div class="notifier-test-row"></div>');
    $field.after($row);
    $row.append($field, $btn);
    $row.after($msg);

    var pendingTo = null;
    var say = function (cls, text) { $msg.attr('class', 'notifier-test-msg ' + cls).text(text); };
    var finish = function () {
      pendingTo = null;
      $btn.prop('disabled', false);
      defaultTokens.unset('run_test');
      submittedTokens.unset('run_test');
    };

    $btn.on('click', function () {
      var to = String(defaultTokens.get('test_to') || '').trim().toLowerCase();
      if (!EMAIL_RE.test(to)) { say('err', 'กรุณาใส่อีเมลสำหรับทดสอบให้ถูกต้องก่อน'); return; }
      if (!defaultTokens.get('src_spl')) { say('err', 'กรุณาเลือกรายชื่อผู้รับ (ช่องที่ 1) ก่อน'); return; }
      pendingTo = to;
      $btn.prop('disabled', true);
      say('run', 'กำลังส่งอีเมลทดสอบไปที่ ' + to + ' …');
      // use what is on screen now (same as pressing Submit), then trigger the test search
      submittedTokens.set(defaultTokens.toJSON());
      var stamp = String(Date.now());
      defaultTokens.set('run_test', stamp);
      submittedTokens.set('run_test', stamp);
    });

    manager.on('search:done', function (props) {
      if (!pendingTo) { return; }
      var count = props && props.content ? Number(props.content.resultCount || 0) : 0;
      if (count > 0) {
        say('ok', '✓ ส่งอีเมลทดสอบไปที่ ' + pendingTo + ' แล้ว (หัวเรื่องขึ้นต้นด้วย [TEST]) — ตรวจกล่องจดหมาย');
      } else {
        say('err', '✕ ไม่ได้ส่ง: ไม่มีผู้รับที่อีเมลถูกต้องในรายชื่อ หรือ sendemail ล้มเหลว — ดูแผง “ข้อผิดพลาดจาก sendemail”');
      }
      finish();
    });
    manager.on('search:fail search:error', function (err) {
      if (!pendingTo) { return; }
      say('err', '✕ ส่งไม่สำเร็จ: ' + (err && err.message ? err.message : 'search error'));
      finish();
    });
    manager.on('search:cancelled', function () {
      if (!pendingTo) { return; }
      say('err', 'ยกเลิกการส่งทดสอบแล้ว');
      finish();
    });
    return true;
  }

  function attachAll() { var a = attachTextarea(); var b = attachTestButton(); return a && b; }
  if (!attachAll()) {
    var tries = 0;
    var timer = setInterval(function () { if (attachAll() || ++tries > 40) { clearInterval(timer); } }, 250);
  }
});
