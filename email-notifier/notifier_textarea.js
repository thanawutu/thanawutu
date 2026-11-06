/*
 * notifier_textarea.js — turns the dashboard's single-line "body" text input into a
 * large email-compose textarea (Enter = new line).
 *
 * Install: copy to $SPLUNK_HOME/etc/apps/<app of the dashboard>/appserver/static/
 *          then open https://<splunk>/en-US/_bump and click "Bump version" (or restart Splunk).
 * The dashboard references it with script="notifier_textarea.js". Without this file the
 * dashboard still works; the body stays a single-line box where \n means a line break.
 *
 * The textarea keeps the original token format: real line breaks are stored as the
 * two characters \n, so every search in the dashboard keeps working unchanged.
 */
require([
  'splunkjs/mvc',
  'jquery',
  'splunkjs/mvc/simplexml/ready!'
], function (mvc, $) {
  'use strict';

  var INPUT_ID = 'in_body';
  var toText = function (v) { return String(v == null ? '' : v).replace(/\\n/g, '\n'); };
  var toToken = function (v) { return String(v).replace(/\r\n?/g, '\n').replace(/\n/g, '\\n'); };

  $('<style>').text([
    '#' + INPUT_ID + ' { width: 100% !important; max-width: 1100px; }',
    '#' + INPUT_ID + ' input[type=text] { display: none !important; }',
    '.notifier-compose { width: 100%; min-height: 380px; resize: vertical; box-sizing: border-box;',
    '  padding: 12px 14px; border: 1px solid #c3cbd4; border-radius: 3px; background: #fff; color: #2b3033;',
    '  font: 14px/1.6 Tahoma, "Segoe UI", "Noto Sans Thai", sans-serif; }',
    '.notifier-compose:focus { outline: none; border-color: #0877a6; box-shadow: 0 0 0 2px rgba(8,119,166,.25); }',
    '.notifier-compose-meta { font-size: 12px; color: #6b7480; margin-top: 4px; }'
  ].join('\n')).appendTo('head');

  function attach() {
    var input = mvc.Components.get(INPUT_ID);
    var $wrap = $('#' + INPUT_ID);
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

    $ta.on('input', function () {
      input.val(toToken($ta.val()));   // updates the token; Submit sends it as usual
      updateMeta();
    });
    // keep the textarea in sync if the token changes elsewhere (URL, reset, etc.)
    input.on('change', function (value) {
      if (toToken($ta.val()) !== value) { $ta.val(toText(value)); updateMeta(); }
    });

    var $field = $wrap.find('input[type=text]').first();
    ($field.length ? $field.parent() : $wrap).append($ta, $meta);
    return true;
  }

  if (!attach()) {
    var tries = 0;
    var timer = setInterval(function () { if (attach() || ++tries > 40) { clearInterval(timer); } }, 250);
  }
});
