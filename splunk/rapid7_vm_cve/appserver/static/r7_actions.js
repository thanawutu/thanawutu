/*
 * Buttons for the Rapid7 VM CVE Response dashboards.
 *
 *   <button class="btn" data-r7-set="launch_nonce" data-r7-value="nonce"
 *           data-r7-confirm="Launch the rescan?" data-r7-unset="preview_nonce">Rescan</button>
 *
 * data-r7-set     token to set (in both the default and submitted token models)
 * data-r7-value   value, or "nonce" for a unique request id (used for de-duplication)
 * data-r7-confirm optional confirmation text
 * data-r7-unset   optional comma-separated tokens to clear
 * data-r7-require optional token that must not be empty (e.g. the server list);
 *                 otherwise a message is shown next to the button and nothing runs
 * data-r7-require-when optional "token=value": only require when that token has this value
 *
 * Tokens set here are not written to the URL, so reloading a dashboard never
 * re-runs a launch; r7rescan also ignores a repeated request_id.
 */
require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc) {
    var defaultTokens = mvc.Components.get('default');
    var submittedTokens = mvc.Components.get('submitted');

    function setToken(name, value) {
        defaultTokens.set(name, value);
        if (submittedTokens) { submittedTokens.set(name, value); }
    }

    function unsetToken(name) {
        defaultTokens.unset(name);
        if (submittedTokens) { submittedTokens.unset(name); }
    }

    function tokenValue(name) {
        var v = defaultTokens.get('form.' + name);
        if (v === undefined || v === null) { v = defaultTokens.get(name); }
        if ($.isArray(v)) { v = v.filter(function (x) { return x !== '' && x !== null; }).join(','); }
        return (v === undefined || v === null) ? '' : String(v).trim();
    }

    function showMessage($b, text) {
        var $p = $b.parent();
        var $m = $p.find('.r7-msg');
        if (!$m.length) {
            $m = $('<span class="r7-msg" style="margin-left:12px;color:#f8be34;font-weight:bold"></span>');
            $b.siblings('button').last().after($m);
        }
        $m.text(text || '');
    }

    $(document).on('click', '[data-r7-set]', function (e) {
        e.preventDefault();
        var $b = $(this);
        var req = $b.attr('data-r7-require');
        if (req) {
            var when = $b.attr('data-r7-require-when');
            var needed = true;
            if (when) {
                var kv = when.split('=');
                needed = tokenValue(kv[0]) === (kv[1] || '');
            }
            if (needed && !tokenValue(req)) {
                showMessage($b, 'Pick at least one server first.');
                return;
            }
        }
        showMessage($b, '');
        var msg = $b.attr('data-r7-confirm');
        if (msg && !window.confirm(msg)) { return; }
        var value = $b.attr('data-r7-value') || '1';
        if (value === 'nonce') {
            value = 'R' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        }
        var unset = $b.attr('data-r7-unset');
        if (unset) {
            unset.split(',').forEach(function (t) { if (t) { unsetToken(t.trim()); } });
        }
        setToken($b.attr('data-r7-set'), value);
    });
});
