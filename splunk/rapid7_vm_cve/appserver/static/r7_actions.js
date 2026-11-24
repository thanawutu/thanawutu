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

    $(document).on('click', '[data-r7-set]', function (e) {
        e.preventDefault();
        var $b = $(this);
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
