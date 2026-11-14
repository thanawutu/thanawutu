// Fake Splunk Simple XML runtime for imperva_form.js (token models, search manager, drilldown)
(function () {
  var cfg = window.HARNESS;           // {p, dark, throwIn}
  var log = window.TOKLOG = [];
  function Model(name) { this.name = name; this.attrs = {}; this.h = {}; }
  Model.prototype.get = function (k) { return this.attrs[k]; };
  Model.prototype.on = function (ev, fn) { var me = this; ev.split(" ").forEach(function (e) { (me.h[e] = me.h[e] || []).push(fn); }); };
  Model.prototype.trigger = function (ev, v) { var me = this; (this.h[ev] || []).slice().forEach(function (fn) { fn(me, v); }); };
  Model.prototype.set = function (k, v) {
    if (this.attrs[k] === v) return;
    this.attrs[k] = v; log.push(this.name + ".set " + k + "=" + v); this.trigger("change:" + k, v);
    // hidden Simple XML input with searchWhenChanged: a form.* change submits ALL form tokens
    if (this === def && k.indexOf("form.") === 0) {
      Object.keys(def.attrs).forEach(function (a) { if (a.indexOf("form.") === 0) sub.set(a.slice(5), def.attrs[a]); });
    }
  };
  Model.prototype.unset = function (k) {
    if (!(k in this.attrs)) return;
    delete this.attrs[k]; log.push(this.name + ".unset " + k); this.trigger("change:" + k, undefined);
  };
  var def = new Model("def"), sub = new Model("sub");
  var p = cfg.p;
  // <init> + input defaults
  var init = {}; init[p + "_sel"] = ","; init[p + "_refresh"] = "init";
  var forms = {}; forms[p + "_q"] = "*"; forms[p + "_tk"] = "-"; forms[p + "_desc"] = "-";
  if (p !== "b") forms[p + "_add"] = "-";
  Object.keys(init).forEach(function (k) { def.attrs[k] = init[k]; sub.attrs[k] = init[k]; });
  Object.keys(forms).forEach(function (k) { def.attrs["form." + k] = forms[k]; def.attrs[k] = forms[k]; sub.attrs[k] = forms[k]; });

  var ROWS = window.ROWS;
  var ALLOWED = {"192.0.2.55": "Allowlist-Partners"};
  var CLOUD = {"52.88.145.123": "Amazon.com, Inc.", "35.240.10.8": "Google LLC"};
  function odd(raw) {
    var s = String(raw || "").replace(/☑ Select all \d+ shown: /g, "").replace(/^,+|,+$/g, ""), c = {}, o = [];
    s.split(",").forEach(function (x) { if (!x || x === "-") return; if (!(x in c)) { c[x] = 0; o.push(x); } c[x]++; });
    return o.filter(function (x) { return c[x] % 2 === 1; }).sort();
  }
  // search manager of the action table
  function Results() { this.h = {}; this.d = null; }
  Results.prototype.on = Model.prototype.on; Results.prototype.trigger = Model.prototype.trigger;
  Results.prototype.data = function () { return this.d; };
  function Mgr(id) { this.id = id; this.h = {}; this.res = new Results(); this.runs = 0; }
  Mgr.prototype.on = Model.prototype.on; Mgr.prototype.trigger = Model.prototype.trigger;
  Mgr.prototype.data = function (kind, opts) { window.RESULT_OPTS = opts; return this.res; };
  var mgr = new Mgr(p + "_act"), t = null;
  function dispatch() {
    clearTimeout(t);
    t = setTimeout(function () {
      mgr.runs++; if (!cfg.noStart) mgr.trigger("search:start");
      setTimeout(function () {
        var sel = odd(sub.get(p + "_sel")), add = String(sub.get(p + "_add") || "-");
        var man = add === "-" ? [] : add.split(/[\s,;]+/).filter(Boolean);
        var ips = sel.concat(man.filter(function (x) { return sel.indexOf(x) < 0; }));
        var q = String(sub.get(p + "_q") || "*").replace(/\*/g, "").trim().toLowerCase().replace(/^ithm[\s:#-]*/, "");
        var shown = ROWS.filter(function (r) { return !q || (r.ip + " " + r.inc + " " + r.rule).toLowerCase().indexOf(q) >= 0; }).map(function (r) { return r.ip; });
        var chk = ips.map(function (ip) {
          if (!/^[0-9a-f:.\/]+$/i.test(ip) || (ip.indexOf(":") < 0 && !/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(ip))) return ip + " is not an IP / CIDR";
          if (CLOUD[ip]) return ip + " is a CLOUD PROVIDER IP (" + CLOUD[ip] + ") - short block: unblocked automatically after a few days without an attack";
          return ALLOWED[ip] ? ip + " is ALLOWED: " + ALLOWED[ip] : null;
        }).filter(Boolean);
        var waf = chk.length ? chk : (ips.length ? "✔ none blocked / allowed on WAF" : "-");
        var fields = p === "b" ? ["Action", "Clear", "selected_ips", "ticket", "description"]
                               : ["Action", "NotBlock", "Clear", "SelectAll", "selected_ips", "waf_check", "cloud_ips", "ticket", "description"];
        var vals = {Action: "-", NotBlock: "-", Clear: "-", SelectAll: shown.length ? "☑ Select all " + shown.length + " shown: " + shown.join(",") : "-",
                    selected_ips: ips.join(", ") || "-", waf_check: waf, cloud_ips: ips.filter(function (x) { return CLOUD[x]; }).join(","), ticket: sub.get(p + "_tk"), description: sub.get(p + "_desc")};
        mgr.res.d = {fields: fields, rows: [fields.map(function (f) { return vals[f]; })]};
        mgr.res.trigger("data");
      }, 40);
    }, 5);
  }
  [p + "_sel", p + "_add", p + "_q", p + "_tk", p + "_desc"].forEach(function (k) { sub.on("change:" + k, dispatch); });
  // result searches (record what would be run)
  window.RUNS = [];
  sub.on("change:" + p + "_exec_ips", function (m, v) { if (v !== undefined) window.RUNS.push({kind: "exec", ips: v, tk: sub.get(p + "_exec_tk"), desc: sub.get(p + "_exec_desc")}); });
  sub.on("change:" + p + "_nb_exec", function (m, v) { if (v !== undefined) window.RUNS.push({kind: "nb", ips: v, tk: sub.get(p + "_nb_tk"), desc: sub.get(p + "_nb_desc")}); });
  // ... and catch a run with stale IPs: exec_tk / exec_desc changing while exec_ips is set
  [p + "_exec_tk", p + "_exec_desc"].forEach(function (k) { sub.on("change:" + k, function () { if (sub.get(p + "_exec_ips") !== undefined) window.RUNS.push({kind: "STALE", ips: sub.get(p + "_exec_ips")}); }); });

  // search <p>_find (impervafind + ES detections): answers for the IPs typed in the search box
  var FIND = {
    "192.0.2.55": ["no", "al¦ALLOWED by policy 1000002 Allowlist-Partners (192.0.2.55) - cannot be blocked"],
    "185.220.101.47": ["no", "no¦already BLOCKED in policy 1000001 Block DDoS policy · on the policy since 2026-05-01 (block date not kept by Imperva)"],
    "54.245.10.21": ["yes", "ok¦not on the WAF and not blocked from Splunk - can be blocked ‖ pg¦detected 2026-11-14 08:00 · Threat - WAF scanner · ticket 1000101 · on the " + (p === "h" ? "Older detections" : "Block – last 7 days") + " page"]
  };
  var fmgr = new Mgr(p + "_find"), ft = null;
  fmgr.data = function (kind, opts) { window.FIND_OPTS = opts; return this.res; };
  function dispatchFind() {
    clearTimeout(ft);
    ft = setTimeout(function () {
      fmgr.runs++;
      if (cfg.findFail) { fmgr.trigger("search:failed", {content: {messages: [{type: "ERROR", text: "Error in 'impervafind' command: boom"}]}}); return; }
      // the running job of the previous keystroke is cancelled when a new one starts (not a failure)
      fmgr.trigger("search:cancelled"); fmgr.trigger("search:start");
      var q = String(sub.get(p + "_q") || "*").replace(/\*/g, "").trim().toLowerCase().replace(/^ithm[\s:#-]*/, "");
      var isip = function (x) { return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(x) || (/:/.test(x) && /^[0-9a-f:.]+(\/\d{1,3})?$/.test(x)); };
      var ips = q.split(/[\s,;]+/).filter(Boolean).filter(isip), rows = [];
      if (ips.length) {
        ips.forEach(function (ip) {
          var f = FIND[ip] || ["yes", "ok¦not on the WAF and not blocked from Splunk - can be blocked"];
          rows.push([ip, f[1] + (CLOUD[ip] ? " ‖ pg¦cloud provider (" + CLOUD[ip] + ") - short block: auto unblock after 7 days without an attack" : ""), f[0], CLOUD[ip] || "-"]);
        });
      } else if (q) {
        rows.push(["-", "pg¦2 blocked from Splunk (Blocked IPs page) ‖ pg¦1 IP rules in other WAF policies ‖ pg¦0 in the Not block list", "-", "-"]);
      }
      fmgr.res.d = {fields: ["ip", "found", "find_blockable", "find_cloud"], rows: rows};
      fmgr.res.trigger("data");
    }, cfg.findDelay || 60);
    if (cfg.findDelay) setTimeout(function () { fmgr.trigger("search:progress"); }, 5);
  }
  if (p !== "b") sub.on("change:" + p + "_q", dispatchFind);

  var tableComp = {settings: {get: function (k) { return k === "managerid" ? p + "_act" : null; }}};
  var comps = {"default": def, "submitted": sub};
  comps[p + "_act"] = cfg.noMgrId ? undefined : mgr;
  comps["mgr_hidden"] = mgr;
  comps[p + "_acttable"] = cfg.noMgrId ? {settings: {get: function () { return "mgr_hidden"; }}} : tableComp;
  if (p !== "b") comps[p + "_find"] = fmgr;
  var mvc = {Components: {get: function (id) { if (cfg.throwIn === id) throw new Error("boom"); return comps[id]; }}};
  window.DEF = def; window.SUB = sub; window.MGR = mgr; window.FMGR = fmgr;

  // drilldown of the IP table: <set token="p_sel">$p_sel$,$row.src$,</set> + <eval token="form.p_tk">
  window.rowClick = function (ip, inc) {
    var v = (sub.get(p + "_sel") || "") + "," + ip + ",";
    def.set(p + "_sel", v); sub.set(p + "_sel", v);
    var tk = def.get("form." + p + "_tk");
    if (tk === undefined || tk === "-" || tk === "") def.set("form." + p + "_tk", inc);
  };
  window.require = function (deps, fn) { fn(window.jQuery, mvc); };
  dispatch();   // the action search runs when the page loads
})();
