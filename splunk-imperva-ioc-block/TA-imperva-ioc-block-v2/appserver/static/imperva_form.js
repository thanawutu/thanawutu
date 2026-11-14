/*
 * Imperva IOC Block - action card of the Block, Older detections and Blocked IPs / Unblock pages.
 *
 * Replaces the Simple XML inputs + action table of panel "<p>_actpanel" with one card:
 *
 *   Search or add IPs (IP / Ticket / Incident no. / Rule)   - one box (mockup v3.12)
 *   Found: where the typed IPs are - every page and every WAF policy (detection pages)
 *   Selected IPs (× = unselect) | Ticket / Incident no. | Description | [⛔ Block n IPs] [✖ Not block n IPs]
 *   WAF check of the selected IPs (detection pages)
 *
 * Full IPs typed in the search box are the manual IPs: the card puts them in $p_add$ for the action
 * search and reads the search "<p>_find" (impervafind: every WAF policy, registry, Not block list,
 * ES detections of both pages). The Block button counts only the typed IPs that can be blocked.
 *
 * The card only reads and sets the SAME tokens as the Simple XML panel ($p_q$, $p_add$, $p_tk$,
 * $p_desc$, $p_sel$, $p_exec_*$, $p_nb_*$), so the searches of the views do not change.
 * If this script does not load, the Simple XML inputs and the action table stay visible and
 * work as before.
 *
 * V2: cloud provider IPs (field cloud_ips of the action search) are blocked like any IP and get a
 *        "short block" tag (Auto unblock removes them after a few quiet days); incident
 *        numbers are digits only ("ITHM 1000101" in the search box -> Ticket 1000101); the
 *        "All paths" table of the IP detail panel scrolls.
 */
require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function ($, mvc) {
    "use strict";

    var PAGES = {
        d: {verb: "block", manual: true, table: "det_table", ipField: "src", page: "Block – last 7 days",
            search: "🔎 Search or add IPs – IP / Ticket / Incident no. / Rule · searches every page and every WAF policy",
            qph: "เช่น 54.245 · 1000101 · หรือวาง IP หลายตัว 203.0.113.10, 198.51.100.7", dph: "เหตุผล / รายละเอียด"},
        h: {verb: "block", manual: true, table: "det_table", ipField: "src", page: "Older detections",
            search: "🔎 Search or add IPs – IP / Ticket / Incident no. / Rule · searches every page and every WAF policy",
            qph: "เช่น 54.245 · 1000101 · หรือวาง IP หลายตัว 203.0.113.10, 198.51.100.7", dph: "เหตุผล / รายละเอียด"},
        b: {verb: "unblock", manual: false, table: "b_table", ipField: "ip",
            search: "🔎 Search IP / Ticket / Incident no. / Description",
            qph: "เช่น 193.42 หรือ 1000090", dph: "เหตุผลที่ unblock"}
    };

    // light = colours of the mockup; body.imp-dark when Splunk draws the dashboard dark
    var CSS = [
        "body.imp-scope{--imp-bg:#ffffff;--imp-bg2:#f5f7f9;--imp-line:#d7dde3;--imp-fg:#18202a;--imp-muted:#5d6b78;--imp-ph:#8a96a3;--imp-accent:#1f6f8b;--imp-sel:#e3f0f5;--imp-crit:#c4362b;--imp-crit-bg:#fbe7e5;--imp-warn:#a86b00;--imp-warn-bg:#fdf1d8;--imp-ok:#2f7d4a;--imp-ok-bg:#e3f3e8;--imp-nb:#5d6b78;--imp-nb-fg:#ffffff;--imp-wait-bg:#e9edf1}",
        "body.imp-scope.imp-dark{--imp-bg:#1b1f24;--imp-bg2:#101418;--imp-line:#3c444d;--imp-fg:#e1e6eb;--imp-muted:#a7b3bf;--imp-ph:#7b8794;--imp-accent:#4fb3d4;--imp-sel:#18323d;--imp-crit:#dc4e41;--imp-crit-bg:#3a1a19;--imp-warn:#f2b445;--imp-warn-bg:#3a2c12;--imp-ok:#53a051;--imp-ok-bg:#16301f;--imp-nb:#5c6773;--imp-nb-fg:#ffffff;--imp-wait-bg:#232d38}",
        ".imp-card{border:1px solid var(--imp-accent);border-radius:6px;padding:12px 14px;margin:2px 0 4px;display:flex;flex-direction:column;gap:10px;background:var(--imp-bg);color:var(--imp-fg);font-size:13px;box-shadow:0 4px 14px rgba(0,0,0,.06)}",
        ".imp-card.imp-u{border-color:var(--imp-ok)}",
        ".imp-row{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:flex-end}",
        ".imp-field{display:flex;flex-direction:column;gap:3px;min-width:0}",
        ".imp-card .imp-field label,.imp-flabel{font-size:12px;color:var(--imp-muted);font-weight:500;margin:0;padding:0;line-height:1.4}",
        ".imp-flabel{display:flex;justify-content:space-between;gap:8px;align-items:baseline}",
        ".imp-card input[type=text]{font:inherit;font-size:13px;height:auto;padding:7px 9px;margin:0;border:1px solid var(--imp-line);border-radius:5px;background:var(--imp-bg2);color:var(--imp-fg);width:100%;min-width:0;box-sizing:border-box;box-shadow:none}",
        ".imp-card input[type=text]::placeholder{color:var(--imp-ph);opacity:1}",
        ".imp-card input[type=text]:focus{outline:2px solid var(--imp-accent);outline-offset:1px;border-color:var(--imp-accent)}",
        ".imp-sel{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-height:36px;border:1px dashed var(--imp-line);border-radius:5px;padding:4px 8px;background:var(--imp-bg2);box-sizing:border-box}",
        ".imp-none{font-size:12px;color:var(--imp-muted)}",
        ".imp-tag{display:inline-flex;align-items:center;gap:2px;font-family:Menlo,Consolas,monospace;font-size:12px;background:var(--imp-sel);border:1px solid var(--imp-accent);border-radius:4px;padding:1px 2px 1px 8px;color:var(--imp-fg);white-space:nowrap}",
        ".imp-tag.imp-man{border-style:dashed;background:var(--imp-warn-bg);padding-right:8px}",
        ".imp-tag.imp-bad{border-color:var(--imp-crit);background:var(--imp-crit-bg);color:var(--imp-crit);padding-right:8px}",
        ".imp-tag.imp-cloud{border-color:var(--imp-warn);background:var(--imp-warn-bg);color:var(--imp-warn)}",
        ".imp-scroll{max-height:360px;overflow-y:auto}",
        ".imp-tag button{border:0;background:transparent;padding:0 5px;margin:0;font-size:15px;line-height:1;color:var(--imp-muted);cursor:pointer}",
        ".imp-tag button:hover{color:var(--imp-fg)}",
        ".imp-link{border:0;background:transparent;padding:0;margin:0 0 0 10px;font-size:12px;color:var(--imp-accent);cursor:pointer;white-space:nowrap}",
        ".imp-link:hover{text-decoration:underline}",
        ".imp-run{font:inherit;font-size:13px;font-weight:700;padding:8px 18px;margin:0;border:0;border-radius:5px;color:#fff;background:var(--imp-crit);cursor:pointer;white-space:nowrap;line-height:1.4}",
        ".imp-run.imp-nb{background:var(--imp-nb);color:var(--imp-nb-fg)}",
        ".imp-run.imp-un{background:var(--imp-ok)}",
        ".imp-run:disabled{opacity:.45;cursor:not-allowed}",
        ".imp-run:focus-visible,.imp-link:focus-visible,.imp-tag button:focus-visible{outline:2px solid var(--imp-accent);outline-offset:2px}",
        ".imp-chk{font-size:12.5px;border-radius:5px;padding:7px 10px;line-height:1.45}",
        ".imp-chk.imp-ok{background:var(--imp-ok-bg);color:var(--imp-ok)}",
        ".imp-chk.imp-warn{background:var(--imp-warn-bg);color:var(--imp-warn)}",
        ".imp-chk.imp-wait{background:var(--imp-wait-bg);color:var(--imp-muted)}",
        ".imp-hidden{display:none!important}",
        ".imp-find{font-size:12.5px;border:1px solid var(--imp-line);border-radius:5px;padding:6px 10px;background:var(--imp-bg2);display:flex;flex-direction:column;gap:4px;line-height:1.45}",
        ".imp-find .imp-hd{font-size:11.5px;color:var(--imp-muted);font-weight:600}",
        ".imp-fl{display:flex;flex-wrap:wrap;gap:2px 14px;align-items:baseline}",
        ".imp-fl b{font-family:Menlo,Consolas,monospace;font-weight:600}",
        ".imp-f-no{color:var(--imp-crit)}.imp-f-al{color:var(--imp-ok)}.imp-f-ok{color:var(--imp-ok)}.imp-f-pg{color:var(--imp-fg)}.imp-f-note{color:var(--imp-muted)}",
        ".imp-tag.imp-wait{border-style:dashed;background:var(--imp-wait-bg);color:var(--imp-muted);padding-right:8px}",
        ".imp-sticky{position:sticky;top:0;z-index:20}",
        "body.imp-scope tr.imp-selrow>td:not([style*=background]){background-color:var(--imp-sel)!important}",
        "body.imp-scope tr.imp-selrow>td:first-child{box-shadow:inset 4px 0 0 var(--imp-accent)}"
    ].join("\n");

    var defTokens = mvc.Components.get("default");
    var subTokens = mvc.Components.get("submitted");
    if (!defTokens) {
        return;
    }

    function getTok(name) {
        var v = subTokens ? subTokens.get(name) : undefined;
        return v === undefined ? defTokens.get(name) : v;
    }

    function setTok(name, value) {
        defTokens.set(name, value);
        if (subTokens) {
            subTokens.set(name, value);
        }
    }

    function unsetTok(name) {
        defTokens.unset(name);
        if (subTokens) {
            subTokens.unset(name);
        }
    }

    // token of a Simple XML input: keep "form.<name>" in step, or the next submit of the
    // (hidden) inputs would copy the old value back
    function setInputTok(name, value) {
        defTokens.set("form." + name, value);
        setTok(name, value);
    }

    function onTok(name, fn) {
        defTokens.on("change:" + name, fn);
        if (subTokens) {
            subTokens.on("change:" + name, fn);
        }
    }

    function debounce(fn, ms) {
        var t = null;
        var wrapped = function () {
            clearTimeout(t);
            t = setTimeout(function () {
                t = null;
                fn();
            }, ms);
        };
        wrapped.flush = function () {
            if (t !== null) {
                clearTimeout(t);
                t = null;
                fn();
            }
        };
        return wrapped;
    }

    // same rule as the SPL of the action panel: an IP clicked an odd number of times is selected;
    // "☑ Select all N shown: a,b" (Select all cell of the old action table) is just a list of IPs
    function selectedFrom(raw) {
        var s = String(raw === undefined || raw === null ? "" : raw)
            .replace(/☑ Select all \d+ shown: /g, "").replace(/^,+|,+$/g, "");
        var count = {}, order = [];
        s.split(",").forEach(function (x) {
            x = x.trim();
            if (!x || x === "-") {
                return;
            }
            if (!count.hasOwnProperty(x)) {
                count[x] = 0;
                order.push(x);
            }
            count[x] += 1;
        });
        return order.filter(function (x) {
            return count[x] % 2 === 1;
        });
    }

    // "ITHM 1000101" / "1000101" -> "1000101" (incident numbers are shown as digits only)
    function incidentOf(v) {
        var m = /^\s*(?:ITHM[\s:#-]*)?(\d{6,})\s*$/i.exec(v || "");
        return m ? m[1] : null;
    }

    function isIp(x) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/.exec(x);
        if (m) {
            return [m[1], m[2], m[3], m[4]].every(function (o) {
                return +o <= 255;
            }) && (m[6] === undefined || +m[6] <= 32);
        }
        return x.indexOf(":") >= 0 && /^[0-9A-Fa-f:.]+(\/\d{1,3})?$/.test(x);
    }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) {
            e.className = cls;
        }
        if (text !== undefined) {
            e.textContent = text;
        }
        return e;
    }

    // order-free key of a list of IPs (the search lists them sorted, the card in click order)
    function setKey(list) {
        var seen = {};
        return list.filter(function (x) {
            x = String(x).trim();
            if (!x || seen[x]) {
                return false;
            }
            seen[x] = true;
            return true;
        }).map(function (x) {
            return String(x).trim();
        }).sort().join(",");
    }

    function plural(n) {
        return n + " IP" + (n === 1 ? "" : "s");
    }

    function blankIf(v, dash) {
        return (v === undefined || v === null || v === dash) ? "" : String(v);
    }

    function Card(p, cfg, $panel, $legacyTable) {
        var self = this;
        this.p = p;
        this.cfg = cfg;
        this.autoTk = false;     // Ticket was filled from an "ITHM ..." search, not typed
        this.shown = [];         // IPs of "Select all shown" (from the action search)
        this.cloud = [];         // selected / added IPs of a cloud provider: short block (auto unblock)
        this.chk = null;         // last WAF check text
        this.chkFor = null;      // IPs that WAF check was made for
        this.chkWait = false;
        this.found = {};         // typed IP -> {lines, blockable, cloud} from the search <p>_find
        this.findText = null;    // Found lines of a text search (no IP typed)
        this.findErr = false;

        var card = el("div", "imp-card" + (cfg.verb === "unblock" ? " imp-u" : ""));
        card.setAttribute("role", "group");
        card.setAttribute("aria-label", cfg.verb === "block" ? "Search and block" : "Search and unblock");

        function field(id, label, flex, placeholder) {
            var f = el("div", "imp-field");
            f.style.flex = flex;
            var l = el("label", null, label);
            l.setAttribute("for", id);
            var i = el("input");
            i.type = "text";
            i.id = id;
            i.autocomplete = "off";
            i.spellcheck = false;
            i.placeholder = placeholder;
            f.appendChild(l);
            f.appendChild(i);
            return {wrap: f, input: i};
        }

        var row1 = el("div", "imp-row");
        var q = field("imp_" + p + "_q", cfg.search, "1 1 300px", cfg.qph);
        row1.appendChild(q.wrap);
        // V2: no separate "Add IPs manually" box - full IPs typed in the search box are added
        var find = el("div", "imp-find imp-hidden");
        find.setAttribute("aria-live", "polite");

        var row2 = el("div", "imp-row");
        var selWrap = el("div", "imp-field");
        selWrap.style.flex = "1 1 340px";
        var selLabel = el("div", "imp-flabel");
        selLabel.appendChild(el("span", null, "Selected IPs — คลิกแถวในตารางด้านล่าง"));
        var links = el("span");
        var allBtn = el("button", "imp-link imp-hidden");
        allBtn.type = "button";
        var clearBtn = el("button", "imp-link imp-hidden", "✖ Clear");
        clearBtn.type = "button";
        links.appendChild(allBtn);
        links.appendChild(clearBtn);
        selLabel.appendChild(links);
        var selBox = el("div", "imp-sel");
        selBox.setAttribute("aria-live", "polite");
        selWrap.appendChild(selLabel);
        selWrap.appendChild(selBox);
        row2.appendChild(selWrap);

        var tk = field("imp_" + p + "_tk", "Ticket / Incident no.", "0 1 190px", "1234567");
        var desc = field("imp_" + p + "_desc", "Description", "1 1 240px", cfg.dph);
        row2.appendChild(tk.wrap);
        row2.appendChild(desc.wrap);

        var go = el("button", "imp-run" + (cfg.verb === "unblock" ? " imp-un" : ""));
        go.type = "button";
        row2.appendChild(go);
        var nb = null;
        if (cfg.manual) {
            nb = el("button", "imp-run imp-nb");
            nb.type = "button";
            nb.title = "hide the selected IPs until they are detected again (nothing is sent to the WAF)";
            row2.appendChild(nb);
        }

        var chk = el("div", "imp-chk imp-hidden");
        chk.setAttribute("aria-live", "polite");

        card.appendChild(row1);
        card.appendChild(find);
        card.appendChild(row2);
        card.appendChild(chk);

        this.el = {card: card, q: q.input, tk: tk.input, desc: desc.input,
            sel: selBox, all: allBtn, clear: clearBtn, go: go, nb: nb, chk: chk, find: find};

        // --- put the card in the panel, hide the Simple XML inputs + action table
        var $dp = $panel.find(".dashboard-panel").first();
        if (!$dp.length) {
            $dp = $panel;
        }
        $dp.prepend(card);
        this.hideLegacy = function () {
            $panel.find(".fieldset").addClass("imp-hidden");
            $panel.find(".panel-title, .panel-head").addClass("imp-hidden");
            $legacyTable.addClass("imp-hidden");
        };
        this.hideLegacy();
        var $row = $panel.closest(".dashboard-row").addClass("imp-sticky");
        if ($row.length && $row.parent().length) {
            $row.css("background-color", drawnBg($row.parent()[0]) || "transparent");
        }

        // --- initial values from the tokens (defaults "*" and "-" = empty)
        q.input.value = blankIf(defTokens.get("form." + p + "_q"), "*");
        tk.input.value = blankIf(defTokens.get("form." + p + "_tk"), "-");
        desc.input.value = blankIf(defTokens.get("form." + p + "_desc"), "-");

        // --- card -> tokens
        this.applyQ = debounce(function () {
            var v = q.input.value.trim();
            setInputTok(p + "_q", v || "*");
            if (cfg.manual) {        // typed IPs = manual IPs of the action search (WAF check, cloud)
                setInputTok(p + "_add", self.manualItems().join(", ") || "-");
            }
            // a search for an incident number fills Ticket / Incident no. (digits only)
            if (incidentOf(v)) {
                if (!tk.input.value.trim() || self.autoTk) {
                    tk.input.value = incidentOf(v);
                    self.autoTk = true;
                    setInputTok(p + "_tk", tk.input.value);
                }
            } else if (self.autoTk) {
                tk.input.value = "";
                self.autoTk = false;
                setInputTok(p + "_tk", "-");
            }
        }, 500);
        this.applyTk = debounce(function () {
            setInputTok(p + "_tk", tk.input.value.trim() || "-");
        }, 600);
        this.applyDesc = debounce(function () {
            setInputTok(p + "_desc", desc.input.value.trim() || "-");
        }, 600);

        $(q.input).on("input", function () {
            self.render();
            self.applyQ();
        }).on("change", this.applyQ.flush).on("keydown", function (e) {
            if (e.key === "Enter") {
                self.applyQ();
                self.applyQ.flush();
            }
        });
        $(tk.input).on("input", function () {
            self.autoTk = false;
            self.applyTk();
        }).on("change", this.applyTk.flush);
        $(desc.input).on("input", this.applyDesc).on("change", this.applyDesc.flush);

        $(selBox).on("click", "button[data-ip]", function () {
            // one more click on an IP = unselect it (same odd / even rule as a row click)
            setTok(p + "_sel", String(getTok(p + "_sel") || ",") + "," + this.getAttribute("data-ip") + ",");
        });
        $(allBtn).on("click", function () {
            if (self.shown.length) {
                setTok(p + "_sel", "," + self.shown.join(",") + ",");
            }
        });
        $(clearBtn).on("click", function () {
            setTok(p + "_sel", ",");
            if (cfg.manual) {        // the typed IPs are in the search box
                q.input.value = "";
                self.applyQ();
                self.applyQ.flush();
            }
            self.render();
        });
        $(go).on("click", function () {
            self.run();
        });
        if (nb) {
            $(nb).on("click", function () {
                self.notBlock();
            });
        }

        // --- tokens -> card (row clicks, Ticket filled from the clicked finding, resets)
        onTok(p + "_sel", function () {
            self.render();
        });
        defTokens.on("change:form." + p + "_tk", function (m, v) {
            if (document.activeElement !== tk.input && (tk.input.value.trim() || "-") !== (v || "-")) {
                tk.input.value = blankIf(v, "-");
                self.autoTk = false;
            }
        });
        defTokens.on("change:form." + p + "_desc", function (m, v) {
            if (document.activeElement !== desc.input && (desc.input.value.trim() || "-") !== (v || "-")) {
                desc.input.value = blankIf(v, "-");
            }
        });
        defTokens.on("change:form." + p + "_q", function (m, v) {
            if (document.activeElement !== q.input && (q.input.value.trim() || "*") !== (v || "*")) {
                q.input.value = blankIf(v, "*");
            }
        });
        this.watchActionSearch();
        this.watchFind();
        this.watchTable();
        this.render();
    }

    Card.prototype.selected = function () {
        return selectedFrom(getTok(this.p + "_sel"));
    };

    // full IPs / CIDRs typed in the search box (text such as a ticket or a rule name is only a search)
    Card.prototype.manualItems = function () {
        if (!this.cfg.manual) {
            return [];
        }
        var seen = {}, out = [];
        this.el.q.value.replace(/^\s*ithm[\s:#-]*/i, "").split(/[\s,;]+/).forEach(function (x) {
            x = x.trim();
            if (x && isIp(x) && !seen[x]) {
                seen[x] = true;
                out.push(x);
            }
        });
        return out;
    };

    // IPs the main button acts on: selected rows + typed IPs that the Found check says can be blocked
    // (if that check fails, every typed IP: impervablock / SOAR check them again)
    Card.prototype.targets = function () {
        var out = this.selected().slice(), self = this;
        this.manualItems().forEach(function (x) {
            var f = self.found[x];
            if (out.indexOf(x) < 0 && ((f && f.blockable === "yes") || (!f && self.findErr))) {
                out.push(x);
            }
        });
        return out;
    };

    var ICON = {no: "⛔ ", al: "✅ ", ok: "✔ ", pg: "• "};

    // "Found" box under the search field (mockup v3.12)
    Card.prototype.renderFind = function () {
        var box = this.el.find, self = this, cfg = this.cfg;
        if (!box) {
            return;
        }
        var q = this.el.q.value.trim();
        if (!cfg.manual || !q || q === "*") {
            $(box).addClass("imp-hidden");
            return;
        }
        var lineEls = function (row, lines) {
            lines.forEach(function (l) {
                var i = l.indexOf("¦"), cls = i > 0 ? l.slice(0, i) : "pg", t = i > 0 ? l.slice(i + 1) : l;
                t = t.replace("on the " + cfg.page + " page", "on this page");
                row.appendChild(el("span", "imp-f-" + (ICON[cls] ? cls : "pg"), (ICON[cls] || ICON.pg) + t));
            });
        };
        box.textContent = "";
        box.appendChild(el("span", "imp-hd", "Found – every page and every WAF policy"));
        var man = this.manualItems();
        if (man.length) {
            man.forEach(function (ip) {
                var row = el("div", "imp-fl"), f = self.found[ip];
                row.appendChild(el("b", null, ip));
                if (!f) {
                    row.appendChild(el("span", "imp-f-note", self.findErr
                        ? "check unavailable – checked again when blocking"
                        : "⏳ checking every page and every WAF policy …"));
                } else {
                    lineEls(row, f.lines);
                    row.appendChild(el("span", "imp-f-note", f.blockable === "yes" ? "→ included in Block" : "→ not blocked again"));
                }
                box.appendChild(row);
            });
        } else {
            var row = el("div", "imp-fl");
            row.appendChild(el("b", null, "“" + q + "”"));
            row.appendChild(el("span", "imp-f-pg", ICON.pg + this.shown.length + " IP on this page"));
            if (this.findText) {
                lineEls(row, this.findText);
            } else if (!this.findErr) {
                row.appendChild(el("span", "imp-f-note", "⏳ …"));
            }
            box.appendChild(row);
        }
        $(box).removeClass("imp-hidden");
    };

    Card.prototype.watchFind = function () {
        var self = this;
        var mgr = this.cfg.manual ? mvc.Components.get(this.p + "_find") : null;
        if (!mgr) {
            return;
        }
        mgr.on("search:failed search:error search:cancelled", function () {
            self.findErr = true;
            self.render();
        });
        var results = mgr.data("results", {count: 0, output_mode: "json_rows"});
        results.on("data", function () {
            var d = results.data() || {};
            var fields = (d.fields || []).map(function (f) {
                return f && typeof f === "object" ? f.name : f;
            });
            var col = function (r, name) {
                var i = fields.indexOf(name), v = i < 0 ? null : r[i];
                return Array.isArray(v) ? v.join(" ‖ ") : v;
            };
            self.findErr = false;
            self.findText = null;
            (d.rows || []).forEach(function (r) {
                var ip = col(r, "ip"), lines = String(col(r, "found") || "").split(" ‖ ").filter(function (x) { return x; });
                if (!ip || ip === "-") {
                    self.findText = lines;
                } else {
                    self.found[ip] = {lines: lines, blockable: col(r, "find_blockable"), cloud: col(r, "find_cloud")};
                }
            });
            self.render();
        });
    };

    Card.prototype.render = function () {
        var e = this.el, sel = this.selected(), man = this.manualItems(), all = this.targets();
        var verb = this.cfg.verb === "block" ? "⛔ Block " : "🔓 Unblock ";

        var cloud = this.cloud;
        e.sel.textContent = "";
        sel.forEach(function (ip) {
            var isCloud = cloud.indexOf(ip) >= 0;
            var t = el("span", "imp-tag" + (isCloud ? " imp-cloud" : ""), isCloud ? "☁ " + ip + " · short block" : ip);
            if (isCloud) {
                t.title = "cloud provider IP - unblocked automatically after a few days without an attack (Auto unblock)";
            }
            var x = el("button", null, "×");
            x.type = "button";
            x.setAttribute("data-ip", ip);
            x.setAttribute("aria-label", "unselect " + ip);
            x.title = "unselect";
            t.appendChild(x);
            e.sel.appendChild(t);
        });
        var found = this.found, findErr = this.findErr, tagged = 0;
        man.forEach(function (x) {
            if (sel.indexOf(x) >= 0) {
                return;
            }
            var f = found[x];
            if (f && f.blockable !== "yes") {
                return;              // already blocked / allowed / cannot be blocked: see Found
            }
            var pending = !f && !findErr;
            var isCloud = (f && f.cloud && f.cloud !== "-") || cloud.indexOf(x) >= 0;
            var t = el("span", "imp-tag " + (pending ? "imp-wait" : "imp-man") + (isCloud ? " imp-cloud" : ""),
                (pending ? "⏳ " : "✍ ") + (isCloud ? "☁ " + x + " · short block" : x));
            t.title = pending ? "typed in the search box - checking every WAF policy …"
                : "typed in the search box" + (isCloud ? " - cloud provider / shared IP, short block (Auto unblock)" : "");
            e.sel.appendChild(t);
            tagged++;
        });
        if (!sel.length && !tagged) {
            e.sel.appendChild(el("span", "imp-none", this.cfg.manual ? "ยังไม่ได้เลือก IP – คลิกแถว หรือพิมพ์ IP ในช่องค้นหา" : "ยังไม่ได้เลือก IP"));
        }

        e.go.textContent = verb + plural(all.length);
        e.go.disabled = !all.length;
        if (e.nb) {
            e.nb.textContent = "✖ Not block " + plural(sel.length);
            e.nb.disabled = !sel.length;
        }
        $(e.clear).toggleClass("imp-hidden", !sel.length && !man.length);
        $(e.all).toggleClass("imp-hidden", !this.shown.length);
        e.all.textContent = "☑ Select all " + this.shown.length + " shown";
        this.renderCheck(sel.concat(all), man);
        this.renderFind();
        this.highlight(sel);
    };

    Card.prototype.renderCheck = function (all, man) {
        var c = this.el.chk;
        if (!this.cfg.manual || !this.selected().length) {      // typed IPs: see the Found box
            $(c).addClass("imp-hidden");
            return;
        }
        var text = this.chk, cls;
        if (this.chkWait || text === null || this.chkFor !== setKey(this.selected().concat(man))) {
            cls = "imp-wait";
            text = "⏳ WAF check …";
        } else if (text === "-" || text === "") {
            $(c).addClass("imp-hidden");
            return;
        } else if (text.indexOf("✔") === 0) {
            cls = "imp-ok";
            text = "✔ WAF check: none of the selected IPs is blocked / allowed on the WAF";
        } else {
            cls = "imp-warn";
            text = "⚠ WAF check: " + text;
        }
        c.className = "imp-chk " + cls;
        c.textContent = text;
    };

    // the action search of the old table still runs: it gives the WAF check and "Select all shown"
    Card.prototype.watchActionSearch = function () {
        var self = this, p = this.p;
        var mgr = mvc.Components.get(p + "_act");
        if (!mgr) {
            var tbl = mvc.Components.get(p + "_acttable");
            var id = tbl && tbl.settings && tbl.settings.get("managerid");
            mgr = id ? mvc.Components.get(id) : null;
        }
        if (!mgr) {
            return;
        }
        mgr.on("search:start search:progress", function () {
            self.chkWait = true;
            self.render();
        });
        mgr.on("search:failed search:error search:cancelled", function () {
            self.chkWait = false;
            self.chk = "WAF check unavailable";
            self.chkFor = setKey(self.selected().concat(self.manualItems()));
            self.render();
        });
        var results = mgr.data("results", {count: 1, output_mode: "json_rows"});
        results.on("data", function () {
            var d = results.data() || {};
            var fields = (d.fields || []).map(function (f) {
                return f && typeof f === "object" ? f.name : f;
            });
            var row = (d.rows || [])[0] || [];
            var get = function (name) {
                var i = fields.indexOf(name);
                var v = i < 0 ? null : row[i];
                return Array.isArray(v) ? v.join(" | ") : v;
            };
            self.chkWait = false;
            self.chk = get("waf_check");
            var ips = get("selected_ips");
            self.chkFor = setKey(!ips || ips === "-" ? [] : String(ips).split(/\s*,\s*/));
            var cl = get("cloud_ips");
            self.cloud = cl && cl !== "-" ? String(cl).split(/\s*[,|]\s*/).filter(function (x) { return x; }) : [];
            var m = /^☑ Select all \d+ shown: (.*)$/.exec(get("SelectAll") || "");
            self.shown = m ? m[1].split(",").filter(function (x) { return x; }) : [];
            self.render();
        });
    };

    // highlight the selected rows of the IP table
    Card.prototype.watchTable = function () {
        var self = this;
        var node = document.getElementById(this.cfg.table);
        if (!node || !window.MutationObserver) {
            return;
        }
        var again = debounce(function () {
            self.highlight(self.selected());
        }, 80);
        new MutationObserver(again).observe(node, {childList: true, subtree: true});
    };

    Card.prototype.highlight = function (sel) {
        var node = document.getElementById(this.cfg.table);
        if (!node) {
            return;
        }
        var field = this.cfg.ipField, idx = -1, set = {};
        sel.forEach(function (ip) {
            set[ip] = true;
        });
        $(node).find("thead th").each(function (i) {
            var key = this.getAttribute("data-sort-key") || $(this).text().trim();
            if (key === field && idx < 0) {
                idx = i;
            }
        });
        if (idx < 0) {
            return;
        }
        $(node).find("tbody tr").each(function () {
            var ip = $(this).children().eq(idx).text().trim();
            $(this).toggleClass("imp-selrow", set[ip] === true);
        });
    };

    Card.prototype.flushAll = function () {
        this.applyQ.flush();
        this.applyTk.flush();
        this.applyDesc.flush();
    };

    Card.prototype.ticket = function () {
        var v = this.el.tk.value.trim();
        var q = this.el.q.value.trim();
        if (!v && incidentOf(q)) {
            v = incidentOf(q);
        }
        return v || "-";
    };

    Card.prototype.reset = function (clearManual) {
        var p = this.p, e = this.el;
        setTok(p + "_sel", ",");
        e.tk.value = "";
        e.desc.value = "";
        this.autoTk = false;
        setInputTok(p + "_tk", "-");
        setInputTok(p + "_desc", "-");
        if (clearManual && this.cfg.manual) {     // typed IPs are in the search box
            e.q.value = "";
            setInputTok(p + "_q", "*");
            setInputTok(p + "_add", "-");
        }
        this.render();
    };

    // one click = do it (no second confirm), same as the old ⛔ BLOCK / 🔓 UNBLOCK cell
    Card.prototype.run = function () {
        var p = this.p, ips = this.targets();
        if (!ips.length) {
            return;
        }
        this.flushAll();
        var ticket = this.ticket(), desc = this.el.desc.value.trim() || "-";
        unsetTok(p + "_exec_ips");          // first, so the result search never runs with old IPs
        setTok(p + "_exec_tk", ticket);
        setTok(p + "_exec_desc", desc);
        setTok(p + "_exec_ips", ips.join(", "));
        this.reset(true);
    };

    // "Not block": hide the selected rows until they are detected again (nothing sent to the WAF)
    Card.prototype.notBlock = function () {
        var p = this.p, ips = this.selected();
        if (!ips.length) {
            return;
        }
        this.flushAll();
        var ticket = this.ticket(), desc = this.el.desc.value.trim() || "-";
        unsetTok(p + "_nb_exec");
        setTok(p + "_nb_tk", ticket);
        setTok(p + "_nb_desc", desc);
        setTok(p + "_nb_exec", ips.join(", "));
        this.reset(false);
    };

    // "All paths" of the IP detail panel: up to 100 rows in a box that scrolls
    function scrollPaths() {
        ["d_paths", "h_paths"].forEach(function (id) {
            var node = document.getElementById(id);
            if (!node || node.getAttribute("data-imp-scroll")) {
                return;
            }
            node.setAttribute("data-imp-scroll", "1");
            var apply = function () {
                var t = node.querySelector("table");
                if (t && t.parentElement && t.parentElement !== node) {
                    t.parentElement.classList.add("imp-scroll");
                }
            };
            apply();
            if (window.MutationObserver) {
                new MutationObserver(apply).observe(node, {childList: true, subtree: true});
            }
        });
    }

    function mount() {
        Object.keys(PAGES).forEach(function (p) {
            var $panel = $("#" + p + "_actpanel");
            var $table = $("#" + p + "_acttable");
            if (!$panel.length || !$table.length || $panel.data("impCard")) {
                return;
            }
            try {
                $panel.data("impCard", new Card(p, PAGES[p], $panel, $table));
            } catch (err) {
                // keep the Simple XML inputs if anything goes wrong
                $panel.find(".imp-card").remove();
                $panel.find(".imp-hidden").removeClass("imp-hidden");
                if (window.console) {
                    window.console.error("imperva_form.js:", err);
                }
            }
        });
    }

    // background actually drawn behind a node (the view says theme="dark", but Splunk may draw it light)
    function drawnBg(node) {
        while (node && node.nodeType === 1) {
            var c = window.getComputedStyle(node).backgroundColor || "";
            var m = /rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/.exec(c);
            if (m && (m[4] === undefined || +m[4] > 0.5)) {
                return c;
            }
            node = node.parentElement;
        }
        return null;
    }

    function drawnDark(node) {
        var m = /(\d+),\s*(\d+),\s*(\d+)/.exec(drawnBg(node) || "");
        return m ? 0.299 * m[1] + 0.587 * m[2] + 0.114 * m[3] < 128 : false;
    }

    var probe = document.querySelector("[id$=_actpanel] .dashboard-panel") || document.querySelector(".dashboard-panel") || document.body;
    $(document.body).addClass("imp-scope").toggleClass("imp-dark", drawnDark(probe));
    if (!document.getElementById("imp-form-css")) {
        var style = el("style");
        style.id = "imp-form-css";
        style.textContent = CSS;
        document.head.appendChild(style);
    }
    mount();
    scrollPaths();
    // inputs / tables can be drawn a little after "ready": hide the old ones again
    [300, 1500].forEach(function (ms) {
        setTimeout(function () {
            mount();
            scrollPaths();
            $("[id$=_actpanel]").each(function () {
                var c = $(this).data("impCard");
                if (c) {
                    c.hideLegacy();
                }
            });
        }, ms);
    });
});
