/*
 * UI test of appserver/static/imperva_form.js (action card) against a fake Splunk Simple XML
 * runtime (harness.js: default / submitted token models, the action search, row-click drilldown).
 *   cd tests/ui && npm install --no-save jquery@3.5.1 playwright && node run.js
 * (use an installed Playwright + Chromium if there is one)
 */
const {chromium} = require("playwright");
const fs = require("fs");
const os = require("os");
const path = require("path");
const build = require("./page.js");
const OUT = fs.mkdtempSync(path.join(os.tmpdir(), "imperva-ui-"));
let fails = 0;
function check(cond, msg) { console.log((cond ? "  ok   " : "  FAIL ") + msg); if (!cond) fails++; }
async function open(browser, p, dark, extra, width) {
  const f = `${OUT}/h_${p}_${dark ? "dark" : "light"}${extra ? "_x" : ""}.html`;
  fs.writeFileSync(f, build(p, dark, extra));
  const page = await browser.newPage({viewport: {width: width || 1500, height: 900}, deviceScaleFactor: 1});
  const errs = [];
  page.on("pageerror", e => errs.push(String(e)));
  page.on("console", m => { if (m.type() === "error") errs.push(m.text()); });
  await page.goto("file://" + f);
  await page.waitForTimeout(150);
  return {page, errs};
}
const tok = (page, name) => page.evaluate(n => [DEF.get(n), SUB.get(n)], name);
const txt = (page, sel) => page.$eval(sel, e => e.textContent);
(async () => {
  const browser = await chromium.launch();

  console.log("Block page (d), light theme");
  let {page, errs} = await open(browser, "d", false);
  check(await page.$(".imp-card") !== null, "card is drawn");
  check(await page.$eval("#d_acttable", e => getComputedStyle(e).display === "none"), "legacy action table hidden");
  check(await page.$eval("#d_actpanel .fieldset", e => getComputedStyle(e).display === "none"), "legacy inputs hidden");
  check(await page.$eval("#d_actpanel .panel-title", e => getComputedStyle(e).display === "none"), "panel title hidden");
  check(await page.$eval("body", e => e.classList.contains("imp-scope") && !e.classList.contains("imp-dark")), "light palette on a light dashboard");
  check(await page.$eval("#d_actpanel", e => e.closest(".dashboard-row").classList.contains("imp-sticky")), "card row is sticky");
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 0 IPs" && await page.$eval(".imp-run:not(.imp-nb)", e => e.disabled), "Block 0 IPs disabled");
  check((await txt(page, ".imp-nb")) === "✖ Not block 0 IPs" && await page.$eval(".imp-nb", e => e.disabled), "Not block 0 IPs disabled");
  check((await txt(page, ".imp-sel")) === "ยังไม่ได้เลือก IP – คลิกแถว หรือพิมพ์ IP ในช่องค้นหา", "empty selection text");
  check(await page.$eval("#imp_d_q", e => e.value === "" && e.placeholder === "เช่น 54.245 · 1000101 · หรือวาง IP หลายตัว 203.0.113.10, 198.51.100.7"), "search empty (token *) with placeholder");
  check(await page.$("#imp_d_add") === null, "one search / add box (no separate Add IPs box)");
  check(await page.$eval(".imp-find", e => e.classList.contains("imp-hidden")), "Found box hidden while the search is empty");
  check(await page.$eval("#imp_d_tk", e => e.value === ""), "ticket empty (token -)");
  await page.waitForTimeout(120);
  check(await page.$eval(".imp-link:not(.imp-hidden)", e => e.textContent) === "☑ Select all 5 shown", "Select all 5 shown (from the action search)");
  check(JSON.stringify(await page.evaluate(() => window.RESULT_OPTS)) === '{"count":1,"output_mode":"json_rows"}', "results model asked for 1 json row");

  // row clicks (drilldown)
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.click("#det_table tbody tr:nth-child(3)");
  await page.waitForTimeout(30);
  check((await page.$$eval(".imp-tag", t => t.map(x => x.firstChild.textContent))).join(",") === "54.245.10.21,198.51.100.23", "two rows clicked -> two tags");
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 2 IPs" && !(await page.$eval(".imp-run:not(.imp-nb)", e => e.disabled)), "Block 2 IPs enabled");
  check((await txt(page, ".imp-nb")) === "✖ Not block 2 IPs", "Not block 2 IPs");
  check(await page.$eval("#imp_d_tk", e => e.value) === "1000101", "ticket filled from the first clicked finding");
  check((await page.$$eval("#det_table tbody tr", r => r.map(x => x.classList.contains("imp-selrow") ? 1 : 0))).join("") === "10100", "selected rows highlighted");
  check(await page.$eval("#det_table tbody tr:nth-child(1) td:nth-child(2)", e => getComputedStyle(e).backgroundColor) === "rgb(44, 98, 179)", "coloured cell keeps its colour");
  check((await txt(page, ".imp-chk")).startsWith("⏳") || (await txt(page, ".imp-chk")).startsWith("✔"), "WAF check shown (waiting or result)");
  await page.waitForTimeout(120);
  check((await txt(page, ".imp-chk")) === "✔ WAF check: none of the selected IPs is blocked / allowed on the WAF", "WAF check ok text");

  // unselect with ×
  await page.click('.imp-tag button[data-ip="54.245.10.21"]');
  await page.waitForTimeout(30);
  check((await page.$$eval(".imp-tag", t => t.map(x => x.firstChild.textContent))).join(",") === "198.51.100.23", "× unselects the IP");
  check((await tok(page, "d_sel"))[1] === ",,54.245.10.21,,198.51.100.23,,54.245.10.21,", "× appends the IP once more (even = unselected)");
  check((await page.$$eval("#det_table tbody tr", r => r.map(x => x.classList.contains("imp-selrow") ? 1 : 0))).join("") === "00100", "highlight follows");

  // click a row again = unselect (drilldown)
  await page.click("#det_table tbody tr:nth-child(3)");
  await page.waitForTimeout(30);
  check((await txt(page, ".imp-sel")) === "ยังไม่ได้เลือก IP – คลิกแถว หรือพิมพ์ IP ในช่องค้นหา", "row clicked twice = unselected");
  await page.click("#det_table tbody tr:nth-child(3)");
  await page.click("#det_table tbody tr:nth-child(4)");

  // IPs typed in the search box = manual IPs; the Found box says where they are
  await page.fill("#imp_d_q", "203.0.113.10, 185.220.101.47 198.51.100.23");
  await page.waitForTimeout(20);
  let tags = await page.$$eval(".imp-tag", t => t.map(x => x.className + "|" + x.textContent));
  check(tags.length === 4 && tags[2] === "imp-tag imp-wait|⏳ 203.0.113.10" && tags[3] === "imp-tag imp-wait|⏳ 185.220.101.47", "typed IPs wait for the Found check (selected IP not repeated) " + tags.join(" ; "));
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 2 IPs", "typed IPs not counted before the check");
  check((await tok(page, "d_add"))[1] === "-", "manual token not set before the debounce");
  await page.waitForTimeout(800);
  check((await tok(page, "d_add"))[1] === "203.0.113.10, 185.220.101.47, 198.51.100.23" && (await tok(page, "form.d_add"))[0] === "203.0.113.10, 185.220.101.47, 198.51.100.23", "typed IPs -> manual token + form token after the debounce");
  check(JSON.stringify(await page.evaluate(() => window.FIND_OPTS)) === '{"count":0,"output_mode":"json_rows"}', "Found search: every row");
  tags = await page.$$eval(".imp-tag", t => t.map(x => x.className + "|" + x.textContent));
  check(tags.length === 3 && tags[2] === "imp-tag imp-man|✍ 203.0.113.10", "only typed IPs that can be blocked get a tag " + tags.join(" ; "));
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 3 IPs", "Block counts selected + blockable typed (3)");
  check((await txt(page, ".imp-nb")) === "✖ Not block 2 IPs", "Not block counts selected only (2)");
  const fnd = await txt(page, ".imp-find");
  check(fnd.startsWith("Found – every page and every WAF policy") && /185\.220\.101\.47⛔ already BLOCKED in policy 1000001 Block DDoS policy.*→ not blocked again/.test(fnd), "Found: blocked in another policy -> not blocked again");
  check(/203\.0\.113\.10✔ not on the WAF and not blocked from Splunk - can be blocked→ included in Block/.test(fnd), "Found: not found -> included in Block");
  await page.waitForTimeout(150);
  check((await txt(page, ".imp-chk")) === "⚠ WAF check: 192.0.2.55 is ALLOWED: Allowlist-Partners", "WAF check warning for the selected IP: " + (await txt(page, ".imp-chk")));
  check(await page.$eval(".imp-chk", e => e.className) === "imp-chk imp-warn", "warning style");

  // description + Block
  await page.fill("#imp_d_desc", "scanner from IOC feed");
  await page.evaluate(() => { TOKLOG.length = 0; });
  await page.click(".imp-run:not(.imp-nb)");
  await page.waitForTimeout(30);
  const runs = await page.evaluate(() => RUNS);
  check(runs.length === 1 && runs[0].kind === "exec", "exactly one block run, no stale run");
  check(runs[0] && runs[0].ips === "198.51.100.23, 192.0.2.55, 203.0.113.10" && runs[0].tk === "1000101" && runs[0].desc === "scanner from IOC feed", "block run gets IPs, ticket, description: " + JSON.stringify(runs[0]));
  const order = await page.evaluate(() => TOKLOG.filter(l => /^sub\.(un)?set d_exec/.test(l)));
  check(order[order.length - 1].startsWith("sub.set d_exec_ips="), "exec_ips set last: " + order.join(" ; "));
  check((await tok(page, "d_sel"))[1] === "," && (await tok(page, "form.d_tk"))[0] === "-" && (await tok(page, "d_desc"))[1] === "-" && (await tok(page, "d_add"))[1] === "-" && (await tok(page, "d_q"))[1] === "*", "selection, ticket, description, search with typed IPs reset after block");
  check(await page.$eval("#imp_d_q", e => e.value === "") && await page.$eval("#imp_d_tk", e => e.value === ""), "inputs cleared");
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 0 IPs", "button back to 0");
  await page.click(".imp-run:not(.imp-nb)", {force: true});
  check((await page.evaluate(() => RUNS.length)) === 1, "disabled button does nothing");

  // block the same IP twice in a row (exec tokens identical): must still run
  await page.click("#det_table tbody tr:nth-child(2)");
  await page.click(".imp-run:not(.imp-nb)");
  await page.click("#det_table tbody tr:nth-child(2)");
  await page.click(".imp-run:not(.imp-nb)");
  check((await page.evaluate(() => RUNS.filter(r => r.kind === "exec").length)) === 3, "same IP blocked again runs again (unset + set)");

  // search ITHM -> ticket auto, other search -> cleared
  await page.fill("#imp_d_q", "ITHM 1000103");
  await page.waitForTimeout(700);
  check((await tok(page, "d_q"))[1] === "ITHM 1000103" && (await tok(page, "form.d_q"))[0] === "ITHM 1000103", "search token set after debounce");
  check(await page.$eval("#imp_d_tk", e => e.value) === "1000103" && (await tok(page, "d_tk"))[1] === "1000103", "ITHM search fills the ticket with digits only");
  await page.waitForTimeout(100);
  check(await page.$eval(".imp-link:not(.imp-hidden)", e => e.textContent) === "☑ Select all 1 shown", "Select all follows the search");
  check(/“ITHM 1000103”• 1 IP on this page• 2 blocked from Splunk \(Blocked IPs page\)• 1 IP rules in other WAF policies/.test(await txt(page, ".imp-find")), "Found for a text search: matches on this page, Blocked IPs page and other policies");
  await page.click(".imp-link:not(.imp-hidden)");
  await page.waitForTimeout(20);
  check((await tok(page, "d_sel"))[1] === ",192.0.2.55," && (await page.$$eval(".imp-tag", t => t.length)) === 1, "Select all replaces the selection");
  await page.fill("#imp_d_q", "54.245");
  await page.press("#imp_d_q", "Enter");
  check((await tok(page, "d_q"))[1] === "54.245" && await page.$eval("#imp_d_tk", e => e.value) === "" && (await tok(page, "d_tk"))[1] === "-", "Enter applies at once; non-ITHM search clears the auto ticket");
  await page.fill("#imp_d_q", "");
  await page.press("#imp_d_q", "Enter");
  check((await tok(page, "d_q"))[1] === "*", "empty search = *");
  // typed ticket is kept
  await page.fill("#imp_d_tk", "INC-77");
  await page.fill("#imp_d_q", "ITHM 1000101");
  await page.press("#imp_d_q", "Enter");
  check(await page.$eval("#imp_d_tk", e => e.value) === "INC-77", "typed ticket not overwritten by an ITHM search");
  await page.click("#det_table tbody tr:nth-child(1)");
  check(await page.$eval("#imp_d_tk", e => e.value) === "INC-77", "typed ticket not overwritten by a row click");

  // Not block
  await page.fill("#imp_d_desc", "quiet 30 days");
  await page.click(".imp-nb");
  await page.waitForTimeout(20);
  const nb = (await page.evaluate(() => RUNS)).filter(r => r.kind === "nb");
  check(nb.length === 1 && nb[0].ips === "192.0.2.55, 54.245.10.21" && nb[0].tk === "INC-77" && nb[0].desc === "quiet 30 days", "not block run: " + JSON.stringify(nb[0]));
  check((await tok(page, "d_sel"))[1] === "," && (await txt(page, ".imp-nb")) === "✖ Not block 0 IPs", "selection reset after not block");
  // Clear
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.fill("#imp_d_q", "203.0.113.9");
  await page.click(".imp-link:not(.imp-hidden) >> text=✖ Clear");
  await page.waitForTimeout(20);
  check((await tok(page, "d_sel"))[1] === "," && await page.$eval("#imp_d_q", e => e.value === "") && (await tok(page, "d_add"))[1] === "-" && (await tok(page, "d_q"))[1] === "*", "Clear empties selection and the typed IPs (search box)");
  // external reset of form tokens (old drilldown) reaches the card
  await page.evaluate(() => DEF.set("form.d_tk", "ITHM 9"));
  check(await page.$eval("#imp_d_tk", e => e.value) === "ITHM 9", "form token change shows in the card");
  check((await page.evaluate(() => RUNS.filter(r => r.kind === "STALE").length)) === 0, "never a run with stale IPs");
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  // screenshot with a selection
  await page.evaluate(() => DEF.set("form.d_tk", "-"));
  await page.fill("#imp_d_q", "");
  await page.press("#imp_d_q", "Enter");
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.click("#det_table tbody tr:nth-child(3)");
  await page.fill("#imp_d_q", "203.0.113.10, 185.220.101.47");
  await page.fill("#imp_d_desc", "IOC scanner");
  await page.waitForTimeout(900);
  await page.screenshot({path: OUT + "/shot_d_light.png", clip: {x: 0, y: 0, width: 1500, height: 420}});
  await page.close();

  console.log("Older detections (h) - same card; dark theme");
  ({page, errs} = await open(browser, "h", true));
  check(await page.$eval("body", e => e.classList.contains("imp-dark")), "dark palette on a dark dashboard");
  await page.click("#det_table tbody tr:nth-child(2)");
  await page.waitForTimeout(150);
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 1 IP", "singular label");
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.screenshot({path: OUT + "/shot_h_dark.png", clip: {x: 0, y: 0, width: 1500, height: 420}});
  await page.close();

  console.log("Blocked IPs / Unblock (b)");
  ({page, errs} = await open(browser, "b", false));
  check(await page.$("#imp_b_add") === null && await page.$(".imp-nb") === null, "no manual box, no Not block");
  check(await page.$eval(".imp-card", e => e.classList.contains("imp-u")) && await page.$eval(".imp-run", e => e.classList.contains("imp-un")), "green card + Unblock button");
  check(await page.$eval("#imp_b_q", e => e.placeholder) === "เช่น 193.42 หรือ 1000090", "unblock placeholder");
  await page.click("#b_table tbody tr:nth-child(1)");
  await page.click("#b_table tbody tr:nth-child(2)");
  await page.waitForTimeout(150);
  check((await txt(page, ".imp-run")) === "🔓 Unblock 2 IPs", "Unblock 2 IPs");
  check(await page.$eval(".imp-chk", e => e.classList.contains("imp-hidden")), "no WAF check line on the unblock page");
  check(await page.$$eval(".imp-link:not(.imp-hidden)", l => l.map(x => x.textContent).join()) === "✖ Clear", "only Clear link (no Select all)");
  await page.fill("#imp_b_desc", "false positive");
  await page.click(".imp-run");
  const r = (await page.evaluate(() => RUNS))[0];
  check(r && r.ips === "54.245.10.21, 54.245.88.7" && r.tk === "1000101" && r.desc === "false positive", "unblock run: " + JSON.stringify(r));
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.close();

  console.log("Fallbacks");
  ({page, errs} = await open(browser, "d", false, {noMgrId: true}));
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.waitForTimeout(150);
  check((await txt(page, ".imp-chk")).startsWith("✔"), "action search found through the table's managerid");
  await page.close();
  ({page, errs} = await open(browser, "d", false, {throwIn: "d_act"}));
  check(await page.$(".imp-card") === null, "error while building -> no card");
  check(await page.$eval("#d_acttable", e => getComputedStyle(e).display !== "none") && await page.$eval("#d_actpanel .fieldset", e => getComputedStyle(e).display !== "none"), "error -> legacy inputs + action table stay visible");
  await page.close();

  console.log("Post-process search without search:start events: stale WAF check shows ⏳");
  ({page, errs} = await open(browser, "d", false, {noStart: true}));
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.waitForTimeout(150);
  check((await txt(page, ".imp-chk")).startsWith("✔"), "check for the selected IP");
  await page.fill("#imp_d_q", "192.0.2.55");
  check((await txt(page, ".imp-chk")).startsWith("⏳"), "old result not shown for a new IP list");
  await page.waitForTimeout(900);
  check((await txt(page, ".imp-chk")) === "⚠ WAF check: 192.0.2.55 is ALLOWED: Allowlist-Partners", "new result shown when it matches the IPs");
  check(/192\.0\.2\.55✅ ALLOWED by policy 1000002/.test(await txt(page, ".imp-find")) && (await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 1 IP", "allowed typed IP: shown in Found, not counted");
  await page.click('.imp-tag button[data-ip="54.245.10.21"]');
  await page.waitForTimeout(200);
  check(await page.$eval(".imp-chk", e => e.classList.contains("imp-hidden")), "no selection: WAF check line hidden (typed IPs are in Found)");
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.close();

  console.log("V2: cloud provider IPs are blocked (short block tag); incident numbers digits only; All paths scrolls");
  ({page, errs} = await open(browser, "d", false));
  await page.click("#det_table tbody tr:nth-child(5)");            // 52.88.145.123 (AWS)
  await page.waitForTimeout(150);
  check((await page.$$eval(".imp-tag", t => t.map(x => x.firstChild.textContent))).join() === "☁ 52.88.145.123 · short block", "cloud tag: short block");
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 1 IP" && !(await page.$eval(".imp-run:not(.imp-nb)", e => e.disabled)), "cloud IP alone: Block 1 IP");
  check((await txt(page, ".imp-nb")) === "✖ Not block 1 IP" && !(await page.$eval(".imp-nb", e => e.disabled)), "cloud IP alone: Not block 1 IP");
  check((await txt(page, ".imp-chk")).indexOf("CLOUD PROVIDER IP (Amazon.com, Inc.)") > 0, "WAF check tells it is a cloud provider IP");
  await page.click("#det_table tbody tr:nth-child(3)");            // 198.51.100.23
  await page.fill("#imp_d_q", "35.240.10.8, 203.0.113.10");
  await page.waitForTimeout(900);
  const ctags = await page.$$eval(".imp-tag", t => t.map(x => x.className + "|" + x.firstChild.textContent));
  check(ctags.indexOf("imp-tag imp-man imp-cloud|✍ ☁ 35.240.10.8 · short block") >= 0, "typed cloud IP: short block tag " + ctags.join(" ; "));
  check((await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 4 IPs" && (await txt(page, ".imp-nb")) === "✖ Not block 2 IPs", "Block 4 (cloud included), Not block 2 (selected rows)");
  await page.evaluate(() => { RUNS.length = 0; });
  await page.click(".imp-run:not(.imp-nb)");
  check((await page.evaluate(() => RUNS))[0].ips === "52.88.145.123, 198.51.100.23, 35.240.10.8, 203.0.113.10", "block run includes cloud IPs: " + (await page.evaluate(() => RUNS))[0].ips);
  await page.click("#det_table tbody tr:nth-child(5)");
  await page.waitForTimeout(150);
  await page.click(".imp-nb");
  check((await page.evaluate(() => RUNS)).filter(r => r.kind === "nb")[0].ips === "52.88.145.123", "Not block of a cloud IP still works");
  await page.fill("#imp_d_q", "1000104");
  await page.press("#imp_d_q", "Enter");
  check(await page.$eval("#imp_d_tk", e => e.value) === "1000104", "search by digits fills the ticket");
  await page.fill("#imp_d_q", "ITHM-1000102");
  await page.press("#imp_d_q", "Enter");
  check(await page.$eval("#imp_d_tk", e => e.value) === "1000102", "ITHM-1000102 -> 1000102");
  await page.waitForTimeout(150);
  check(await page.$eval(".imp-link:not(.imp-hidden)", e => e.textContent) === "☑ Select all 1 shown", "search ITHM-1000102 finds the digits-only incident");
  check(await page.$eval("#d_paths .table-wrap", e => e.classList.contains("imp-scroll") && e.scrollHeight > e.clientHeight), "All paths table scrolls");
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.close();

  console.log("Found search fails: typed IPs still go to the server, which checks them again");
  ({page, errs} = await open(browser, "d", false, {findFail: true}));
  await page.fill("#imp_d_q", "203.0.113.10");
  await page.waitForTimeout(900);
  check((await page.$$eval(".imp-tag", t => t.map(x => x.textContent))).join() === "✍ 203.0.113.10" && (await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 1 IP", "fallback: typed IP counted");
  check((await txt(page, ".imp-find")).indexOf("check unavailable (Error in 'impervafind' command: boom) – checked again when blocking") > 0, "Found shows the error of the search: " + (await txt(page, ".imp-find")));
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.close();

  console.log("Slow Found search: a cancelled older job is not a failure");
  ({page, errs} = await open(browser, "d", false, {findDelay: 1500}));
  await page.fill("#imp_d_q", "199.19.95.68");
  await page.waitForTimeout(900);
  check((await txt(page, ".imp-find")).indexOf("⏳ checking every page and every WAF policy") > 0 && (await txt(page, ".imp-find")).indexOf("unavailable") < 0, "while the search runs: ⏳ checking, not unavailable");
  check((await page.$$eval(".imp-tag", t => t.map(x => x.textContent))).join() === "⏳ 199.19.95.68" && (await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 0 IPs", "not counted before the check");
  await page.waitForTimeout(1500);
  check(/199\.19\.95\.68✔ not on the WAF/.test(await txt(page, ".imp-find")) && (await txt(page, ".imp-run:not(.imp-nb)")) === "⛔ Block 1 IP", "result arrives: can be blocked, counted");
  check(errs.length === 0, "no JS errors " + errs.join(" | "));
  await page.close();

  console.log("Phone width 390");
  ({page, errs} = await open(browser, "d", false, null, 390));
  await page.click("#det_table tbody tr:nth-child(1)");
  await page.fill("#imp_d_q", "203.0.113.10, 185.220.101.47");
  await page.waitForTimeout(900);
  const ov = await page.$eval(".imp-card", e => e.scrollWidth - e.clientWidth);
  check(ov <= 0, "card has no horizontal overflow at 390px (" + ov + ")");
  await page.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILED` : "\nALL PASSED");
  console.log("pages and screenshots: " + OUT);
  process.exit(fails ? 1 : 0);
})();
