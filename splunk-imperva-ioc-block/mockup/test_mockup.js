// Function-by-function test of the mockup (every page, button, filter, search, run flow).
// Run: node mockup/test_mockup.js   (needs playwright; prints PASS / FAIL per function)
const { chromium } = require('playwright');
const URL = 'file://' + (process.argv[2] || require('path').join(__dirname, 'dashboard-mockup.html'));
const R = [];
let page, errs = [];
const T = (area, name, ok, detail = '') => { R.push({ area, name, ok: !!ok, detail }); };
const txt = sel => page.locator(sel).innerText();
const rows = sel => page.locator(sel + ' tr[data-ip]').evaluateAll(t => t.map(r => r.dataset.ip));
const go = async h => { await page.evaluate(x => { location.hash = x; }, h); await page.waitForTimeout(250); };
const num = s => +String(s).replace(/[^0-9.-]/g, '');
const wait = ms => page.waitForTimeout(ms);

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 } });
  page = await ctx.newPage();
  page.on('pageerror', e => errs.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  await page.goto(URL); await wait(600);

  // ---------------- general
  T('General', 'page loads without JavaScript error', errs.length === 0, errs.join(' | '));
  const tabs = await page.locator('.tabs a').evaluateAll(a => a.map(x => x.dataset.page));
  T('General', '5 tabs (Block, Older, Blocked/Unblock/Auto, Rules, Audit)', tabs.join(',') === 'dash,history,blocked,rules,audit', tabs.join(','));
  for (const [h, title] of [['history', 'Older detections'], ['blocked', 'Blocked IPs / Unblock / Auto unblock'], ['rules', 'Detection rules'], ['audit', 'Audit log'], ['', 'IOC Block']]) {
    await go(h);
    const vis = await page.locator('#v-' + (h || 'dash')).isVisible();
    T('General', `tab #${h || 'dash'} opens its page and title`, vis && (await txt('#pageTitle')).includes(title), await txt('#pageTitle'));
  }
  await go('auto');
  T('General', 'old link #auto opens the merged page', await page.locator('#v-blocked').isVisible());

  // ---------------- page 1: Block - last 7 days
  await go('');
  const dRows0 = await rows('#d_tbl');
  T('Block 7d', 'KPIs filled', num(await txt('#kDet')) === dRows0.length && (await txt('#kWaf')) !== '0', `detected ${await txt('#kDet')}, rows ${dRows0.length}`);
  T('Block 7d', 'chart of 7 days drawn', await page.locator('#chart7 svg g.day').count() === 7);
  T('Block 7d', 'tab count = rows', num(await txt('#nDash')) === dRows0.length);
  T('Block 7d', 'already blocked / allowed IPs are not listed', !dRows0.includes('185.220.101.47') && !dRows0.includes('20.20.20.20'));
  await page.fill('#d_q', 'DDoS'); await wait(150);
  let r = await rows('#d_tbl');
  T('Block 7d', 'text search filters rows (rule name)', r.length > 0 && r.length < dRows0.length, `${r.length} of ${dRows0.length}`);
  await page.fill('#d_q', 'ITHM 1000101'); await wait(150);
  r = await rows('#d_tbl');
  T('Block 7d', 'incident search "ITHM 1000101" = digits only', r.length === 3, r.join(','));
  T('Block 7d', 'Select all shows the number of matches', (await txt('#d_all')).includes('Select all 3'), await txt('#d_all'));
  await page.click('#d_all'); await wait(100);
  T('Block 7d', 'Select all selects them + ticket from the search', (await txt('#d_run')).includes('Block 3') && (await page.inputValue('#d_tk')) === '1000101', `${await txt('#d_run')} tk=${await page.inputValue('#d_tk')}`);
  T('Block 7d', 'cloud IP tag says short block', (await txt('#d_sel')).includes('unblock after 7 quiet days'));
  T('Block 7d', 'WAF check shown for the selection', await page.locator('#d_chk').isVisible(), await txt('#d_chk'));
  await page.click('#d_clr'); await wait(100);
  T('Block 7d', 'Clear empties selection and search', (await txt('#d_run')).includes('Block 0') && (await page.inputValue('#d_q')) === '');
  await page.fill('#d_q', '193.42.33.7, 185.220.101.47, 20.20.20.20, 45.95.147.236, 203.0.113.10'); await wait(200);
  const find = await txt('#d_find');
  T('Block 7d', 'Found: blocked in own policy -> not blocked again', /193\.42\.33\.7[\s\S]*already BLOCKED in policy 2169031[\s\S]*not blocked again/.test(find));
  T('Block 7d', 'Found: blocked in another policy (rule name)', /185\.220\.101\.47[\s\S]*already BLOCKED in policy 1000001 Block DDoS policy/.test(find));
  T('Block 7d', 'Found: allowed IP cannot be blocked', /20\.20\.20\.20[\s\S]*ALLOWED/.test(find));
  T('Block 7d', 'Found: IP on the other page', /45\.95\.147\.236[\s\S]*Older detections page[\s\S]*included in Block/.test(find));
  T('Block 7d', 'Found: not found anywhere -> can be blocked', /203\.0\.113\.10[\s\S]*not found anywhere[\s\S]*included in Block/.test(find));
  T('Block 7d', 'Block button counts the 2 blockable typed IPs', (await txt('#d_run')).includes('Block 2'), await txt('#d_run'));
  await page.fill('#d_q', ''); await wait(100);
  const ip1 = dRows0[0];
  await page.click(`#d_tbl tr[data-ip="${ip1}"] td.ip`); await wait(100);
  T('Block 7d', 'row click selects (tag, highlight, buttons)', (await txt('#d_sel')).includes(ip1) && (await page.locator(`#d_tbl tr[data-ip="${ip1}"]`).getAttribute('class')).includes('selected') && (await txt('#d_nb')).includes('Not block 1'));
  T('Block 7d', 'ticket filled from the clicked finding', (await page.inputValue('#d_tk')) !== '');
  await page.click(`#d_sel [data-rm="${ip1}"]`); await wait(100);
  T('Block 7d', '× on the tag unselects', !(await txt('#d_sel')).includes(ip1 + '×') && (await txt('#d_run')).includes('Block 0'));
  await page.click(`#d_tbl tr[data-ip="${ip1}"] td.ip`); await page.click(`#d_tbl tr[data-ip="${ip1}"] td.ip`); await wait(100);
  T('Block 7d', 'second click unselects', (await txt('#d_run')).includes('Block 0'));
  await page.fill('#d_tk', '');
  await page.click(`#d_tbl tr[data-ip="${ip1}"] [data-detail]`); await wait(150);
  T('Block 7d', 'Decision aid cell opens IP detail', await page.locator('#d_detail').isVisible() && (await txt('#d_detail')).includes(ip1));
  await page.click('#d_detail [data-dsel]'); await wait(100);
  T('Block 7d', 'IP detail "select this IP" selects it', (await txt('#d_run')).includes('Block 1'));
  await page.click('#d_detail [data-dclose]'); await wait(100);
  T('Block 7d', 'IP detail closes', !(await page.locator('#d_detail').isVisible()) || (await txt('#d_detail')).trim() === '');
  // Block run: selected row + a typed private IP (rejected)
  const blk0 = num(await txt('#nBlk'));
  await page.fill('#d_q', '10.1.2.3'); await page.fill('#d_tk', '1000201'); await page.fill('#d_desc', 'test block'); await wait(150);
  T('Block 7d', 'typed private IP counted (checked by the server)', (await txt('#d_run')).includes('Block 2'), await txt('#d_run'));
  await page.click('#d_run'); await wait(1900);
  const res = await txt('#d_res');
  T('Block 7d', 'Block run: blocked + verified message', res.includes('✔ Block 1 IP') && res.includes('1000201'), res.slice(0, 160));
  T('Block 7d', 'Block run: private IP rejected', res.includes('10.1.2.3 (private IP)'));
  T('Block 7d', 'blocked IP leaves the page and joins Blocked IPs', !(await rows('#d_tbl')).includes(ip1) && num(await txt('#nBlk')) === blk0 + 1, `${blk0} -> ${await txt('#nBlk')}`);
  T('Block 7d', 'inputs reset after the run', (await page.inputValue('#d_tk')) === '' && (await page.inputValue('#d_q')) === '');
  // Not block
  const ip2 = (await rows('#d_tbl'))[0];
  await page.click(`#d_tbl tr[data-ip="${ip2}"] td.ip`); await page.click('#d_nb'); await wait(150);
  T('Block 7d', 'Not block hides the IP (no WAF call)', (await txt('#d_res')).includes('Not block 1 IP') && !(await rows('#d_tbl')).includes(ip2));
  await page.fill('#d_q', ip2); await wait(150);
  T('Block 7d', 'search finds the hidden IP: hidden by Not block, can still be blocked', /hidden by Not block[\s\S]*can still be blocked/.test(await txt('#d_find')));
  await page.fill('#d_q', ''); await wait(100);

  // ---------------- page 2: Older detections
  await go('history');
  T('Older', 'chart of 30 days drawn', await page.locator('#chart30 svg g.day').count() === 30);
  const counts = {};
  for (const v of ['30', '90', 'all']) { await page.selectOption('#h_rng', v); await wait(150); counts[v] = (await rows('#h_tbl')).length; }
  T('Older', 'Detected range 8-30 / 31-90 / all changes rows', counts.all >= counts['30'] && counts.all >= counts['90'] && counts.all === num(await txt('#nHist')), JSON.stringify(counts));
  T('Older', 'title follows the range', (await txt('#h_title')).includes('older than 7 days'));
  T('Older', 'no Not blocked (hidden) table any more', await page.locator('#nb_tbl').count() === 0 && !(await txt('#v-history')).includes('Not blocked (hidden)'));
  T('Older', 'hidden IP stays hidden until it is detected again', !(await rows('#h_tbl')).includes(ip2) && !(await rows('#h_tbl')).includes('118.193.33.60'));
  const hIp = (await rows('#h_tbl'))[0];
  await page.click(`#h_tbl tr[data-ip="${hIp}"] td.ip`); await page.fill('#h_desc', 'old finding'); await page.click('#h_run'); await wait(1900);
  T('Older', 'Block from the Older page works', (await txt('#h_res')).includes('✔ Block 1 IP') && !(await rows('#h_tbl')).includes(hIp));

  // ---------------- page 3: Blocked IPs / Unblock / Auto unblock
  await go('blocked');
  const all0 = await rows('#b_tbl');
  T('Blocked+Auto', 'table lists every policy (own + other)', all0.includes('185.220.101.47') && all0.includes('193.42.33.7') && all0.includes(ip1), `${all0.length} rows`);
  T('Blocked+Auto', 'KPI Blocked on the WAF = rows', num(await txt('#bWaf')) === all0.length, await txt('#bWafSub'));
  T('Blocked+Auto', 'rules strip shows 7 / 60 days, all policies, rounds of 10, no daily limit', /7 days[\s\S]*60 days[\s\S]*All enabled policies[\s\S]*Rounds of 10 IPs[\s\S]*no daily limit/.test(await txt('.austrip')));
  await page.click('#b_howBtn'); await wait(100);
  const howOpen = await page.locator('#b_how').isVisible() && await page.locator('#au_chart svg').count() === 1;
  await page.click('#b_howBtn'); await wait(100);
  T('Blocked+Auto', 'How it works opens (flow + 30-day chart) and closes', howOpen && !(await page.locator('#b_how').isVisible()));
  const chips = await page.locator('#b_filters button').evaluateAll(x => x.map(b => [b.dataset.f, +b.querySelector('.n').textContent]));
  let chipOk = true, chipDet = [];
  for (const [f, n] of chips) { await page.click(`#b_filters [data-f="${f}"]`); await wait(80); const k = (await rows('#b_tbl')).length; chipDet.push(`${f}:${n}/${k}`); if (k !== n) chipOk = false; }
  T('Blocked+Auto', 'each filter chip shows exactly its count', chipOk, chipDet.join(' '));
  await page.click('#b_filters [data-f="all"]');
  const sorted = await page.locator('#b_tbl tr[data-ip]').evaluateAll(t => t.map(r => r.children[6].innerText.trim()));
  const dated = sorted.filter(x => x !== '-');
  T('Blocked+Auto', 'sorted by unblock date (Kept last)', dated.join() === [...dated].sort().join() && sorted[sorted.length - 1] === '-');
  for (const [q, want] of [['193.42', '193.42.33.7'], ['1000090', '193.42.33.7'], ['Tor exit', '185.220.101.47'], ['DDoS', '61.177.172.13']]) {
    await page.fill('#b_q', q); await wait(100);
    const rr = await rows('#b_tbl'); T('Blocked+Auto', `search "${q}" finds ${want}`, rr.includes(want), rr.join(','));
  }
  await page.fill('#b_q', ''); await wait(100);
  const other = '35.165.106.69';
  await page.click(`#b_tbl tr[data-ip="${other}"]`); await wait(100);
  T('Blocked+Auto', 'select an IP of another policy: Unblock + Apply enabled', (await txt('#b_run')).includes('Unblock 1') && !(await page.locator('#b_apply').isDisabled()));
  const statusOf = async ip => (await page.locator(`#b_tbl tr[data-ip="${ip}"] td:nth-child(3)`).innerText()).trim();
  const afterOf = async ip => (await page.locator(`#b_tbl tr[data-ip="${ip}"] td:nth-child(6)`).innerText()).trim();
  await page.selectOption('#b_setDur', 'keep'); await page.fill('#b_desc', 'partner asked'); await page.click('#b_apply'); await wait(120);
  T('Blocked+Auto', 'Apply rule Keep -> status Kept, KPI Kept +1', (await statusOf(other)) === 'Kept' && (await txt('#b_res')).includes('Keep'), await statusOf(other));
  await page.click(`#b_tbl tr[data-ip="${other}"]`); await page.selectOption('#b_setDur', '30'); await page.click('#b_apply'); await wait(120);
  T('Blocked+Auto', 'Apply rule 30 days -> "30 d quiet"', (await afterOf(other)).includes('30 d quiet'), await afterOf(other));
  await page.click(`#b_tbl tr[data-ip="${other}"]`); await page.selectOption('#b_setDur', 'default'); await page.click('#b_apply'); await wait(120);
  T('Blocked+Auto', 'Apply rule Default -> cloud 7 d quiet', (await afterOf(other)).includes('cloud 7 d quiet'), await afterOf(other));
  T('Blocked+Auto', 'Apply rule never calls the WAF', (await txt('#b_res')).includes('ไม่ได้ส่งอะไรไป WAF'));
  const un0 = num(await txt('#bUn7')), n0 = (await rows('#b_tbl')).length;
  await page.click('#b_tbl tr[data-ip="141.98.10.60"]'); await page.click('#b_tbl tr[data-ip="218.92.0.112"]'); await wait(80);
  T('Blocked+Auto', 'ticket filled from the first selected IP', (await page.inputValue('#b_tk')) === '1000071');
  await page.click('#b_clr'); await wait(80);
  T('Blocked+Auto', 'Clear empties the selection', (await txt('#b_run')).includes('Unblock 0'));
  await page.click('#b_tbl tr[data-ip="141.98.10.60"]'); await page.click('#b_tbl tr[data-ip="218.92.0.112"]');
  await page.fill('#b_desc', 'false positive'); await page.click('#b_run'); await wait(1900);
  const ures = await txt('#b_res');
  T('Blocked+Auto', 'Unblock now: own + other policy, verified', ures.includes('Unblock 2 IP') && ures.includes('2169031') && ures.includes('1000001'), ures);
  T('Blocked+Auto', 'unblocked IPs leave the table, KPI Unblocked 7 days +2', (await rows('#b_tbl')).length === n0 - 2 && num(await txt('#bUn7')) === un0 + 2, `${un0} -> ${await txt('#bUn7')}`);
  await go('audit');
  T('Audit', 'manual unblocks appear in the unblock log (Audit log page)', (await txt('#au_log')).includes('218.92.0.112'));
  const due = num(await txt('#bDue'));
  T('Blocked+Auto', 'Next run plan = Due now, in rounds of 10', (await txt('#au_plan')).includes(`${due} to unblock`) && due > 0, await txt('#au_plan'));
  await page.click('#au_run'); await wait(1800);
  T('Audit', 'Run now (Audit log page) unblocks every due IP', (await txt('#au_res')).includes(`Unblocked ${due} IP`) && num(await txt('#bDue')) === 0, await txt('#au_res'));
  T('Audit', 'auto unblocks logged with the reason', /auto unblock[\s\S]*no attack for (7|60) days/.test(await txt('#au_log')));
  await go('blocked');

  // ---------------- detection rules
  await go('rules');
  const dash0 = num(await txt('#nDash'));
  await page.fill('#rName', ''); await page.click('#rAdd'); await wait(80);
  T('Rules', 'empty name refused', (await txt('#toast')).includes('ใส่ชื่อ'));
  await page.fill('#rName', 'Bot - *'); await page.fill('#rNote', 'bots'); await page.click('#rAdd'); await wait(120);
  T('Rules', 'add Include rule: listed + preview uses the search', (await txt('#rules')).includes('Bot - *') && /✔ used\s+Bot - Credential Stuffing/.test(await txt('#esPrev')));
  await page.fill('#rName', 'bot - *'); await page.click('#rAdd'); await wait(80);
  T('Rules', 'duplicate rule refused', (await txt('#toast')).includes('มี rule นี้อยู่แล้ว'));
  await page.click('#rules [data-tg="1"]'); await wait(120);
  T('Rules', 'disable *WAF* -> Block page empty', num(await txt('#nDash')) === 0, await txt('#nDash'));
  await page.click('#rules [data-tg="1"]'); await wait(120);
  T('Rules', 'enable again -> rows back', num(await txt('#nDash')) === dash0);
  await page.selectOption('#rMode', 'exclude'); await page.fill('#rName', '*DDoS*'); await page.click('#rAdd'); await wait(120);
  T('Rules', 'Exclude rule removes those findings', num(await txt('#nDash')) < dash0, `${dash0} -> ${await txt('#nDash')}`);
  const lastId = await page.locator('#rules [data-del]').last().getAttribute('data-del');
  await page.click(`#rules [data-del="${lastId}"]`); await wait(120);
  T('Rules', 'Remove rule -> findings back', num(await txt('#nDash')) === dash0);

  // ---------------- audit log
  await go('audit');
  const aRows = await page.locator('#audit tr').evaluateAll(t => t.map(r => [r.children[0]?.innerText, r.children[2]?.innerText]));
  T('Audit', 'every action above is in the audit log', ['block', 'unblock', 'not_block', 'rule_add', 'rule_remove', 'rule_enable', 'rule_disable', 'auto_unblock_rule'].every(a => aRows.some(x => x[1] === a)), [...new Set(aRows.map(x => x[1]))].join(','));
  T('Audit', 'newest first', aRows.map(x => x[0]).join() === [...aRows.map(x => x[0])].sort().reverse().join());
  await page.fill('#aq', '141.98.10.60'); await wait(100);
  T('Audit', 'search by IP', (await page.locator('#audit tr').evaluateAll(t => t.every(r => r.innerText.includes('141.98.10.60')))));
  await page.fill('#aq', '');
  const opts = await page.locator('#aact option').evaluateAll(o => o.map(x => x.value).filter(Boolean));
  let fOk = true, fDet = [];
  for (const o of opts) { await page.selectOption('#aact', o); await wait(60); const acts = await page.locator('#audit tr').evaluateAll(t => t.map(r => r.children[2]?.innerText)); const good = acts.every(a => a === o || a === undefined); fDet.push(`${o}:${acts.length}`); if (!good) fOk = false; }
  T('Audit', 'action filter shows only that action', fOk, fDet.join(' '));
  T('Audit', 'action filter offers every action written', ['auto_unblock_rule'].every(a => opts.includes(a)), opts.join(','));
  await page.selectOption('#aact', '');
  const autoRows = await page.locator('#audit tr').evaluateAll(t => t.filter(r => r.children[1]?.innerText === 'auto-unblock').length);
  T('Audit', 'auto unblock rows written as user auto-unblock', autoRows > 0, String(autoRows));

  // ---------------- dark theme + phone width
  const ctxD = await b.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark' });
  const pd = await ctxD.newPage(); await pd.goto(URL + '#blocked'); await pd.waitForTimeout(400);
  const bg = await pd.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const sum = bg.match(/\d+/g).slice(0, 3).reduce((a, c) => a + +c, 0);
  T('Layout', 'dark theme follows the system', sum < 200, bg);
  const ctxM = await b.newContext({ viewport: { width: 390, height: 844 } });
  const pm = await ctxM.newPage(); const mErr = [];
  pm.on('pageerror', e => mErr.push(e.message));
  let mOk = true, mDet = [];
  for (const h of ['', 'history', 'blocked', 'rules', 'audit']) { await pm.goto(URL + '#' + h); await pm.waitForTimeout(300); const w = await pm.evaluate(() => document.documentElement.scrollWidth); mDet.push(`${h || 'dash'}:${w}`); if (w > 390) mOk = false; }
  T('Layout', 'phone width 390 px: no sideways scroll on any page', mOk, mDet.join(' '));
  T('General', 'no JavaScript error during the whole test', errs.length === 0 && mErr.length === 0, errs.concat(mErr).join(' | '));

  await b.close();
  const areas = [...new Set(R.map(x => x.area))];
  let n = 0;
  for (const a of areas) {
    console.log('\n' + a);
    for (const x of R.filter(y => y.area === a)) { n++; console.log(`  ${x.ok ? 'PASS' : 'FAIL'}  ${String(n).padStart(2)}. ${x.name}${x.ok ? '' : '   <- ' + x.detail}`); }
  }
  const f = R.filter(x => !x.ok).length;
  console.log(`\n${R.length - f} / ${R.length} passed${f ? `, ${f} FAILED` : ''}`);
  process.exit(f ? 1 : 0);
})().catch(e => { console.error('TEST CRASH', e); process.exit(2); });
