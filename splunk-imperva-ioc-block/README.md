# Splunk → Imperva WAF: Manual IOC IP Block Button

> **V2** (`TA-imperva-ioc-block-v2`, auto unblock, cloud IPs blockable) is a separate app installed next to this one: see [README_V2.md](README_V2.md).

A Splunk app (`TA-imperva-ioc-block`) with a dashboard. A SOC analyst picks a malicious IP IOC,
confirms it, and presses **Submit**. The app then adds the IP to the **Blacklisted IPs ACL**
of one or more Imperva Cloud WAF sites.

```
Splunk dashboard (Simple XML form + Submit button)
   │  | makeresults | impervablock action=block ip="x.x.x.x" dry_run=false reason="..."
   ▼
impervablock.py  (custom search command, passauth)
   │  reads API ID/Key from storage/passwords, settings from imperva.conf
   │  validates IPs (public only, CIDR limit, protected networks, max per click)
   ▼
Imperva API v1:  sites/status  (read current blacklist)
                 sites/configure/acl rule_id=api.acl.blacklisted_ips  (write merged list)
   │
   ▼
audit → $SPLUNK_HOME/var/log/splunk/imperva_ioc_block.log  (indexed into _internal)
```

## VirusTotal verification + per-IP Block button
For each attacking IP (top 50 by count), `vtcheck` calls the **VirusTotal v3 API**
(`GET /api/v3/ip_addresses/{ip}`). It also reads the current Imperva blacklist. The table then shows:

| Column | Source |
|---|---|
| `suggestion` / `suggestion_reason` | `vt_lib.suggest()`, explained below |
| `vt_score`, `vt_reputation`, `vt_network` | VirusTotal |
| `location` | Splunk `iplocation` (City, Region, Country) plus `[VT: country]` |
| `asn` | VirusTotal ASN and AS owner |
| `⛔ Block n IPs` button | action card above the table → `impervablock action=block` (one click, see Dashboards) |
| `VirusTotal` | `🔗 Open` opens the VirusTotal GUI page for the IP |

How the suggestion is decided (thresholds are in `imperva.conf [virustotal]`):

| Suggestion | When |
|---|---|
| `BLOCK` | `malicious >= 3`, **or** (`malicious >= 1` / `suspicious >= 2` / reputation < 0) **and** count >= 1000 |
| `REVIEW` | some VT detections, **or** VT is clean but count >= 1000, **or** the VT lookup failed or hit its rate limit |
| `MONITOR` | VT is clean and attack volume is moderate. Not recommended to block yet |
| `ALREADY_BLOCKED` | The IP is already on the Imperva blacklist |
| `DO_NOT_BLOCK` | Private, reserved, or in `protected_networks` |

VirusTotal free-API limits are 4 requests/minute and 500/day. The command therefore:
- caches each result for 24h (`$SPLUNK_HOME/var/run/splunk/ta_imperva_vt_cache.json`);
- makes at most `max_lookups_per_run` (10) new lookups per run; the rest show `not_checked`;
- includes a saved search, **"Imperva - VT cache warm-up"** (disabled by default), that refreshes the cache every 30 min.

With a premium key, raise `requests_per_minute` and `max_lookups_per_run`.

Store the VirusTotal key:
```bash
curl -k -u admin https://localhost:8089/servicesNS/nobody/TA-imperva-ioc-block/storage/passwords -d name=vt -d password=<VT_API_KEY> -d realm=virustotal
```

## Live blocked-IP list, verification and description registry
- **`| impervalist`** is a generating command that reads the *Blacklisted IPs* ACL **live from Imperva**
  (`sites/status`) for every configured site, with no Splunk data in between.
- **Verification on write:** after each block or unblock, `impervablock` re-reads the blacklist from the WAF.
  The `verified_in_waf` column is `yes` only when the IP is really there. If the write was
  accepted but the IP is missing, the status becomes `error`.
- **Description per block:** *Threat actor name*, *Incident no.* and *Comment* go into the bulk form,
  or into the confirmation panel for the per-IP button. They are stored with date/time and user in the KV store
  collection `imperva_block_registry` (`_key = <site_id>_<ip>`) and written to the audit log.
- **Blocked IPs on Imperva WAF** table: the live WAF list joined with the registry.

  | verification | meaning |
  |---|---|
  | ✔ Verified on WAF | blocked from Splunk and present on the WAF |
  | ✔ On WAF (blocked outside Splunk) | present on the WAF, no description in Splunk |
  | ✖ NOT on WAF | registry says blocked but the WAF no longer has it (removed manually, or the write failed) |
  | ⚠ Unknown | the WAF API could not be read |

  The list refreshes **every 2 minutes** and **right after every block** (token `$waf_refresh$`).
  Blocks from the last hour are marked `🆕 NEW`.
- **Statistics (last 30 days, from the audit log):** total unique IPs blocked, IPs blocked today with trend,
  average per day, a daily block/unblock column chart, and daily blocks by threat actor / incident.
  The default `_internal` retention is 30 days. For longer history, query the registry (`blocked_at`).

## Search and Unblock on the blocked list
- **🔎 Search box** above *Blocked IPs on Imperva WAF* matches IP, site, threat actor, incident no., comment or user.
  `*` (the default) shows everything.
- **🔓 Unblock** on each row that is on the WAF opens a confirmation panel. It shows when the IP was blocked, by whom,
  and the block description. Enter an *Unblock reason* and an *Incident / change no.*, then click **🔓 CONFIRM UNBLOCK**.
  This runs `impervablock action=unblock site_id=<that site>`, so other sites keep the block.
  The command re-reads the WAF to confirm the IP is gone, marks the registry record `unblocked`
  (with time, user, reason and change no.), and refreshes the list.
- **🔍 Search** on each row opens Splunk Search in a new tab with
  `index=imperva sourcetype="incapsula:cef" src=<ip>` for the last 7 days.

## Imperva API mode: Policies v2 (default) or v1 site ACL
Set `api_mode` in `local/imperva.conf`:

| `api_mode` | Endpoint | Target IDs | Effect |
|---|---|---|---|
| `v2_policy` (default) | `GET/PUT https://api.imperva.com/policies/v2/policies/{policyId}` | `policy_ids` | Updates the **IP / BLOCK** setting of an **ACL policy**. Every site the policy is applied to gets the block |
| `v1_site` | `POST https://my.imperva.com/api/prov/v1/sites/configure/acl` | `site_ids` | Legacy per-site "Blacklisted IPs" ACL rule |

Both modes authenticate with the `x-API-Id` / `x-API-Key` headers.

How v2 works:
- It reads the policy (`?extended=true`), changes only the `policySettings` entry with
  `policySettingType=IP, settingsAction=BLOCK` (creating it if missing), and PUTs the whole policy back.
- GEO/URL settings, exceptions and `defaultPolicyConfig` are kept.
- It refuses to touch a policy whose `policyType` is not `ACL`.
- When the last IP is unblocked, the empty IP setting is removed.

In v2 mode the dashboard/registry field `site_id` holds the **policy ID**, and `site_name` holds the policy name.

Prepare a dedicated policy:
1. Cloud Security Console → **Policies** → **Add policy** → type **ACL**. Name it, e.g. `SOC IOC Blocklist`.
2. Add one IP block entry (any test IP), save, and apply the policy to the target websites.
3. Copy its **Policy ID**, then `policy_ids = <id>`.
4. The API key needs permission to read and edit policies.
5. If the key belongs to a parent account, set `caid`.

Test it:
```bash
curl -s "https://api.imperva.com/policies/v2/policies/<POLICY_ID>?extended=true" -H "accept: application/json" -H "x-API-Id: <API_ID>" -H "x-API-Key: <API_KEY>"
```

## No route from the Search Head to Imperva? Use SOAR mode
Set `api_mode = soar`. Splunk sends each block, unblock or list request to Splunk SOAR, and the playbook
`imperva_ioc_block` calls Imperva. The dashboard works the same. Setup is in [soar/README.md](soar/README.md).

## Safety controls
| Control | Where |
|---|---|
| Nothing runs until **Submit** is pressed (`autoRun="false"`) | dashboard |
| The block search is not sent until **"I confirm"** is ticked. The tick is cleared after every run | dashboard |
| **Dry-run** is the default mode | dashboard |
| Private, loopback, reserved and multicast IPs are refused | `validate_ips` |
| CIDR can be no wider than /24 (v4) or /48 (v6) | `imperva.conf` |
| `protected_networks` are never blocked | `imperva.conf` |
| IPs of **cloud providers** (AWS, Google Cloud, Azure, ...) are never blocked - Not block only | `imperva.conf` `cloud_providers`, `ip_owner.py` |
| `max_ips_per_action` (default 50) | `imperva.conf` |
| Per-IP button needs two clicks (Block → CONFIRM). Its tokens are not kept in the URL, so reloading the page never re-runs it | dashboard |
| **Read → merge → write**, so the existing blacklist is never overwritten | `apply_action` |
| Idempotent: re-running for the same IP writes nothing | `merge_blacklist` |
| Only `admin` / `imperva_blocker` can run the command or view the dashboard | `metadata/default.meta`, `authorize.conf` |
| Every action is logged with the user, IP, site, status and reason | `_internal` |

## Install
1. Copy `TA-imperva-ioc-block/` to `$SPLUNK_HOME/etc/apps/` on the **search head**, then restart Splunk.
2. In Imperva, create an API ID / API Key (Account → API Keys) that is allowed to change site settings.
3. Store the credential in Splunk. Realm must be `imperva_waf`, username = API ID, password = API Key:
   ```bash
   curl -k -u admin https://localhost:8089/servicesNS/nobody/TA-imperva-ioc-block/storage/passwords -d name=<API_ID> -d password=<API_KEY> -d realm=imperva_waf
   ```
4. Create `local/imperva.conf`:
   ```ini
   [settings]
   site_ids = 12345678,23456789
   protected_networks = <your egress IPs>, <partner IPs>, <scanner IPs>
   # proxy = http://proxy.corp:8080
   ```
5. Give analysts the `imperva_blocker` role (Settings → Roles).
6. Create the audit CSV once (the file is not shipped, so an app update never overwrites it):
   ```
   | makeresults | eval time=now(), user="install", action="install", ip="-", ticket="-", description="audit log created", status="-", verified="-", policy="-", backend="-", soar_container="-", detail="-"
   | table time user action ip ticket description status verified policy backend soar_container detail
   | outputlookup imperva_audit
   ```
   Optional: run the saved search **"Imperva - audit CSV backfill from log (run once)"** to copy the
   old block / unblock history from `index=_internal` into the CSV (run it only once).
   On a search head cluster push with `-preserve-lookups true` as an extra safety.

## Usage
Dashboard: **Apps → Imperva IOC Block**. Five pages (links at the top of every page):

| Page | What you can do |
|---|---|
| ⛔ **Block – last 7 days** (`imperva_ioc_block`) | KPIs (detected WAF IPs, blocked on WAF now, blocked today / 7 days, unblocked 7 days), daily chart, **Search + Block** of IPs detected in the last 7 days that are not blocked yet |
| 🗂 **Older detections** (`imperva_ioc_history`) | 30-day chart, **Search + Block** of IPs last detected 8–30 / 31–90 days ago |
| 🔓 **Blocked IPs / Unblock** (`imperva_ioc_blocked`) | live list of the WAF policy, **Search + Unblock**; an unblocked IP disappears |
| ⚙ **Detection rules** (`imperva_ioc_rules`) | which ES correlation searches feed the Block pages (KV store `imperva_ioc_rules`, Include / Exclude, `*` wildcard, enable / disable / remove) + preview |
| 📄 **Audit log** (`imperva_ioc_audit`) | every Block / Unblock / rule change from the CSV lookup `imperva_audit.csv`, search + export |

Block / Unblock: click rows to select IPs (click again, or × on the IP, to unselect), check
**Ticket / Incident no.** (filled from the ITHM note of the finding) and **Description**, then click
the red `⛔ Block n IPs` (or green `🔓 Unblock n IPs`) button - one click, no second confirmation.

The action card (Search | Add IPs manually / Selected IPs | Ticket | Description | buttons / WAF check)
is drawn by `appserver/static/imperva_form.js` in panel `<p>_actpanel` (p = `d` Block, `h` Older
detections, `b` Unblock). It only sets the tokens of that Simple XML panel (`$p_q$`, `$p_add$`, `$p_tk$`,
`$p_desc$`, `$p_sel$`, `$p_exec_*$`, `$p_nb_*$`) and reads the WAF check / "Select all shown" from the
panel's action search (`<p>_act`), so the searches are unchanged. If the script is not loaded (old
browser cache, script error) the Simple XML inputs and the action table are shown and work as before.
After installing a new version, reload the page with Ctrl+F5 if the old panel is still shown.
The result is verified on the WAF and appended to the audit CSV (`imperva_audit_write` macro).
IPs that are allow-listed or already blocked by another WAF policy cannot be selected.

Detection rules: defaults are Include `*WAF*` and Exclude `*WAF Monitor Error code 404*`
(written on first use). Add a rule by picking a correlation search from the list (or typing a
pattern), choose Include / Exclude, click `＋ ADD ... RULE`. Changes apply on the next search.

The dashboards never call VirusTotal or wait for it (`vtcheck cache_only=true`): they read the
cache, and IPs not checked yet show `pending` (suggestion REVIEW). The cache is shared by every
search head of the cluster (KV store `imperva_cache`), as is the WAF-policy cache, which the
saved search **"Imperva - WAF policy cache refresh"** renews every 5 min. "Blocked on WAF" on the
Block page comes from the registry; only the Blocked IPs page reads the WAF live.

WAF activity per detected IP (Imperva logs): column **Block / Allow** = requests the WAF blocked / let
through, **Web Block / Allow** = websites (`dest_name`) on which the IP was blocked / let through, e.g.
`500 / 18` and `5 / 2` (block number red, allow number green - cell renderer
`appserver/static/imperva_cells.js`). Block page: last 24 h (saved search
"Imperva - WAF activity of detected IPs (24h)", every 15 min, KV `imperva_ip_activity`).
Older detections page: last 30 days + **WAF last seen** (saved search "... (30d)", hourly, KV
`imperva_ip_activity_30d`). Classification: macro `imperva_waf_action_class`.

IP of a finding: macro `imperva_ioc_ip` - `src` / `src_ip`, `threat_match_value`, and for risk-based
rules (e.g. "Threat - ... Threat Hunting (IP) ...") `ip` / `threat_object`. Add a field there if a new
correlation search stores the IP elsewhere.

**✖ Not block** (Block / Older detections pages): hides the clicked IPs until they are detected again
(KV `imperva_ioc_dismissed`, command `impervadismiss`); nothing is sent to the WAF. The list with
**↩ Restore** is at the bottom of the Older detections page; both actions go to the audit CSV. Computed every 15 min by the saved search
**"Imperva - WAF activity of detected IPs (24h)"** into KV store `imperva_ip_activity`.

VirusTotal rate limit (HTTP 429): the lookup waits `rate_limit_retry_seconds` (60) and calls
again for the same IP until all IPs are done or `rate_limit_max_wait_seconds` is used up.
The scheduled search **"Imperva - VT cache warm-up"** (every 10 min, enabled) has no per-run
limit and keeps retrying, so every detected IP gets a VT score; the dashboards read the cache.
Imperva API calls are retried on HTTP 429 / 503 (honours `Retry-After`).

### Decision aid and IP detail (1.3.0)

Added on the Block and Older detections pages; the existing columns, suggestion logic, buttons
and saved searches are not changed.

- Column **Decision aid (24h|30d)** at the end of the table (macro `imperva_ioc_decision_aid(win)`):
  owner of the IP from the VirusTotal AS owner (Cloud provider / Crawler verified by Imperva /
  Mobile ISP / Hosting / ISP), warning signals (cloud = Not block only, shared mobile IP, attacks
  + 2xx responses let through, active in the last hour, unblocked / not blocked before) and
  `🔎 detail`. Owner word lists: macros `imperva_cloud_providers`, `imperva_mobile_providers`,
  `imperva_hosting_providers`.
- Data: saved searches **"Imperva - Decision aid of detected IPs (24h)"** (every 15 min) and
  **"(30d)"** (every 4 h) -> KV `imperva_ip_context_24h` / `imperva_ip_context_30d`.
- Click the Decision aid cell -> **IP detail** panels above the table: summary (✖ Close, VT,
  all events), WAF attack types, HTTP codes of the requests let through, client / User-Agent,
  requests per hour / day, audit history, ES detections of 90 days, neighbours (same /24 or ASN)
  and **All paths** (host + path, highest count first, scrolls). Request fields come from macro
  `imperva_waf_request_fields`, which tries several field names (request / url / uri_path,
  Response_Code / cn1 / status, requestClientApplication / http_user_agent, ...): adapt it if
  this Imperva add-on names them differently.
- **Cloud provider IPs are never blocked**: suggestion DO_NOT_BLOCK, the card counts them only
  in Not block (field `cloud_ips` of the action search), and `impervablock` rejects them
  (`ip_owner.py`: VirusTotal cache, else up to `cloud_check_max_lookups` lookups; owner unknown
  -> blocked with a warning). Word list `cloud_providers` in `imperva.conf`, the same as macro
  `imperva_cloud_providers`.
- Incident numbers are shown as digits only (`ITHM 1000101` -> `1000101`); the search box
  accepts both.

From SPL:
```
| makeresults | impervablock action=block ip="8.8.4.4" incident_no="ITHM 1234567" description="C2 beacon"
| makeresults | impervablock action=unblock ip="8.8.4.4" incident_no="ITHM 1234568" description="false positive"
| impervalist
| inputlookup imperva_block_registry
| inputlookup imperva_audit
| impervarules
```

## Tests (no Splunk needed)
```bash
python3 -m unittest discover -s tests
```
UI of the action card (fake Simple XML runtime, Playwright): see `tests/ui/run.js`.

## Notes
- The sample lookup uses documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`). These are
  rejected on purpose so you can see the guard working.
- `configure/acl` replaces the whole list. That is why the code always reads the current list first.
- If you prefer Imperva API v2 (policies API, ACL policy with `BLACKLISTED_IPS`), only
  `ImpervaClient.get_blacklist/set_blacklist` need to change.
