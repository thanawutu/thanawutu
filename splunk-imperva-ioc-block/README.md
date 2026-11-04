# Splunk → Imperva WAF: Manual IOC IP Block Button

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
| `Block` button | `⛔ Block` → confirmation panel → `✅ CONFIRM BLOCK` → `impervablock dry_run=false` |
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
6. The IOC panel reads from Imperva WAF logs (`index=imperva sourcetype="incapsula:cef"`). It shows
   attack events (`category!=normal act!=allowed`) from the last 24h, grouped by `src`, and keeps
   sources with `count > 300`. To change the threshold or time range, edit the base search
   `attack_ips` in the dashboard.

## Usage
Dashboard: **Apps → Imperva IOC Block**
**Per IP (quickest):** click `⛔ Block` on a row, check the VT and location details in the
confirmation panel, then click `✅ CONFIRM BLOCK`. That blocks the IP for real on every configured site.

**Bulk / dry-run / unblock (form):**
1. Click any other cell in *Attacking IPs*. Its `src` goes into the IP box and its `msg` goes into Reason.
   Or click the *Select ALL* panel to load every attacking IP at once (capped by `max_ips_per_action`).
   You can also paste several IPs, separated by commas.
2. Pick Block or Unblock and set the Mode (Dry-run first).
3. Fill in Reason / Ticket.
4. Tick **I confirm** and press **Submit**.
5. Check the *Result* panel: `would_be_blocked`, `blocked`, `no_change`, `rejected` or `error`.

You can also run it straight from SPL:
```
| makeresults | impervablock action=block ip="8.8.4.4" dry_run=true reason="TI-123" threat_actor="APT-X" incident_no="INC-2026-0042" comment="C2 beacon"
| impervalist
| inputlookup imperva_block_registry
index=imperva sourcetype="incapsula:cef" category!=normal act!=allowed
| stats count BY src | where count > 300
| impervablock action=block field=src dry_run=true reason="Imperva attack count>300"
```

## Tests (no Splunk needed)
```bash
python3 -m unittest -v tests/test_imperva_lib.py tests/test_vt_lib.py tests/test_policy_v2.py tests/test_soar_e2e.py
```

## Notes
- The sample lookup uses documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`). These are
  rejected on purpose so you can see the guard working.
- `configure/acl` replaces the whole list. That is why the code always reads the current list first.
- If you prefer Imperva API v2 (policies API, ACL policy with `BLACKLISTED_IPS`), only
  `ImpervaClient.get_blacklist/set_blacklist` need to change.
