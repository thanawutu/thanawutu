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
| makeresults | impervablock action=block ip="8.8.4.4" dry_run=true reason="TI-123"
index=imperva sourcetype="incapsula:cef" category!=normal act!=allowed
| stats count BY src | where count > 300
| impervablock action=block field=src dry_run=true reason="Imperva attack count>300"
```

## Tests (no Splunk needed)
```bash
python3 -m unittest -v tests/test_imperva_lib.py tests/test_vt_lib.py
```

## Notes
- The sample lookup uses documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`). These are
  rejected on purpose so you can see the guard working.
- `configure/acl` replaces the whole list. That is why the code always reads the current list first.
- If you prefer Imperva API v2 (policies API, ACL policy with `BLACKLISTED_IPS`), only
  `ImpervaClient.get_blacklist/set_blacklist` need to change.
