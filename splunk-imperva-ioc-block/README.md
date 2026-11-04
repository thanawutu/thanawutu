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
1. Click a row in *Attacking IPs*. Its `src` goes into the IP box and its `msg` goes into Reason.
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
python3 -m unittest -v tests/test_imperva_lib.py
```

## Notes
- The sample lookup uses documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`). These are
  rejected on purpose so you can see the guard working.
- `configure/acl` replaces the whole list. That is why the code always reads the current list first.
- If you prefer Imperva API v2 (policies API, ACL policy with `BLACKLISTED_IPS`), only
  `ImpervaClient.get_blacklist/set_blacklist` need to change.
