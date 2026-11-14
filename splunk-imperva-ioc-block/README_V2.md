# Imperva IOC Block V2 (`TA-imperva-ioc-block-v2`)

V2 is a separate Splunk app installed **next to V1** (`TA-imperva-ioc-block`). V1 is not changed.
When V2 is tested and confirmed, V1 is removed (see *Cut-over*).

## What is new in V2

| | V1 (1.3.x) | V2 (2.0.0) |
|---|---|---|
| Cloud provider IPs (AWS, Google Cloud, Azure, ...) | never blocked (Not block only) | **blocked**, tagged "short block" |
| Auto unblock | - | always on: IP rules of **every enabled WAF policy** are unblocked when the IP sent **no request for 7 days (cloud provider / shared IP) / 60 days (others)**, at most 50 per run (fixed values) |
| Pages | 5 | 5: **Blocked IPs / Unblock / Auto unblock** is one page: every policy in one table (own policy read live), Status / Last attack / Attacks 24h / Unblock after / Unblock on, 🔓 Unblock from any policy, auto unblock rule per IP, run now and log |
| IP reputation | VirusTotal | VirusTotal + **AbuseIPDB** + **GreyNoise**, all through SOAR, 24 h cache; they adjust the Block suggestion |
| SOAR playbook | `imperva_ioc_block` | its own playbook **`imperva_ioc_block_v2`** (label `imperva_ioc_block_v2`): same code + AbuseIPDB / GreyNoise; the V1 playbook is not touched |

Everything else (Decision aid, IP detail, card, Select all, incident digits) is the same as V1.

### Auto unblock

* **Last attack** = last Imperva event *Blocked IP* / `act=REQ_BLOCKED_ACL` from the IP (the IP is on a
  block list and still sends requests), collected every hour by
  **"Imperva V2 - Last attack of blocked IPs (hourly)"** into KV `imperva_blocked_seen`, together with
  the number of requests the WAF still blocked from each IP in the last 24 hours (**Attacks 24h**, per IP
  and as a total on the Blocked IPs page).
* The countdown of a rule starts at the latest of: last attack, block date (registry), the day V2
  first saw the rule (= **the day V2 is installed** for rules already on the WAF).
* **"Imperva V2 - Auto unblock (daily)"** (02:17) unblocks what is due through the normal backend
  (SOAR) with the rule's policy ID, writes the audit CSV (`user = auto-unblock`) and closes the
  registry entry of IPs blocked from Splunk. A rule added again later starts a new countdown.
* Per IP (Blocked IPs page: select rows, then *Auto unblock rule for the selected IPs* > ✔ APPLY RULE):
  **Default**, **📌 Keep** (never unblock) or 7 / 30 / 90 / 180 / 365 quiet days. **🔓 UNBLOCK** in the card
  unblocks the selected IPs at once, each from the policy that holds it
  (`impervaautounblock action=unblock`); IPs marked *NOT on WAF* close their registry entry.
* Fixed values, no settings and no report-only mode: always on, 7 days for cloud provider / shared IPs,
  60 days for other IPs, every enabled policy, at most 50 IP rules per run (the rest at the next run).
  The Blocked IPs page shows them in one line at the top.
* Only `BLOCK` IP / CIDR rules of IP settings are handled; ALLOW rules, exceptions and range rules
  (`a-b`) are never touched. Disabled policies are ignored (except the own policy).
* Cloud provider / shared IP = VirusTotal AS owner matches `imperva.conf cloud_providers` (AWS, Google,
  Azure ...) or `shared_ip_providers` (mobile carriers: many customers behind one IP). Looked up when the
  IP is blocked; for rules of other policies, only IPs VirusTotal already knows - others count as normal.

### AbuseIPDB and GreyNoise

Same flow as VirusTotal: the saved search **"Imperva V2 - AbuseIPDB / GreyNoise cache warm-up"** (hourly,
minute 25) looks the detected IPs up through SOAR (playbook actions `abusecheck` / `gncheck`) and keeps the
answers 24 h in KV `imperva_cache`; the Block and Older detections pages only read that cache (`intelcheck
cache_only=true`), so they never wait for the APIs. New IPs show `pending` until the next warm-up run.

* Columns **AbuseIPDB %** (confidence of abuse, red ≥ 75, yellow ≥ 25) and **GreyNoise** (malicious /
  benign / RIOT = known service / not observed); click = the IP's page on AbuseIPDB / GreyNoise.
  The IP detail shows reports, users, usage type, ISP, Tor, last report, GreyNoise name and last seen.
* Suggestion (after VirusTotal): AbuseIPDB ≥ `block_score` (75) → BLOCK, ≥ `review_score` (25) → at least
  REVIEW, GreyNoise malicious → at least REVIEW, GreyNoise RIOT / benign or AbuseIPDB whitelisted → at most
  REVIEW (a known service: the analyst decides). DO_NOT_BLOCK / ALREADY_BLOCKED never change.
* Quotas: at most `max_lookups_per_run` new lookups per hourly run (AbuseIPDB 40 = 960 / day, inside the free
  1,000 / day; GreyNoise 10). HTTP 429 → `rate_limited`, retried at the next run. Settings: `imperva.conf
  [abuseipdb]` / `[greynoise]` (`enabled = false` turns one off).
* Without SOAR (`via = direct`): keys in storage/passwords realm `abuseipdb` / `greynoise`.

### Living next to V1

* All V2 objects are app-local (`export = none`); V1 keeps `export = system`. Same names do not collide.
* V2 has its own KV store, audit CSV and saved searches (named `Imperva V2 - ...`), and writes its
  own logs (`v2_imperva_ioc_block.log`, `v2_imperva_auto_unblock.log`, ...).
* Credentials: V2 reads its own, then V1's, until they are copied with the import (below).
* Both apps call SOAR / VirusTotal while both are installed (policy refresh, VT warm-up).
* SOAR: V2 sends its requests with label `imperva_ioc_block_v2` to its own playbook, so the V1 playbook
  `imperva_ioc_block` (and its `IMPERVA_POLICY_IDS`) stays exactly as it is until V1 is removed.

## Install (Deployer)

0. First create the V2 playbook on SOAR (section *SOAR: the V2 playbook* below).
1. Extract `TA-imperva-ioc-block-v2` to `$SPLUNK_HOME/etc/shcluster/apps/` and copy V1's `local/` and
   `certs/` into it (same `imperva.conf` settings and SOAR CA file).
2. `splunk apply shcluster-bundle -preserve-lookups true ...` (new app, commands and KV collections:
   expect a rolling restart).
3. Run once (Settings > Searches, reports, and alerts, app *Imperva IOC Block V2*: enable, Run, disable):
   * **Imperva V2 - Import data from V1 (run once)** - registry, detection rules, Not block list,
     VirusTotal cache, credentials (copied server side, never shown)
   * **Imperva V2 - Import audit log from V1 (run once)**
   * optional **Imperva V2 - Last attack backfill 7 days (run once)**
4. Optional, to fill AbuseIPDB / GreyNoise at once: Run **Imperva V2 - AbuseIPDB / GreyNoise cache warm-up**
   (otherwise it runs by itself at minute 25 of every hour).

## SOAR: the V2 playbook

V2 has its own playbook so the V1 playbook keeps running unchanged. Do this **before** pushing V2.

1. **Network** (SOAR, through `IMPERVA_PROXY` if used): `api.abuseipdb.com:443` and `api.greynoise.io:443`,
   besides `api.imperva.com` and `www.virustotal.com` that V1 already uses.
2. **Label**: Administration > Event Settings > Label Settings > add `imperva_ioc_block_v2`.
3. **Playbook**: Playbooks > + Playbook > Automation, name `imperva_ioc_block_v2`, *Operates on* label
   `imperva_ioc_block_v2`, Python 3. In the Python editor select all and paste
   **`soar/imperva_ioc_block_playbook.py`** (generated, includes AbuseIPDB / GreyNoise).
4. **Settings** in `IMPERVA_CONFIG` at the top of `code_1`: copy the values from the V1 playbook
   (`IMPERVA_API_ID`, `IMPERVA_API_KEY`, `IMPERVA_PROXY`, `IMPERVA_PROTECTED_NETWORKS`, `VT_API_KEY`, ...), then:
   * `"IMPERVA_POLICY_IDS": "2169031,<id>,<id>"`: every policy Auto unblock may change. Splunk always sends
     the policy ID with each request, so extra IDs do not send blocks elsewhere. List them on the Auto
     unblock part of the Blocked IPs page (panel *Policies with BLOCK IP rules*) or with `| makeresults | impervaautounblock action=policies`.
   * `"ABUSEIPDB_API_KEY"`: your AbuseIPDB key. `"GREYNOISE_API_KEY"`: your GreyNoise key (the Community API
     also answers without one, with a lower limit).
5. Save, set the playbook **Active**. The same automation user / token as V1 is used.
6. If V1's `local/imperva.conf` (copied into V2) sets `soar_label`, remove that line from V2's copy.

Without a policy ID in step 4 the daily run reports `error ... not allowed on SOAR (add the policy ID to
IMPERVA_POLICY_IDS on SOAR)` for that policy and retries the next day. Without `ABUSEIPDB_API_KEY` the
AbuseIPDB column shows `error` (detail: `ABUSEIPDB_API_KEY is not set on SOAR`).

## Cut-over (after V2 is confirmed)

1. Make sure **Import data from V1** showed `credential ... copied` / `exists` for `splunk_soar`
   (and `imperva_waf` / `virustotal` if used).
2. Remove `TA-imperva-ioc-block` from `etc/shcluster/apps` (keep a backup) and push.
   On SOAR, deactivate (later delete) the V1 playbook `imperva_ioc_block`.
3. Optional: set `export = system` in V2 `metadata/default.meta` so the macros / commands work from
   the Search app again.

Rollback: remove `TA-imperva-ioc-block-v2` and push; V1 was never changed.

## Tests

```bash
python3 -m unittest discover -s tests_v2
```
UI of the card: `tests_v2/ui/run.js` (needs jquery + playwright).
