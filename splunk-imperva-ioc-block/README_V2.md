# Imperva IOC Block V2 (`TA-imperva-ioc-block-v2`)

V2 is a separate Splunk app installed **next to V1** (`TA-imperva-ioc-block`). V1 is not changed.
When V2 is tested and confirmed, V1 is removed (see *Cut-over*).

## What is new in V2

| | V1 (1.3.x) | V2 (2.0.0) |
|---|---|---|
| Cloud provider IPs (AWS, Google Cloud, Azure, ...) | never blocked (Not block only) | **blocked**, tagged "short block" |
| Auto unblock | - | always on: IP rules of **every enabled WAF policy** are unblocked when the IP sent **no request for 7 days (cloud provider / shared IP) / 60 days (others)**, at most 50 per run (fixed values) |
| Pages | 5 | 6 (new **⏱ Auto unblock**; Blocked IPs page shows *Attacks 24h / Last attack / Unblock after / Unblock on / Auto unblock*) |

Everything else (Decision aid, IP detail, card, Select all, incident digits) is the same as V1.

### Auto unblock

* **Last attack** = last Imperva event *Blocked IP* / `act=REQ_BLOCKED_ACL` from the IP (the IP is on a
  block list and still sends requests), collected every hour by
  **"Imperva V2 - Last attack of blocked IPs (hourly)"** into KV `imperva_blocked_seen`, together with
  the number of requests the WAF still blocked from each IP in the last 24 hours (**Attacks 24h**, per IP
  and as a total on the Blocked IPs and Auto unblock pages).
* The countdown of a rule starts at the latest of: last attack, block date (registry), the day V2
  first saw the rule (= **the day V2 is installed** for rules already on the WAF).
* **"Imperva V2 - Auto unblock (daily)"** (02:17) unblocks what is due through the normal backend
  (SOAR) with the rule's policy ID, writes the audit CSV (`user = auto-unblock`) and closes the
  registry entry of IPs blocked from Splunk. A rule added again later starts a new countdown.
* Per rule (Auto unblock page): **📌 Keep** (never unblock), **↺ Default**, **🔓 Unblock now**.
* Fixed values, no settings and no report-only mode: always on, 7 days for cloud provider / shared IPs,
  60 days for other IPs, every enabled policy, at most 50 IP rules per run (the rest at the next run).
  The Auto unblock page shows them in one line at the top.
* Only `BLOCK` IP / CIDR rules of IP settings are handled; ALLOW rules, exceptions and range rules
  (`a-b`) are never touched. Disabled policies are ignored (except the own policy).
* Cloud provider / shared IP = VirusTotal AS owner matches `imperva.conf cloud_providers` (AWS, Google,
  Azure ...) or `shared_ip_providers` (mobile carriers: many customers behind one IP). Looked up when the
  IP is blocked; for rules of other policies, only IPs VirusTotal already knows - others count as normal.

### Living next to V1

* All V2 objects are app-local (`export = none`); V1 keeps `export = system`. Same names do not collide.
* V2 has its own KV store, audit CSV and saved searches (named `Imperva V2 - ...`), and writes its
  own logs (`v2_imperva_ioc_block.log`, `v2_imperva_auto_unblock.log`, ...).
* Credentials: V2 reads its own, then V1's, until they are copied with the import (below).
* Both apps call SOAR / VirusTotal while both are installed (policy refresh, VT warm-up).

## Install (Deployer)

1. Extract `TA-imperva-ioc-block-v2` to `$SPLUNK_HOME/etc/shcluster/apps/` and copy V1's `local/` and
   `certs/` into it (same `imperva.conf` settings and SOAR CA file).
2. `splunk apply shcluster-bundle -preserve-lookups true ...` (new app, commands and KV collections:
   expect a rolling restart).
3. Run once (Settings > Searches, reports, and alerts, app *Imperva IOC Block V2*: enable, Run, disable):
   * **Imperva V2 - Import data from V1 (run once)** - registry, detection rules, Not block list,
     VirusTotal cache, credentials (copied server side, never shown)
   * **Imperva V2 - Import audit log from V1 (run once)**
   * optional **Imperva V2 - Last attack backfill 7 days (run once)**

## SOAR: allow the other policies

SOAR only writes to policies listed in `IMPERVA_POLICY_IDS` (`IMPERVA_CONFIG` at the top of code block
`code_1` of playbook `imperva_ioc_block`). Splunk always sends the policy ID with each request, so adding
IDs does not send blocks elsewhere; it lets Auto unblock (and *Unblock now*) remove rules from them.

1. List the policies: Auto unblock page, panel *Policies with BLOCK IP rules*, or
   `| makeresults | impervaautounblock action=policies`.
2. SOAR > Playbooks > `imperva_ioc_block` > `code_1` > `IMPERVA_CONFIG`:
   `"IMPERVA_POLICY_IDS": "2169031,<id>,<id>"` > Save (keep the playbook active).
3. Without step 2 the daily run reports `error ... not allowed on SOAR (add the policy ID to
   IMPERVA_POLICY_IDS on SOAR)` for those policies and retries the next day.

## Cut-over (after V2 is confirmed)

1. Make sure **Import data from V1** showed `credential ... copied` / `exists` for `splunk_soar`
   (and `imperva_waf` / `virustotal` if used).
2. Remove `TA-imperva-ioc-block` from `etc/shcluster/apps` (keep a backup) and push.
3. Optional: set `export = system` in V2 `metadata/default.meta` so the macros / commands work from
   the Search app again.

Rollback: remove `TA-imperva-ioc-block-v2` and push; V1 was never changed.

## Tests

```bash
python3 -m unittest discover -s tests_v2
```
UI of the card: `tests_v2/ui/run.js` (needs jquery + playwright).
