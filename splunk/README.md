# Splunk – AD Account & Computer Search dashboard

Files (generated from one SPL source by `tools/build_dashboards.py` – edit the script, then re-run it):
- `dashboards/ad_account_computer_search.xml` – Classic / Simple XML (version 1.1, dark)
- `dashboards/ad_account_computer_search_studio.json` – Dashboard Studio definition (paste into *Source*)
- `dashboards/ad_account_computer_search_studio.xml` – Studio dashboard wrapped for *New from XML* / app deployment
- `VALIDATION.md` – manual verification runbook + validated findings

## Requirements
| Component | Purpose |
|---|---|
| **Splunk Supporting Add-on for Active Directory (SA-ldapsearch)** | `| ldapsearch` against AD (configure a domain stanza; default `default`) |
| **Splunk Add-on for Microsoft Windows (TA-windows)** | Field extractions/CIM for `WinEventLog:Security` / `XmlWinEventLog:Security` |
| DC audit policy | Logon (4624/4625/4771/4776), Account Mgmt (4720-4767, 4728-4757), Computer acct (4741-4743) |

## Install
Settings → User interface → Views → **New from XML** → paste the file, or copy it to
`$SPLUNK_HOME/etc/apps/<app>/local/data/ui/views/`.

## Inputs
- **Account** – sAMAccountName / CN / displayName / mail / UPN, wildcards allowed (`john*`)
- **Computer** – computer name or DNS host name, wildcards allowed (`WS-*`)
- **LDAP domain stanza**, **Windows event index**, **stale threshold**, **time range**

## Panels
1. KPIs – matching accounts / computers, disabled-locked, failed logons, lockouts
2. Account table (status, pwd never expires, days since logon, pwd age, OU) → click row for:
   group membership (privileged groups highlighted), computers used, logon timeline, AD change history
3. Computer table (role, OS, status, days since logon) + OS breakdown → click row for:
   accounts that logged on, computer-account change events
4. Hygiene – stale enabled accounts/computers, top failed-logon accounts (spray/brute-force indicator)

Drilldowns are cross-linked: clicking a computer in "Computers used by" fills the Computer input,
and clicking a user in a computer's logon list fills the Account input.

## Input rules
The Account / Computer text is inserted into an LDAP filter: use plain values or `*` wildcards only
(`5324340`, `53243*`, `WS-*`). **Do not type quotes, parentheses, `&`, `|` or `\`** – they cause
`ldapsearch ... invalid filter`.

## SentinelOne EDR enrichment (lookup `s1_agent_inventory.csv`)
The EDR coverage panels and the EDR columns of the computer table read a small lookup with one row per agent,
built from **`sentinelone:channel:agents`** (agent snapshots). `sentinelone:channel:applications` is *not* used for
status because it only carries software changes (validated: 429–2,552 agents/day, spiky). Fields are search-time
JSON, so `tstats` is not possible. Create the lookup in the **same app as the dashboard** (e.g. `search`).

**1. Backfill once**
```spl
index=sentinelone sourcetype="sentinelone:channel:agents" earliest=-7d
| eval agent=upper(coalesce(computerName, agentComputerName))
| eval active_e=coalesce(strptime(lastActiveDate,"%Y-%m-%dT%H:%M:%S.%6NZ"), strptime(lastActiveDate,"%Y-%m-%dT%H:%M:%S.%3NZ"), strptime(lastActiveDate,"%Y-%m-%dT%H:%M:%SZ"), _time)
| stats max(active_e) AS LastSeen latest(domain) AS EDR_Domain latest(agentVersion) AS EDR_Version
        latest(machineType) AS EDR_MachineType latest(networkStatus) AS EDR_Network latest(infected) AS EDR_Infected
        latest(activeThreats) AS EDR_ActiveThreats latest(isActive) AS EDR_Active latest(isDecommissioned) AS EDR_Decommissioned
        latest(operationalState) AS EDR_OpState latest(osName) AS EDR_OsName latest(isUpToDate) AS EDR_UpToDate
        latest(appsVulnerabilityStatus) AS EDR_AppsVuln latest(lastLoggedInUserName) AS EDR_LastUser
        latest(siteName) AS EDR_Site latest(groupName) AS EDR_Group by agent
| where isnotnull(agent)
| outputlookup s1_agent_inventory.csv
```

**2. Schedule the daily update** – *Save As → Report* `S1 agent inventory – lookup`, *Edit Schedule*: daily
(e.g. 02:17), time range *Last 24 hours*. Same SPL without `earliest=-7d`, and replace the last line with:
```spl
| inputlookup append=true s1_agent_inventory.csv
| sort 0 -LastSeen | dedup agent
| where LastSeen > relative_time(now(), "-90d")
| outputlookup s1_agent_inventory.csv
```
EDR status in the dashboard: **Installed** (agent active ≤ 7 d), **Stale (>7d)**, **Decommissioned**, **Missing**
(no agent with that computer name). Coverage counts only *enabled* computers that logged on within the stale
threshold. The software drill-down and the fleet risky-apps panel query `sentinelone:channel:applications` directly.
