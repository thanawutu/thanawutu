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
The EDR coverage panels and the EDR columns of the computer table read a small lookup with one row per
agent (fields extracted from `sentinelone:channel:applications` are search-time JSON, so `tstats` is not
possible and a raw 4,000-host join on every load would be slow). Create it in the **same app as the dashboard**
(e.g. `search`).

**1. Backfill once** (Search & Reporting, time range is in the query):
```spl
index=sentinelone sourcetype="sentinelone:channel:applications" earliest=-30d
| eval agent=upper(agentComputerName)
| stats latest(_time) AS LastSeen latest(agentDomain) AS EDR_Domain latest(agentVersion) AS EDR_Version
        latest(agentMachineType) AS EDR_MachineType latest(agentNetworkStatus) AS EDR_Network
        latest(agentInfected) AS EDR_Infected latest(agentIsActive) AS EDR_Active
        latest(agentIsDecommissioned) AS EDR_Decommissioned latest(agentOperationalState) AS EDR_OpState
        latest(agentOsType) AS EDR_OsType by agent
| outputlookup s1_agent_inventory.csv
```

**2. Schedule the daily update** – *Save As → Report*, name `S1 agent inventory – lookup`, then
*Edit Schedule*: daily (e.g. 02:17), time range *Last 2 days*:
```spl
index=sentinelone sourcetype="sentinelone:channel:applications"
| eval agent=upper(agentComputerName)
| stats latest(_time) AS LastSeen latest(agentDomain) AS EDR_Domain latest(agentVersion) AS EDR_Version
        latest(agentMachineType) AS EDR_MachineType latest(agentNetworkStatus) AS EDR_Network
        latest(agentInfected) AS EDR_Infected latest(agentIsActive) AS EDR_Active
        latest(agentIsDecommissioned) AS EDR_Decommissioned latest(agentOperationalState) AS EDR_OpState
        latest(agentOsType) AS EDR_OsType by agent
| inputlookup append=true s1_agent_inventory.csv
| sort 0 -LastSeen | dedup agent
| where LastSeen > relative_time(now(), "-90d")
| outputlookup s1_agent_inventory.csv
```
EDR status in the dashboard: **Installed** (seen ≤ 7 d), **Stale (>7d)**, **Decommissioned**, **Missing** (no agent
with that computer name). Coverage counts only *enabled* computers that logged on within the stale threshold.
The software drill-down and the fleet risky-apps panel query the raw index directly.
