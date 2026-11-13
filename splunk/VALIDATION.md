# Manual query & verification runbook – AD Account & Computer Search

Run these in **Search & Reporting** *before* building/importing the dashboard.
Replace the placeholders: `<IDX>` = Windows index (e.g. `wineventlog`), `<DOMAIN>` = SA-ldapsearch stanza
(e.g. `default`), `<USER>` = a known test account, `<HOST>` = a known computer.
Record each result in the checklist at the bottom (Pass / Fail / Notes).

Ground truth comes from a domain-joined admin host with RSAT PowerShell (`Import-Module ActiveDirectory`)
and Event Viewer on a DC.

---

## Phase 0 – Prerequisites

| # | SPL | Expected |
|---|-----|----------|
| 0.1 | `\| rest /services/apps/local splunk_server=local \| search title IN ("SA-ldapsearch","Splunk_TA_windows") \| table title version disabled` | Both apps listed, `disabled=0` |
| 0.2 | `\| ldaptestconnection domain=<DOMAIN>` | All checks *Success* |
| 0.3 | `\| tstats count where index=<IDX> by sourcetype source` | `WinEventLog:Security` or `XmlWinEventLog:Security` present |
| 0.4 | `\| tstats count where index=<IDX> by host` | All DCs appear (lockout/account events are logged **only on DCs**) |

## Phase 1 – Event-code coverage (audit policy)

```spl
index=<IDX> source="*WinEventLog:Security" earliest=-7d
  EventCode IN (4624,4625,4740,4771,4776,4720,4722,4723,4724,4725,4726,4738,4767,4728,4729,4732,4733,4756,4757,4741,4742,4743)
| stats count by EventCode host
| xyseries EventCode host count
```
**Expected:** every code that the dashboard uses has events. A missing code = audit policy gap
(`auditpol /get /category:*` on the DC) → the panel using it will always be empty.

## Phase 2 – Field-name check (CIM / TA-windows extractions)

```spl
index=<IDX> source="*WinEventLog:Security" EventCode IN (4624,4625) earliest=-24h
| head 1000
| fieldsummary
| search field IN (user, dest, src, ComputerName, Account_Name, Target_User_Name, Workstation_Name, Source_Network_Address, Logon_Type, Sub_Status, Failure_Reason)
| table field count distinct_count values
```
**Expected:** `user`, `dest`, `src`, `Logon_Type` populated. If they are missing (e.g. XML events without TA),
note the real field names – the dashboard `coalesce()` lines must be adjusted.

Check how `Account_Name` is multivalued (subject vs. target) on 4624:
```spl
index=<IDX> EventCode=4624 earliest=-1h | head 5
| table _time ComputerName Account_Name Target_User_Name user dest src Logon_Type
```
**Expected:** `user` = the account that logged on (target), not the machine account (`HOST$`).

## Phase 3 – LDAP raw output (attribute formats)

```spl
| ldapsearch domain=<DOMAIN> search="(&(objectCategory=person)(objectClass=user)(sAMAccountName=<USER>))"
    attrs="sAMAccountName,userAccountControl,lockoutTime,lastLogonTimestamp,pwdLastSet,whenCreated,memberOf,manager"
| table *
```
Verify and write down:
- **Date format** of `lastLogonTimestamp` / `pwdLastSet` (e.g. `2026-11-10T08:22:11.123456Z`). The dashboard
  parses `%Y-%m-%dT%H:%M:%S.%6NZ` and `%Y-%m-%dT%H:%M:%SZ` – if yours differ, update `strptime`.
- **userAccountControl** is decoded to text flags (`NORMAL_ACCOUNT`, `ACCOUNTDISABLE`, `DONT_EXPIRE_PASSWD`…),
  not the integer `66048`. If it is an integer, use `bitand(userAccountControl,2)` instead of `mvfind`.
- **lockoutTime** value when *not* locked (`0`, empty, or `1601-01-01T00:00:00Z`).

Then run the computed fields and confirm they are not null:
```spl
| ldapsearch domain=<DOMAIN> search="(sAMAccountName=<USER>)" attrs="lastLogonTimestamp,pwdLastSet"
| eval lastLogon_e=coalesce(strptime(lastLogonTimestamp,"%Y-%m-%dT%H:%M:%S.%6NZ"),strptime(lastLogonTimestamp,"%Y-%m-%dT%H:%M:%SZ"))
| eval DaysSinceLogon=round((now()-lastLogon_e)/86400,0)
| table lastLogonTimestamp lastLogon_e DaysSinceLogon
```

## Phase 4 – Panel-by-panel comparison with AD ground truth

| # | Dashboard panel | Verification SPL | Ground truth (PowerShell / Event Viewer) | Pass rule |
|---|---|---|---|---|
| 4.1 | Accounts count | `\| ldapsearch domain=<DOMAIN> search="(&(objectCategory=person)(objectClass=user))" attrs="sAMAccountName" \| stats count` | `(Get-ADUser -Filter *).Count` | Equal |
| 4.2 | Disabled accounts | same + `search="(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"` | `(Search-ADAccount -AccountDisabled -UsersOnly).Count` | Equal |
| 4.3 | Locked accounts | base_users query `\| where Status="Locked"` | `Search-ADAccount -LockedOut -UsersOnly` | Same names ¹ |
| 4.4 | Account row | base_users `\| search sAMAccountName=<USER>` | `Get-ADUser <USER> -Properties Department,Title,Manager,PasswordNeverExpires,PasswordLastSet,LastLogonDate,Enabled` | All columns match |
| 4.5 | Group membership | `\| ldapsearch domain=<DOMAIN> search="(sAMAccountName=<USER>)" attrs="memberOf" \| mvexpand memberOf \| stats count` | `(Get-ADUser <USER> -Properties MemberOf).MemberOf.Count` | Equal ² |
| 4.6 | Computers count | `\| ldapsearch domain=<DOMAIN> search="(objectClass=computer)" attrs="name" \| stats count` | `(Get-ADComputer -Filter *).Count` | Equal |
| 4.7 | Computer row | base_computers `\| search name=<HOST>` | `Get-ADComputer <HOST> -Properties OperatingSystem,OperatingSystemVersion,LastLogonDate,Enabled,ManagedBy` | All columns match |
| 4.8 | Domain Controllers | base_computers `\| where Role="Domain Controller"` | `Get-ADDomainController -Filter * \| select Name` | Same names |
| 4.9 | OS breakdown | base_computers `\| stats count by operatingSystem` | `Get-ADComputer -Filter * -Properties OperatingSystem \| group OperatingSystem` | Equal per OS |
| 4.10 | Stale accounts | base_users stale filter (90 d) | `Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly \| ? Enabled` | Same names ³ |
| 4.11 | Stale computers | base_computers stale filter | `Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -ComputersOnly \| ? Enabled` | Same names ³ |

¹ `lockoutTime` persists until the next successful logon/unlock; AD's `LockedOut` also considers lockout duration – small differences are expected, document them.
² `memberOf` excludes the primary group (*Domain Users*) and nested groups – `Get-ADPrincipalGroupMembership` includes the primary group, so it will be +1.
³ `lastLogonTimestamp` only replicates every 9–14 days → treat ±14 days as a tolerance, not a failure.

## Phase 5 – Controlled test events (event panels)

Generate known activity with a **dedicated test account** in a lab/approved window, then confirm Splunk sees
exactly what you generated. (These map to MITRE ATT&CK and can be reproduced later with a BAS tool for the thesis.)

| # | Action (lab) | ATT&CK | Verification SPL | Expected |
|---|---|---|---|---|
| 5.1 | Interactive logon to `<HOST>` as `<USER>` | – | `index=<IDX> EventCode=4624 user=<USER> dest=<HOST>* earliest=-15m \| table _time user dest src Logon_Type` | 1+ events, `Logon_Type=2` (or 10 RDP) |
| 5.2 | 3 wrong passwords (`runas /user:DOMAIN\<USER> cmd`) | T1110.001 | `index=<IDX> EventCode IN (4625,4771,4776) user=<USER> earliest=-15m \| stats count by EventCode host` | count = 3 (per DC/host type) |
| 5.3 | Exceed lockout threshold | T1110 | `index=<IDX> EventCode=4740 Target_User_Name=<USER> earliest=-15m` | 1 event on PDC emulator |
| 5.4 | Unlock account (ADUC) | – | `... EventCode=4767 Target_User_Name=<USER>` | 1 event |
| 5.5 | Reset password | T1098 | `... EventCode=4724 Target_User_Name=<USER>` | 1 event, `Account_Name` = admin who reset |
| 5.6 | Add `<USER>` to a test group | T1098 | `... EventCode IN (4728,4732,4756) Member_Name="*<USER>*" \| table _time Group_Name Account_Name` | Correct group & actor |
| 5.7 | Create & delete computer `TESTPC99` | T1136.002 | `... EventCode IN (4741,4743) Target_User_Name="TESTPC99*"` | Created + Deleted |
| 5.8 | Password spray: 1 wrong pwd × 5 test accounts | T1110.003 | base_auth `\| where Result="Failure" \| stats dc(user) by src` | src shows 5 distinct users |

For each test compare the Splunk count with **Event Viewer → Security** on the DC (filter by Event ID + account).
Also measure **ingest latency**: `... \| eval lag=_indextime-_time \| stats avg(lag) max(lag)` (useful for the thesis).

## Phase 6 – Token & performance checks

| # | Check | How | Expected |
|---|---|---|---|
| 6.1 | Wildcard input | Run base_users with `acct=*` and `acct=j*` | Both return; `j*` subset only |
| 6.2 | No match | `acct=doesnotexist` | 0 rows, no error |
| 6.3 | Special chars | `acct=o'brien`, `acct=svc_*` | No SPL/LDAP syntax error |
| 6.4 | LDAP size | base_users with `*` → Job Inspector | Completes < 60 s; note row count vs. AD (`sizelimit`) |
| 6.5 | Event search cost | base_auth over 7 d → Job Inspector `scanCount`, run time | Record; consider `tstats`/data model if slow |

---

## Results checklist

| Test | Result (Pass/Fail) | Splunk value | Ground-truth value | Notes |
|---|---|---|---|---|
| 0.1 – 0.4 | | | | |
| 1 (codes) | | | | missing codes: |
| 2 (fields) | | | | real field names: |
| 3 (formats) | | | | date fmt / UAC fmt: |
| 4.1 | | | | |
| 4.2 | | | | |
| 4.3 | | | | |
| 4.4 | | | | |
| 4.5 | | | | |
| 4.6 | | | | |
| 4.7 | | | | |
| 4.8 | | | | |
| 4.9 | | | | |
| 4.10 | | | | |
| 4.11 | | | | |
| 5.1 – 5.8 | | | | |
| 6.1 – 6.5 | | | | |

Once every row passes (or deviations are explained), fix the queries if needed and then build the
Dashboard Studio JSON from the **verified** SPL.

---

## Validated findings (target environment, privacy-safe checks S1–S9)

| Area | Finding | Applied in SPL |
|---|---|---|
| Add-ons | SA-ldapsearch 3.0.6, Splunk_TA_windows 8.7.0 enabled; LDAP test OK | – |
| Data | `sourcetype=WinEventLog`, `source=WinEventLog:Security` (classic, non-XML); ~48 M events/24 h | exact `source=`; auth base search is **aggregated** (`stats`) to avoid the 500k post-process cap |
| Event codes | 19/22 present in 24 h; 4720/4743/4757 absent (rare activity, same audit subcategories are logging) | – |
| `Target_User_Name`, `User` | 0 % populated | removed; use `user` (= last `Account_Name`, 100 %) |
| Machine accounts | 43 % of 4624 are `HOST$` | `NOT like(user,"%$$")` (`$$` = literal `$` in dashboards) |
| `dest` | = `ComputerName`, FQDN 99 % | `dest="<name>" OR dest="<name>.*"`, `dest_short` |
| `src` | 81 % (Source_Network_Address 100 %) | `coalesce(src,Source_Network_Address,Workstation_Name)` |
| Logon types | 2,3,4,5,7,8,9 observed | named; **8 = NetworkCleartext** highlighted |
| LDAP dates | `lastLogonTimestamp`/`pwdLastSet`/`lockoutTime` = `%Y-%m-%dT%H:%M:%S.%6NZ` (500/500 parsed); `(never)` literal | `pwdLastSet="(never)"` → "must change" |
| `whenCreated` | different format `%Y-%m-%d %H:%M:%S%:z` | separate `strptime` |
| `userAccountControl` | text flags: ACCOUNTDISABLE, DONT_EXPIRE_PASSWD, INTERDOMAIN_TRUST_ACCOUNT, NORMAL_ACCOUNT, PASSWD_NOTREQD | `mvfind`; trust accounts excluded via LDAP filter (bit 2048) |
| 47xx events | `user` = target, `src_user` = actor (100 %); 4724 `user` 85 % → fallback `mvindex(Account_Name,-1)` | – |
| 4728/4729 | `user` = member **CN** (not sAMAccountName); `Group_Name` 100 %; `Member_Name` 0 % | match on `$sel_cn$` as well as `$sel_user$` |
| 4728/4729 (S10) | `user` = member CN with spaces (89–94 %); last `Account_Name` = member **DN** (98 %); never = group or actor | CN match confirmed |
| 4732/4733 (S10–S13) | member is a **raw SID**; 3 SIDs = actor, **member (pos 1)**, **group (pos 2, 98–100 % resolve to AD groups)**; LDAP `objectSid` is text `S-1-5-…`. S14: **all sampled 4732/4733 are on member servers** (local groups); members = local/other-domain SIDs (6–7 distinct domain SIDs) ~96 %, this-domain accounts 2–4 % | match `mvindex(Security_ID,1)` = `$sel_sid$`; new **Local group changes on servers (T1098)** panel |
| 4740 | `Caller_Computer_Name` 97 % | new "Lockout sources" panel |
| DC coverage | **2 of 9 DCs send no Security logs**; 3 DC names lack "DC" | DC list from LDAP (bit 8192), new coverage panel + KPI |

Security observations to report: (1) DC logging gap, (2) enabled accounts with `PASSWD_NOTREQD`,
(3) Logon Type 8 (cleartext) present – review which services use it.
| Data models (S7) | Authentication & Change accelerated (Splunk_SA_CIM); Authentication complete 0.9993, summaries back to 2024 | logon panels use `tstats summariesonly=true` |
| Authentication DM content (S7b) | 4624 ≈ raw minus machine accounts (1.38 M vs 2.29 M); 4625 ≈ raw (112.5 k vs 113 k); **4771 / 4776 absent**; other products (sig 52xx/54xx…) also present | filter `sourcetype="WinEventLog"`; 4771/4776 kept on raw search |
| DM fields (S7c) | user unknown 0.1 %, dest unknown 0.2 %, **src unknown 29 %**, machine 0.8 %, `DOMAIN\\` or `@` in user 1.9 %, dest FQDN 93 % | strip domain from user, short dest, exclude `src=unknown` from spray |

| 4771 / 4776 (S15) | 4771: `Failure_Code` **and** `Error_Code` 100 % (codes 0x12, 0x18); 4776: `Error_Code` 100 % (0x0, 0xc0000064, 0xc000006a, 0xc0000072, 0xc0000234); `user` 100 %, `src` 98–100 % | coalesce order `Sub_Status, Failure_Code, Error_Code`; all observed codes mapped to reasons; 4776 `0x0` (success) excluded |

| SentinelOne sourcetypes (S16a) | activities, **agents** (~51 k/7 d), applications (~412 k/7 d), groups, threats (~3.7 k/7 d), mgmt | – |
| S1 applications cadence (S16a) | 429–2,552 agents/day, spiky → change feed, not full inventory | status lookup built from **agents** channel instead |
| S1 agents fields (S17a) | computerName, lastActiveDate, updatedAt, domain, agentVersion, machineType, networkStatus, infected, activeThreats, isActive, isDecommissioned, operationalState, osName, isUpToDate, appsVulnerabilityStatus, lastLoggedInUserName, siteName, groupName – all 99.5 % | backfill SPL uses these names as-is |

Pending (optional): S6 (30-day check of 4720/4743/4757), S8 (AD count match).
