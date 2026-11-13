# Splunk – AD Account & Computer Search dashboard

File: `dashboards/ad_account_computer_search.xml` (Simple XML, version 1.1, dark theme)

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
