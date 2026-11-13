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
