# Rapid7 VM CVE Response (Splunk app 1.1.2)

CVE impact, software and OS inventory, rescans launched from Splunk with
before/after results, saved CVEs and CMDB changes, for Rapid7 InsightVM.

It is a companion to your existing Rapid7 collector app (v1.0, sites / assets /
scans). It does not change or replace it, and it reads the same `index=rapid7`
and the CMDB lookups used by the "CMDB and Rapid7 Asset Mapping" dashboard.

## What is inside

| Part | Name | Runs on |
|---|---|---|
| Collector | `rapid7_software://` daily: software and OS per asset, plus the asset's site and last scan (`rapid7:vm:software`, `rapid7:vm:asset_site`) | Heavy forwarder |
| Collector | `rapid7_vuln_content://` every 6 h: new and updated Rapid7 checks (`rapid7:vm:vuln_content`) | Heavy forwarder |
| Collector | `rapid7_asset_vulns://` daily: one event per asset with its vulnerability IDs (`rapid7:vm:asset_vuln`) | Heavy forwarder |
| Commands | `r7cve`, `r7rescan`, `r7cvewatch`, `r7scanstatus`, `r7vercheck`, `r7scanpoll` | Search head |
| Scheduled searches | scan job poller (every minute), CMDB change tracker and snapshot (hourly), saved CVE refresh (4-hourly), CMDB history backfill (run once) | Search head |
| Dashboards | CVE impact overview, CVE response, Software & OS inventory, Scan jobs & reports, CMDB changes, Saved CVEs | Search head |
| KV store | `r7_saved_cves`, `r7_scan_jobs`, `r7_cmdb_changes`, `r7_cmdb_prev` | Search head |
| Roles | `rapid7_cve_analyst` (use the app, save CVEs), `rapid7_cve_rescan` (also launch rescans) | Search head |

Every collector run writes a `run_id` on its events and a summary event
`sourcetype=rapid7:vm:run`, so it appears in your "Data sources and freshness" panel.

## How a rescan works

1. A user clicks **Run rescan** (or types `| r7rescan ... dryrun=false`).
   The command checks the `rapid7_cve_rescan` capability and the 50-server
   limit, saves a snapshot of each server (version, Rapid7 finding) and records
   the job as **Requested**. Users never need the Rapid7 password.
2. The poller (scheduled search, every minute, on the search head) starts one
   Rapid7 scan per site with the scan account → **Running**.
3. It checks `GET /api/3/scans/{id}` every minute until every scan is
   finished, stopped or failed → **Collecting**.
4. It re-reads each server's software and the CVE's findings and compares them
   with the snapshot → **Finished**, with per server: software still installed?,
   version change, CVE before/after and the result (CVE fixed, Still vulnerable,
   Newly found, Not vulnerable, Not verified, No Rapid7 check yet).
   "CVE fixed" needs the server to be assessed by this job's scan **and** the
   scan to return software data (login worked); otherwise "Not verified".
5. Results are kept in the KV store and written to the index
   (`rapid7:vm:scan_job`, `rapid7:vm:scan_result`).

A repeated `request_id` never launches twice, and reloading a dashboard never
re-runs a launch.

## Install

### Before you start

1. **Share the CMDB lookups with all apps.** Settings → Lookups → Lookup table
   files: set `cmdb_assets.csv`, `cmdb_ip_map.csv`, `asset_context.csv` and
   `rapid7_host_context.csv` to **Global** (Permissions → All apps).
2. **Firewall:** the search head must reach the Rapid7 console API (usually
   tcp/3780). The forwarder already does.
3. **Rapid7 accounts:** the read-only collector account you already use, and an
   account for rescans with permission to start scans on the relevant sites
   (can be the same account if you accept that).

### 1. Heavy forwarder (SIEMFWDPR01): collectors

1. Apps → Manage apps → Install app from file → `rapid7_vm_cve-1.1.2.tgz`.
2. Create `$SPLUNK_HOME/etc/apps/rapid7_vm_cve/local/rapid7_cve.conf`:
   ```
   [settings]
   console_url = https://<rapid7-console>:3780
   verify_ssl = true
   ca_bundle = /path/to/rapid7-ca.pem
   collector_username = <collector account>
   index = rapid7
   ```
3. Store the password (encrypted by Splunk) in this app:
   ```
   curl -k -u admin https://localhost:8089/servicesNS/nobody/rapid7_vm_cve/storage/passwords \
        -d realm=rapid7_vm_cve -d name=<collector account> -d password='<password>'
   ```
4. Enable the inputs in `local/inputs.conf` (start with software and
   vuln_content; add asset_vulns once those work):
   ```
   [rapid7_software://daily]
   disabled = 0

   [rapid7_vuln_content://every_6h]
   disabled = 0

   [rapid7_asset_vulns://daily]
   disabled = 0
   ```
   Keep your v1.0 `asset_vulns` collector disabled; this app has its own.
5. Restart Splunk on the forwarder. Leave the scheduled searches disabled here.

### 2. Search head: dashboards, commands, rescans

1. Install the same package.
2. `local/rapid7_cve.conf`:
   ```
   [settings]
   console_url = https://<rapid7-console>:3780
   verify_ssl = true
   ca_bundle = /path/to/rapid7-ca.pem
   scan_username = <scan account>
   index = rapid7
   # optional: scan_template_id = full-audit-without-web-spider
   ```
3. Store the scan account password the same way as above (on the search head).
   In a search head cluster, store it on one member; it replicates.
4. Settings → Searches, reports, and alerts (app Rapid7 VM CVE Response):
   enable **Rapid7 CVE - scan job poller** and **Rapid7 CVE - saved CVE
   refresh**. The CMDB change tracker and snapshot are enabled by default.
   Optionally run **Rapid7 CVE - CMDB history backfill (run once)** once.
5. Give users roles: `rapid7_cve_analyst` to use the app, `rapid7_cve_rescan`
   to launch rescans.

## Test plan

Run these in Search (app Rapid7 VM CVE Response), in order.

1. Collectors ran (after the first run on the forwarder):
   ```
   index=rapid7 sourcetype=rapid7:vm:run collector IN (software, vuln_content, asset_vulns)
   | table _time collector status events api_calls duration_s error
   ```
2. Version logic:
   ```
   | makeresults count=3 | streamstats count | eval version=case(count=1,"8.1.27",count=2,"8.1.34",count=3,"2.4.6-99.el7")
   | r7vercheck ranges="8.1 < 8.1.34 ; < 2.4.63"
   ```
   Expect In range, Not in range, Check advisory.
3. Software query, no CVE needed: `| r7cve software="OpenSSH" ranges="< 9.8"`
4. Save a CVE and query it:
   ```
   | r7cvewatch action=add cve=CVE-2026-XXXXX announced=2026-11-18 software="PHP" ranges="8.1 < 8.1.34 ; 8.2 < 8.2.29"
   | r7cve cve=CVE-2026-XXXXX env="Non-prod"
   ```
5. Rescan **one non-prod server** first:
   ```
   | r7rescan cve=CVE-2026-XXXXX hosts="<one UAT hostname>" dryrun=true detail=true
   | r7rescan cve=CVE-2026-XXXXX hosts="<one UAT hostname>" dryrun=false
   | r7scanstatus
   | r7scanstatus job=<job id>
   ```
   Within a minute the job moves to Running; the Rapid7 console shows a scan
   named "Splunk JOB-... CVE-...". When it finishes, `r7scanstatus job=...`
   shows the before/after report.
6. Dashboards: open each page from the app menu.

## Settings

All in `local/rapid7_cve.conf` `[settings]` (see `default/rapid7_cve.conf`):
`max_servers_per_job` (50), `stale_days` (7), `max_job_hours` (12),
`scan_template_id` (empty = site default), `threads` (4), `page_size` (500),
`vuln_content_first_days` (30), `vuln_content_overlap_days` (2).

Environment labels come from the macro `r7_env_label`: Prod · DC = `cmdb_class`
PROD, Prod · DR = DR, Non-prod · UAT / SIT / DEV = NONPROD split by `cmdb_env`.
Edit the macro if your `cmdb_env` values differ.

## Known limits in 1.1.2

- Not yet run against your Rapid7 console or Splunk. Logic is covered by unit
  and end-to-end tests with simulated Rapid7 and splunkd.
- Version history and software data start when the software collector is
  enabled (the Rapid7 API only returns current software).
- The vulnerability content collector reads 30 days on its first run. Older
  checks are not found by `r7cve` until they are modified again.
- The CMDB history backfill covers `ServerStatus` only; environment history
  needs the `cmdb_class` rules of your "CMDB servers" report.
- Server selection on the dashboards uses a multi-select list, not tick boxes
  in the table as in the mockup.
- AppInspect: 0 errors; 2 Splunk Cloud / Splunk 10 rules (`python.required`)
  not set, which do not affect Splunk Enterprise 9.x.
