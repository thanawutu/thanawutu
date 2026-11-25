# Read-only test pack for Rapid7 VM CVE Response

`r7_app_test.py` runs, through the Splunk REST API, the searches the app's pages and buttons run,
and writes a report (errors, warnings, row counts, run times). It never saves or changes anything:
searches that would (launches, saving CVEs, fix requests, the poller, outputlookup, collect,
savedsearch ...) are refused and listed as skipped. The report holds no hostnames, IPs or result rows.

Run on a search head with an account that has the `rapid7_cve_analyst` role:

    /opt/splunk/bin/splunk cmd python3 r7_app_test.py --user <account> --out r7_app_test_report.txt

The password is asked at a prompt. `--quick` skips the search-box and drop-down pass. About 5–15 minutes.
