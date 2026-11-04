# SOAR mode: the Search Head has no route to Imperva

```
Splunk dashboard / SPL ──HTTPS──▶ Splunk SOAR ──HTTPS──▶ Imperva Policies API v2
 impervablock / impervalist        playbook "imperva_ioc_block"
   1. POST /rest/container          3. re-validates the request
      + artifact imperva_request    4. read → merge → PUT → re-read policy
   2. polls /rest/container/{id}    5. adds artifact imperva_result
      /artifacts for the result        (rows as JSON), closes container
```
The dashboard, buttons, verification, KV store registry and audit log all work as in direct mode.
**Block descriptions stay in Splunk.** Threat actor, incident no., comment and reason go only to the KV store
registry, the audit log and the dashboard, because the WAF has no field for them. SOAR receives just
the action, the IPs, the policy IDs, dry-run and the requesting user.
**VirusTotal lookups also go through SOAR** (`vt_via = auto`), so the Search Head needs no internet
access at all. SOAR checks VirusTotal for the `vtcheck` command and returns the verdicts.
Splunk caches them for 24h, so the next dashboard load costs no VirusTotal quota.
Each block/unblock leaves a **closed container on SOAR** as an extra audit trail. The short-lived
containers created by the live list are deleted after they are read (`soar_delete_list_containers`).

## A. Splunk SOAR

1. **Network**
   - SOAR → `api.imperva.com:443` and `www.virustotal.com:443`. If they go through a proxy, set
     `IMPERVA_PROXY`. **Do not** set a global `HTTPS_PROXY` just for this: every other SOAR app would then
     use the proxy too.
   - Search Head → SOAR REST port (443, or 8443 for unprivileged on-prem installs).
2. **Label**: Administration → Event Settings → Label Settings → add `imperva_ioc_block`.
3. **Automation user** for Splunk: Administration → User Management → Users → **+ User**, type **Automation**.
   - Role: allowed to create containers and artifacts, read containers and playbook runs, and delete containers.
   - *Allowed IPs*: the Search Head IP(s).
   - Copy the user's **REST API token**. Splunk sends it as the `ph-auth-token` header.
4. **Settings**: SOAR 8.x passes the *Global Environment* variables only to apps, **not to
   playbooks**. Put the values in the **`IMPERVA_CONFIG`** dict at the top of the playbook's code block.
   Environment variables with the same names are used only as a fallback.
   The values are visible to anyone who can edit playbooks, so restrict playbook edit rights.

   | Name | Value |
   |---|---|
   | `IMPERVA_API_ID` | Imperva API ID |
   | `IMPERVA_API_KEY` | Imperva API key (secret) |
   | `IMPERVA_POLICY_IDS` | `2169031`. Allow-list: SOAR refuses any other policy |
   | `IMPERVA_PROTECTED_NETWORKS` | own egress, partner and scanner IPs (never blocked) |
   | `IMPERVA_MAX_IPS` | `50` |
   | `IMPERVA_CAID` | only if the key belongs to a parent account |
   | `VT_API_KEY` | VirusTotal API key (secret). SOAR does the VirusTotal lookups too |
   | `VT_REQUESTS_PER_MINUTE` | `4` for the public API; raise it for a premium key |
   | `VT_MAX_LOOKUPS` | `10` new lookups per request |
   | `IMPERVA_PROXY` | e.g. `http://10.12.30.100:8080`. A proxy used **only by this playbook** for Imperva and VirusTotal |

5. **Playbook**: Playbooks → **+ Playbook** → Automation.
   1. Name it `imperva_ioc_block`. Set *Operates on* to label `imperva_ioc_block`, and use Python 3.
   2. Add one **Code** block, wired `start → code → end`.
   3. **SOAR 8.x** (no Global Custom Code section in the editor). Pick the easier option:
      - **Whole file**: in *Python editor* select all (Ctrl+A) and paste
        **`imperva_ioc_block_playbook.py`**. It is the complete playbook with code_1 already filled in.
      - **Code block only**: paste **`imperva_ioc_block_code_block.py`** between `## Custom Code Start`
        and `## Custom Code End` of `code_1`. The library sits inside a raw string that is compiled with
        `exec()`, so the indentation of the pasted library lines does not matter.
   4. **Editors that have Global Custom Code**: paste `imperva_ioc_block_global_code.py` there instead,
      and put only `imperva_soar_handle(container, phantom)` in the code block.
   5. These files are generated, so don't edit them. Rebuild with `python3 soar/build_global_code.py`.
   5. Save, and set the playbook **Active**.
6. **Check it on SOAR**: in the debug output of a test run you should see
   `imperva block request ... -> ok`. If the environment variables do not reach the playbook on your
   SOAR version, add `phantom.debug(os.environ.get("IMPERVA_POLICY_IDS"))` in the code block to check.

## B. Splunk Search Head

1. Store the SOAR token. The Imperva key is **not** needed on the Search Head in this mode.
   ```bash
   curl -k -u admin https://localhost:8089/servicesNS/nobody/TA-imperva-ioc-block/storage/passwords -d name=soar -d password=<SOAR_AUTOMATION_TOKEN> -d realm=splunk_soar
   ```
2. `local/imperva.conf`:
   ```ini
   [settings]
   api_mode = soar
   soar_url = https://<soar-host>
   policy_ids = 2169031
   # soar_verify_ssl = false   (only for a self-signed SOAR cert in a lab)
   protected_networks = ...
   ```
3. Test the connection from the Search Head:
   ```bash
   curl -s -H "ph-auth-token: <SOAR_AUTOMATION_TOKEN>" "https://<soar-host>/rest/version"
   ```
4. Test in Splunk:

   | SPL | Expected |
   |---|---|
   | `\| impervalist` | IPs of policy 2169031, `backend=soar` |
   | `\| makeresults \| impervablock action=block ip="<TEST_IP>" dry_run=true` | `would_be_blocked` |
   | `\| makeresults \| impervablock action=block ip="<TEST_IP>" incident_no="TEST-001"` | `blocked`, `verified_in_waf=yes`, `soar_container=<id>` |
   | `\| makeresults \| impervablock action=unblock ip="<TEST_IP>" reason="test"` | `unblocked`, `verified_in_waf=removed` |

## Relation to `| sendalert sendtophantom` (Splunk App for SOAR Export)
`sendtophantom` already sends data from the Search Head to SOAR over the same REST API, so the network path exists.
- Use the same SOAR server as the Export app's *"Splunk - SOAR"* entry for `soar_url`. Its automation user
  token can be reused, but a dedicated one is better.
- `sendalert` is fire-and-forget. `impervablock` waits for the playbook result, so the dashboard can show
  `verified_in_waf` and save the description.

The playbook **also accepts containers created by `sendalert sendtophantom`**, or by a detection rule's
*Send to SOAR* adaptive response. Use label `imperva_ioc_block` and give the event these fields:
`imperva_action` (`block`/`unblock`), and `src` (or `ip`/`ips`/`src_ip`). Example, in the same style as your AD dashboard:
```
| makeresults
| eval imperva_action="block", src="185.220.101.47"
| sendalert sendtophantom param.phantom_server="Splunk - SOAR" param.label="imperva_ioc_block" param.severity="low" param.sensitivity="amber" param.name="Imperva IOC block from Splunk"
```
SOAR applies the same allow-list and IP checks, then writes the result into the container.
These blocks appear in the dashboard's live list as *"On WAF (blocked outside Splunk)"*, because
`sendalert` does not write the Splunk KV store registry (no description).

## Troubleshooting
| Message | Fix |
|---|---|
| `Cannot reach SOAR` | Search Head → SOAR firewall, or wrong `soar_url` / port |
| `SOAR HTTP 401` | Wrong token, or the Search Head IP is not in the automation user's *Allowed IPs* |
| `No result from SOAR within 90s` | Playbook not **Active**, wrong label, or SOAR is busy. Raise `soar_wait_seconds` |
| `SOAR playbook failed ...` | Open the container on SOAR and read the playbook debug log |
| `policy ids [...] are not allowed on SOAR` | Add the policy to `IMPERVA_POLICY_IDS` on SOAR |
| `HTTP 401 ... /policies/v2` | Imperva key in the SOAR environment variables is wrong |
| `vt_status=error`, `VT_API_KEY is not set on SOAR` | Add `VT_API_KEY` to the SOAR environment variables |
| `vt_status=rate_limited` | VirusTotal quota used up. Lower `max_lookups_per_run` or use a premium key |
