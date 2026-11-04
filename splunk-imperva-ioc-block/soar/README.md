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
Each block/unblock leaves a **closed container on SOAR** as an extra audit trail. The short-lived
containers created by the live list are deleted after they are read (`soar_delete_list_containers`).

## A. Splunk SOAR

1. **Network**
   - SOAR → `api.imperva.com:443`. If SOAR uses a proxy, set `HTTPS_PROXY` in its environment.
   - Search Head → SOAR REST port (443, or 8443 for unprivileged on-prem installs).
2. **Label**: Administration → Event Settings → Label Settings → add `imperva_ioc_block`.
3. **Automation user** for Splunk: Administration → User Management → Users → **+ User**, type **Automation**.
   - Role: allowed to create containers and artifacts, read containers and playbook runs, and delete containers.
   - *Allowed IPs*: the Search Head IP(s).
   - Copy the user's **REST API token**. Splunk sends it as the `ph-auth-token` header.
4. **Environment variables**: Administration → Administration Settings → Environment Variables.
   Tick *secret* for the keys.

   | Name | Value |
   |---|---|
   | `IMPERVA_API_ID` | Imperva API ID |
   | `IMPERVA_API_KEY` | Imperva API key (secret) |
   | `IMPERVA_POLICY_IDS` | `2169031`. Allow-list: SOAR refuses any other policy |
   | `IMPERVA_PROTECTED_NETWORKS` | own egress, partner and scanner IPs (never blocked) |
   | `IMPERVA_MAX_IPS` | `50` |
   | `IMPERVA_CAID` | only if the key belongs to a parent account |

5. **Playbook**: Playbooks → **+ Playbook** → Automation.
   1. Name it `imperva_ioc_block`. Set *Operates on* to label `imperva_ioc_block`, and use Python 3.
   2. Open **Global Custom Code** and paste the whole of `imperva_ioc_block_global_code.py`.
      This file is generated, so don't edit it. Rebuild it with `python3 soar/build_global_code.py`.
   3. Add one **Code** block, wired `start → code → end`.
   4. In its custom code section, add this one line:
      ```python
      imperva_soar_handle(container, phantom)
      ```
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

## Troubleshooting
| Message | Fix |
|---|---|
| `Cannot reach SOAR` | Search Head → SOAR firewall, or wrong `soar_url` / port |
| `SOAR HTTP 401` | Wrong token, or the Search Head IP is not in the automation user's *Allowed IPs* |
| `No result from SOAR within 90s` | Playbook not **Active**, wrong label, or SOAR is busy. Raise `soar_wait_seconds` |
| `SOAR playbook failed ...` | Open the container on SOAR and read the playbook debug log |
| `policy ids [...] are not allowed on SOAR` | Add the policy to `IMPERVA_POLICY_IDS` on SOAR |
| `HTTP 401 ... /policies/v2` | Imperva key in the SOAR environment variables is wrong |
