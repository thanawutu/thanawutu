"""
Backend selection for the Splunk commands.

  api_mode = v2_policy | v1_site -> DirectBackend : Search Head calls Imperva itself
  api_mode = soar                -> SoarBackend   : Search Head asks Splunk SOAR,
                                                   SOAR's playbook calls Imperva

Both expose the same two methods and return the same row format, so the
commands, KV store registry, audit log and dashboard do not care which is used.
"""

import imperva_lib as il
import soar_bridge as sb

IMPERVA_REALM = "imperva_waf"
SOAR_REALM = "splunk_soar"


def _true(v):
    return str(v).strip().lower() in ("1", "t", "true", "y", "yes")


class DirectBackend(object):
    def __init__(self, client, targets, mode):
        self.client, self.targets, self.mode = client, targets, mode

    def execute(self, action, ips, dry_run, meta, user):
        return il.run_action(self.client, self.targets, ips, action=action, dry_run=dry_run)

    def list_blocked(self):
        return il.list_targets(self.client, self.targets)


class SoarBackend(object):
    mode = "soar"

    def __init__(self, bridge, targets):
        self.bridge, self.targets = bridge, targets

    def execute(self, action, ips, dry_run, meta, user):
        return self.bridge.execute(action, ips, self.targets, dry_run, meta, user)

    def list_blocked(self):
        return self.bridge.list_blocked(self.targets)


def get_backend(conf, load_credential, session_key, override_ids=None):
    """load_credential(session_key, realm) -> (username, password)"""
    mode = (conf.get("api_mode") or "v2_policy").strip().lower()
    if mode == "soar":
        _user, token = load_credential(session_key, SOAR_REALM)
        bridge = sb.SoarBridge(
            conf.get("soar_url", ""), token,
            label=conf.get("soar_label") or "imperva_ioc_block",
            verify_ssl=_true(conf.get("soar_verify_ssl", "true")),
            proxy=conf.get("soar_proxy") or None,
            timeout=int(conf.get("timeout", 30)),
            wait_seconds=int(conf.get("soar_wait_seconds", 90)),
            delete_list_containers=_true(conf.get("soar_delete_list_containers", "true")))
        targets = il.parse_ip_list(override_ids or conf.get("policy_ids", ""))
        if not targets:
            raise il.ImpervaError("No policy_ids configured in imperva.conf [settings]")
        return SoarBackend(bridge, targets)
    api_id, api_key = load_credential(session_key, IMPERVA_REALM)
    client, targets, mode = il.make_client(conf, api_id, api_key, override_ids=override_ids)
    return DirectBackend(client, targets, mode)
