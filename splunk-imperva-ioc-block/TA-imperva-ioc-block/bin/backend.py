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

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        return il.run_action(self.client, self.targets, ips, action=action, dry_run=dry_run)

    def list_blocked(self):
        return il.list_targets(self.client, self.targets)

    def policy_entries(self):
        if not hasattr(self.client, "list_policies"):
            raise il.ImpervaError("checking all policies needs api_mode = v2_policy or soar")
        return il.policy_ip_entries(self.client.list_policies())


class SoarBackend(object):
    mode = "soar"

    def __init__(self, bridge, targets):
        self.bridge, self.targets = bridge, targets

    def execute(self, action, ips, dry_run, meta, user, protected=()):
        return self.bridge.execute(action, ips, self.targets, dry_run, meta, user, protected=protected)

    def list_blocked(self):
        return self.bridge.list_blocked(self.targets)

    def policy_entries(self):
        rows = self.bridge.policy_entries()
        for r in rows:
            r.pop("soar_container", None)
        return rows


def _ca_path(value):
    """soar_ca_file may be absolute or relative to the app directory (e.g. local/soar_ca.pem)."""
    import os
    value = (value or "").strip()
    if not value:
        return None
    if os.path.isabs(value):
        return value
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(app_dir, value)


def get_soar_bridge(conf, load_credential, session_key):
    """SoarBridge from imperva.conf [settings] + token in storage/passwords realm splunk_soar."""
    _user, token = load_credential(session_key, SOAR_REALM)
    return sb.SoarBridge(
        conf.get("soar_url", ""), token,
        label=conf.get("soar_label") or "imperva_ioc_block",
        verify_ssl=_true(conf.get("soar_verify_ssl", "true")),
        proxy=conf.get("soar_proxy") or None,
        timeout=int(conf.get("timeout", 30)),
        wait_seconds=int(conf.get("soar_wait_seconds", 90)),
        delete_list_containers=_true(conf.get("soar_delete_list_containers", "true")),
        ca_file=_ca_path(conf.get("soar_ca_file")))


def get_backend(conf, load_credential, session_key, override_ids=None):
    """load_credential(session_key, realm) -> (username, password)"""
    mode = (conf.get("api_mode") or "v2_policy").strip().lower()
    if mode == "soar":
        bridge = get_soar_bridge(conf, load_credential, session_key)
        targets = il.parse_ip_list(override_ids or conf.get("policy_ids", ""))
        if not targets:
            raise il.ImpervaError("No policy_ids configured in imperva.conf [settings]")
        return SoarBackend(bridge, targets)
    api_id, api_key = load_credential(session_key, IMPERVA_REALM)
    client, targets, mode = il.make_client(conf, api_id, api_key, override_ids=override_ids)
    return DirectBackend(client, targets, mode)
