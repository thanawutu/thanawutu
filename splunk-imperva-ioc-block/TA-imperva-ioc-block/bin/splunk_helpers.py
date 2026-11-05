"""Shared Splunk helpers: REST, conf stanzas, storage/passwords, logging."""

import json
import logging
import logging.handlers
import os

import splunk.rest as rest

APP = "TA-imperva-ioc-block"
TRUE = ("1", "t", "true", "y", "yes")


def is_true(v):
    return str(v).strip().lower() in TRUE


def splunk_home():
    return os.environ.get("SPLUNK_HOME", "/opt/splunk")


def policy_cache_path():
    """Cache of the IP rules of every WAF policy (written by impervapolicycheck)."""
    return os.path.join(splunk_home(), "var", "run", "splunk", "ta_imperva_policies_cache.json")


def drop_policy_cache():
    """Called after a block / unblock so the next policy check reads the WAF again."""
    try:
        os.remove(policy_cache_path())
    except OSError:
        pass


def get_logger(name, filename):
    log = logging.getLogger(name)
    if not log.handlers:
        path = os.path.join(splunk_home(), "var", "log", "splunk", filename)
        h = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
    return log


def rest_json(path, session_key):
    sep = "&" if "?" in path else "?"
    _resp, content = rest.simpleRequest(path + sep + "output_mode=json&count=0",
                                        sessionKey=session_key, method="GET", raiseAllErrors=True)
    return json.loads(content)


def load_conf_stanza(session_key, conf, stanza):
    js = rest_json("/servicesNS/nobody/%s/configs/conf-%s/%s" % (APP, conf, stanza), session_key)
    return js["entry"][0]["content"]


def load_credential(session_key, realm):
    """Return (username, clear_password) of the first credential with this realm."""
    js = rest_json("/servicesNS/nobody/%s/storage/passwords" % APP, session_key)
    for e in js.get("entry", []):
        c = e.get("content", {})
        if c.get("realm") == realm:
            return c.get("username"), c.get("clear_password")
    raise RuntimeError("No credential with realm '%s' in storage/passwords "
                       "(user needs list_storage_passwords capability)" % realm)


# --------------------------------------------------------------------------- #
# KV store registry of blocks (description / threat actor / incident no.)
# --------------------------------------------------------------------------- #
REGISTRY = "imperva_block_registry"


def registry_key(site_id, ip):
    return "%s_%s" % (site_id, ip.replace("/", "_").replace(":", "-"))


def _kv_path(suffix="", collection=REGISTRY):
    return "/servicesNS/nobody/%s/storage/collections/data/%s%s" % (APP, collection, suffix)


def kv_get(session_key, key, collection=REGISTRY):
    try:
        resp, content = rest.simpleRequest(_kv_path("/" + key, collection) + "?output_mode=json",
                                           sessionKey=session_key, method="GET")
    except Exception:  # noqa: BLE001
        return None
    if int(resp.status) != 200:
        return None
    return json.loads(content)


def kv_upsert(session_key, docs, collection=REGISTRY):
    """docs: list of dicts each containing _key. Inserts or replaces."""
    if not docs:
        return
    rest.simpleRequest(_kv_path("/batch_save", collection), sessionKey=session_key, method="POST",
                       jsonargs=json.dumps(docs), raiseAllErrors=True)


def kv_list(session_key, collection):
    _resp, content = rest.simpleRequest(_kv_path("", collection) + "?output_mode=json",
                                        sessionKey=session_key, method="GET", raiseAllErrors=True)
    return json.loads(content) or []


def kv_delete(session_key, key, collection):
    rest.simpleRequest(_kv_path("/" + key, collection), sessionKey=session_key, method="DELETE",
                       raiseAllErrors=True)


def protected_networks(conf):
    """IP/CIDRs that must never be blocked: imperva.conf [settings] protected_networks."""
    import imperva_lib as il
    return il.parse_ip_list(conf.get("protected_networks", ""))


# --------------------------------------------------------------------------- #
# Option parsing for legacy (Intersplunk) commands
# --------------------------------------------------------------------------- #
def parse_options(argv, known):
    """
    Robust key=value parsing for legacy search commands.

    splunk.Intersplunk.getKeywordsAndOptions() cuts quoted values that contain
    spaces (comment="setup test from Splunk" -> "setup"). Splunk hands the
    command the words separately, so we re-join argv, honour quotes with shlex,
    and append any word that is not a known `key=` to the previous option's value.
    """
    import re
    import shlex
    raw = " ".join(argv)
    try:
        toks = shlex.split(raw)
    except ValueError:          # unbalanced quote, e.g. an apostrophe in a comment
        toks = [t.strip('"') for t in raw.split()]
    opts, last = {}, None
    for t in toks:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", t, re.S)
        if m and m.group(1) in known:
            last = m.group(1)
            opts[last] = m.group(2)
        elif last is not None:
            opts[last] = (opts[last] + " " + t).strip()
    return opts
