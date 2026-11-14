"""Shared Splunk helpers: REST, conf stanzas, storage/passwords, logging."""

import json
import logging
import logging.handlers
import os

import splunk.rest as rest

# V2: the app name comes from the folder (TA-imperva-ioc-block-v2), so V2 keeps its own KV store,
# settings and credentials and never touches V1 (TA-imperva-ioc-block) while both are installed.
APP = os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V1_APP = "TA-imperva-ioc-block"
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
    # V2 writes its own log files (v2_imperva_ioc_block.log, ...) next to V1's
    if APP != V1_APP and not filename.startswith("v2_"):
        filename = "v2_" + filename
        name = "v2_" + name
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
    """Return (username, clear_password) of the first credential with this realm.
    V2: looked up in this app first, then in V1 (TA-imperva-ioc-block) until the credentials are
    copied with | impervav1import action=credentials (needed before V1 is removed)."""
    for app in [APP] + ([V1_APP] if APP != V1_APP else []):
        try:
            js = rest_json("/servicesNS/nobody/%s/storage/passwords" % app, session_key)
        except Exception:  # noqa: BLE001 - e.g. V1 already removed
            continue
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


KV_BATCH = 500     # limits.conf [kvstore] max_documents_per_batch_save = 1000 by default


def kv_upsert(session_key, docs, collection=REGISTRY):
    """docs: list of dicts each containing _key. Inserts or replaces, KV_BATCH documents per request
    (one batch_save of more than 1000 documents fails: "Request exceeds API limits")."""
    docs = list(docs or [])
    for k in range(0, len(docs), KV_BATCH):
        rest.simpleRequest(_kv_path("/batch_save", collection), sessionKey=session_key, method="POST",
                           jsonargs=json.dumps(docs[k:k + KV_BATCH]), raiseAllErrors=True)


def kv_list(session_key, collection):
    _resp, content = rest.simpleRequest(_kv_path("", collection) + "?output_mode=json",
                                        sessionKey=session_key, method="GET", raiseAllErrors=True)
    return json.loads(content) or []


def kv_query(session_key, collection, query):
    """Documents of `collection` matching a KV store query dict, e.g. {"_key": {"$in": [...]}}."""
    import urllib.parse
    q = urllib.parse.urlencode({"query": json.dumps(query), "output_mode": "json"})
    _resp, content = rest.simpleRequest(_kv_path("?" + q, collection), sessionKey=session_key,
                                        method="GET", raiseAllErrors=True)
    return json.loads(content) or []


# Cache shared by every search head of the cluster (KV store collection imperva_cache):
#   vt_<ip>   VirusTotal result of one IP          {ts, data: json}
#   policies  IP rules of every WAF policy          {ts, data: json}
CACHE = "imperva_cache"


def cache_key_ip(ip):
    return "vt_" + ip.replace(":", "-").replace("/", "_")


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
