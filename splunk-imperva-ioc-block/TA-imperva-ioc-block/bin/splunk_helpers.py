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
