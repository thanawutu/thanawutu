#!/usr/bin/env python3
"""A stand-in for the Group-IB TI API v2, used to test gib_ioc.py offline.

It implements the parts of the contract the client depends on -- Basic auth,
granted collections, the sequence_list cursor and a paged /updated feed -- with
synthetic records. It is a test fixture, not an emulator: it proves the client's
auth header, pagination, error handling and normalization are correct, it does
not prove the live schema.

    ./mock_server.py --port 877
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MOCK_USERNAME = "analyst@example.com"
MOCK_API_KEY = "mock-api-key-0123456789"

GRANTED_COLLECTIONS = [
    {"name": "ioc/common", "actions": ["read", "search"]},
    {"name": "malware/cnc", "actions": ["read", "search"]},
    {"name": "attacks/phishing_group", "actions": ["read"]},
    {"name": "osi/vulnerability", "actions": ["read"]},
]

START_SEQ = 17000000000000

# 25 synthetic IOC records, cycling through the indicator shapes the client
# normalizes, so pagination has something to walk.
def _build_records(count: int = 25) -> list[dict]:
    records = []
    for index in range(count):
        seq = START_SEQ + (index + 1) * 100
        flavour = index % 4
        record = {
            "id": f"mock-ioc-{index:04d}",
            "seqUpdate": seq,
            "dateFirstSeen": "2026-07-01T00:00:00+00:00",
            "dateLastSeen": "2026-07-30T00:00:00+00:00",
            "threatActor": {"name": f"MockActor-{index % 3}"},
        }
        if flavour == 0:
            record["indicators"] = [
                {"type": "domain", "params": {"domain": f"evil-{index}.example.net"}},
                {"type": "ip", "params": {"ipv4": f"198.51.100.{index % 254 + 1}"}},
            ]
        elif flavour == 1:
            record["indicators"] = [
                {
                    "type": "hash",
                    "params": {"hashes": {"md5": f"{index:032x}", "sha256": f"{index:064x}"}},
                }
            ]
        elif flavour == 2:
            record["indicators"] = [
                {"type": "url", "value": f"http://malicious-{index}.example.org/payload"}
            ]
        else:
            record["url"] = f"http://cnc-{index}.example.com/gate.php"
            record["ipv4"] = f"203.0.113.{index % 254 + 1}"
        records.append(record)
    return records


RECORDS = _build_records()


class MockHandler(BaseHTTPRequestHandler):
    server_version = "MockGroupIB/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep test output readable
        if self.server.verbose:
            super().log_message(fmt, *args)

    # -- helpers -----------------------------------------------------------

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode()
        except Exception:
            return False
        username, _, api_key = decoded.partition(":")
        return username == MOCK_USERNAME and api_key == MOCK_API_KEY

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if not self._authorized():
            self._send_json(
                {"error": "Unauthorized", "message": "bad username or API key"}, status=401
            )
            return

        if path == "/api/v2/user/granted_collections":
            self._send_json({"count": len(GRANTED_COLLECTIONS), "items": GRANTED_COLLECTIONS})
            return

        match = re.fullmatch(r"/api/v2/sequence_list/update/(.+)", path)
        if match:
            self._route_sequence(match.group(1))
            return

        match = re.fullmatch(r"/api/v2/(.+)/updated", path)
        if match:
            self._route_updated(match.group(1), params)
            return

        self._send_json({"error": "Not Found", "path": path}, status=404)

    def _granted(self, collection: str) -> bool:
        return collection in {entry["name"] for entry in GRANTED_COLLECTIONS}

    def _route_sequence(self, collection: str) -> None:
        if not self._granted(collection):
            self._send_json(
                {"error": "Forbidden", "message": f"no grant for {collection}"}, status=403
            )
            return
        self._send_json({"seqUpdate": START_SEQ})

    def _route_updated(self, collection: str, params: dict) -> None:
        if not self._granted(collection):
            self._send_json(
                {"error": "Forbidden", "message": f"no grant for {collection}"}, status=403
            )
            return

        limit = self._int_param(params, "limit", 100)
        seq_update = self._int_param(params, "seqUpdate", 0)

        # The real feed returns records strictly after the cursor, ordered by
        # seqUpdate, and echoes the last seqUpdate of the page as the next cursor.
        pending = [record for record in RECORDS if record["seqUpdate"] > seq_update]
        page = pending[:limit]
        next_seq = page[-1]["seqUpdate"] if page else seq_update

        self._send_json({"count": len(pending), "seqUpdate": next_seq, "items": page})

    @staticmethod
    def _int_param(params: dict, name: str, default: int) -> int:
        values = params.get(name)
        if not values:
            return default
        try:
            return int(values[0])
        except (TypeError, ValueError):
            return default


def serve(port: int = 0, verbose: bool = False) -> ThreadingHTTPServer:
    """Start the mock in a daemon thread and return the bound server."""
    server = ThreadingHTTPServer(("127.0.0.1", port), MockHandler)
    server.verbose = verbose
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock Group-IB TI API v2 server.")
    parser.add_argument("--port", type=int, default=877)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    server = serve(args.port, args.verbose)
    host, port = server.server_address
    print(f"Mock Group-IB TI API on http://{host}:{port}/api/v2")
    print(f"  GIB_USERNAME={MOCK_USERNAME}")
    print(f"  GIB_API_KEY={MOCK_API_KEY}")
    print("Ctrl-C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
