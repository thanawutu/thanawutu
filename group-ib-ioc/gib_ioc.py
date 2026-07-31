#!/usr/bin/env python3
"""Test client for the Group-IB Threat Intelligence API (v2) IOC endpoints.

Standard library only -- no pip install required. Point it at the real API or
at the bundled mock server (mock_server.py) to exercise the request path
without live egress.

Credentials come from the environment by default:

    GIB_USERNAME   account e-mail used to log into the TI portal
    GIB_API_KEY    API key generated in the portal profile page
    GIB_BASE_URL   override the API base (default https://tap.group-ib.com/api/v2)

Usage:

    ./gib_ioc.py preflight                    # auth check + granted collections
    ./gib_ioc.py collections                  # list collections this key can read
    ./gib_ioc.py seq -c ioc/common            # starting seqUpdate for a collection
    ./gib_ioc.py fetch -c ioc/common -l 10    # pull one page of IOCs
    ./gib_ioc.py fetch -c ioc/common --pages 3 --normalize
    ./gib_ioc.py fetch -c ioc/common --date-from 2026-07-01 --date-to 2026-07-31
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://tap.group-ib.com/api/v2"
DEFAULT_COLLECTION = "ioc/common"
USER_AGENT = "gib-ioc-test/1.0 (+stdlib-urllib)"

# Collections that carry indicators of compromise. The API rejects a collection
# the key has no grant for, so `collections` is the authoritative list at runtime.
IOC_COLLECTIONS = (
    "ioc/common",
    "malware/cnc",
    "attacks/phishing_group",
    "attacks/phishing_kit",
    "attacks/ddos",
    "apt/threat",
    "hi/threat",
)


class GibError(RuntimeError):
    """An API call failed in a way the caller should see verbatim."""

    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class GibClient:
    """Minimal Group-IB TI API v2 client.

    Auth is HTTP Basic with the portal login as the username and the API key as
    the password. The header is sent pre-emptively -- the API answers 401 without
    a WWW-Authenticate challenge that urllib could react to.
    """

    def __init__(
        self,
        username: str,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        retries: int = 3,
        verbose: bool = False,
    ):
        if not username or not api_key:
            raise GibError(
                "missing credentials: set GIB_USERNAME and GIB_API_KEY "
                "(or pass --username/--api-key)"
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        token = base64.b64encode(f"{username}:{api_key}".encode()).decode()
        self._auth_header = f"Basic {token}"
        # Honours SSL_CERT_FILE / SSL_CERT_DIR, so a corporate or proxy CA bundle
        # is picked up without disabling verification.
        self._ssl_context = ssl.create_default_context()
        # urllib reads HTTPS_PROXY from the environment on its own.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(),
            urllib.request.HTTPSHandler(context=self._ssl_context),
        )

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"  [http] {message}", file=sys.stderr)

    def get(self, path: str, params: dict | None = None) -> dict:
        """GET a JSON endpoint, retrying throttles and transient server errors."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        query = {k: v for k, v in (params or {}).items() if v is not None}
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        last_error: GibError | None = None
        for attempt in range(1, self.retries + 1):
            request = urllib.request.Request(url, method="GET")
            request.add_header("Authorization", self._auth_header)
            request.add_header("Accept", "application/json")
            request.add_header("User-Agent", USER_AGENT)

            started = time.monotonic()
            try:
                self._log(f"GET {url} (attempt {attempt}/{self.retries})")
                with self._opener.open(request, timeout=self.timeout) as response:
                    payload = response.read()
                    elapsed = time.monotonic() - started
                    self._log(f"{response.status} in {elapsed:.2f}s, {len(payload)} bytes")
                    return self._decode(payload)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")[:2000]
                error = GibError(
                    f"HTTP {exc.code} {exc.reason} for {url}", status=exc.code, body=body
                )
                # 401/403 are credential or grant problems -- retrying cannot help.
                if exc.code in (429,) or 500 <= exc.code < 600:
                    last_error = error
                    delay = self._retry_delay(exc, attempt)
                    if attempt < self.retries:
                        self._log(f"retryable {exc.code}, sleeping {delay:.1f}s")
                        time.sleep(delay)
                        continue
                raise error
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                error = GibError(f"connection failed for {url}: {reason}")
                last_error = error
                if attempt < self.retries:
                    delay = 2.0 ** (attempt - 1)
                    self._log(f"connection error, sleeping {delay:.1f}s")
                    time.sleep(delay)
                    continue
                raise error

        raise last_error or GibError(f"request to {url} failed")

    @staticmethod
    def _retry_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
        return 2.0 ** (attempt - 1)

    @staticmethod
    def _decode(payload: bytes) -> dict:
        text = payload.decode("utf-8", "replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise GibError(f"response was not JSON: {exc}; first 500 bytes: {text[:500]}")

    # -- endpoints ---------------------------------------------------------

    def granted_collections(self) -> dict:
        """Collections and actions this API key is entitled to."""
        return self.get("user/granted_collections")

    def sequence_start(self, collection: str) -> dict:
        """Starting seqUpdate cursor for a collection.

        Without arguments the API returns the cursor for *now*; pass a date to
        rewind the feed to that point.
        """
        return self.get(f"sequence_list/update/{collection}")

    def updated(
        self,
        collection: str,
        seq_update: int | None = None,
        limit: int = 100,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> dict:
        """One page of the incremental feed for a collection."""
        return self.get(
            f"{collection}/updated",
            {
                "seqUpdate": seq_update,
                "limit": limit,
                "df": date_from,
                "dt": date_to,
            },
        )

    def iter_updated(
        self,
        collection: str,
        seq_update: int | None = None,
        limit: int = 100,
        max_pages: int = 1,
        date_from: str | None = None,
        date_to: str | None = None,
    ):
        """Walk the feed page by page, following the seqUpdate cursor.

        Yields (page_number, payload). Stops early when a page comes back empty
        or the cursor stops advancing, so it cannot spin on a stalled feed.
        """
        cursor = seq_update
        for page in range(1, max_pages + 1):
            payload = self.updated(
                collection,
                seq_update=cursor,
                limit=limit,
                # A date window applies to the first request only; afterwards the
                # cursor carries the position.
                date_from=date_from if page == 1 else None,
                date_to=date_to if page == 1 else None,
            )
            yield page, payload

            items = extract_items(payload)
            next_cursor = payload.get("seqUpdate") if isinstance(payload, dict) else None
            if not items:
                break
            # A short page is the tail of the feed; requesting again just to see
            # an empty page wastes a round trip against the rate limit.
            if len(items) < limit:
                break
            if next_cursor is None or next_cursor == cursor:
                break
            cursor = next_cursor


def extract_items(payload) -> list:
    """Pull the record list out of a feed page.

    The v2 feed nests records under "items"; some collections/proxies return a
    bare list or use "data". Accept all three rather than guessing one.
    """
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("items", "data", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def normalize_iocs(item: dict) -> list[dict]:
    """Best-effort flattening of one record into {type, value, source} rows.

    Group-IB schemas differ per collection, so this walks the shapes seen in the
    IOC collections and falls back to well-known scalar field names. It is a
    convenience view -- use --raw when you need the untouched record.
    """
    rows: list[dict] = []
    record_id = item.get("id") or item.get("_id")

    def add(ioc_type: str, value, source: str) -> None:
        if isinstance(value, (list, tuple, set)):
            for entry in value:
                add(ioc_type, entry, source)
            return
        if isinstance(value, str) and value.strip():
            rows.append(
                {"id": record_id, "type": ioc_type, "value": value.strip(), "source": source}
            )

    # Shape A: an "indicators" list of typed objects.
    for indicator in item.get("indicators") or []:
        if not isinstance(indicator, dict):
            continue
        ioc_type = indicator.get("type") or "unknown"
        params = indicator.get("params")
        params = params if isinstance(params, dict) else {}
        hashes = params.get("hashes")
        hashes = hashes if isinstance(hashes, dict) else {}
        value = (
            indicator.get("value")
            or indicator.get("url")
            or indicator.get("domain")
            or indicator.get("ip")
            or params.get("ipv4")
            or params.get("domain")
            or params.get("url")
            or hashes.get("sha256")
            or hashes.get("sha1")
            or hashes.get("md5")
        )
        add(ioc_type, value, "indicators")

    # Shape B: typed scalar/array fields hanging off the record itself.
    field_types = {
        "url": "url",
        "urls": "url",
        "domain": "domain",
        "domains": "domain",
        "ip": "ip",
        "ips": "ip",
        "ipv4": "ip",
        "md5": "hash-md5",
        "sha1": "hash-sha1",
        "sha256": "hash-sha256",
        "cnc": "cnc",
        "cncUrl": "url",
    }
    for field, ioc_type in field_types.items():
        if field in item:
            value = item[field]
            if isinstance(value, dict):
                value = value.get("value") or value.get("ip") or value.get("url")
            add(ioc_type, value, field)

    return rows


# -- CLI -------------------------------------------------------------------


def build_client(args: argparse.Namespace) -> GibClient:
    return GibClient(
        username=args.username or os.environ.get("GIB_USERNAME", ""),
        api_key=args.api_key or os.environ.get("GIB_API_KEY", ""),
        base_url=args.base_url,
        timeout=args.timeout,
        retries=args.retries,
        verbose=args.verbose,
    )


def dump(label: str, payload) -> None:
    print(f"\n--- {label} ---")
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)[:8000])


def cmd_preflight(args: argparse.Namespace) -> int:
    client = build_client(args)
    print(f"Base URL   : {client.base_url}")
    print(f"Credentials: GIB_USERNAME set, GIB_API_KEY set ({len(args.api_key or os.environ.get('GIB_API_KEY', ''))} chars)")
    payload = client.granted_collections()
    names = collection_names(payload)
    print(f"Auth       : OK -- {len(names)} granted collection(s)")
    ioc_grants = [name for name in names if name in IOC_COLLECTIONS]
    print(f"IOC-bearing: {', '.join(ioc_grants) if ioc_grants else '(none of the known IOC collections)'}")
    if args.raw:
        dump("granted_collections", payload)
    return 0


def collection_names(payload) -> list[str]:
    """Collection names out of a granted_collections response."""
    entries = extract_items(payload)
    if not entries and isinstance(payload, dict):
        entries = payload.get("collections") or []
    names = []
    for entry in entries:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict):
            name = entry.get("name") or entry.get("collection")
            if name:
                names.append(name)
    return names


def cmd_collections(args: argparse.Namespace) -> int:
    client = build_client(args)
    payload = client.granted_collections()
    for name in sorted(collection_names(payload)):
        marker = "*" if name in IOC_COLLECTIONS else " "
        print(f" {marker} {name}")
    print("\n(* = known to carry IOCs)")
    if args.raw:
        dump("granted_collections", payload)
    return 0


def cmd_seq(args: argparse.Namespace) -> int:
    client = build_client(args)
    payload = client.sequence_start(args.collection)
    print(f"{args.collection}: seqUpdate = {payload.get('seqUpdate') if isinstance(payload, dict) else payload}")
    if args.raw:
        dump("sequence_list", payload)
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    client = build_client(args)
    seq_update = args.seq_update
    if seq_update is None and not (args.date_from or args.date_to):
        # Without a cursor or a date window the feed starts at "now" and returns
        # nothing, which reads as a broken call. Rewind to the collection start.
        start = client.sequence_start(args.collection)
        seq_update = start.get("seqUpdate") if isinstance(start, dict) else None
        print(f"Starting cursor: seqUpdate={seq_update}")

    total_records = 0
    total_iocs = 0
    for page, payload in client.iter_updated(
        args.collection,
        seq_update=seq_update,
        limit=args.limit,
        max_pages=args.pages,
        date_from=args.date_from,
        date_to=args.date_to,
    ):
        items = extract_items(payload)
        total_records += len(items)
        count = payload.get("count") if isinstance(payload, dict) else None
        cursor = payload.get("seqUpdate") if isinstance(payload, dict) else None
        print(
            f"page {page}: {len(items)} record(s), "
            f"server count={count}, next seqUpdate={cursor}"
        )

        if args.raw:
            dump(f"page {page} raw", payload)
        if args.normalize:
            for item in items:
                rows = normalize_iocs(item) if isinstance(item, dict) else []
                total_iocs += len(rows)
                for row in rows:
                    print(f"    {row['type']:<12} {row['value']}  (id={row['id']})")

    print(f"\nTotal: {total_records} record(s)" + (f", {total_iocs} indicator(s)" if args.normalize else ""))
    if total_records == 0:
        print("No records returned -- check the cursor, the date window, and the collection grant.")
    return 0


def add_common_args(parser: argparse.ArgumentParser, *, sub: bool) -> None:
    """Shared options, accepted both before and after the subcommand.

    On the subparsers the defaults are SUPPRESS: without it argparse would write
    the subparser's default over a value already parsed from the main parser,
    so `--raw fetch` would silently lose the flag.
    """

    def default(value):
        return argparse.SUPPRESS if sub else value

    parser.add_argument("--base-url", default=default(os.environ.get("GIB_BASE_URL", DEFAULT_BASE_URL)))
    parser.add_argument("--username", default=default(None), help="defaults to $GIB_USERNAME")
    parser.add_argument("--api-key", default=default(None), help="defaults to $GIB_API_KEY")
    parser.add_argument("-c", "--collection", default=default(DEFAULT_COLLECTION))
    parser.add_argument("--timeout", type=float, default=default(30.0))
    parser.add_argument("--retries", type=int, default=default(3))
    parser.add_argument("--raw", action="store_true", default=default(False), help="dump raw JSON responses")
    parser.add_argument("-v", "--verbose", action="store_true", default=default(False), help="log each HTTP call")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Test Group-IB Threat Intelligence API v2 IOC calls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common_args(parser, sub=False)

    shared = argparse.ArgumentParser(add_help=False)
    add_common_args(shared, sub=True)

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", parents=[shared], help="verify auth and show IOC grants")
    subparsers.add_parser("collections", parents=[shared], help="list granted collections")
    subparsers.add_parser("seq", parents=[shared], help="show the starting seqUpdate for a collection")

    fetch = subparsers.add_parser("fetch", parents=[shared], help="pull IOC records")
    fetch.add_argument("-l", "--limit", type=int, default=10, help="records per page")
    fetch.add_argument("--pages", type=int, default=1, help="pages to walk")
    fetch.add_argument("--seq-update", type=int, default=None, help="resume from this cursor")
    fetch.add_argument("--date-from", default=None, help="YYYY-MM-DD (maps to df)")
    fetch.add_argument("--date-to", default=None, help="YYYY-MM-DD (maps to dt)")
    fetch.add_argument("--normalize", action="store_true", help="flatten records to IOC rows")

    args = parser.parse_args(argv)
    handlers = {
        "preflight": cmd_preflight,
        "collections": cmd_collections,
        "seq": cmd_seq,
        "fetch": cmd_fetch,
    }
    try:
        return handlers[args.command](args)
    except GibError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        if exc.status in (401, 403):
            print(
                "  -> 401/403 means the username/API key pair was rejected or the key "
                "has no grant for this collection. Check GIB_USERNAME (portal e-mail) "
                "and GIB_API_KEY, then run `collections`.",
                file=sys.stderr,
            )
        if exc.body:
            print(f"  body: {exc.body}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
