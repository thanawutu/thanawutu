#!/usr/bin/env python3
"""End-to-end test of gib_ioc.py against the mock Group-IB TI API.

Real HTTP over loopback -- the client is not stubbed, so the auth header,
query building, pagination cursor, error handling and IOC normalization are all
exercised as they would be against the live API.

    ./test_gib_ioc.py
"""

from __future__ import annotations

import os
import sys

# The mock listens on loopback; make sure the outbound proxy is bypassed for it.
os.environ["NO_PROXY"] = "127.0.0.1,localhost," + os.environ.get("NO_PROXY", "")
os.environ["no_proxy"] = os.environ["NO_PROXY"]

import gib_ioc
import mock_server

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS  {label}")
    else:
        FAILED += 1
        print(f"  FAIL  {label}{(' -- ' + detail) if detail else ''}")


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def main() -> int:
    server = mock_server.serve(port=0)
    host, port = server.server_address
    base_url = f"http://{host}:{port}/api/v2"
    print(f"Mock API listening on {base_url}")

    good = gib_ioc.GibClient(
        username=mock_server.MOCK_USERNAME,
        api_key=mock_server.MOCK_API_KEY,
        base_url=base_url,
        retries=1,
    )

    section("1. Missing credentials are rejected before any request")
    try:
        gib_ioc.GibClient(username="", api_key="", base_url=base_url)
        check("empty credentials raise GibError", False, "no exception raised")
    except gib_ioc.GibError as exc:
        check("empty credentials raise GibError", "missing credentials" in str(exc))

    section("2. Bad API key returns 401")
    bad = gib_ioc.GibClient(
        username=mock_server.MOCK_USERNAME, api_key="wrong-key", base_url=base_url, retries=1
    )
    try:
        bad.granted_collections()
        check("wrong key raises", False, "call unexpectedly succeeded")
    except gib_ioc.GibError as exc:
        check("wrong key raises GibError", True)
        check("status is 401", exc.status == 401, f"got {exc.status}")
        check("error body is surfaced", "Unauthorized" in exc.body, exc.body[:120])

    section("3. Auth succeeds and grants are listed")
    payload = good.granted_collections()
    names = gib_ioc.collection_names(payload)
    check("granted_collections returns names", len(names) == 4, f"got {names}")
    check("ioc/common is granted", "ioc/common" in names)

    section("4. Collection with no grant returns 403")
    try:
        good.updated("compromised/card", limit=1)
        check("ungranted collection raises", False, "call unexpectedly succeeded")
    except gib_ioc.GibError as exc:
        check("ungranted collection is 403", exc.status == 403, f"got {exc.status}")

    section("5. Starting cursor is retrieved")
    start = good.sequence_start("ioc/common")
    seq = start.get("seqUpdate")
    check("seqUpdate is an int", isinstance(seq, int), f"got {seq!r}")
    check("seqUpdate matches mock start", seq == mock_server.START_SEQ)

    section("6. Single page respects limit")
    page = good.updated("ioc/common", seq_update=seq, limit=10)
    items = gib_ioc.extract_items(page)
    check("returned 10 records", len(items) == 10, f"got {len(items)}")
    check("count reports full backlog", page.get("count") == 25, f"got {page.get('count')}")
    check("cursor advanced", page.get("seqUpdate") > seq, f"got {page.get('seqUpdate')}")

    section("7. Pagination walks the whole feed without repeats")
    seen_ids: list[str] = []
    pages = 0
    for page_no, payload in good.iter_updated("ioc/common", seq_update=seq, limit=10, max_pages=10):
        pages += 1
        batch = gib_ioc.extract_items(payload)
        seen_ids.extend(record["id"] for record in batch)
        print(f"    page {page_no}: {len(batch)} record(s), next cursor {payload.get('seqUpdate')}")
    check("walked 3 pages (10+10+5)", pages == 3, f"got {pages}")
    check("collected all 25 records", len(seen_ids) == 25, f"got {len(seen_ids)}")
    check("no duplicate records", len(set(seen_ids)) == 25, f"got {len(set(seen_ids))} unique")

    section("8. Pagination stops at the end of the feed")
    exhausted = list(good.iter_updated("ioc/common", seq_update=mock_server.START_SEQ + 10**6, limit=10, max_pages=5))
    check("stops after one empty page", len(exhausted) == 1, f"got {len(exhausted)} pages")
    check("empty page has no records", gib_ioc.extract_items(exhausted[0][1]) == [])

    section("9. IOC normalization across record shapes")
    all_rows = []
    for record in mock_server.RECORDS:
        all_rows.extend(gib_ioc.normalize_iocs(record))
    types = {row["type"] for row in all_rows}
    check("extracted indicators from every shape", len(all_rows) >= 25, f"got {len(all_rows)}")
    check("domain indicators found", "domain" in types, f"types={sorted(types)}")
    check("ip indicators found", "ip" in types, f"types={sorted(types)}")
    check("url indicators found", "url" in types, f"types={sorted(types)}")
    check("hash indicators found", "hash" in types or "hash-md5" in types, f"types={sorted(types)}")
    check("every row carries a value", all(row["value"] for row in all_rows))
    check("every row carries a record id", all(row["id"] for row in all_rows))
    print(f"    sample: {all_rows[0]}")
    print(f"    sample: {all_rows[2]}")

    section("10. CLI end-to-end")
    argv_base = ["--base-url", base_url, "--username", mock_server.MOCK_USERNAME,
                 "--api-key", mock_server.MOCK_API_KEY]
    rc = gib_ioc.main(argv_base + ["preflight"])
    check("preflight exits 0 (flags before subcommand)", rc == 0, f"got {rc}")
    rc = gib_ioc.main(["preflight"] + argv_base)
    check("preflight exits 0 (flags after subcommand)", rc == 0, f"got {rc}")
    rc = gib_ioc.main(argv_base + ["fetch", "-c", "ioc/common", "-l", "5", "--pages", "2", "--normalize"])
    check("fetch --normalize exits 0", rc == 0, f"got {rc}")
    rc = gib_ioc.main(argv_base + ["seq"])
    check("seq exits 0", rc == 0, f"got {rc}")
    rc = gib_ioc.main(["--base-url", base_url, "--username", mock_server.MOCK_USERNAME,
                       "--api-key", "wrong", "preflight"])
    check("bad-credential CLI exits 1", rc == 1, f"got {rc}")

    server.shutdown()

    print(f"\n{'=' * 46}")
    print(f"  {PASSED} passed, {FAILED} failed")
    print("=" * 46)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
