# Group-IB Threat Intelligence — IOC API test client

A dependency-free test harness for pulling indicators of compromise from the
Group-IB Threat Intelligence API (v2). Standard library only, Python 3.9+.

| File | Purpose |
| --- | --- |
| `gib_ioc.py` | Client + CLI (`preflight`, `collections`, `seq`, `fetch`) |
| `mock_server.py` | Mock TI API for offline testing |
| `test_gib_ioc.py` | End-to-end test over real HTTP against the mock |

## Status of the live test

**The live API call has not been executed — it is blocked in this environment
for two independent reasons.**

1. **Egress policy.** The session's network policy denies all Group-IB hosts.
   The proxy answers `403` to the CONNECT, before TLS:

   ```
   $ GIB_USERNAME=... GIB_API_KEY=... python3 gib_ioc.py preflight
   Base URL   : https://tap.group-ib.com/api/v2
   ERROR: connection failed for https://tap.group-ib.com/api/v2/user/granted_collections:
          Tunnel connection failed: 403 Forbidden
   ```

   `tap.group-ib.com`, `api.group-ib.com` and `docs.group-ib.com` are all
   refused; package registries and GitHub are allowed. Lifting this means
   allowlisting the Group-IB host in the environment's network policy.

2. **No credentials.** There is no `GIB_USERNAME` / `GIB_API_KEY` in the
   environment, and none in the repository.

What *has* been verified is the client itself: every request-path behaviour
below was exercised over real HTTP against `mock_server.py`, 29/29 checks
passing. Run `python3 test_gib_ioc.py` to reproduce.

```
1. Missing credentials rejected before any request
2. Bad API key  -> 401, error body surfaced
3. Valid auth   -> granted collections parsed
4. Ungranted collection -> 403
5. sequence_list cursor retrieved
6. limit honoured, count and cursor parsed
7. Pagination walks 25 records over 3 pages, no duplicates
8. Pagination stops at end of feed (no wasted request)
9. IOC normalization across domain / ip / url / hash record shapes
10. CLI exit codes, flags accepted before and after the subcommand
```

## Running it for real

```bash
export GIB_USERNAME='you@company.com'     # TI portal login e-mail
export GIB_API_KEY='<api key from the portal profile page>'

python3 gib_ioc.py preflight                 # auth check + which IOC collections you can read
python3 gib_ioc.py collections               # full grant list
python3 gib_ioc.py seq -c ioc/common         # current cursor
python3 gib_ioc.py fetch -c ioc/common -l 10 --normalize
python3 gib_ioc.py fetch -c ioc/common --pages 5 -l 100 --raw
python3 gib_ioc.py fetch -c malware/cnc --date-from 2026-07-01 --date-to 2026-07-31
```

Add `-v` to log every HTTP call, `--raw` to dump untouched JSON.

Start with `preflight`. It fails fast and distinguishes the three failure modes
that look alike from the outside: unreachable host, rejected credentials, and
valid credentials with no grant for the collection you asked for.

### Against the mock, no credentials needed

```bash
python3 mock_server.py --port 8777 &
python3 gib_ioc.py --base-url http://127.0.0.1:8777/api/v2 \
  --username analyst@example.com --api-key mock-api-key-0123456789 \
  fetch -c ioc/common -l 5 --pages 2 --normalize
```

## How the API is used

- **Auth** — HTTP Basic, portal e-mail as the username and the API key as the
  password, sent pre-emptively (the API returns 401 without a challenge urllib
  could respond to).
- **Cursor** — the feed is incremental, not offset-paged. `GET
  /sequence_list/update/{collection}` gives a starting `seqUpdate`; each page of
  `GET /{collection}/updated` echoes the next one. `fetch` fetches the starting
  cursor automatically when you give neither `--seq-update` nor a date window,
  because a bare call starts at *now* and returns nothing — which reads as a
  broken integration rather than an empty one.
- **Date window** — `--date-from` / `--date-to` map to `df` / `dt` and apply to
  the first request only; after that the cursor carries the position.
- **Retries** — `429` and `5xx` back off exponentially and honour `Retry-After`.
  `401`/`403` are not retried; they cannot succeed on a second attempt.

### Verified vs. assumed

The **client behaviour** is verified by the test suite. The **wire contract** —
base URL, the `user/granted_collections`, `sequence_list/update/{collection}`
and `{collection}/updated` paths, the `seqUpdate` / `limit` / `df` / `dt`
parameters, and Basic auth — is written to the documented v2 API but could not
be confirmed against the live service from here, since the docs host is blocked
too. Treat it as unconfirmed until `preflight` succeeds against the real
endpoint.

Two deliberate hedges limit the damage if a detail is off:

- `extract_items()` accepts a page whose records live under `items`, `data`,
  `results`, or a bare top-level list.
- `normalize_iocs()` is best-effort over several record shapes and never
  suppresses anything — `--raw` always shows the untouched response, so a schema
  surprise is visible rather than silently dropped.

If the live schema differs, `--raw` output is the thing to adjust against, and
only `extract_items` / `normalize_iocs` should need to change.

## Collections carrying IOCs

`ioc/common` is the aggregate feed and the right default. Also indicator-bearing:
`malware/cnc`, `attacks/phishing_group`, `attacks/phishing_kit`, `attacks/ddos`,
`apt/threat`, `hi/threat`. Your key will not have all of them — `collections`
prints what it actually has, marking the IOC-bearing ones with `*`.
