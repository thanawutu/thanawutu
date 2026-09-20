# Claude Remote Control ↔ Home Assistant bridge (Debian Docker)

Manage Home Assistant by remote-connecting to a Claude Code session
running in Docker on your Debian/Synology box — from the Claude app on
your tablet, not by adding a connector directly in the app.

```
Tablet (Claude app) --Remote Control (outbound only)--> Claude Code in Docker
                                                                 │
                                                                 │ .mcp.json → local network
                                                                 ▼
                                                    ha-mcp container (full REST API)
                                                                 │
                                                                 ▼
                                                Home Assistant (LAN only, never exposed)
```

Two containers:
- **`claude`** — Claude Code CLI in [Remote Control server
  mode](https://code.claude.com/docs/en/remote-control). It only makes
  outbound HTTPS requests to Anthropic; no port is opened on your network.
  Your tablet pairs with it through your claude.ai account.
- **`ha-mcp`** — a small custom MCP server (`full-control-mcp/`) that talks
  to Home Assistant's REST API directly (`/api/states`, `/api/services`).
  Unlike HA's own "Model Context Protocol Server" integration, it isn't
  limited to entities exposed to Assist/voice — any entity, any service.

Home Assistant itself is **never reachable from the internet** in this
setup — only the `claude` container talks out, and it only talks to
Anthropic and to `ha-mcp` over the private Docker network.

> Prefer to skip the desktop session and add Home Assistant as a connector
> straight in the Claude app instead? See [`connector/`](connector/README.md) —
> that approach needs a public HTTPS endpoint (Cloudflare Tunnel) and, with
> HA's built-in MCP integration, is limited to Assist-exposed entities.

## 1. Prepare Home Assistant

1. Create a **dedicated Home Assistant user** for this (Settings → People
   → Users → Add User) — since this setup has full API access (not just
   exposed entities), give it only the account you're willing to hand
   Claude full control of.
2. Log in as that user, open its profile → **Security → Long-lived access
   tokens → Create token**. Copy it.

## 2. Start the bridge

```bash
cd claude-ha-bridge
./setup.sh
```

The script builds both images, asks for `HA_URL` and the token, generates
a random `MCP_PATH_SECRET`, then walks you through signing in to Claude
once (`/login` inside an interactive session) before starting the
persistent Remote Control server.

Or do it by hand:

```bash
cp .env.example .env      # fill in HA_URL, HA_TOKEN, MCP_PATH_SECRET
docker compose build
docker compose run --rm claude claude    # run /login once, then /exit
docker compose up -d
```

## 3. Connect from the tablet

Open the **Claude app** — the session shows up in your session list under
your own account (Remote Control auto-registers there). If you need the
pairing URL or QR code again:

```bash
docker compose logs -f claude
```

Then just talk to it:

> "Turn off all the lights downstairs"
> "What's the state of climate.bedroom?"
> "Set the thermostat to 24 degrees at 21:00 tonight"

Inside a session, `/mcp` lists the `home-assistant` server and its tools
(`list_states`, `get_state`, `call_service`, `list_services`).

## Health check

```bash
./healthcheck.sh
```

Checks that Home Assistant answers directly, that `ha-mcp` is responding
locally, and prints the containers' status and the `claude` container's
recent log (useful for spotting a dropped Remote Control connection —
see the "reconnecting" notes below).

## If the session goes offline

Remote Control reconnects automatically after a network blip. If the
`claude` container itself restarted or its process died, bring it back:

```bash
docker compose up -d claude       # container down/exited
docker compose exec claude claude remote-control   # process alive but disconnected
```

Because the container's `CMD` is `claude remote-control`, a restarted
container re-registers on its own in most cases — check
`docker compose logs claude` first.

## Security notes

- The HA token grants full REST API access for whatever HA user it
  belongs to — always use a dedicated, scoped-down user, never your main
  admin account.
- `MCP_PATH_SECRET` and `ha-mcp` are only reachable on the compose's
  internal Docker network; nothing needs a public port for this setup.
- Remote Control session transcripts (your messages, Claude's tool calls)
  are stored on Anthropic's servers to keep devices in sync — see
  [Data usage](https://code.claude.com/docs/en/data-usage).
- Treat `.env` like a password file; it's already git-ignored.
