# Claude ↔ Home Assistant bridge (Debian Docker)

Control Home Assistant from a tablet, through Claude running in a Docker
container on your Debian box.

```
Tablet browser ──> ttyd web terminal (this container, port 7681)
                        │
                  Claude Code CLI
                        │  MCP over SSE + Bearer token
                        ▼
        Home Assistant  http://<ha-ip>:8123/mcp_server/sse
```

The container runs **Claude Code** (Anthropic's official CLI agent) connected
to Home Assistant's official **MCP Server** integration. `ttyd` serves the
Claude session as a web page, so any browser on your LAN — including a
tablet — becomes the remote control.

## 1. Prepare Home Assistant (requires HA 2025.2 or newer)

1. **Settings → Devices & Services → Add Integration → "Model Context
   Protocol Server"** and add it. This exposes the endpoint
   `http://<ha-ip>:8123/mcp_server/sse`.
2. **Settings → Voice assistants → Expose** — expose the entities (lights,
   switches, climate, …) you want Claude to see and control. Claude can only
   touch what you expose here.
3. Create a token: click your user profile (bottom left) → **Security →
   Long-lived access tokens → Create token**. Copy it.

## 2. Start the bridge container

```bash
cd claude-ha-bridge
cp .env.example .env     # then edit .env: HA_URL, HA_TOKEN, TTYD_PASS
docker compose up -d --build
```

## 3. First login (one time)

Open `http://<docker-host-ip>:7681` in any browser, log in with the
`TTYD_USER`/`TTYD_PASS` you set, and Claude Code starts. On first run it
prints a claude.ai login URL — open that URL on your tablet, sign in, and
paste the code back into the terminal. The login is stored in the
`claude-home` volume, so this only happens once.

## 4. Use it from the tablet

Browse to `http://<docker-host-ip>:7681` and just talk to Claude:

> "Turn off all the lights downstairs"
> "What's the temperature in the bedroom?"
> "Set the thermostat to 24 degrees at 21:00 tonight"

Inside Claude, `/mcp` shows the `home-assistant` server and its tools; if it
shows as failed, check `HA_URL`/`HA_TOKEN` in `.env` and that the MCP Server
integration is installed in HA.

## Security notes

- Keep port 7681 **LAN-only** (don't port-forward it on your router). The
  ttyd login protects it, but it is plain HTTP unless you put a
  reverse proxy with TLS in front.
- The HA token grants your full HA account's access — treat `.env` like a
  password file and never commit it.
- Prefer a dedicated HA user with limited rights for the token.

## Alternative: the same bridge for Claude Desktop

If you run the (unofficial) Claude Desktop build for Linux in a
VNC/webtop-style container instead, point it at HA with `mcp-proxy`
(Claude Desktop only speaks stdio) in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "Home Assistant": {
      "command": "mcp-proxy",
      "args": ["http://<ha-ip>:8123/mcp_server/sse"],
      "env": { "API_ACCESS_TOKEN": "<your-long-lived-token>" }
    }
  }
}
```

(`pip install mcp-proxy` or `uv tool install mcp-proxy` inside that
container.) You then reach the desktop from the tablet through the
container's web-VNC page. This works, but the web-terminal setup above is
lighter and more reliable on a tablet.

## Alternative: no Docker at all

- **Anthropic integration inside HA**: install the "Anthropic" integration
  in Home Assistant and pick Claude as the conversation agent for Assist —
  then the HA companion app on your tablet already gives you a Claude chat
  that controls your home.
- **claude.ai custom connector**: if you expose the HA MCP endpoint
  publicly over HTTPS (Nabu Casa or a Cloudflare Tunnel), you can add it as
  a custom connector at claude.ai and use it straight from the Claude app
  on the tablet.
