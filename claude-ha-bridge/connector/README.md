# Home Assistant connector for the Claude app (tablet/phone)

Lets the **Claude application** on your tablet control Home Assistant
directly — no browser, no terminal. The Docker container on your Debian box
acts as a gateway: it publishes Home Assistant's MCP endpoint over HTTPS
(via a Cloudflare Tunnel, no open router ports) and injects your HA access
token on every request, because the Claude app's custom connectors cannot
send custom headers themselves.

```
Claude app (tablet) ──HTTPS──> Cloudflare Tunnel ──> Caddy (adds HA token)
                                                          │
                                                          ▼
                                    Home Assistant /mcp_server/sse
```

Requirements:

- Home Assistant 2025.2+ with the **Model Context Protocol Server**
  integration installed, and your entities exposed under
  *Settings → Voice assistants → Expose*.
- A Claude **Pro/Max/Team/Enterprise** plan (custom connectors are a paid
  feature; they work in the mobile/tablet app).
- A free Cloudflare account with a domain on it (for the tunnel).

## 1. Create the Cloudflare Tunnel

1. Go to <https://one.dash.cloudflare.com> → *Networks → Tunnels* →
   **Create a tunnel** (Cloudflared type). Copy the tunnel token.
2. Under the tunnel's *Public hostname*, add a hostname on your domain —
   pick something unguessable, e.g. `ha-x7k2q9.yourdomain.com` — and point
   its service to `http://caddy:80`.

## 2. Start the gateway

Run the setup wizard — it prompts for `HA_URL`/`HA_TOKEN`/`CF_TUNNEL_TOKEN`,
writes `.env`, starts the containers, and checks that Home Assistant's MCP
endpoint answers:

```bash
cd claude-ha-bridge/connector
./setup.sh
```

Or do it manually:

```bash
cd claude-ha-bridge/connector
cp .env.example .env    # fill in HA_URL, HA_TOKEN, CF_TUNNEL_TOKEN
docker compose up -d
```

Sanity check from any device:
`https://ha-x7k2q9.yourdomain.com/mcp_server/sse` should start streaming
(an `event: endpoint` line), while `https://ha-x7k2q9.yourdomain.com/`
returns 404 — only the MCP path is exposed.

Or run the health check script on the Docker host any time — it verifies
Home Assistant directly, the local gateway, and (if you set
`TUNNEL_HOSTNAME` in `.env`) the public tunnel URL:

```bash
./healthcheck.sh
```

## 3. Add the connector in the Claude app

On the tablet: **Settings → Connectors → Add custom connector**, and enter:

```
https://ha-x7k2q9.yourdomain.com/mcp_server/sse
```

(No OAuth fields needed — the gateway handles authentication.) Then in any
chat, enable the connector from the tools menu and ask away:

> "Which lights are on?" · "Turn off everything downstairs" ·
> "Set the living room thermostat to 24"

## Security — read this

The gateway authenticates to HA *for* the caller, so **anyone who knows the
exact URL can control the exposed entities**. Mitigate accordingly:

- Use a long, random hostname and treat the URL like a password.
- Create the token from a **dedicated, non-admin HA user**, and expose only
  the entities you actually want controllable (the MCP server only serves
  exposed entities).
- Optionally add Cloudflare rate limiting / WAF rules on that hostname, and
  rotate the hostname or HA token if you ever suspect a leak.
- `docker compose logs -f caddy` shows every request if you want an audit
  trail.

## No-domain alternative

If you don't have a domain, HA's **Nabu Casa cloud** URL also reaches
`/mcp_server/sse`, but it can't inject the token header for you — the
Claude app would be refused. So either use this gateway, or use the
browser-terminal bridge one folder up (`claude-ha-bridge/`), which needs no
public exposure at all.
