#!/usr/bin/env bash
# One-shot setup for the Home Assistant connector gateway (Caddy + cloudflared).
# Run this on the Debian/Synology Docker host, inside claude-ha-bridge/connector/.
set -euo pipefail

cd "$(dirname "$0")"

echo "== Home Assistant connector gateway setup =="

if ! command -v docker >/dev/null 2>&1; then
	echo "docker not found. Install Docker first (Synology: Package Center -> Container Manager)." >&2
	exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
	echo "'docker compose' plugin not found. Install/enable it and re-run." >&2
	exit 1
fi

if [ -f .env ]; then
	echo ".env already exists, keeping it. Delete it first to redo this wizard."
else
	echo
	echo "-- Home Assistant --"
	read -rp "HA base URL as seen from this host [http://homeassistant.local:8123]: " HA_URL
	HA_URL=${HA_URL:-http://homeassistant.local:8123}

	read -rsp "HA long-lived access token (Profile -> Security -> Long-lived access tokens): " HA_TOKEN
	echo
	while [ -z "$HA_TOKEN" ]; do
		read -rsp "Token cannot be empty, paste it again: " HA_TOKEN
		echo
	done

	echo
	echo "-- Cloudflare Tunnel --"
	echo "Create one at https://one.dash.cloudflare.com -> Networks -> Tunnels,"
	echo "point its public hostname to http://caddy:80, then paste the tunnel token."
	read -rsp "Cloudflare Tunnel token: " CF_TUNNEL_TOKEN
	echo
	while [ -z "$CF_TUNNEL_TOKEN" ]; do
		read -rsp "Token cannot be empty, paste it again: " CF_TUNNEL_TOKEN
		echo
	done

	cat >.env <<EOF
HA_URL=${HA_URL}
HA_TOKEN=${HA_TOKEN}
CF_TUNNEL_TOKEN=${CF_TUNNEL_TOKEN}
EOF
	chmod 600 .env
	echo ".env written."
fi

echo
echo "Starting containers..."
docker compose up -d

echo
echo "Waiting for the gateway to come up..."
sleep 3

# shellcheck disable=SC1091
source .env
if curl -fsS -m 5 -o /dev/null "${HA_URL%/}/mcp_server/sse" 2>/dev/null; then
	echo "OK: Home Assistant MCP endpoint is reachable directly from this host."
else
	echo "WARNING: could not reach ${HA_URL%/}/mcp_server/sse from this host." >&2
	echo "Check that the 'Model Context Protocol Server' integration is installed in Home Assistant." >&2
fi

echo
echo "Containers:"
docker compose ps

cat <<'EOF'

Next steps:
  1. In Cloudflare Zero Trust, confirm the tunnel shows "Healthy" and its
     public hostname points to http://caddy:80.
  2. From any device, open https://<your-tunnel-hostname>/mcp_server/sse
     - it should start streaming (an "event: endpoint" line).
     Opening https://<your-tunnel-hostname>/ should return 404 (expected;
     only /mcp_server/* is exposed).
  3. On the tablet: Claude app -> Settings -> Connectors -> Add custom
     connector -> paste https://<your-tunnel-hostname>/mcp_server/sse
  4. Enable the connector in a chat and ask something like
     "which lights are on?"

Logs:  docker compose logs -f
Stop:  docker compose down
EOF
