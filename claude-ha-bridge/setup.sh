#!/usr/bin/env bash
# One-shot setup for Claude Remote Control + full-control Home Assistant
# bridge. Run this on the Debian/Synology Docker host, inside claude-ha-bridge/.
set -euo pipefail

cd "$(dirname "$0")"

echo "== Claude Remote Control <-> Home Assistant bridge setup =="

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
	read -rp "HA base URL as seen from this host [http://homeassistant.local:8123]: " HA_URL
	HA_URL=${HA_URL:-http://homeassistant.local:8123}

	echo
	echo "Use a dedicated Home Assistant user for this token - it gets full"
	echo "REST API access (any entity, any service), not just Assist-exposed ones."
	read -rsp "HA long-lived access token: " HA_TOKEN
	echo
	while [ -z "$HA_TOKEN" ]; do
		read -rsp "Token cannot be empty, paste it again: " HA_TOKEN
		echo
	done

	MCP_PATH_SECRET=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 48)

	cat >.env <<EOF
HA_URL=${HA_URL}
HA_TOKEN=${HA_TOKEN}
MCP_PATH_SECRET=${MCP_PATH_SECRET}
EOF
	chmod 600 .env
	echo ".env written (generated a random MCP_PATH_SECRET)."
fi

echo
echo "Building images..."
docker compose build

echo
echo "== One-time login =="
echo "Claude needs to sign in once before Remote Control will work."
echo "An interactive session will start: run '/login', open the URL it prints"
echo "on any device, sign in, then type '/exit' here to continue."
echo
docker compose run --rm claude claude

echo
echo "Starting the persistent Remote Control server..."
docker compose up -d

echo
echo "Waiting for it to register..."
sleep 3
docker compose logs claude | tail -20

cat <<'EOF'

Next steps:
  - Open the Claude app on your tablet/phone - this session should show
    up in your session list under your own claude.ai account.
  - If you need the pairing URL/QR code again: docker compose logs -f claude
  - Ask it things like "turn off the living room lights" or "what's the
    state of climate.bedroom" - it has full Home Assistant REST API access
    through the local home-assistant MCP tool, not limited to entities
    exposed to Assist.

Logs:  docker compose logs -f
Stop:  docker compose down
EOF
