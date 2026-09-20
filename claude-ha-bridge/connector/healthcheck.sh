#!/usr/bin/env bash
# Health check for the Home Assistant MCP connector gateway.
# Run on the Docker host (checks Caddy + HA locally) or anywhere
# (checks the public tunnel URL). Exits non-zero if any check fails.
set -uo pipefail

cd "$(dirname "$0")"

status=0
check() {
	local name="$1" url="$2"
	printf '%-32s ' "$name"
	if code=$(curl -fsS -m 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null); then
		echo "OK (HTTP $code)"
	else
		echo "FAIL ($url)"
		status=1
	fi
}

if [ -f .env ]; then
	# shellcheck disable=SC1091
	source .env
fi

echo "== Home Assistant connector health check =="
echo

if [ -n "${HA_URL:-}" ]; then
	check "Home Assistant (direct)" "${HA_URL%/}/mcp_server/sse"
else
	echo "HA_URL not set (no .env found) - skipping direct HA check."
fi

if docker compose ps --status running --services 2>/dev/null | grep -qx caddy; then
	check "Gateway (local, via Caddy)" "http://localhost:80/mcp_server/sse"
else
	echo "caddy container not running - run 'docker compose up -d' first."
	status=1
fi

if [ -n "${TUNNEL_HOSTNAME:-}" ]; then
	check "Public tunnel" "https://${TUNNEL_HOSTNAME}/mcp_server/sse"
else
	echo "TUNNEL_HOSTNAME not set - skipping public tunnel check."
	echo "(add TUNNEL_HOSTNAME=ha-x7k2q9.yourdomain.com to .env to enable this check)"
fi

echo
if command -v docker >/dev/null 2>&1; then
	echo "Container status:"
	docker compose ps 2>/dev/null
fi

echo
if [ "$status" -eq 0 ]; then
	echo "All checks passed."
else
	echo "One or more checks failed - see above. Try: docker compose logs -f"
fi
exit "$status"
