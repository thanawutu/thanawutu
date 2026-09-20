#!/usr/bin/env bash
# Health check for the Claude Remote Control <-> Home Assistant bridge.
# Run on the Docker host. Exits non-zero if any check fails.
set -uo pipefail

cd "$(dirname "$0")"

status=0

if [ -f .env ]; then
	# shellcheck disable=SC1091
	source .env
fi

echo "== Claude/Home Assistant bridge health check =="
echo

if [ -n "${HA_URL:-}" ]; then
	printf '%-32s ' "Home Assistant (direct)"
	code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "${HA_URL%/}/api/" 2>/dev/null)
	if [ "$code" = "200" ] || [ "$code" = "401" ]; then
		echo "reachable (HTTP $code)"
	else
		echo "FAIL (got '${code:-none}' from ${HA_URL%/}/api/)"
		status=1
	fi
else
	echo "HA_URL not set (no .env found) - skipping direct HA check."
fi

if [ -n "${MCP_PATH_SECRET:-}" ]; then
	printf '%-32s ' "ha-mcp (local)"
	if curl -fsS -m 5 -o /dev/null "http://localhost:8000/mcp/${MCP_PATH_SECRET}/sse" 2>/dev/null; then
		echo "OK"
	else
		echo "FAIL (ha-mcp container not responding on :8000)"
		status=1
	fi
else
	echo "MCP_PATH_SECRET not set - skipping ha-mcp check."
fi

echo
echo "Container status:"
docker compose ps 2>/dev/null

echo
echo "Remote Control status (last lines of claude container log):"
docker compose logs --tail 10 claude 2>/dev/null

echo
if [ "$status" -eq 0 ]; then
	echo "All checks passed."
else
	echo "One or more checks failed - see above. Try: docker compose logs -f"
fi
exit "$status"
