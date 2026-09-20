"""Custom MCP server giving full control of Home Assistant's REST API.

Unlike Home Assistant's built-in "Model Context Protocol Server"
integration, this talks to /api/states and /api/services directly, so it
is not limited to entities exposed to Assist/voice — any entity, any
service, any domain.

The trade-off: this is unofficial and unreviewed compared to HA's own
integration. Treat the mount path secret as a password (see README).
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

HA_URL = os.environ["HA_URL"].rstrip("/")
HA_TOKEN = os.environ["HA_TOKEN"]
PATH_SECRET = os.environ["MCP_PATH_SECRET"]

mcp = FastMCP("Home Assistant Full Control")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=HA_URL,
        headers={
            "Authorization": f"Bearer {HA_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=15,
    )


@mcp.tool()
def list_states() -> list:
    """List every entity's current state in Home Assistant, including
    entities not exposed to Assist/voice."""
    with _client() as c:
        r = c.get("/api/states")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_state(entity_id: str) -> dict:
    """Get one entity's current state, e.g. entity_id='light.living_room'."""
    with _client() as c:
        r = c.get(f"/api/states/{entity_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_services() -> list:
    """List every service Home Assistant exposes, grouped by domain."""
    with _client() as c:
        r = c.get("/api/services")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def call_service(
    domain: str, service: str, entity_id: str = "", data: dict = {}
) -> dict:
    """Call any Home Assistant service, e.g. domain='light',
    service='turn_on', entity_id='light.living_room'. Extra service fields
    (brightness, temperature, ...) go in data."""
    payload = dict(data)
    if entity_id:
        payload["entity_id"] = entity_id
    with _client() as c:
        r = c.post(f"/api/services/{domain}/{service}", json=payload)
        r.raise_for_status()
        return r.json()


app = Starlette(routes=[Mount(f"/mcp/{PATH_SECRET}", app=mcp.sse_app())])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
