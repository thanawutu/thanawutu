FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# Claude Code native installer (installs to /root/.local/bin)
RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /workspace
# Claude Code reads project-scoped MCP servers from .mcp.json in the cwd
COPY mcp.json /workspace/.mcp.json

ENTRYPOINT ["tini", "--"]
# Server mode: registers with Remote Control so the Claude app on your
# tablet can attach to sessions here. Requires signing in once first
# (see README) - the login persists in the mounted claude-home volume.
CMD ["claude", "remote-control"]
