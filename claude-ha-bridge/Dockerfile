FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates ttyd tini \
    && rm -rf /var/lib/apt/lists/*

# Claude Code native installer (installs to /root/.local/bin)
RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /workspace
# Claude Code reads project-scoped MCP servers from .mcp.json in the cwd
COPY mcp.json /workspace/.mcp.json

EXPOSE 7681

ENTRYPOINT ["tini", "--"]
# ttyd serves a terminal in the browser; -W allows keyboard input,
# credentials come from TTYD_USER/TTYD_PASS at runtime (see compose file)
CMD ["sh", "-c", "ttyd -W -p 7681 -c ${TTYD_USER}:${TTYD_PASS} claude"]
