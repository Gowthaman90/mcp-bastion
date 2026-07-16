# Container image so MCP catalogs (e.g. Glama) can start mcp-bastion and introspect it over stdio.
#
# mcp-bastion is a security *proxy*: it needs at least one upstream server to run. For a
# self-contained introspection start, this image fronts the official reference server
# (@modelcontextprotocol/server-everything), so a `tools/list` returns that server's tools
# (namespaced `everything__*`) alongside Bastion's own `bastion__*` control tools.
#
# This image is for catalog listing / smoke-testing, not a production deployment — for real use,
# point Bastion at your own MCP servers via a config file (see the README).
FROM node:20-slim

WORKDIR /app

# Build Bastion from source (lockfile present -> reproducible install).
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# A reference upstream, pre-installed so runtime needs no network fetch during introspection.
# It exposes the bin `mcp-server-everything` on PATH.
RUN npm install -g @modelcontextprotocol/server-everything

# Minimal demo config: front the reference server by its installed bin; no health checks
# for a clean single-shot start.
RUN printf '%s' '{"servers":{"everything":{"command":"mcp-server-everything"}},"reconnect":{"auto":false},"healthCheck":{"enabled":false}}' > /app/glama.config.json

# Bastion speaks MCP over stdio by default — exactly what catalog introspection expects.
ENTRYPOINT ["node", "dist/cli.js", "--config", "/app/glama.config.json"]
