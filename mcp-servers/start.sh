#!/bin/bash
set -e

echo "Starting MCP servers..."

# 3000: Fetch
mcp-proxy --port 3000 npx fetch-mcp &

# 3001: Memory
mcp-proxy --port 3001 npx @modelcontextprotocol/server-memory &

# 3002: Filesystem
mcp-proxy --port 3002 npx @modelcontextprotocol/server-filesystem /tmp/mcp-test &

# 3003: GitHub
mcp-proxy --port 3003 npx @modelcontextprotocol/server-github &

# 3004: Exa
mcp-proxy --port 3004 npx exa-mcp-server &

# 3005: Tavily
mcp-proxy --port 3005 npx tavily-mcp &

echo "All MCP servers started. Tailing logs..."
wait
