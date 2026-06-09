FROM node:20-slim

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g \
    @modelcontextprotocol/server-filesystem \
    @modelcontextprotocol/server-memory \
    @modelcontextprotocol/server-github \
    fetch-mcp \
    exa-mcp-server \
    tavily-mcp \
    mcp-proxy

WORKDIR /app
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Create dummy directory for filesystem server
RUN mkdir -p /tmp/mcp-test && echo "hello world" > /tmp/mcp-test/hello.txt

CMD ["/app/start.sh"]
