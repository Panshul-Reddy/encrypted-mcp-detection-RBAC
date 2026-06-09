FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY package.json .
RUN npm install --omit=dev

# Self-signed cert — noise server has its own identity
RUN openssl req -x509 -newkey rsa:2048 \
      -keyout key.pem -out cert.pem \
      -days 3650 -nodes \
      -subj "/CN=noise-server/O=MCPLab" \
      -addext "subjectAltName=IP:10.10.0.20,DNS:noise-server"

COPY server.js .

EXPOSE 9443
CMD ["node", "server.js"]