FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY package.json .
RUN npm install --omit=dev

COPY server.js .

EXPOSE 9444
CMD ["node", "server.js"]