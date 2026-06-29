import http         from "http";
import fs           from "fs";
import crypto       from "crypto";
import express      from "express";
import { WebSocketServer } from "ws";

const PORT = 9444;
const app  = express();
app.use(express.json({ limit: "1mb" }));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand  = (lo, hi) => lo + Math.random() * (hi - lo);

// Pre-generated payloads
// Generate a set of realistic JSON payloads at multiple sizes.
// This avoids per-request generation overhead and produces consistent TLS record sizes.

function makeJsonPayload(targetBytes) {
  const items = [];
  const fields = ["id","ts","user","action","resource","ip","status","duration_ms","trace"];
  while (JSON.stringify({ items }).length < targetBytes) {
    const obj = {};
    fields.forEach(f => {
      switch (f) {
        case "id":          obj[f] = crypto.randomUUID(); break;
        case "ts":          obj[f] = new Date(Date.now() - rand(0,86400000)).toISOString(); break;
        case "user":        obj[f] = `user_${Math.floor(rand(0,500))}`; break;
        case "action":      obj[f] = ["read","write","delete","login","logout"][Math.floor(rand(0,5))]; break;
        case "resource":    obj[f] = `/api/v2/${crypto.randomBytes(4).toString("hex")}`; break;
        case "ip":          obj[f] = `10.${Math.floor(rand(0,256))}.${Math.floor(rand(0,256))}.${Math.floor(rand(0,256))}`; break;
        case "status":      obj[f] = [200,200,200,201,400,404,500][Math.floor(rand(0,7))]; break;
        case "duration_ms": obj[f] = Math.floor(rand(1,3000)); break;
        case "trace":       obj[f] = crypto.randomBytes(8).toString("hex"); break;
      }
    });
    items.push(obj);
  }
  return JSON.stringify({ count: items.length, items });
}

const PAYLOAD_BANK = {
  tiny:   makeJsonPayload(128),          // Approximately 128 B; fast endpoint.
  small:  makeJsonPayload(2_048),        // Approximately 2 KB.
  medium: makeJsonPayload(20_000),       // Approximately 20 KB.
  large:  makeJsonPayload(100_000),      // Approximately 100 KB.
  xlarge: makeJsonPayload(200_000),      // Approximately 200 KB.
};
console.log("[noise-server] Payload bank ready:", Object.fromEntries(
  Object.entries(PAYLOAD_BANK).map(([k,v]) => [k, `${v.length}B`])));

// Internal event bus for SSE and WS push
// The background generator pushes events to all active SSE and WebSocket subscribers.
// Rate: approximately 1–4 events per second with occasional bursts; this differs
// from MCP's request-driven notification pattern.

const sseClients = new Set();
const wsClients  = new Set();

function scheduleEventPush() {
  const n = Math.random() < 0.2 ? Math.floor(rand(3, 8)) : 1;
  for (let i = 0; i < n; i++) {
    const evt = JSON.stringify({
      id:    crypto.randomUUID(),
      ts:    new Date().toISOString(),
      type:  ["metric","log","alert","heartbeat","status"][Math.floor(rand(0,5))],
      value: parseFloat(rand(0, 1000).toFixed(3)),
      tags:  { service: ["api","db","cache"][Math.floor(rand(0,3))],
               env: "prod" },
    });

    // Push the event to SSE clients.
    for (const res of sseClients) {
      try { res.write(`data: ${evt}\n\n`); }
      catch (_) { sseClients.delete(res); }
    }
    // Push the event to WebSocket clients.
    for (const ws of wsClients) {
      if (ws.readyState === 1 /* OPEN */) {
        try { ws.send(evt); }
        catch (_) { wsClients.delete(ws); }
      }
    }
  }

  // Recursive setTimeout with a varying interval on each call.
  // This ensures inter-arrival-time variance consistent with realistic traffic patterns.
  const nextInterval = Math.floor(rand(250, 1000));
  setTimeout(scheduleEventPush, nextInterval);
}

// Start the event push loop.
scheduleEventPush();

// REST endpoints

// Fast and small; this endpoint simulates a CDN edge or cache hit.
app.get("/api/fast", async (req, res) => {
  await sleep(rand(0.5, 4));
  res.json({ ok: true, ts: Date.now(), v: crypto.randomBytes(8).toString("hex") });
});

// Endpoint that returns variable-sized payloads.
app.get("/api/data", async (req, res) => {
  const size = req.query.size ?? "medium";
  const payload = PAYLOAD_BANK[size] ?? PAYLOAD_BANK.medium;
  await sleep(rand(50, 300));
  res.setHeader("Content-Type", "application/json");
  res.send(payload);
});

// Submission endpoint: clients send payloads and the server returns a small acknowledgment.
// This exercises client-to-server byte asymmetry, which contrasts with MCP tool calls.
app.post("/api/submit", async (req, res) => {
  await sleep(rand(10, 80));
  res.json({
    accepted: true,
    id:       crypto.randomUUID(),
    ts:       new Date().toISOString(),
    bytes:    JSON.stringify(req.body).length,
  });
});

// Poll endpoint with bimodal behavior: 40% of requests return empty responses (HTTP 204)
// and 60% return a batch of events.
app.get("/api/poll", async (req, res) => {
  await sleep(rand(5, 30));
  if (Math.random() < 0.4) {
    res.status(204).send();
    return;
  }
  const n = Math.floor(rand(1, 15));
  const items = Array.from({ length: n }, () => ({
    id:    crypto.randomUUID(),
    ts:    new Date().toISOString(),
    event: ["msg","task","alert"][Math.floor(rand(0,3))],
    data:  crypto.randomBytes(32).toString("hex"),
  }));
  res.json({ count: n, items });
});

// Chunked transfer streaming
// Long-lived HTTP/1.1 connection. The server transmits chunks over 5–30 seconds.
// This is structurally similar to SSE, but it uses raw chunked encoding and
// therefore produces a different TLS record pattern.

app.get("/stream/chunked", async (req, res) => {
  res.setHeader("Content-Type",     "application/octet-stream");
  res.setHeader("Transfer-Encoding","chunked");
  res.setHeader("Cache-Control",    "no-cache");
  res.flushHeaders();

  const duration  = rand(5000, 30000);
  const chunkSize = Math.floor(rand(64, 2048));     // bytes per chunk
  const interval  = rand(100, 800);                  // ms between chunks
  const n_chunks  = Math.floor(duration / interval);

  for (let i = 0; i < n_chunks; i++) {
    if (res.destroyed) break;
    try {
      res.write(crypto.randomBytes(chunkSize));
      await sleep(interval * (0.5 + Math.random()));
    } catch (_) { break; }
  }
  res.end();
});

// Server-Sent Events (non-MCP)
// Long-lived connection. The server pushes JSON events from the internal bus.
// This is the most challenging negative case: the transport matches MCP SSE, but the
// message structure, timing distribution, and absence of a POST channel differ.

app.get("/stream/sse", (req, res) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  // Send an initial connection event.
  res.write(`event: connected\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);

  sseClients.add(res);

  // Send a heartbeat every 15 seconds to keep the connection alive.
  const hb = setInterval(() => {
    try { res.write(`: heartbeat ${Date.now()}\n\n`); }
    catch (_) { clearInterval(hb); }
  }, 15000);

  req.on("close", () => {
    clearInterval(hb);
    sseClients.delete(res);
  });
});

// JSON-RPC 2.0 endpoint (Hard Negative for MCP detection)
// This mirrors MCP's HTTPS + JSON-RPC request-response cadence but uses
// non-MCP method names and lacks MCP-specific shapes (no tools/list, no SSE channel).
// The TLS record patterns and timing are intentionally similar to MCP RPC traffic.

const JSONRPC_METHODS = {
  "system.status": async () => {
    await sleep(rand(1, 8));
    return {
      uptime_s: Math.floor(process.uptime()),
      memory_mb: Math.floor(process.memoryUsage().rss / 1024 / 1024),
      version: "2.4.1",
      healthy: true,
      ts: new Date().toISOString(),
    };
  },

  "data.query": async (params) => {
    const limit = Math.min(params?.limit ?? 50, 500);
    await sleep(rand(20, 200));
    const rows = Array.from({ length: limit }, (_, i) => ({
      id: crypto.randomUUID(),
      ts: new Date(Date.now() - rand(0, 86400000)).toISOString(),
      metric: parseFloat(rand(0, 1000).toFixed(3)),
      source: ["sensor-a", "sensor-b", "gateway", "edge"][Math.floor(rand(0, 4))],
    }));
    return { count: rows.length, rows };
  },

  "config.get": async (params) => {
    const key = params?.key ?? "default";
    await sleep(rand(1, 5));
    const configs = {
      default:   { log_level: "info", retention_days: 30, max_connections: 100 },
      security:  { tls_version: "1.3", cert_expiry: "2027-01-01", mfa_enabled: true },
      limits:    { rate_limit_rps: 500, burst: 50, timeout_ms: 30000 },
      features:  { dark_mode: true, beta_api: false, webhooks: true },
    };
    return configs[key] ?? configs.default;
  },

  "job.submit": async (params) => {
    const job_type = params?.type ?? "process";
    await sleep(rand(5, 30));
    return {
      job_id: crypto.randomUUID(),
      status: "queued",
      type: job_type,
      estimated_ms: Math.floor(rand(2000, 10000)),
      created_at: new Date().toISOString(),
    };
  },

  "metrics.fetch": async (params) => {
    const window = params?.window_m ?? 60;
    const points = Math.min(Math.floor(window), 120);
    await sleep(rand(30, 150));
    const series = Array.from({ length: points }, (_, i) => ({
      t: Date.now() - (points - i) * 60000,
      cpu: parseFloat(rand(5, 95).toFixed(1)),
      mem: parseFloat(rand(20, 80).toFixed(1)),
      iops: Math.floor(rand(100, 5000)),
    }));
    return { window_m: window, points: series.length, series };
  },

  "echo": async (params) => {
    await sleep(rand(0.5, 3));
    return { echo: true, params, ts: Date.now() };
  },
};

app.post("/jsonrpc", async (req, res) => {
  const body = req.body;

  // Validate JSON-RPC 2.0 envelope
  if (!body || body.jsonrpc !== "2.0" || !body.method) {
    return res.json({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid Request" },
      id: body?.id ?? null,
    });
  }

  const handler = JSONRPC_METHODS[body.method];
  if (!handler) {
    return res.json({
      jsonrpc: "2.0",
      error: { code: -32601, message: "Method not found", data: { method: body.method } },
      id: body.id,
    });
  }

  try {
    const result = await handler(body.params ?? {});
    res.json({ jsonrpc: "2.0", result, id: body.id });
  } catch (err) {
    res.json({
      jsonrpc: "2.0",
      error: { code: -32603, message: "Internal error", data: err.message },
      id: body.id,
    });
  }
});

// HTTPS server and WebSocket upgrade

const httpServer = http.createServer(app);

// WebSocket server attached to the same HTTP server (WS).
const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

wss.on("connection", (ws, req) => {
  wsClients.add(ws);
  console.log(`[ws] connect   total=${wsClients.size}`);

  // Immediately send a welcome frame.
  ws.send(JSON.stringify({ type: "welcome", ts: Date.now(),
    session: crypto.randomBytes(8).toString("hex") }));

  // Periodic server-initiated push, independent of client messages.
  // The rate varies per connection and simulates dashboard or ticker behaviour.
  const pushInterval = rand(300, 3000);
  const pushTimer = setInterval(() => {
    if (ws.readyState !== 1) { clearInterval(pushTimer); return; }
    // Variable-size push messages.
    const size = Math.random() < 0.7 ? "small" : Math.random() < 0.8 ? "medium" : "tiny";
    const sizeBytes = { tiny: 64, small: 512, medium: 4096 }[size];
    try {
      ws.send(JSON.stringify({
        type:  "push",
        ts:    Date.now(),
        seq:   Math.floor(rand(0, 100000)),
        data:  crypto.randomBytes(sizeBytes).toString("base64").slice(0, sizeBytes),
      }));
    } catch (_) { clearInterval(pushTimer); }
  }, pushInterval);

  // Echo client messages back with a small transformation.
  ws.on("message", (msg) => {
    try {
      const parsed = JSON.parse(msg.toString());
      ws.send(JSON.stringify({ type: "ack", echo: true,
        original_type: parsed.type ?? "unknown",
        ts: Date.now() }));
    } catch (_) {
      ws.send(JSON.stringify({ type: "ack", echo: true, ts: Date.now() }));
    }
  });

  ws.on("close", () => {
    clearInterval(pushTimer);
    wsClients.delete(ws);
    console.log(`[ws] disconnect total=${wsClients.size}`);
  });

  ws.on("error", () => {
    clearInterval(pushTimer);
    wsClients.delete(ws);
  });
});

httpServer.listen(PORT, () => {
  console.log(`[noise-server] HTTP+WS listening on port ${PORT}`);
  console.log(`[noise-server] Endpoints: /api/fast /api/data /api/submit /api/poll`);
  console.log(`[noise-server]            /stream/chunked /stream/sse  wss://.../ws`);
  console.log(`[noise-server]            /jsonrpc (JSON-RPC 2.0 hard negative)`);
});