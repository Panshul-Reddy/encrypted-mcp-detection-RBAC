import express      from "express";
import https        from "https";
import fs           from "fs";
import fsPromises   from "fs/promises";
import path         from "path";
import { spawn }    from "child_process";
import crypto       from "crypto";
import sqlite3      from "sqlite3";

import { McpServer }          from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z }                  from "zod";

// Constants

const PORT    = 8443;
const SANDBOX = "/app/sandbox";

// Global state for tool backends

// Key-value store pre-populated with realistic session, config, and cache keys.
const kvStore = new Map();
(function initKv() {
  const prefixes = ["session", "config", "cache", "lock", "feature"];
  // Addressable by the client (session:000 through session:099).
  for (let i = 0; i < 100; i++) {
    kvStore.set(`session:${String(i).padStart(3, "0")}`, JSON.stringify({
      user:    `user_${i % 50}`,
      token:   crypto.randomBytes(24).toString("hex"),
      expires: Date.now() + 3_600_000,
      scopes:  ["read", "write"].slice(0, (i % 2) + 1),
    }));
  }
  // Background keys.
  for (let i = 0; i < 400; i++) {
    const prefix = prefixes[i % prefixes.length];
    kvStore.set(`${prefix}:${crypto.randomBytes(4).toString("hex")}`, JSON.stringify({
      v:   crypto.randomBytes(16).toString("hex"),
      ts:  Date.now() - Math.floor(Math.random() * 86_400_000),
      ttl: 300 + Math.floor(Math.random() * 7200),
    }));
  }
  console.log(`[kv] Initialized with ${kvStore.size} key-value pairs`);
})();

// Message queue: the background process enqueues events at approximately 1 Hz with occasional bursts.
const messageQueue = [];
const MQ_TOPICS = [
  "user.created", "user.deleted", "order.placed", "order.cancelled",
  "payment.done", "payment.failed", "alert.triggered", "job.complete",
  "metric.spike", "audit.event",
];
setInterval(() => {
  if (messageQueue.length >= 500) return;
  // Mostly single events, with occasional bursts of 3 to 8 events.
  const n = Math.random() < 0.15 ? Math.floor(Math.random() * 7) + 2 : 1;
  for (let i = 0; i < n; i++) {
    messageQueue.push({
      id:      crypto.randomUUID(),
      ts:      new Date().toISOString(),
      topic:   MQ_TOPICS[Math.floor(Math.random() * MQ_TOPICS.length)],
      payload: {
        entity_id: crypto.randomUUID(),
        data:      crypto.randomBytes(48).toString("hex"),
        meta:      { source: "internal", version: 2 },
      },
    });
  }
}, 900);

// Asynchronous job registry: jobId to { status, createdAt, result? }
const jobRegistry = new Map();
const JOB_TYPES   = ["etl", "report", "index", "backup", "aggregate", "export"];

// Sandbox

function initSandbox() {
  const dirs = [SANDBOX, `${SANDBOX}/logs`, `${SANDBOX}/config`,
                `${SANDBOX}/data`, `${SANDBOX}/scripts`];
  dirs.forEach((d) => fs.mkdirSync(d, { recursive: true }));

  const files = {
    [`${SANDBOX}/README.md`]:
      `# Internal Tooling Sandbox\n\nManaged by MCP server v4.0.\n` +
      `Generated: ${new Date().toISOString()}\n`,

    [`${SANDBOX}/config/app.json`]: JSON.stringify({
      environment: "production",
      log_level:   "info",
      db_pool:     { min: 2, max: 20, idle_timeout: 30000 },
      features:    { auth_v2: true, rate_limit: true, audit_log: true,
                     dark_mode: false, beta_ui: false },
      services:    { auth: "auth-svc:9000", cache: "redis:6379",
                     queue: "rabbitmq:5672" },
    }, null, 2),

    [`${SANDBOX}/config/services.yaml`]:
      `services:\n  auth:\n    host: auth-svc\n    port: 9000\n    timeout: 5s\n` +
      `  db-proxy:\n    host: db-proxy\n    port: 5432\n    pool_size: 20\n` +
      `  cache:\n    host: redis\n    port: 6379\n    max_memory: 512mb\n` +
      `  queue:\n    host: rabbitmq\n    port: 5672\n    vhost: /prod\n`,

    [`${SANDBOX}/data/users.csv`]:
      ["id,username,email,role,created_at",
       ...Array.from({ length: 100 }, (_, i) =>
         `${i + 1},user_${i + 1},user_${i + 1}@corp.internal,` +
         `${["admin","viewer","editor","service-account"][i % 4]},2024-${String((i%12)+1).padStart(2,"0")}-01`)
      ].join("\n"),

    [`${SANDBOX}/scripts/deploy.sh`]:
      `#!/bin/bash\nset -euo pipefail\n` +
      `echo "Deploying \${SERVICE:-app}..."\n` +
      `docker pull \${IMAGE:-app:latest}\n` +
      `docker service update --image \${IMAGE} \${SERVICE:-app}\n` +
      `echo "Health-checking..."\nsleep 5\ncurl -sf http://localhost/health\n` +
      `echo "Deploy complete."\n`,

    [`${SANDBOX}/logs/app.log`]:
      Array.from({ length: 500 }, (_, i) => {
        const levels = ["INFO","WARN","ERROR","DEBUG"];
        const svcs   = ["auth","api-gateway","scheduler","worker","db-proxy"];
        return `2024-${String((i%12)+1).padStart(2,"0")}-${String((i%28)+1).padStart(2,"0")}T` +
               `${String(i%24).padStart(2,"0")}:${String(i%60).padStart(2,"0")}:00Z ` +
               `[${levels[i%4]}] ${svcs[i%5]}: event_${i} ` +
               `trace=${crypto.randomBytes(8).toString("hex")} ` +
               `duration=${Math.floor(Math.random()*2000)}ms`;
      }).join("\n"),
  };

  Object.entries(files).forEach(([fpath, content]) => {
    if (!fs.existsSync(fpath)) fs.writeFileSync(fpath, content);
  });
  console.log("[sandbox] Initialized at", SANDBOX);
}

// SQLite

const db = new sqlite3.Database("./dummy.db");

function initDb() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT DEFAULT (datetime('now')),
      level TEXT, service TEXT, message TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT, email TEXT, role TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, body TEXT, author TEXT, tags TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    )`);

    const levels   = ["INFO","WARN","ERROR","DEBUG"];
    const services = ["auth","api-gateway","db-proxy","scheduler","worker"];
    const roles    = ["admin","viewer","editor","service-account"];
    const docTags  = ["security","ops","finance","hr","eng","infra","legal"];

    db.get("SELECT COUNT(*) as c FROM logs", (_, r) => {
      if (r?.c > 0) return;
      const s = db.prepare("INSERT INTO logs (level,service,message) VALUES (?,?,?)");
      for (let i = 0; i < 8000; i++)
        s.run(levels[i%4], services[i%5],
              `event_${i}: req_id=${crypto.randomBytes(8).toString("hex")} ` +
              `duration=${Math.floor(Math.random()*3000)}ms status=${[200,200,200,400,500][i%5]}`);
      s.finalize();
    });
    db.get("SELECT COUNT(*) as c FROM users", (_, r) => {
      if (r?.c > 0) return;
      const s = db.prepare("INSERT INTO users (username,email,role) VALUES (?,?,?)");
      for (let i = 0; i < 500; i++)
        s.run(`user_${i}`, `user_${i}@corp.internal`, roles[i%4]);
      s.finalize();
    });
    db.get("SELECT COUNT(*) as c FROM documents", (_, r) => {
      if (r?.c > 0) return;
      const s = db.prepare("INSERT INTO documents (title,body,author,tags) VALUES (?,?,?,?)");
      // Structured document bodies that resemble realistic content rather than random bytes.
      const templates = [
        "This document describes the operational procedure for {topic}. " +
        "Follow these steps carefully to ensure system stability. " +
        "Last reviewed by the platform team on {date}.",
        "## {topic} Runbook\n\nThis runbook covers incident response for {topic}. " +
        "Severity levels: P0 (page immediately), P1 (page within 15m), P2 (next business day).",
        "Access to {topic} requires approval from the security team. " +
        "Submit a request via the internal ticketing system with justification.",
      ];
      const topics = ["database failover","auth service","rate limiting","cache eviction",
                      "deployment pipeline","monitoring alerts","backup verification"];
      for (let i = 0; i < 800; i++) {
        const tmpl  = templates[i % templates.length];
        const topic = topics[i % topics.length];
        const body  = tmpl.replace(/{topic}/g, topic)
                          .replace(/{date}/g, `2024-${String((i%12)+1).padStart(2,"0")}-01`);
        // Pad the document body to create variable sizes (1x to 8x the template).
        const padding = "\n\nAdditional context: " + "x".repeat((i % 7) * 120);
        s.run(`${topic} — doc ${i}`, body + padding,
              `author_${i%20}`, docTags[i%docTags.length]);
      }
      s.finalize();
    });
  });
  console.log("[db] Initialized");
}

// Helpers

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function latency(fastMs = 60, slowMs = 1500, slowProb = 0.15) {
  return Math.random() < slowProb
    ? slowMs  + Math.random() * slowMs
    : fastMs  + Math.random() * fastMs * 3;
}

const dbAll = (q, p = []) => new Promise((res, rej) =>
  db.all(q, p, (e, rows) => e ? rej(e) : res(rows)));
const dbGet = (q, p = []) => new Promise((res, rej) =>
  db.get(q, p, (e, row)  => e ? rej(e) : res(row)));
const dbRun = (q, p = []) => new Promise((res, rej) =>
  db.run(q, p, function(e) { e ? rej(e) : res(this); }));

function sandboxPath(userPath) {
  const resolved = path.resolve(SANDBOX, userPath.replace(/^\/+/, ""));
  if (!resolved.startsWith(SANDBOX)) throw new Error("Path traversal denied");
  return resolved;
}

// Generate a structured blob artifact with a specified target size in bytes.
function makeBlobArtifact(artifactType, targetBytes) {
  const header = {
    type:       artifactType,
    version:    "1.0",
    generated:  new Date().toISOString(),
    checksum:   crypto.randomBytes(16).toString("hex"),
    schema:     `https://internal.corp/schemas/${artifactType}/v1`,
  };

  let body;
  switch (artifactType) {
    case "log_archive": {
      const entries = [];
      const levels   = ["INFO","WARN","ERROR","DEBUG"];
      const services = ["auth","gateway","worker","scheduler","cache"];
      while (JSON.stringify({ header, entries }).length < targetBytes) {
        entries.push({
          ts:      new Date(Date.now() - Math.random()*86_400_000).toISOString(),
          level:   levels[Math.floor(Math.random()*4)],
          service: services[Math.floor(Math.random()*5)],
          msg:     `event_${crypto.randomBytes(4).toString("hex")} duration=${Math.floor(Math.random()*2000)}ms`,
          trace:   crypto.randomBytes(8).toString("hex"),
        });
      }
      body = { header, entries };
      break;
    }
    case "config_snapshot": {
      const config = { header, services: {}, feature_flags: {}, limits: {} };
      const svcNames = ["auth","api","cache","db","queue","worker","scheduler"];
      svcNames.forEach((svc) => {
        config.services[svc] = {
          host: `${svc}.internal`, port: 8000 + Math.floor(Math.random()*1000),
          tls: true, timeout_ms: 5000, max_conns: 100,
          env: { LOG_LEVEL: "info", METRICS: "true" },
        };
      });
      while (JSON.stringify(config).length < targetBytes) {
        config.feature_flags[`flag_${crypto.randomBytes(4).toString("hex")}`] = Math.random() > 0.5;
        config.limits[`limit_${crypto.randomBytes(4).toString("hex")}`] = Math.floor(Math.random()*10000);
      }
      body = config;
      break;
    }
    case "metrics_dump": {
      const metrics = { header, series: [] };
      const metricNames = ["req_rate","error_rate","p99_latency","cache_hit","db_conns","cpu_util"];
      const now = Date.now();
      while (JSON.stringify(metrics).length < targetBytes) {
        metricNames.forEach((name) => {
          metrics.series.push({
            name, service: "api",
            points: Array.from({length:10}, (_, i) => ({
              ts: new Date(now - (10-i)*60000).toISOString(),
              v:  parseFloat((Math.random()*100).toFixed(3)),
            })),
          });
        });
      }
      body = metrics;
      break;
    }
    default: { // audit_export
      const events = { header, audit_events: [] };
      const actions = ["login","logout","read","write","delete","admin.grant","config.change"];
      while (JSON.stringify(events).length < targetBytes) {
        events.audit_events.push({
          id:        crypto.randomUUID(),
          ts:        new Date(Date.now() - Math.random()*604_800_000).toISOString(),
          actor:     `user_${Math.floor(Math.random()*100)}`,
          action:    actions[Math.floor(Math.random()*actions.length)],
          resource:  `/api/v2/${crypto.randomBytes(4).toString("hex")}`,
          ip:        `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
          outcome:   Math.random() > 0.05 ? "success" : "denied",
        });
      }
      body = events;
    }
  }
  return JSON.stringify(body);
}

// MCP server factory

function createMcpServer() {
  const mcp = new McpServer({ name: "Secure-MCP", version: "4.0.0" });

  async function sendChunk(data, logger = "stream") {
    try {
      await mcp.server.notification({
        method: "notifications/message",
        params: { level: "info", logger, data },
      });
    } catch (_) { /* Client disconnected. */ }
  }

  // SQL backend: variable latency and JSON payloads

  // Tool 1: query_logs
  mcp.tool("query_logs", {
    limit:   z.number().int().min(1).max(5000).describe("Rows to fetch"),
    level:   z.enum(["INFO","WARN","ERROR","DEBUG","ALL"]).default("ALL"),
    service: z.string().optional(),
  }, async ({ limit, level, service }) => {
    await sleep(latency(80, 2000, 0.2));
    const wheres = [], params = [];
    if (level !== "ALL") { wheres.push("level=?");   params.push(level);   }
    if (service)         { wheres.push("service=?"); params.push(service); }
    const where = wheres.length ? `WHERE ${wheres.join(" AND ")}` : "";
    params.push(limit);
    const rows = await dbAll(
      `SELECT * FROM logs ${where} ORDER BY RANDOM() LIMIT ?`, params);
    return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
  });

  // Tool 2: get_user
  mcp.tool("get_user", {
    user_id:  z.number().int().optional(),
    username: z.string().optional(),
  }, async ({ user_id, username }) => {
    await sleep(latency(10, 200, 0.05));
    const [q, p] = user_id
      ? ["SELECT * FROM users WHERE id=?",       [user_id]]
      : ["SELECT * FROM users WHERE username=?", [username ?? "user_1"]];
    const row = await dbGet(q, p);
    return { content: [{ type: "text", text: JSON.stringify(row ?? {}) }] };
  });

  // Tool 3: search_documents
  mcp.tool("search_documents", {
    query: z.string(),
    limit: z.number().int().min(1).max(50).default(10),
    tag:   z.string().optional(),
  }, async ({ query, limit, tag }) => {
    await sleep(latency(150, 800, 0.1));
    const params = [`%${query}%`];
    let q = "SELECT id,title,author,tags,updated_at FROM documents WHERE title LIKE ?";
    if (tag) { q += " AND tags=?"; params.push(tag); }
    q += " LIMIT ?"; params.push(limit);
    const rows = await dbAll(q, params);
    return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
  });

  // Tool 4: generate_report
  // Intentionally slow (1–8 seconds) to simulate resource-intensive report generation.
  mcp.tool("generate_report", {
    report_type: z.enum(["summary","audit","compliance","activity"]),
    days:        z.number().int().min(1).max(90).default(7),
  }, async ({ report_type, days }) => {
    await sleep(1000 + Math.random() * 7000);
    const stats = await dbAll(
      "SELECT service, level, COUNT(*) as count FROM logs GROUP BY service, level");
    const topUsers = await dbAll(
      "SELECT username, role, created_at FROM users ORDER BY RANDOM() LIMIT 10");

    // Structured report content rather than pseudorandom bytes.
    const sections = [
      { title: "Executive Summary",
        body: `This ${report_type} report covers the last ${days} days of platform activity. ` +
              `Total events processed: ${8000 + Math.floor(Math.random()*2000)}. ` +
              `Error rate: ${(Math.random()*2).toFixed(2)}%. SLA compliance: ${(97+Math.random()*3).toFixed(1)}%.` },
      { title: "Service Health",
        body: stats.map(r => `${r.service}/${r.level}: ${r.count} events`).join(" | ") },
      { title: "User Activity",
        body: topUsers.map(u => `${u.username} (${u.role})`).join(", ") },
      { title: "Recommendations",
        body: "Review error spike in auth service. Consider increasing db-proxy pool size. " +
              "Rotate service account tokens due within 30 days." },
      { title: "Compliance Notes",
        body: `Audit log retention: ${days * 2} days. PII fields encrypted at rest. ` +
              `Last pen-test: 2024-09-01. Next scheduled: 2025-03-01.` },
    ];

    const report = {
      type: report_type, generated_at: new Date().toISOString(),
      period_days: days, stats, top_users: topUsers, sections,
    };
    return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
  });

  // Tool 5: update_record
  mcp.tool("update_record", {
    table: z.enum(["logs","users","documents"]),
    id:    z.number().int(),
    field: z.string(),
    value: z.string(),
  }, async ({ table, id, field, value }) => {
    await sleep(latency(30, 300, 0.08));
    const allowed = {
      logs:      ["message","level"],
      users:     ["role"],
      documents: ["title","tags"],
    };
    if (!allowed[table]?.includes(field))
      return { content: [{ type: "text",
        text: JSON.stringify({ error: "Field not allowed" }) }] };
    const result = await dbRun(
      `UPDATE ${table} SET ${field}=? WHERE id=?`, [value, id]);
    return { content: [{ type: "text",
      text: JSON.stringify({ updated: result.changes, table, id }) }] };
  });

  // Tool 6: list_tables
  // Deliberately fast and small; this models schema discovery.
  mcp.tool("list_tables", {}, async () => {
    await sleep(5 + Math.random() * 15);
    const rows = await dbAll(
      "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name");
    // Return column names as well to better reflect realistic responses.
    const enriched = await Promise.all(rows.map(async (r) => {
      const cols = await dbAll(`PRAGMA table_info(${r.name})`);
      return { table: r.name, columns: cols.map(c => ({ name: c.name, type: c.type })) };
    }));
    return { content: [{ type: "text", text: JSON.stringify(enriched, null, 2) }] };
  });

  // Health checks: fast, small, and under 10 ms

  // Tool 7: health_check
  mcp.tool("health_check", {
    verbose: z.boolean().default(false),
  }, async ({ verbose }) => {
    await sleep(2 + Math.random() * 8);
    const resp = {
      status: "ok", timestamp: new Date().toISOString(),
      ...(verbose && {
        db:      "connected",
        kv_keys: kvStore.size,
        mq_depth: messageQueue.length,
        jobs:    { active: [...jobRegistry.values()].filter(j=>j.status==="running").length,
                   total:  jobRegistry.size },
        uptime:  process.uptime(),
        memory:  process.memoryUsage(),
      }),
    };
    return { content: [{ type: "text", text: JSON.stringify(resp) }] };
  });

  // Filesystem tools: under 30 ms with small-to-medium payloads

  // Tool 8: list_directory
  mcp.tool("list_directory", {
    dir_path: z.string().default("/").describe("Path relative to sandbox root"),
  }, async ({ dir_path }) => {
    await sleep(5 + Math.random() * 25);
    const abs = sandboxPath(dir_path);
    const entries = await fsPromises.readdir(abs, { withFileTypes: true });
    const listing = entries.map((e) => ({
      name: e.name,
      type: e.isDirectory() ? "dir" : "file",
      ...(e.isFile() && { size: fs.statSync(path.join(abs, e.name)).size }),
    }));
    return { content: [{ type: "text", text: JSON.stringify(listing, null, 2) }] };
  });

  // Tool 9: read_file
  mcp.tool("read_file", {
    file_path: z.string().describe("Path relative to sandbox root"),
    max_bytes: z.number().int().min(1).max(65536).default(16384),
  }, async ({ file_path, max_bytes }) => {
    await sleep(latency(20, 200, 0.05));
    const abs = sandboxPath(file_path);
    const fd  = await fsPromises.open(abs, "r");
    const buf = Buffer.alloc(max_bytes);
    const { bytesRead } = await fd.read(buf, 0, max_bytes, 0);
    await fd.close();
    return { content: [{ type: "text",
      text: buf.subarray(0, bytesRead).toString("utf8") }] };
  });

  // Shell streaming: small notification packets with tight inter-arrival times

  // Tool 10: run_shell
  const ALLOWED_CMDS = {
    ls:      { bin: "ls",    args: ["-la", SANDBOX] },
    ps:      { bin: "ps",    args: ["aux"] },
    df:      { bin: "df",    args: ["-h"] },
    uptime:  { bin: "uptime",args: [] },
    free:    { bin: "free",  args: ["-h"] },
    env:     { bin: "env",   args: [] },
    netstat: { bin: "ss",    args: ["-tnp"] },
    wc_logs: { bin: "wc",    args: ["-l", `${SANDBOX}/logs/app.log`] },
    find:    { bin: "find",  args: [SANDBOX, "-type", "f"] },
  };

  mcp.tool("run_shell", {
    command:     z.enum(Object.keys(ALLOWED_CMDS)),
    chunk_lines: z.number().int().min(1).max(20).default(5)
                  .describe("Lines per streamed notification"),
  }, async ({ command, chunk_lines }) => {
    const { bin, args } = ALLOWED_CMDS[command];
    const allLines = [];
    let   pending  = [];

    return new Promise((resolve) => {
      const proc = spawn(bin, args, { timeout: 15000 });

      const flushChunk = () => {
        if (pending.length === 0) return Promise.resolve();
        const data = pending.join("\n");
        pending = [];
        return sendChunk(data, "run_shell");
      };

      proc.stdout.on("data", (data) => {
        const lines = data.toString().split("\n").filter(Boolean);
        allLines.push(...lines);
        pending.push(...lines);
        if (pending.length >= chunk_lines) flushChunk().catch(() => {});
      });
      proc.stderr.on("data", (data) => {
        allLines.push(`[stderr] ${data.toString().trim()}`);
      });
      proc.on("close", async (code) => {
        await flushChunk();
        resolve({ content: [{ type: "text",
          text: JSON.stringify({ exit_code: code, output: allLines.join("\n") }) }] });
      });
      proc.on("error", (err) => {
        resolve({ content: [{ type: "text",
          text: JSON.stringify({ error: err.message }) }] });
      });
    });
  });

  // SSE streaming: sustained low-bandwidth output with jittered inter-arrival times

  // Tool 11: stream_logs
  mcp.tool("stream_logs", {
    limit:       z.number().int().min(1).max(200).default(50),
    chunk_size:  z.number().int().min(1).max(20).default(5),
    interval_ms: z.number().int().min(10).max(2000).default(150),
    level:       z.enum(["INFO","WARN","ERROR","DEBUG","ALL"]).default("ALL"),
  }, async ({ limit, chunk_size, interval_ms, level }) => {
    const params = [];
    let q = "SELECT * FROM logs";
    if (level !== "ALL") { q += " WHERE level=?"; params.push(level); }
    q += " ORDER BY RANDOM() LIMIT ?"; params.push(limit);
    const rows = await dbAll(q, params);

    for (let i = 0; i < rows.length; i += chunk_size) {
      await sendChunk(JSON.stringify(rows.slice(i, i + chunk_size)), "stream_logs");
      // Bursty jitter: most intervals remain near the baseline, with occasional long pauses.
      const jitter = Math.random() < 0.15
        ? interval_ms * (2.0 + Math.random() * 3.0)   // Occasional long pause.
        : interval_ms * (0.6 + Math.random() * 0.8);  // Normal jitter.
      await sleep(jitter);
    }
    return { content: [{ type: "text",
      text: JSON.stringify({ streamed: rows.length, status: "complete" }) }] };
  });

  // Outbound HTTP: external round-trip-time variance and variable payload size

  // Tool 12: fetch_url
  const ALLOWED_URLS = [
    "https://httpbin.org/get",
    "https://httpbin.org/uuid",
    "https://httpbin.org/headers",
    "https://hacker-news.firebaseio.com/v0/topstories.json",
    "https://api.github.com/events",
    "https://jsonplaceholder.typicode.com/posts",
    "https://jsonplaceholder.typicode.com/users",
    "https://api.open-meteo.com/v1/forecast?latitude=51.5&longitude=-0.1&current_weather=true",
  ];

  mcp.tool("fetch_url", {
    url:       z.enum(ALLOWED_URLS),
    max_bytes: z.number().int().min(1).max(32768).default(8192),
  }, async ({ url, max_bytes }) => {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 10000);
    try {
      const resp    = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "MCP-Server/4.0" },
      });
      const text    = await resp.text();
      const trimmed = text.slice(0, max_bytes);
      return { content: [{ type: "text", text: JSON.stringify({
        url,
        status: resp.status,
        content_length: text.length,
        truncated: text.length > max_bytes,
        body: trimmed,
      }) }] };
    } catch (err) {
      return { content: [{ type: "text",
        text: JSON.stringify({ error: err.message, url }) }] };
    } finally {
      clearTimeout(timeout);
    }
  });

  // In-memory key-value store: sub-5 ms, tiny payloads, and the fastest tool class

  // Tool 13: kv_get
  mcp.tool("kv_get", {
    key: z.string().describe("Key to look up (e.g. session:042, config:abc12ef3)"),
  }, async ({ key }) => {
    await sleep(0.5 + Math.random() * 3);   // sub-5ms
    const value = kvStore.get(key);
    return { content: [{ type: "text",
      text: JSON.stringify(value !== undefined
        ? { hit: true,  key, value: JSON.parse(value) }
        : { hit: false, key }) }] };
  });

  // Tool 14: kv_set
  // Client-to-server asymmetry: the request contains a payload, while the response is a small acknowledgment.
  mcp.tool("kv_set", {
    key:   z.string(),
    value: z.string().describe("Value to store (will be JSON-encoded)"),
    ttl:   z.number().int().min(1).max(86400).default(3600).describe("TTL in seconds"),
  }, async ({ key, value, ttl }) => {
    await sleep(0.5 + Math.random() * 3);
    kvStore.set(key, JSON.stringify({ value, ts: Date.now(), ttl }));
    return { content: [{ type: "text",
      text: JSON.stringify({ ok: true, key, ttl }) }] };
  });

  // Binary blob responses: 50–500 ms with large TLS records (10–100 KB)

  // Tool 15: fetch_blob
  mcp.tool("fetch_blob", {
    artifact: z.enum(["log_archive","config_snapshot","metrics_dump","audit_export"]),
    max_kb:   z.number().int().min(5).max(100).default(25)
               .describe("Approximate maximum response size in KB"),
  }, async ({ artifact, max_kb }) => {
    // Latency scales with size; larger blobs take longer to load.
    await sleep(50 + max_kb * 3 + Math.random() * 200);
    const blob = makeBlobArtifact(artifact, max_kb * 1024);
    return { content: [{ type: "text", text: JSON.stringify({
      artifact, size_bytes: blob.length, data: blob,
    }) }] };
  });

  // Message queue: bimodal responses that are either empty or medium-sized batches

  // Tool 16: queue_poll
  mcp.tool("queue_poll", {
    max_items:   z.number().int().min(1).max(50).default(10),
    topic_filter: z.string().optional().describe("Optional topic prefix filter"),
  }, async ({ max_items, topic_filter }) => {
    await sleep(5 + Math.random() * 15);

    let eligible = topic_filter
      ? messageQueue.filter(m => m.topic.startsWith(topic_filter))
      : messageQueue;

    const taken = eligible.slice(0, max_items);
    // Remove consumed items.
    taken.forEach(item => {
      const idx = messageQueue.indexOf(item);
      if (idx !== -1) messageQueue.splice(idx, 1);
    });

    return { content: [{ type: "text", text: JSON.stringify({
      count: taken.length,
      queue_depth: messageQueue.length,
      items: taken,
    }) }] };
  });

  // Asynchronous job: two-burst pattern with a small submit, repeated small polls, and a large final result

  // Tool 17: submit_job
  mcp.tool("submit_job", {
    job_type: z.enum(JOB_TYPES),
    priority: z.enum(["low","normal","high"]).default("normal"),
    params:   z.record(z.string()).optional(),
  }, async ({ job_type, priority, params }) => {
    await sleep(3 + Math.random() * 10);    // Near-instant.
    const job_id    = crypto.randomUUID();
    const durationMs = priority === "high"
      ? 1500  + Math.random() * 3000
      : 3000  + Math.random() * 8000;

    const resultSize = job_type === "report" || job_type === "export"
      ? 30 + Math.floor(Math.random() * 50)   // 30–80 KB result.
      : 2  + Math.floor(Math.random() * 8);   // 2–10 KB result.

    jobRegistry.set(job_id, {
      status:    "running",
      job_type,
      priority,
      params:    params ?? {},
      created_at: new Date().toISOString(),
      result_kb:  resultSize,
    });

    // Background task: mark the job as done after durationMs.
    setTimeout(() => {
      const job = jobRegistry.get(job_id);
      if (!job) return;
      job.status     = "done";
      job.finished_at = new Date().toISOString();
      job.result      = makeBlobArtifact(
        job_type === "backup" ? "config_snapshot"
        : job_type === "report" || job_type === "export" ? "audit_export"
        : "metrics_dump",
        job.result_kb * 1024,
      );
    }, durationMs);

    return { content: [{ type: "text", text: JSON.stringify({
      job_id, status: "running", job_type, priority,
      estimated_ms: Math.round(durationMs),
    }) }] };
  });

  // Tool 18: poll_job
  mcp.tool("poll_job", {
    job_id: z.string().uuid(),
  }, async ({ job_id }) => {
    await sleep(3 + Math.random() * 8);     // Fast poll.
    const job = jobRegistry.get(job_id);
    if (!job)
      return { content: [{ type: "text",
        text: JSON.stringify({ error: "unknown_job", job_id }) }] };

    if (job.status !== "done")
      return { content: [{ type: "text",
        text: JSON.stringify({ job_id, status: job.status, job_type: job.job_type }) }] };

    // Job complete: return the full result, which is a large payload.
    const out = {
      job_id, status: "done",
      job_type:    job.job_type,
      created_at:  job.created_at,
      finished_at: job.finished_at,
      result:      job.result,
    };
    // Clean up the completed job record.
    jobRegistry.delete(job_id);
    return { content: [{ type: "text", text: JSON.stringify(out) }] };
  });

  return mcp;
}

// Express and SSE routing

const app = express();
app.use(express.json({ limit: "1mb" }));

const transports = new Map();

app.get("/sse", async (req, res) => {
  const sessionId = crypto.randomUUID();
  console.log(`[sse] connect    ${sessionId}`);

  const mcpServer = createMcpServer();
  const transport = new SSEServerTransport(`/message?sessionId=${sessionId}`, res);
  transports.set(sessionId, transport);

  res.on("close", () => {
    console.log(`[sse] disconnect ${sessionId}`);
    transports.delete(sessionId);
  });

  await mcpServer.connect(transport);
});

app.post("/message", async (req, res) => {
  const transport =
    transports.get(req.query.sessionId) ??
    [...transports.values()].at(-1);

  const parsedBody = req.body && Object.keys(req.body).length ? req.body : undefined;

  if (transport) {
    try {
      await transport.handlePostMessage(req, res, parsedBody);
    } catch (err) {
      console.error("[message] handlePostMessage error", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Message processing failed" });
      }
    }
  } else {
    res.status(503).json({ error: "No active SSE session" });
  }
});

// Boot

initSandbox();
initDb();

const httpsOptions = {
  key:  fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem"),
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`[server] Listening on https://0.0.0.0:${PORT}`);
  console.log(`[server] 18 tools across 6 backend profiles registered`);
});