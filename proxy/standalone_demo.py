"""
Standalone RBAC Demo — Industry-Grade MCP Access Control

Runs WITHOUT Docker. Starts a mock MCP backend + the real TLS proxy
with policy enforcement + sends test requests showing ALLOW/DENY.

Demonstrates:
  1. Three-tier role hierarchy (readonly → analyst → full)
  2. Tool-level access control at the JSON-RPC layer
  3. API key-based client identity resolution
  4. Explicit deny lists (analyst can create but NOT delete)
  5. Rate limiting per role
  6. JSON Lines audit logging for compliance

Usage:
    cd proxy
    .venv\\Scripts\\python.exe standalone_demo.py
"""

import json
import os
import subprocess
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests as req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
CERT = os.path.join(PROJECT_ROOT, "nginx", "ssl", "mcp.crt")
KEY  = os.path.join(PROJECT_ROOT, "nginx", "ssl", "mcp.key")
POLICY = os.path.join(HERE, "tool_policy.yaml")
AUDIT_LOG = os.path.join(PROJECT_ROOT, "logs", "rbac_audit.jsonl")

BACKEND_PORT = 13000
PROXY_PORT   = 18441

# ANSI
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; D = "\033[2m"; X = "\033[0m"; M = "\033[95m"

# Track results
results = []


# =============================================================================
# Mock MCP Backend
# =============================================================================

class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if "/sse" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"event: endpoint\ndata: /messages?sessionId=demo\n\n")
            self.wfile.flush()
            try: time.sleep(0.5)
            except: pass
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body)
            method = payload.get("method", "")
            rpc_id = payload.get("id", 1)
            params = payload.get("params", {})
        except: method, rpc_id, params = "unknown", 1, {}

        if method == "tools/list":
            result = {"tools": [
                {"name": "list_directory"}, {"name": "read_file"},
                {"name": "write_file"}, {"name": "create_entities"},
                {"name": "delete_entities"}, {"name": "search"},
                {"name": "fetch"}, {"name": "get_file_info"},
            ]}
        elif method == "tools/call":
            tool = params.get("name", "unknown")
            result = {"content": [{"type": "text", "text": f"[MOCK] {tool} OK"}]}
        else:
            result = {"status": "ok"}

        resp = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": result})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp.encode())


# =============================================================================
# Test Helpers
# =============================================================================

def send(desc, method, params=None, api_key=None, expect_deny=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-MCP-API-Key"] = api_key

    status = -1
    for attempt in range(3):
        try:
            r = req_lib.post(
                f"https://127.0.0.1:{PROXY_PORT}/messages?sessionId=demo",
                json=payload, headers=headers, timeout=5, verify=False,
            )
            status = r.status_code
            break
        except Exception:
            time.sleep(0.5 * (attempt + 1))

    tool = (params or {}).get("name", "")
    tool_str = f" → {tool}" if tool else ""

    if status == 403:
        icon = f"{R}✗ DENIED {X}"
        result = "DENIED"
    elif status == 429:
        icon = f"{Y}⚡ RATE  {X}"
        result = "RATE_LIMITED"
    elif status > 0:
        icon = f"{G}✓ ALLOWED{X}"
        result = "ALLOWED"
    else:
        icon = f"{Y}? ERROR  {X}"
        result = "ERROR"

    print(f"  {icon}  {method}{tool_str}")
    results.append({"desc": desc, "method": method, "tool": tool, "result": result})
    time.sleep(0.3)  # Brief pause between requests for proxy stability


def section(title, subtitle=""):
    time.sleep(1)  # Let proxy's async loop settle between scenarios
    print(f"\n{B}{M}{'─' * 58}{X}")
    print(f"{B}{M}  {title}{X}")
    if subtitle:
        print(f"  {D}{subtitle}{X}")
    print(f"{B}{M}{'─' * 58}{X}\n")


# =============================================================================
# Main Demo
# =============================================================================

def run_demo():
    print(f"\n{B}{C}╔{'═' * 56}╗{X}")
    print(f"{B}{C}║   MCP Tool-Level Access Control — Live RBAC Demo      ║{X}")
    print(f"{B}{C}║   Three-Tier Role Hierarchy • Audit Logging • Rate Limits ║{X}")
    print(f"{B}{C}╚{'═' * 56}╝{X}")

    # ── SCENARIO 1: Full-access ──
    section("SCENARIO 1: Full-Access Admin",
            "API Key: full-access-key-001  |  Role: full  |  Can do EVERYTHING")

    key = "full-access-key-001"
    send("List tools", "tools/list", {}, key)
    send("Read file", "tools/call", {"name": "read_file", "arguments": {"path": "/tmp/hello.txt"}}, key)
    send("Create entities", "tools/call", {"name": "create_entities", "arguments": {"entities": []}}, key)
    send("Write file", "tools/call", {"name": "write_file", "arguments": {"path": "/tmp/x.txt", "content": "test"}}, key)
    send("Delete entities", "tools/call", {"name": "delete_entities", "arguments": {"entityNames": ["x"]}}, key)

    # ── SCENARIO 2: Analyst ──
    section("SCENARIO 2: Data Analyst",
            "API Key: analyst-key-001  |  Role: analyst  |  Can READ + CREATE but NOT delete/write files")

    key = "analyst-key-001"
    send("List tools", "tools/list", {}, key)
    send("Read file", "tools/call", {"name": "read_file", "arguments": {"path": "/tmp/hello.txt"}}, key)
    send("Search repos", "tools/call", {"name": "search", "arguments": {"query": "MCP protocol"}}, key)
    send("Create entities (ALLOWED for analyst)", "tools/call", {"name": "create_entities", "arguments": {"entities": [{"name": "test"}]}}, key)
    print(f"\n  {R}{B}  Attempting restricted operations...{X}\n")
    send("Write file (DENIED - explicit deny)", "tools/call", {"name": "write_file", "arguments": {"path": "/tmp/evil.txt", "content": "hacked"}}, key, expect_deny=True)
    send("Delete entities (DENIED - explicit deny)", "tools/call", {"name": "delete_entities", "arguments": {"entityNames": ["test"]}}, key, expect_deny=True)

    # ── SCENARIO 3: Readonly ──
    section("SCENARIO 3: External Read-Only User",
            "API Key: readonly-key-001  |  Role: readonly  |  Can ONLY read and search")

    key = "readonly-key-001"
    send("List tools", "tools/list", {}, key)
    send("List directory", "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}}, key)
    send("Fetch URL", "tools/call", {"name": "fetch", "arguments": {"url": "https://example.com"}}, key)
    print(f"\n  {R}{B}  Attempting ALL write operations...{X}\n")
    send("Create entities (DENIED)", "tools/call", {"name": "create_entities", "arguments": {}}, key, expect_deny=True)
    send("Write file (DENIED)", "tools/call", {"name": "write_file", "arguments": {}}, key, expect_deny=True)
    send("Delete entities (DENIED)", "tools/call", {"name": "delete_entities", "arguments": {}}, key, expect_deny=True)

    # ── SCENARIO 4: Unknown API key (falls to default) ──
    section("SCENARIO 4: Unknown API Key (Zero-Trust)",
            "Bogus API key 'visitor-key-999'  |  No match in policy  |  Falls to default_role = readonly")

    key = "visitor-key-999"
    send("List tools (allowed)", "tools/list", {}, key)
    time.sleep(0.2)
    send("Read file (allowed)", "tools/call", {"name": "read_file", "arguments": {"path": "/tmp/hello.txt"}}, key)
    time.sleep(0.2)
    send("Create entities (DENIED - unknown = readonly)", "tools/call", {"name": "create_entities", "arguments": {}}, key, expect_deny=True)
    time.sleep(0.2)

    # ── SCENARIO 5: API Key overrides IP ──
    section("SCENARIO 5: API Key Overrides IP",
            "localhost (normally full) + readonly key = RESTRICTED")

    send("Write file with readonly key (DENIED despite localhost)",
         "tools/call", {"name": "write_file", "arguments": {}}, "readonly-key-001", expect_deny=True)
    time.sleep(0.2)
    send("Delete with analyst key (DENIED - explicit deny overrides IP)",
         "tools/call", {"name": "delete_entities", "arguments": {}}, "analyst-key-001", expect_deny=True)
    time.sleep(0.2)
    print(f"\n{B}{C}╔{'═' * 56}╗{X}")
    print(f"{B}{C}║                    RESULTS SUMMARY                    ║{X}")
    print(f"{B}{C}╚{'═' * 56}╝{X}\n")

    allowed = sum(1 for r in results if r["result"] == "ALLOWED")
    denied = sum(1 for r in results if r["result"] == "DENIED")
    other = len(results) - allowed - denied

    print(f"  Total requests:  {B}{len(results)}{X}")
    print(f"  {G}✓ Allowed:       {allowed}{X}")
    print(f"  {R}✗ Denied:        {denied}{X}")
    if other:
        print(f"  {Y}? Other:         {other}{X}")

    print(f"\n  {B}Role Hierarchy:{X}")
    print(f"    {G}full{X}     →  All methods, all tools, no limits")
    print(f"    {Y}analyst{X}  →  Read + create, but {R}NO{X} write_file / delete")
    print(f"    {R}readonly{X} →  Read/search only, rate-limited to 30/min")
    print(f"    {D}unknown{X}  →  Defaults to readonly (zero-trust)")

    # Show audit log
    if os.path.exists(AUDIT_LOG):
        print(f"\n  {B}Audit log written to:{X} {AUDIT_LOG}")
        print(f"  {D}Run 'python audit_report.py' to generate the security report{X}")

    print(f"\n  {B}Key Takeaways for your Mentor:{X}")
    print(f"  1. RBAC operates at Layer 7 (app), complementing the ML firewall at Layer 4")
    print(f"  2. Three-tier roles: readonly → analyst → full (real-world hierarchy)")
    print(f"  3. Denied_tools list gives fine-grained control (analyst can create but NOT delete)")
    print(f"  4. Every decision is audit-logged to JSONL for compliance")
    print(f"  5. API keys override IP-based roles (defense against IP spoofing)")
    print()


def main():
    if not os.path.exists(CERT) or not os.path.exists(KEY):
        print(f"{R}ERROR: SSL certs not found at {CERT}{X}")
        sys.exit(1)

    # Clear old audit log for clean demo
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    if os.path.exists(AUDIT_LOG):
        os.remove(AUDIT_LOG)

    print(f"\n{B}{C}Initializing Standalone RBAC Demo...{X}\n")

    # Start mock backend
    print(f"  {G}[1/3]{X} Mock MCP backend on port {BACKEND_PORT}")
    server = HTTPServer(("127.0.0.1", BACKEND_PORT), MockHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.5)

    # Start TLS proxy with random ports to avoid conflicts
    import random as _rnd
    ctrl_port = _rnd.randint(19000, 19999)
    proxy_log = os.path.join(PROJECT_ROOT, "logs", "demo_proxy.log")
    os.makedirs(os.path.dirname(proxy_log), exist_ok=True)
    print(f"  {G}[2/3]{X} TLS proxy on port {PROXY_PORT} with RBAC policy")
    proxy_err_f = open(proxy_log, "w")
    proxy_proc = subprocess.Popen(
        [sys.executable, "tls_proxy.py",
         "--cert", CERT, "--key", KEY,
         "--backend-host", "127.0.0.1",
         "--mappings", f"{PROXY_PORT}:{BACKEND_PORT}",
         "--control-port", str(ctrl_port),
         "--policy", POLICY],
        cwd=HERE, stdout=subprocess.DEVNULL, stderr=proxy_err_f,
    )
    time.sleep(3)

    if proxy_proc.poll() is not None:
        try:
            with open(proxy_log, "r") as f:
                err = f.read()
        except:
            err = "unknown"
        print(f"{R}Proxy failed: {err}{X}")
        sys.exit(1)

    print(f"  {G}[3/3]{X} Sending test requests...")

    try:
        run_demo()
    finally:
        try:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=5)
        except:
            try: proxy_proc.kill()
            except: pass
        try: proxy_err_f.close()
        except: pass
        server.shutdown()
        print(f"  {D}Services stopped.{X}\n")


if __name__ == "__main__":
    main()
