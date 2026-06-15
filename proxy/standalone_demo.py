"""
Standalone RBAC Demo — runs WITHOUT Docker.

Starts a mock MCP backend + the real TLS proxy + sends test requests,
all from one script. Shows ALLOW vs DENY in real-time.

Usage:
    cd proxy
    ..\\proxy\\.venv\\Scripts\\python.exe standalone_demo.py
"""

import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import threading

# Force UTF-8 output on Windows
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

# Ports
BACKEND_PORT = 13000   # Mock MCP backend
PROXY_PORT   = 18441   # TLS proxy (like production 8441)

# ANSI colors
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
C = "\033[96m"   # cyan
B = "\033[1m"    # bold
X = "\033[0m"    # reset


# =============================================================================
# 1. Mock MCP Backend (simple HTTP server that accepts JSON-RPC)
# =============================================================================

def run_mock_backend():
    """A tiny HTTP server that pretends to be an MCP server."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # Suppress default logging

        def do_GET(self):
            if "/sse" in self.path:
                # Simulate SSE endpoint — send sessionId then keep alive briefly
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                session_id = "demo-session-001"
                msg = f"event: endpoint\ndata: /messages?sessionId={session_id}\n\n"
                self.wfile.write(msg.encode())
                self.wfile.flush()
                # Keep connection open briefly
                try:
                    time.sleep(2)
                except Exception:
                    pass
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

        def do_POST(self):
            # Read body
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""

            # Parse JSON-RPC
            try:
                payload = json.loads(body)
                method = payload.get("method", "unknown")
                rpc_id = payload.get("id", 1)
            except Exception:
                method = "unknown"
                rpc_id = 1

            # Return a mock response
            if method == "tools/list":
                result = {"tools": [
                    {"name": "list_directory", "description": "List files in a directory"},
                    {"name": "read_file", "description": "Read file contents"},
                    {"name": "write_file", "description": "Write to a file"},
                    {"name": "create_entities", "description": "Create knowledge entities"},
                    {"name": "delete_entities", "description": "Delete entities"},
                    {"name": "search_repositories", "description": "Search GitHub repos"},
                    {"name": "fetch", "description": "Fetch a URL"},
                    {"name": "search", "description": "Search the web"},
                ]}
            elif method == "tools/call":
                tool = payload.get("params", {}).get("name", "unknown")
                result = {"content": [{"type": "text", "text": f"[MOCK] Tool '{tool}' executed successfully"}]}
            else:
                result = {"status": "ok", "method": method}

            response = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": result})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode())

    server = HTTPServer(("127.0.0.1", BACKEND_PORT), Handler)
    server.serve_forever()


# =============================================================================
# 2. Test Runner — sends requests and shows results
# =============================================================================

def send_test(desc, method, params=None, api_key=None, expect_deny=False):
    """Send a JSON-RPC request to the proxy and print the result."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-MCP-API-Key"] = api_key

    try:
        r = req_lib.post(
            f"https://127.0.0.1:{PROXY_PORT}/messages?sessionId=demo-test",
            json=payload, headers=headers, timeout=5, verify=False,
        )
        status = r.status_code
        body = r.text[:200]
    except Exception as e:
        status = -1
        body = str(e)[:100]

    if status == 403:
        icon = f"{R}✗ BLOCKED{X}"
        try:
            err = json.loads(body)
            reason = err.get("error", {}).get("message", "")
        except Exception:
            reason = body
    elif status > 0:
        icon = f"{G}✓ ALLOWED{X}"
        reason = f"HTTP {status}"
    else:
        icon = f"{Y}? ERROR{X}"
        reason = body

    tool_str = ""
    if params and "name" in params:
        tool_str = f" → {params['name']}"

    print(f"  {icon}  {B}{method}{X}{tool_str}")
    if status == 403:
        print(f"           {Y}Reason: {reason}{X}")
    print()


def run_tests():
    """Run the RBAC demo tests."""
    print()
    print(f"{B}{C}{'=' * 60}{X}")
    print(f"{B}{C}   MCP Tool-Level Access Control — Live RBAC Demo{X}")
    print(f"{B}{C}{'=' * 60}{X}")

    # ── Full-access client ──
    print(f"\n{B}━━━ FULL-ACCESS Client (API key: full-access-key-001) ━━━{X}\n")
    print(f"  {C}This client has the 'full' role — can use ALL tools.{X}\n")

    send_test("tools/list",
              "tools/list", {},
              api_key="full-access-key-001")
    send_test("tools/call → list_directory (READ)",
              "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}},
              api_key="full-access-key-001")
    send_test("tools/call → create_entities (WRITE)",
              "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
              api_key="full-access-key-001")
    send_test("tools/call → write_file (WRITE)",
              "tools/call", {"name": "write_file", "arguments": {"path": "/tmp/x.txt", "content": "hi"}},
              api_key="full-access-key-001")

    # ── Readonly client ──
    print(f"{B}━━━ READONLY Client (API key: readonly-key-001) ━━━{X}\n")
    print(f"  {C}This client has the 'readonly' role — can only use GET/read tools.{X}")
    print(f"  {C}Write tools (create, write, delete) will be BLOCKED.{X}\n")

    send_test("tools/list (metadata — ALLOWED)",
              "tools/list", {},
              api_key="readonly-key-001")
    send_test("tools/call → list_directory (READ — ALLOWED)",
              "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}},
              api_key="readonly-key-001")
    send_test("tools/call → read_file (READ — ALLOWED)",
              "tools/call", {"name": "read_file", "arguments": {"path": "/tmp/hello.txt"}},
              api_key="readonly-key-001")
    send_test("tools/call → fetch (READ — ALLOWED)",
              "tools/call", {"name": "fetch", "arguments": {"url": "https://example.com"}},
              api_key="readonly-key-001")
    send_test("tools/call → search (READ — ALLOWED)",
              "tools/call", {"name": "search", "arguments": {"query": "hello"}},
              api_key="readonly-key-001")

    print(f"  {R}{B}--- Now attempting WRITE tools (should be BLOCKED) ---{X}\n")

    send_test("tools/call → create_entities (WRITE — BLOCKED!)",
              "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
              api_key="readonly-key-001", expect_deny=True)
    send_test("tools/call → write_file (WRITE — BLOCKED!)",
              "tools/call", {"name": "write_file", "arguments": {"path": "/evil.txt", "content": "pwned"}},
              api_key="readonly-key-001", expect_deny=True)
    send_test("tools/call → delete_entities (WRITE — BLOCKED!)",
              "tools/call", {"name": "delete_entities", "arguments": {"entityNames": ["test"]}},
              api_key="readonly-key-001", expect_deny=True)

    # ── No API key (unknown client → defaults to readonly) ──
    print(f"{B}━━━ UNKNOWN Client (no API key — defaults to readonly) ━━━{X}\n")
    print(f"  {C}Clients without an API key get the 'readonly' role by default.{X}\n")

    send_test("tools/list (ALLOWED)",
              "tools/list", {})
    send_test("tools/call → list_directory (READ — ALLOWED)",
              "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}})
    send_test("tools/call → create_entities (WRITE — BLOCKED!)",
              "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
              expect_deny=True)

    # ── API key overrides IP ──
    print(f"{B}━━━ API Key OVERRIDES IP Address ━━━{X}\n")
    print(f"  {C}Even if a client's IP gives 'full' access, a 'readonly' API key{X}")
    print(f"  {C}takes priority and restricts them.{X}\n")

    send_test("localhost + readonly key → create_entities (BLOCKED by key!)",
              "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
              api_key="readonly-key-001", expect_deny=True)

    # ── Summary ──
    print(f"{B}{C}{'=' * 60}{X}")
    print(f"{B}{C}   Demo Complete!{X}")
    print(f"{B}{C}{'=' * 60}{X}")
    print()
    print(f"  {B}What you just saw:{X}")
    print(f"  • Full-access clients can call ANY tool (read + write)")
    print(f"  • Readonly clients can only call read/get tools")
    print(f"  • Write tools (create, write, delete) are {R}BLOCKED{X} with HTTP 403")
    print(f"  • Unknown clients default to readonly (zero-trust)")
    print(f"  • API keys override IP-based roles")
    print()
    print(f"  {B}Check the proxy logs above for ALLOW/DENY details!{X}")
    print()


# =============================================================================
# 3. Main — orchestrate everything
# =============================================================================

def main():
    # Check cert files exist
    if not os.path.exists(CERT) or not os.path.exists(KEY):
        print(f"{R}ERROR: SSL certs not found at {CERT}{X}")
        print(f"  Generate them with: openssl req -x509 -nodes -days 365 \\")
        print(f"    -newkey rsa:2048 -keyout mcp.key -out mcp.crt")
        sys.exit(1)

    if not os.path.exists(POLICY):
        print(f"{R}ERROR: Policy file not found at {POLICY}{X}")
        sys.exit(1)

    print(f"\n{B}{C}Starting Standalone RBAC Demo...{X}\n")

    # ── Start mock backend ──
    print(f"  {G}[1/3]{X} Starting mock MCP backend on port {BACKEND_PORT}...")
    backend_thread = threading.Thread(target=run_mock_backend, daemon=True)
    backend_thread.start()
    time.sleep(1)

    # ── Start TLS proxy ──
    print(f"  {G}[2/3]{X} Starting TLS proxy on port {PROXY_PORT} with RBAC policy...")
    proxy_cmd = [
        sys.executable, "tls_proxy.py",
        "--cert", CERT,
        "--key", KEY,
        "--backend-host", "127.0.0.1",
        "--mappings", f"{PROXY_PORT}:{BACKEND_PORT}",
        "--policy", POLICY,
    ]
    proxy_proc = subprocess.Popen(
        proxy_cmd,
        cwd=HERE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # Check proxy started
    if proxy_proc.poll() is not None:
        err = proxy_proc.stderr.read().decode()
        print(f"{R}ERROR: Proxy failed to start: {err}{X}")
        sys.exit(1)

    print(f"  {G}[3/3]{X} Proxy running! Sending test requests...\n")

    try:
        run_tests()
    finally:
        # Cleanup
        try:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=5)
        except Exception:
            try:
                proxy_proc.kill()
            except Exception:
                pass
        print(f"  {Y}Proxy stopped. Demo finished.{X}\n")


if __name__ == "__main__":
    main()
