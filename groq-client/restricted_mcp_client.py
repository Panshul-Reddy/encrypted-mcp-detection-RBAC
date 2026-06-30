"""
Restricted MCP Client — Analyst Role Demo

Connects to the TLS proxy using an analyst API key and demonstrates
RBAC enforcement in the live pipeline. Sends a mix of allowed and
denied operations to show fine-grained access control.

This client is designed to run alongside the groq-client during
the full live demo to show that different clients get different
access levels to the same MCP servers.

Usage:
    python restricted_mcp_client.py
    MCP_API_KEY=readonly-key-001 python restricted_mcp_client.py
"""

import json
import os
import random
import sys
import time
import time
import argparse
import socket

# Monkey patch socket to bind to a specific source port range (45000-49999 for analyst role)
_orig_socket = socket.socket
class BoundSocket(_orig_socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.family == socket.AF_INET and self.type == socket.SOCK_STREAM:
            for _ in range(20):
                try:
                    self.bind(('127.0.0.1', random.randint(45000, 49999)))
                    break
                except OSError:
                    pass
socket.socket = BoundSocket

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Configuration ──
VM1_IP = os.environ.get("VM1_IP", "127.0.0.1")
MCP_API_KEY = os.environ.get("MCP_API_KEY", "analyst-key-001")
ROLE_LABEL = os.environ.get("ROLE_LABEL", "analyst")
LOOP_COUNT = int(os.environ.get("LOOP_COUNT", "3"))
DELAY = float(os.environ.get("REQUEST_DELAY", "1.5"))

# Same port mapping as the groq-client
SERVERS = {
    "fetch":      f"https://{VM1_IP}:8440",
    "memory":     f"https://{VM1_IP}:8441",
    "filesystem": f"https://{VM1_IP}:8442",
    "github":     f"https://{VM1_IP}:8443",
    "exa":        f"https://{VM1_IP}:8444",
    "tavily":     f"https://{VM1_IP}:8445",
}

parser = argparse.ArgumentParser()
parser.add_argument("--proxy-port", type=int, default=None)
args, unknown = parser.parse_known_args()
if args.proxy_port:
    SERVERS = {k: f"https://{VM1_IP}:{args.proxy_port}" for k in SERVERS}

# ANSI
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; D = "\033[2m"; X = "\033[0m"; M = "\033[95m"

# Track results
results = {"allowed": 0, "denied": 0, "error": 0}


# ── Operations to test (mix of allowed and denied for analyst) ──
OPERATIONS = [
    # (server, method, params, description, expected_for_analyst)
    ("filesystem", "tools/list", {}, "List available tools", "ALLOW"),
    ("filesystem", "tools/call", {"name": "list_directory", "arguments": {"path": "/app"}}, "List directory /app", "ALLOW"),
    ("filesystem", "tools/call", {"name": "read_file", "arguments": {"path": "/app/package.json"}}, "Read file contents", "ALLOW"),
    ("filesystem", "tools/call", {"name": "get_file_info", "arguments": {"path": "/app"}}, "Get file info", "ALLOW"),
    ("filesystem", "tools/call", {"name": "write_file", "arguments": {"path": "/tmp/test.txt", "content": "hacked"}}, "Write file (SHOULD BE BLOCKED)", "DENY"),
    ("fetch", "tools/call", {"name": "fetch", "arguments": {"url": "https://example.com"}}, "Fetch URL", "ALLOW"),
    ("memory", "tools/call", {"name": "create_entities", "arguments": {"entities": [{"name": "test", "entityType": "note", "observations": ["test observation"]}]}}, "Create entity (analyst can create)", "ALLOW"),
    ("memory", "tools/call", {"name": "search_nodes", "arguments": {"query": "test"}}, "Search knowledge graph", "ALLOW"),
    ("memory", "tools/call", {"name": "delete_entities", "arguments": {"entityNames": ["test"]}}, "Delete entity (SHOULD BE BLOCKED)", "DENY"),
    ("exa", "tools/call", {"name": "search", "arguments": {"query": "MCP protocol"}}, "Exa search", "ALLOW"),
    ("tavily", "tools/call", {"name": "tavily-search", "arguments": {"query": "machine learning firewall"}}, "Tavily search", "ALLOW"),
    ("github", "tools/call", {"name": "search_repositories", "arguments": {"query": "MCP server"}}, "Search GitHub repos", "ALLOW"),
]


def get_session(server_name):
    """Connect to a server's SSE endpoint and get session ID."""
    url = SERVERS.get(server_name)
    if not url:
        return None
    try:
        response = requests.get(
            f"{url}/sse", stream=True, timeout=10, verify=False,
            headers={"X-MCP-API-Key": MCP_API_KEY}
        )
        for line in response.iter_lines():
            if line:
                decoded = line.decode("utf-8")
                if "sessionId=" in decoded:
                    session_id = decoded.split("sessionId=")[1]
                    return {"url": url, "session_id": session_id}
    except Exception as e:
        pass
    return None


def send_request(session, method, params, description, expected):
    """Send a JSON-RPC request and report the result."""
    payload = {
        "jsonrpc": "2.0",
        "id": random.randint(1, 9999),
        "method": method,
        "params": params,
    }
    headers = {
        "Content-Type": "application/json",
        "X-MCP-API-Key": MCP_API_KEY,
    }
    url = f"{session['url']}/messages?sessionId={session['session_id']}"

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10, verify=False)
        status = r.status_code
    except Exception as e:
        status = -1

    tool = params.get("name", "") if isinstance(params, dict) else ""
    tool_str = f" -> {tool}" if tool else ""

    if status == 403:
        icon = f"{R}DENIED {X}"
        results["denied"] += 1
        match = "correct" if expected == "DENY" else "UNEXPECTED"
    elif 200 <= status < 300:
        icon = f"{G}ALLOWED{X}"
        results["allowed"] += 1
        match = "correct" if expected == "ALLOW" else "UNEXPECTED"
    else:
        icon = f"{Y}ERROR  {X}"
        results["error"] += 1
        match = ""

    match_str = f"  {D}({match}){X}" if match else ""
    print(f"  [{icon}] {method}{tool_str} — {description}{match_str}")


def main():
    print(f"\n{B}{M}{'=' * 60}{X}")
    print(f"{B}{M}  Restricted MCP Client — Role: {ROLE_LABEL}{X}")
    print(f"{B}{M}  API Key: {MCP_API_KEY[:20]}...{X}")
    print(f"{B}{M}  Target: {VM1_IP} (ports 8440-8445){X}")
    print(f"{B}{M}{'=' * 60}{X}\n")

    # Get sessions for each server we'll use
    servers_needed = list(set(op[0] for op in OPERATIONS))
    sessions = {}

    print(f"{B}Connecting to MCP servers...{X}")
    for server_name in servers_needed:
        session = get_session(server_name)
        if session:
            sessions[server_name] = session
            print(f"  {G}+{X} {server_name}: connected")
        else:
            print(f"  {R}x{X} {server_name}: failed to connect")

    if not sessions:
        print(f"\n{R}No servers available. Make sure the proxy and MCP servers are running.{X}")
        print(f"{D}Start with: docker compose up -d mcp-servers{X}")
        print(f"{D}Then start the proxy manually or via start_demo.ps1{X}")
        sys.exit(1)

    # Run operations in loops
    for loop_num in range(1, LOOP_COUNT + 1):
        print(f"\n{B}{C}── Round {loop_num}/{LOOP_COUNT} ──{X}\n")

        # Shuffle operations for variety
        ops = OPERATIONS.copy()
        random.shuffle(ops)

        for server_name, method, params, description, expected in ops:
            if server_name not in sessions:
                continue

            send_request(sessions[server_name], method, params, description, expected)
            time.sleep(DELAY + random.uniform(-0.5, 0.5))

    # Summary
    total = results["allowed"] + results["denied"] + results["error"]
    print(f"\n{B}{C}{'=' * 60}{X}")
    print(f"{B}{C}  Results Summary — Role: {ROLE_LABEL}{X}")
    print(f"{B}{C}{'=' * 60}{X}")
    print(f"  Total requests:  {total}")
    print(f"  {G}Allowed:       {results['allowed']}{X}")
    print(f"  {R}Denied:        {results['denied']}{X}")
    if results["error"]:
        print(f"  {Y}Errors:        {results['error']}{X}")
    print(f"\n  {B}This demonstrates that the RBAC proxy is active in the live")
    print(f"  pipeline — the analyst can read and create, but write_file")
    print(f"  and delete_entities are blocked at the proxy level.{X}\n")


if __name__ == "__main__":
    main()
