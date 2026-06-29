"""
Manual RBAC Demo — send real requests to the proxy and see policy enforcement.

Usage (proxy must be running on 8441):
    python manual_test.py
"""

import json
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Force UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROXY = "https://127.0.0.1:8441"
DUMMY_SESSION = "test-manual"


def send(desc, method, params=None, api_key=None, expect_denied=False):
    """Send a JSON-RPC request and print the result."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-MCP-API-Key"] = api_key

    try:
        r = requests.post(
            f"{PROXY}/messages?sessionId={DUMMY_SESSION}",
            json=payload, headers=headers, timeout=5, verify=False,
        )
        status = r.status_code
        body = r.text[:200]
    except Exception as e:
        status = -1
        body = str(e)

    if status == 403:
        icon = "[BLOCKED]"
        color = "\033[91m"  # red
    else:
        icon = "[ALLOWED]"
        color = "\033[92m"  # green

    print(f"  {color}{icon}\033[0m  HTTP {status}  |  {desc}")
    if status == 403:
        try:
            err = json.loads(r.text)
            print(f"           Reason: {err['error']['message']}")
        except Exception:
            pass
    print()


print("=" * 60)
print("  MCP RBAC Manual Test -- Live Proxy Demo")
print("=" * 60)

# --- Test 1: Full-access key -> tools/list ---
print("\n--- FULL-ACCESS client (API key: full-access-key-001) ---\n")

send("tools/list",
     "tools/list", {},
     api_key="full-access-key-001")

send("tools/call -> create_entities (WRITE tool)",
     "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
     api_key="full-access-key-001")

send("tools/call -> list_directory (READ tool)",
     "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp/mcp-test"}},
     api_key="full-access-key-001")

# --- Test 2: Readonly key ---
print("--- READONLY client (API key: readonly-key-001) ---\n")

send("tools/list",
     "tools/list", {},
     api_key="readonly-key-001")

send("tools/call -> list_directory (READ tool -- should be ALLOWED)",
     "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp/mcp-test"}},
     api_key="readonly-key-001")

send("tools/call -> create_entities (WRITE tool -- should be BLOCKED)",
     "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
     api_key="readonly-key-001",
     expect_denied=True)

send("tools/call -> write_file (WRITE tool -- should be BLOCKED)",
     "tools/call", {"name": "write_file", "arguments": {"path": "/tmp/evil.txt", "content": "pwned"}},
     api_key="readonly-key-001",
     expect_denied=True)

send("tools/call -> delete_entities (WRITE tool -- should be BLOCKED)",
     "tools/call", {"name": "delete_entities", "arguments": {"entityNames": ["test"]}},
     api_key="readonly-key-001",
     expect_denied=True)

# --- Test 3: No API key (default role = readonly) ---
print("--- NO API KEY (unknown client -- defaults to readonly) ---\n")

send("tools/list (no key)",
     "tools/list", {})

send("tools/call -> create_entities (no key -- should be BLOCKED)",
     "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
     expect_denied=True)

print("=" * 60)
print("  Done. Check the proxy terminal for ALLOW/DENY logs.")
print("=" * 60)
