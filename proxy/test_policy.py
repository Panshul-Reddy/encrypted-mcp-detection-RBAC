"""
MCP Tool-Level Access Control — Policy Engine Tests (v2)

Tests three roles: readonly, analyst, full
Covers: method access, tool access, denied_tools, API key priority,
        default role, wildcard matching.

Usage:
    python test_policy.py
    python test_policy.py --live --proxy-host 127.0.0.1 --proxy-port 18441
"""

import argparse
import json
import os
import sys

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_proxy import PolicyEngine


class C:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def passed(name):
    print(f"  {C.GREEN}[PASS]{C.RESET}  {name}")

def failed(name, detail=""):
    print(f"  {C.RED}[FAIL]{C.RESET}  {name}")
    if detail:
        print(f"          {C.YELLOW}{detail}{C.RESET}")


def run_unit_tests(policy_path):
    print(f"\n{C.BOLD}{C.CYAN}== Unit Tests: PolicyEngine (v2) =={C.RESET}")
    print(f"   Policy file: {policy_path}\n")

    engine = PolicyEngine(policy_path)
    total = 0
    failures = 0

    def check(desc, client_ip, api_key, method, tool, expect_allowed):
        nonlocal total, failures
        total += 1
        allowed, reason = engine.evaluate(client_ip, api_key, method, tool)
        if allowed == expect_allowed:
            passed(desc)
        else:
            failures += 1
            expected_word = "ALLOW" if expect_allowed else "DENY"
            actual_word = "ALLOW" if allowed else "DENY"
            failed(desc, f"Expected {expected_word}, got {actual_word}: {reason}")

    # ── Full-access client (by IP) ──
    print(f"  {C.BOLD}-- Full-access client (IP: 10.11.0.30) --{C.RESET}")
    check("tools/list", "10.11.0.30", "", "tools/list", "", True)
    check("tools/call → list_directory", "10.11.0.30", "", "tools/call", "list_directory", True)
    check("tools/call → create_entities", "10.11.0.30", "", "tools/call", "create_entities", True)
    check("tools/call → write_file", "10.11.0.30", "", "tools/call", "write_file", True)
    check("tools/call → delete_entities", "10.11.0.30", "", "tools/call", "delete_entities", True)
    check("resources/read", "10.11.0.30", "", "resources/read", "", True)

    # ── Readonly client (by IP) ──
    print(f"\n  {C.BOLD}-- Readonly client (IP: 10.11.0.40) --{C.RESET}")
    check("tools/list (allowed)", "10.11.0.40", "", "tools/list", "", True)
    check("tools/call → list_directory (allowed)", "10.11.0.40", "", "tools/call", "list_directory", True)
    check("tools/call → search (allowed)", "10.11.0.40", "", "tools/call", "search", True)
    check("tools/call → fetch (allowed)", "10.11.0.40", "", "tools/call", "fetch", True)
    check("tools/call → create_entities (DENIED)", "10.11.0.40", "", "tools/call", "create_entities", False)
    check("tools/call → write_file (DENIED)", "10.11.0.40", "", "tools/call", "write_file", False)
    check("tools/call → delete_entities (DENIED)", "10.11.0.40", "", "tools/call", "delete_entities", False)
    check("resources/read (allowed)", "10.11.0.40", "", "resources/read", "", True)
    check("initialize (allowed)", "10.11.0.40", "", "initialize", "", True)
    check("ping (allowed)", "10.11.0.40", "", "ping", "", True)

    # ── Analyst client (by API key) ──
    print(f"\n  {C.BOLD}-- Analyst client (API key: analyst-key-001) --{C.RESET}")
    check("tools/list (allowed)", "10.11.0.40", "analyst-key-001", "tools/list", "", True)
    check("tools/call → list_directory (allowed)", "10.11.0.40", "analyst-key-001", "tools/call", "list_directory", True)
    check("tools/call → read_file (allowed)", "10.11.0.40", "analyst-key-001", "tools/call", "read_file", True)
    check("tools/call → search (allowed)", "10.11.0.40", "analyst-key-001", "tools/call", "search", True)
    check("tools/call → create_entities (ALLOWED for analyst)", "10.11.0.40", "analyst-key-001", "tools/call", "create_entities", True)
    check("tools/call → search_nodes (ALLOWED for analyst)", "10.11.0.40", "analyst-key-001", "tools/call", "search_nodes", True)
    check("tools/call → write_file (DENIED — explicit deny)", "10.11.0.40", "analyst-key-001", "tools/call", "write_file", False)
    check("tools/call → delete_entities (DENIED — explicit deny)", "10.11.0.40", "analyst-key-001", "tools/call", "delete_entities", False)
    check("resources/subscribe (allowed for analyst)", "10.11.0.40", "analyst-key-001", "resources/subscribe", "", True)

    # ── Method-level restrictions ──
    print(f"\n  {C.BOLD}-- Method-level restrictions (readonly) --{C.RESET}")
    check("unknown/method (DENIED)", "10.11.0.40", "", "some/unknown/method", "", False)
    check("__unparseable__ body (DENIED)", "10.11.0.40", "", "__unparseable__", "", False)

    # ── Wildcard method matching ──
    print(f"\n  {C.BOLD}-- Wildcard method matching --{C.RESET}")
    check("notifications/initialized (allowed via notifications/*)", "10.11.0.40", "", "notifications/initialized", "", True)
    check("notifications/cancelled (allowed via notifications/*)", "10.11.0.40", "", "notifications/cancelled", "", True)

    # ── API key overrides IP ──
    print(f"\n  {C.BOLD}-- API key priority over IP --{C.RESET}")
    check("Readonly IP + full API key → create_entities (allowed)",
          "10.11.0.40", "full-access-key-001", "tools/call", "create_entities", True)
    check("Full IP + readonly API key → create_entities (DENIED)",
          "10.11.0.30", "readonly-key-001", "tools/call", "create_entities", False)
    check("Full IP + analyst key → write_file (DENIED — explicit deny)",
          "10.11.0.30", "analyst-key-001", "tools/call", "write_file", False)
    check("Full IP + analyst key → create_entities (allowed)",
          "10.11.0.30", "analyst-key-001", "tools/call", "create_entities", True)

    # ── Unknown client (default role) ──
    print(f"\n  {C.BOLD}-- Unknown client (default role = readonly) --{C.RESET}")
    check("Unknown IP → tools/list (allowed)", "192.168.1.99", "", "tools/list", "", True)
    check("Unknown IP → create_entities (DENIED)", "192.168.1.99", "", "tools/call", "create_entities", False)
    check("Unknown IP → list_directory (allowed)", "192.168.1.99", "", "tools/call", "list_directory", True)

    # ── Localhost ──
    print(f"\n  {C.BOLD}-- Localhost (127.0.0.1 = full) --{C.RESET}")
    check("localhost → create_entities (allowed)", "127.0.0.1", "", "tools/call", "create_entities", True)
    check("localhost → write_file (allowed)", "127.0.0.1", "", "tools/call", "write_file", True)

    # ── Summary ──
    print(f"\n  {C.BOLD}Results: {total - failures}/{total} passed", end="")
    if failures:
        print(f" ({C.RED}{failures} failed{C.RESET}{C.BOLD}){C.RESET}")
    else:
        print(f" {C.GREEN}(all passed){C.RESET}")

    return failures


def run_integration_tests(proxy_host, proxy_port):
    print(f"\n{C.BOLD}{C.CYAN}== Integration Tests: Live Proxy =={C.RESET}")
    print(f"   Target: {proxy_host}:{proxy_port}\n")

    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        print(f"  {C.YELLOW}Skipped: 'requests' library not installed{C.RESET}")
        return 0

    base_url = f"https://{proxy_host}:{proxy_port}"
    total = 0
    failures = 0

    def send_jsonrpc(method, params=None, api_key=None):
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-MCP-API-Key"] = api_key
        try:
            r = requests.post(f"{base_url}/messages?sessionId=test",
                              json=payload, headers=headers, timeout=5, verify=False)
            return r.status_code, r.text
        except Exception as e:
            return -1, str(e)

    def check_live_allowed(desc, method, params, api_key):
        nonlocal total, failures
        total += 1
        status, body = send_jsonrpc(method, params, api_key)
        if status != 403 and status > 0:
            passed(f"{desc} -> HTTP {status}")
        else:
            failures += 1
            failed(desc, f"Expected not 403, got {status}")

    def check_live_denied(desc, method, params, api_key):
        nonlocal total, failures
        total += 1
        status, body = send_jsonrpc(method, params, api_key)
        if status == 403:
            passed(f"{desc} -> HTTP 403")
        else:
            failures += 1
            failed(desc, f"Expected 403, got {status}")

    print(f"  {C.BOLD}-- Full-access API key --{C.RESET}")
    check_live_allowed("tools/list", "tools/list", {}, "full-access-key-001")
    check_live_allowed("tools/call → create_entities",
                       "tools/call", {"name": "create_entities", "arguments": {}}, "full-access-key-001")

    print(f"\n  {C.BOLD}-- Analyst API key --{C.RESET}")
    check_live_allowed("tools/call → create_entities (allowed)",
                       "tools/call", {"name": "create_entities", "arguments": {}}, "analyst-key-001")
    check_live_denied("tools/call → write_file (denied)",
                      "tools/call", {"name": "write_file", "arguments": {}}, "analyst-key-001")
    check_live_denied("tools/call → delete_entities (denied)",
                      "tools/call", {"name": "delete_entities", "arguments": {}}, "analyst-key-001")

    print(f"\n  {C.BOLD}-- Readonly API key --{C.RESET}")
    check_live_allowed("tools/list", "tools/list", {}, "readonly-key-001")
    check_live_denied("tools/call → create_entities (denied)",
                      "tools/call", {"name": "create_entities", "arguments": {}}, "readonly-key-001")

    print(f"\n  {C.BOLD}Results: {total - failures}/{total} passed", end="")
    if failures:
        print(f" ({C.RED}{failures} failed{C.RESET}{C.BOLD}){C.RESET}")
    else:
        print(f" {C.GREEN}(all passed){C.RESET}")
    return failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test MCP RBAC Policy Engine")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=18441)
    args = parser.parse_args()

    policy_path = args.policy
    if not policy_path:
        here = os.path.dirname(os.path.abspath(__file__))
        policy_path = os.path.join(here, "tool_policy.yaml")

    if not os.path.exists(policy_path):
        print(f"{C.RED}Policy file not found: {policy_path}{C.RESET}")
        sys.exit(1)

    print(f"{C.BOLD}{C.CYAN}{'=' * 52}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}   MCP RBAC Policy Engine -- Test Suite (v2)       {C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 52}{C.RESET}")

    total_failures = run_unit_tests(policy_path)

    if args.live:
        total_failures += run_integration_tests(args.proxy_host, args.proxy_port)
    else:
        print(f"\n  {C.YELLOW}[i] Integration tests skipped (use --live to enable){C.RESET}")

    print()
    if total_failures:
        print(f"{C.RED}{C.BOLD}FAILED: {total_failures} test(s) failed.{C.RESET}")
        sys.exit(1)
    else:
        print(f"{C.GREEN}{C.BOLD}ALL TESTS PASSED{C.RESET}")
        sys.exit(0)
