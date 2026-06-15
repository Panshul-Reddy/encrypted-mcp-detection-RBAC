"""
MCP Tool-Level Access Control — Policy Engine Tests

This script validates the RBAC policy engine in two modes:

  1. UNIT TESTS (offline):  Exercise the PolicyEngine class directly against
     the YAML policy file without any network dependencies. These tests
     verify all combinations of client identity, methods, and tools.

  2. INTEGRATION TESTS (live): Connect to a running TLS proxy and verify
     that policy enforcement is applied to real MCP JSON-RPC requests.
     Requires: proxy + MCP servers running (e.g., via start_demo.ps1).

Usage:
    # Unit tests only (no network required)
    python test_policy.py

    # Unit + integration tests (proxy must be running)
    python test_policy.py --live --proxy-host 127.0.0.1 --proxy-port 8441
"""

import argparse
import json
import os
import sys
import traceback

# Force UTF-8 output on Windows (avoids cp1252 encoding errors)
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─── Add the proxy directory to the path so we can import PolicyEngine ───
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_proxy import PolicyEngine


# =============================================================================
# ANSI Colors for terminal output
# =============================================================================

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


# =============================================================================
# Unit Tests — PolicyEngine logic
# =============================================================================

def run_unit_tests(policy_path):
    """Test the PolicyEngine against all relevant scenarios."""
    print(f"\n{C.BOLD}{C.CYAN}== Unit Tests: PolicyEngine =={C.RESET}")
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

    # -- Full-access client (by IP) --
    print(f"  {C.BOLD}-- Full-access client (IP: 10.11.0.30) --{C.RESET}")
    check("tools/list",
          "10.11.0.30", "", "tools/list", "", True)
    check("tools/call → list_directory",
          "10.11.0.30", "", "tools/call", "list_directory", True)
    check("tools/call → create_entities",
          "10.11.0.30", "", "tools/call", "create_entities", True)
    check("tools/call → write_file",
          "10.11.0.30", "", "tools/call", "write_file", True)
    check("resources/read",
          "10.11.0.30", "", "resources/read", "", True)

    # -- Readonly client (by IP) --
    print(f"\n  {C.BOLD}-- Readonly client (IP: 10.11.0.40) --{C.RESET}")
    check("tools/list (allowed)",
          "10.11.0.40", "", "tools/list", "", True)
    check("tools/call → list_directory (allowed — read tool)",
          "10.11.0.40", "", "tools/call", "list_directory", True)
    check("tools/call → search (allowed — read tool)",
          "10.11.0.40", "", "tools/call", "search", True)
    check("tools/call → fetch (allowed — read tool)",
          "10.11.0.40", "", "tools/call", "fetch", True)
    check("tools/call → create_entities (DENIED — write tool)",
          "10.11.0.40", "", "tools/call", "create_entities", False)
    check("tools/call → write_file (DENIED — write tool)",
          "10.11.0.40", "", "tools/call", "write_file", False)
    check("tools/call → delete_entities (DENIED — write tool)",
          "10.11.0.40", "", "tools/call", "delete_entities", False)
    check("resources/read (allowed)",
          "10.11.0.40", "", "resources/read", "", True)
    check("initialize (allowed)",
          "10.11.0.40", "", "initialize", "", True)
    check("ping (allowed)",
          "10.11.0.40", "", "ping", "", True)

    # -- Readonly client: method-level denial --
    print(f"\n  {C.BOLD}-- Readonly: method-level restrictions --{C.RESET}")
    check("some/unknown/method (DENIED)",
          "10.11.0.40", "", "some/unknown/method", "", False)
    check("__unparseable__ body (DENIED — fail-closed)",
          "10.11.0.40", "", "__unparseable__", "", False)

    # -- Wildcard method matching (notifications/*) --
    print(f"\n  {C.BOLD}-- Wildcard method matching --{C.RESET}")
    check("notifications/initialized (allowed via notifications/*)",
          "10.11.0.40", "", "notifications/initialized", "", True)
    check("notifications/cancelled (allowed via notifications/*)",
          "10.11.0.40", "", "notifications/cancelled", "", True)

    # -- API key overrides IP --
    print(f"\n  {C.BOLD}-- API key priority over IP --{C.RESET}")
    check("Readonly IP + full API key → tools/call create_entities (allowed)",
          "10.11.0.40", "full-access-key-001", "tools/call", "create_entities", True)
    check("Full IP + readonly API key → tools/call create_entities (DENIED)",
          "10.11.0.30", "readonly-key-001", "tools/call", "create_entities", False)
    check("Full IP + readonly API key → tools/list (allowed)",
          "10.11.0.30", "readonly-key-001", "tools/list", "", True)

    # -- Unknown client (default role) --
    print(f"\n  {C.BOLD}-- Unknown client (default role) --{C.RESET}")
    check("Unknown IP → tools/list (allowed — readonly default)",
          "192.168.1.99", "", "tools/list", "", True)
    check("Unknown IP → tools/call create_entities (DENIED — readonly default)",
          "192.168.1.99", "", "tools/call", "create_entities", False)
    check("Unknown IP → tools/call list_directory (allowed — read tool)",
          "192.168.1.99", "", "tools/call", "list_directory", True)

    # -- Localhost (full access in default policy) --
    print(f"\n  {C.BOLD}-- Localhost (127.0.0.1) --{C.RESET}")
    check("localhost → tools/call create_entities (allowed)",
          "127.0.0.1", "", "tools/call", "create_entities", True)
    check("localhost → tools/call write_file (allowed)",
          "127.0.0.1", "", "tools/call", "write_file", True)

    # ── Summary ──
    print(f"\n  {C.BOLD}Results: {total - failures}/{total} passed", end="")
    if failures:
        print(f" ({C.RED}{failures} failed{C.RESET}{C.BOLD}){C.RESET}")
    else:
        print(f" {C.GREEN}(all passed){C.RESET}")

    return failures


# =============================================================================
# Integration Tests — Live proxy
# =============================================================================

def run_integration_tests(proxy_host, proxy_port):
    """Test against a running TLS proxy with policy enforcement."""
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
        """Send a JSON-RPC request to the proxy and return the HTTP status code."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {}
        }
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-MCP-API-Key"] = api_key
        try:
            # We need a session ID. For simplicity, use a dummy one —
            # the policy check happens before the backend processes it.
            r = requests.post(
                f"{base_url}/messages?sessionId=test-policy",
                json=payload, headers=headers, timeout=5, verify=False
            )
            return r.status_code, r.text
        except Exception as e:
            return -1, str(e)

    def check_live_allowed(desc, method, params, api_key):
        """Verify the proxy ALLOWS the request (forwards to backend, any non-403 status)."""
        nonlocal total, failures
        total += 1
        status, body = send_jsonrpc(method, params, api_key)
        if status != 403 and status > 0:
            passed(f"{desc} -> HTTP {status} (forwarded)")
        else:
            failures += 1
            failed(desc, f"Expected proxy to ALLOW (not 403), got {status}: {body[:120]}")

    def check_live_denied(desc, method, params, api_key):
        """Verify the proxy DENIES the request (returns 403, never reaches backend)."""
        nonlocal total, failures
        total += 1
        status, body = send_jsonrpc(method, params, api_key)
        if status == 403:
            passed(f"{desc} -> HTTP 403 (blocked)")
        else:
            failures += 1
            failed(desc, f"Expected proxy to DENY (403), got {status}: {body[:120]}")

    # -- Full-access via API key --
    print(f"  {C.BOLD}-- Full-access API key --{C.RESET}")
    check_live_allowed("tools/list (full key)",
               "tools/list", {}, "full-access-key-001")
    check_live_allowed("tools/call -> list_directory (full key)",
               "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}},
               "full-access-key-001")
    check_live_allowed("tools/call -> create_entities (full key)",
               "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
               "full-access-key-001")

    # -- Readonly via API key --
    print(f"\n  {C.BOLD}-- Readonly API key --{C.RESET}")
    check_live_allowed("tools/list (readonly key)",
               "tools/list", {}, "readonly-key-001")
    check_live_allowed("tools/call -> list_directory (readonly key)",
               "tools/call", {"name": "list_directory", "arguments": {"path": "/tmp"}},
               "readonly-key-001")
    check_live_denied("tools/call -> create_entities (readonly key -- DENIED)",
               "tools/call", {"name": "create_entities", "arguments": {"entities": []}},
               "readonly-key-001")

    # -- No API key (uses IP-based or default role) --
    print(f"\n  {C.BOLD}-- No API key (IP/default role) --{C.RESET}")
    check_live_allowed("tools/list (no key, localhost=full)",
               "tools/list", {}, None)

    print(f"\n  {C.BOLD}Results: {total - failures}/{total} passed", end="")
    if failures:
        print(f" ({C.RED}{failures} failed{C.RESET}{C.BOLD}){C.RESET}")
    else:
        print(f" {C.GREEN}(all passed){C.RESET}")

    return failures


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test MCP RBAC Policy Engine")
    parser.add_argument("--policy", default=None,
                        help="Path to tool_policy.yaml (default: auto-detect)")
    parser.add_argument("--live", action="store_true",
                        help="Run integration tests against a live proxy")
    parser.add_argument("--proxy-host", default="127.0.0.1",
                        help="Proxy host for integration tests")
    parser.add_argument("--proxy-port", type=int, default=8441,
                        help="Proxy port for integration tests")
    args = parser.parse_args()

    # Auto-detect policy file
    policy_path = args.policy
    if not policy_path:
        here = os.path.dirname(os.path.abspath(__file__))
        policy_path = os.path.join(here, "tool_policy.yaml")

    if not os.path.exists(policy_path):
        print(f"{C.RED}Policy file not found: {policy_path}{C.RESET}")
        sys.exit(1)

    print(f"{C.BOLD}{C.CYAN}{'=' * 52}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}   MCP Tool-Level Access Control -- Test Suite     {C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 52}{C.RESET}")

    total_failures = 0

    # Always run unit tests
    total_failures += run_unit_tests(policy_path)

    # Optionally run integration tests
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
