"""
RBAC Audit Report Generator

Reads the JSON Lines audit log produced by the TLS proxy and generates
a formatted security report showing access patterns, violations, and
per-role statistics.

Usage:
    python audit_report.py
    python audit_report.py --log ../logs/rbac_audit.jsonl
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ANSI colors
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; D = "\033[2m"; X = "\033[0m"


def load_audit_log(path):
    """Load all entries from a JSONL audit log."""
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def generate_report(entries, log_path=None):
    """Generate and print a formatted security report."""
    if not entries:
        print(f"{Y}No audit entries found.{X}")
        return

    total = len(entries)
    allowed = sum(1 for e in entries if e.get("decision") == "ALLOW")
    denied = total - allowed

    # Per-role stats
    role_stats = defaultdict(lambda: {"allow": 0, "deny": 0, "tools": Counter()})
    denied_attempts = []
    tool_usage = Counter()

    for e in entries:
        role = e.get("role", "unknown")
        decision = e.get("decision", "DENY")
        tool = e.get("tool", "")
        method = e.get("method", "")

        if decision == "ALLOW":
            role_stats[role]["allow"] += 1
        else:
            role_stats[role]["deny"] += 1
            denied_attempts.append(e)

        if tool:
            role_stats[role]["tools"][tool] += 1
            tool_usage[tool] += 1

    # ── Print Report ──
    print(f"\n{B}{C}{'=' * 62}{X}")
    print(f"{B}{C}   RBAC Security Audit Report{X}")
    print(f"{B}{C}{'=' * 62}{X}")

    ts_first = entries[0].get("timestamp", "?")
    ts_last = entries[-1].get("timestamp", "?")
    print(f"\n  {D}Period: {ts_first} → {ts_last}{X}")
    print(f"  {D}Total events: {total}{X}")

    # Summary bar
    allow_pct = (allowed / total) * 100 if total else 0
    deny_pct = (denied / total) * 100 if total else 0
    bar_len = 40
    allow_bar = int(bar_len * allowed / total) if total else 0
    deny_bar = bar_len - allow_bar
    print(f"\n  {G}{'█' * allow_bar}{R}{'█' * deny_bar}{X}")
    print(f"  {G}ALLOWED: {allowed} ({allow_pct:.0f}%){X}  {R}DENIED: {denied} ({deny_pct:.0f}%){X}")

    # Per-role breakdown
    print(f"\n{B}  ── Per-Role Breakdown ──{X}\n")
    for role in sorted(role_stats.keys()):
        stats = role_stats[role]
        r_total = stats["allow"] + stats["deny"]
        print(f"  {B}{role.upper()}{X} ({r_total} requests)")
        print(f"    {G}Allowed: {stats['allow']}{X}  {R}Denied: {stats['deny']}{X}")
        if stats["tools"]:
            top_tools = stats["tools"].most_common(5)
            tools_str = ", ".join(f"{t}({c})" for t, c in top_tools)
            print(f"    Tools used: {tools_str}")
        print()

    # Denied attempts detail
    if denied_attempts:
        print(f"{B}  ── Policy Violations (Denied Requests) ──{X}\n")
        for e in denied_attempts[-15:]:  # Show last 15
            ts = e.get("timestamp", "?")[11:19]  # Time only
            role = e.get("role", "?")
            method = e.get("method", "?")
            tool = e.get("tool", "")
            reason = e.get("reason", "")
            tool_str = f" → {tool}" if tool else ""
            print(f"    {R}✗{X} [{ts}] {D}role={role}{X} {method}{tool_str}")
            if reason:
                # Truncate long reasons
                short = reason[:80] + "..." if len(reason) > 80 else reason
                print(f"      {Y}{short}{X}")
        if len(denied_attempts) > 15:
            print(f"    {D}... and {len(denied_attempts) - 15} more{X}")
        print()

    # Most targeted tools
    print(f"{B}  ── Most Used Tools ──{X}\n")
    for tool, count in tool_usage.most_common(10):
        bar = "▓" * min(count, 30)
        print(f"    {tool:30s} {bar} {count}")

    # Per-server breakdown
    server_stats = defaultdict(lambda: {"allow": 0, "deny": 0})
    for e in entries:
        server = e.get("server", "")
        if server:
            if e.get("decision") == "ALLOW":
                server_stats[server]["allow"] += 1
            else:
                server_stats[server]["deny"] += 1

    if server_stats:
        print(f"\n{B}  ── Per-Server Breakdown ──{X}\n")
        for server in sorted(server_stats.keys()):
            s = server_stats[server]
            s_total = s["allow"] + s["deny"]
            print(f"    {server:15s}  {G}✓{s['allow']:3d}{X}  {R}✗{s['deny']:3d}{X}  (total: {s_total})")

    # Payload inspection log
    payload_path = os.path.join(os.path.dirname(log_path), "payload_inspection.jsonl")
    if os.path.exists(payload_path):
        p_entries = load_audit_log(payload_path)
        if p_entries:
            print(f"\n{B}  ── Payload Inspection Summary ({len(p_entries)} entries) ──{X}\n")
            # Show last 10 entries
            for e in p_entries[-10:]:
                ts = e.get("timestamp", "?")[11:19]
                server = e.get("server", "?")
                role = e.get("role", "?")
                tool = e.get("tool", "")
                args = e.get("arguments", "")
                decision = e.get("decision", "?")
                d_color = G if decision == "ALLOW" else R
                tool_str = f" → {tool}" if tool else ""
                args_str = f"  {D}{args[:60]}{'...' if len(args) > 60 else ''}{X}" if args else ""
                print(f"    [{ts}] {d_color}{decision}{X} {server}{tool_str}{args_str}")

    print(f"\n{B}{C}{'=' * 62}{X}\n")


def main():
    parser = argparse.ArgumentParser(description="RBAC Audit Report Generator")
    parser.add_argument("--log", default=None,
                        help="Path to rbac_audit.jsonl")
    args = parser.parse_args()

    log_path = args.log
    if not log_path:
        here = os.path.dirname(os.path.abspath(__file__))
        project = os.path.dirname(here)
        log_path = os.path.join(project, "logs", "rbac_audit.jsonl")

    print(f"Reading audit log: {log_path}")
    entries = load_audit_log(log_path)
    generate_report(entries, log_path)


if __name__ == "__main__":
    main()
