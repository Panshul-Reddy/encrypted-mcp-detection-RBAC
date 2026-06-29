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
    role_stats = defaultdict(lambda: {"allow": 0, "deny": 0, "wait": 0, "pass": 0, "servers": Counter()})
    denied_attempts = []
    
    for e in entries:
        role = e.get("role", "unknown")
        decision = e.get("decision", "DENY")
        server = e.get("predicted_server", "unknown")
        
        if decision == "ALLOW":
            role_stats[role]["allow"] += 1
        elif decision == "DENY":
            role_stats[role]["deny"] += 1
            denied_attempts.append(e)
        elif decision == "WAIT":
            role_stats[role]["wait"] += 1
        elif decision == "PASS":
            role_stats[role]["pass"] += 1

        if server and server != "noise":
            role_stats[role]["servers"][server] += 1

    # ── Print Report ──
    print(f"\n{B}{C}{'=' * 68}{X}")
    print(f"{B}{C}   Encrypted RBAC Security Audit Report (Layer 4 Firewall){X}")
    print(f"{B}{C}{'=' * 68}{X}")

    ts_first = entries[0].get("timestamp", "?")
    ts_last = entries[-1].get("timestamp", "?")
    print(f"\n  {D}Period: {ts_first} → {ts_last}{X}")
    print(f"  {D}Total connections evaluated: {total}{X}")

    allowed = sum(1 for e in entries if e.get("decision") == "ALLOW")
    denied = sum(1 for e in entries if e.get("decision") == "DENY")
    wait = sum(1 for e in entries if e.get("decision") == "WAIT")
    passed = sum(1 for e in entries if e.get("decision") == "PASS")

    # Summary bar (we'll just show ALLOW vs DENY for actual policy decisions)
    policy_total = allowed + denied
    allow_pct = (allowed / policy_total) * 100 if policy_total else 0
    deny_pct = (denied / policy_total) * 100 if policy_total else 0
    bar_len = 40
    allow_bar = int(bar_len * allowed / policy_total) if policy_total else 0
    deny_bar = bar_len - allow_bar
    print(f"\n  {D}Traffic Breakdown: {passed} Noise (PASS), {wait} Pending (WAIT){X}")
    print(f"  {D}Policy Decisions : {policy_total} total{X}")
    print(f"  {G}{'█' * allow_bar}{R}{'█' * deny_bar}{X}")
    print(f"  {G}ALLOWED: {allowed} ({allow_pct:.0f}%){X}  {R}DENIED: {denied} ({deny_pct:.0f}%){X}")

    # Per-role breakdown
    print(f"\n{B}  ── Per-Role Breakdown ──{X}\n")
    for role in sorted(role_stats.keys()):
        stats = role_stats[role]
        r_total = stats["allow"] + stats["deny"] + stats["wait"] + stats["pass"]
        print(f"  {B}{role.upper()}{X} ({r_total} flows evaluated)")
        print(f"    {G}Allowed: {stats['allow']}{X}  {R}Denied: {stats['deny']}{X}  {Y}Wait: {stats['wait']}{X}  {D}Pass (Noise): {stats['pass']}{X}")
        if stats["servers"]:
            top_servers = stats["servers"].most_common(5)
            servers_str = ", ".join(f"{s}({c})" for s, c in top_servers)
            print(f"    Targeted servers: {servers_str}")
        print()

    # Denied attempts detail
    if denied_attempts:
        print(f"\n{B}  ── Policy Violations (Blocked at Network Layer) ──{X}\n")
        for e in denied_attempts[-15:]:  # Show last 15
            ts = e.get("timestamp", "?")[11:19]  # Time only
            role = e.get("role", "?")
            ip = e.get("source_ip", "?")
            server = e.get("predicted_server", "?")
            conf = e.get("confidence", 0) * 100
            print(f"    {R}✗{X} [{ts}] {D}IP: {ip} | Role: {role}{X} → {server} (conf: {conf:.1f}%)")
        if len(denied_attempts) > 15:
            print(f"    {D}... and {len(denied_attempts) - 15} more{X}")
        print()

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
        log_path = os.path.join(project, "classifier", "logs", "encrypted_rbac_audit.jsonl")

    print(f"Reading Encrypted RBAC audit log: {log_path}")
    entries = load_audit_log(log_path)
    generate_report(entries, log_path)


if __name__ == "__main__":
    main()
