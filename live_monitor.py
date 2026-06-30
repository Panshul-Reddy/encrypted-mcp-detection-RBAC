import os
import sys
import time
import json
import threading
import colorama
from colorama import Fore, Back, Style

colorama.init()

ML_LOG = os.path.join(os.path.dirname(__file__), "logs", "encrypted_rbac_audit.jsonl")
PROXY_LOG = os.path.join(os.path.dirname(__file__), "logs", "rbac_audit.jsonl")

# Global state
stats = {"ALLOW": 0, "DENY": 0, "PASS": 0, "WAIT": 0, "total": 0}
log_counter = 0
lock = threading.Lock()

def render_header():
    # ANSI save cursor
    sys.stdout.write("\033[s")
    # ANSI move to top-left
    sys.stdout.write("\033[H")
    
    header = f"""\033[36m══════════════════════════════════════════════════════════════════════
      LIVE ENCRYPTED RBAC MONITOR
  Detecting MCP traffic WITHOUT decryption  ·  Ctrl+C to stop
══════════════════════════════════════════════════════════════════════
  \033[92m▐ ALLOW   {stats['ALLOW']:<4}\033[36m \033[91m▐ DENY   {stats['DENY']:<4}\033[36m \033[94m▐ PASS   {stats['PASS']:<4}\033[36m \033[93m▐ WAIT   {stats['WAIT']:<4}\033[36m │ Total {stats['total']:<4}
══════════════════════════════════════════════════════════════════════\033[0m
"""
    sys.stdout.write(header)
    # ANSI restore cursor
    sys.stdout.write("\033[u")
    sys.stdout.flush()

def tail_file(filepath, callback, prefix):
    if not os.path.exists(os.path.dirname(filepath)):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if not os.path.exists(filepath):
        with open(filepath, "a") as f: pass

    with open(filepath, "r", encoding="utf-8") as f:
        # Skip to end
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                entry = json.loads(line.strip())
                callback(entry, prefix)
            except Exception:
                pass

def log_callback(entry, source):
    global log_counter
    with lock:
        log_counter += 1
        counter_str = f"#{log_counter:04d}"
        
        decision = entry.get("decision", "PASS")
        stats[decision] = stats.get(decision, 0) + 1
        stats["total"] += 1
        
        ts = entry.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ"))
        # Parse time nicely
        if "T" in ts and "Z" in ts:
            ts = ts.split("T")[1].replace("Z", "")
            
        src_ip = entry.get("source_ip", "127.0.0.1")
        if "dst_port" in entry:
            src_ip = f"{src_ip}:{entry['dst_port']}"
            
        role = entry.get("role", "UNKNOWN").upper()
        reason = entry.get("reason", "")
        # truncate reason if too long
        if len(reason) > 30:
            reason = reason[:27] + "..."
            
        color_map = {
            "ALLOW": Fore.GREEN,
            "DENY": Fore.RED,
            "PASS": Fore.BLUE,
            "WAIT": Fore.YELLOW
        }
        dec_color = color_map.get(decision, Fore.WHITE)
        dec_str = f"{dec_color}[{decision:<6}]{Style.RESET_ALL}"
        
        if source == "ML Firewall":
            server = entry.get("predicted_server", "unknown")
            pkts = entry.get("packet_count", "?")
            bytes_val = entry.get("total_bytes", "?")
            conf = entry.get("confidence", 0.0)
            gt = entry.get("ground_truth", "unknown")
            model = entry.get("model", "unknown")
            
            # format conf
            if isinstance(conf, float):
                conf_str = f"{conf:.3f}"
            else:
                conf_str = str(conf)
            
            box = f"""
┌──────────────────────────────────────────────────────────────────┐
│ {counter_str}  \033[36m[ML-L4 ]\033[0m  {ts}  {src_ip:<15}  → {server:<15} │
├──────────────────────────────────────────────────────────────────┤
│ Pkts:{pkts:<3}  Bytes:{bytes_val:<5}  Conf:{conf_str:<5}  GT:{gt:<5}  Model:N={model:<11} │
├──────────────────────────────────────────────────────────────────┤
│ Role: {role:<10} ══▶  {dec_str}  {reason:<30} │
└──────────────────────────────────────────────────────────────────┘"""
            sys.stdout.write(box + "\n")
            
        elif source == "TLS Proxy":
            server = entry.get("server", "unknown")
            method = entry.get("method", "unknown")
            tool = entry.get("tool", "")
            action = f"{method} ({tool})" if tool else method
            
            box = f"""
┌──────────────────────────────────────────────────────────────────┐
│ {counter_str}  \033[35m[L7-PRXY]\033[0m  {ts}  {src_ip:<15}  → {server:<15} │
├──────────────────────────────────────────────────────────────────┤
│ Action: {action:<56} │
├──────────────────────────────────────────────────────────────────┤
│ Role: {role:<10} ══▶  {dec_str}  {reason:<30} │
└──────────────────────────────────────────────────────────────────┘"""
            sys.stdout.write(box + "\n")
            
        render_header()

def main():
    # Initial clear screen and make room for header
    sys.stdout.write("\033[2J\033[H")
    for _ in range(8):
        sys.stdout.write("\n")
    render_header()

    t1 = threading.Thread(target=tail_file, args=(ML_LOG, log_callback, "ML Firewall"), daemon=True)
    t2 = threading.Thread(target=tail_file, args=(PROXY_LOG, log_callback, "TLS Proxy"), daemon=True)
    
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting Live Monitor...")
        sys.exit(0)

if __name__ == "__main__":
    main()
