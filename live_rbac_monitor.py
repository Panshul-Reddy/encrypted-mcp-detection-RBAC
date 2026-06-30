import os
import sys
import time
import json
import threading

ML_LOG = os.path.join(os.path.dirname(__file__), "logs", "encrypted_rbac_audit.jsonl")
PROXY_LOG = os.path.join(os.path.dirname(__file__), "logs", "rbac_audit.jsonl")

def tail_file(filepath, callback, prefix):
    if not os.path.exists(os.path.dirname(filepath)):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if not os.path.exists(filepath):
        with open(filepath, "a") as f: pass

    with open(filepath, "r", encoding="utf-8") as f:
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
    if source == "ML Firewall":
        role = entry.get("role", "unknown")
        server = entry.get("predicted_server", "unknown")
        decision = entry.get("decision", "PASS")
        reason = entry.get("reason", "")
        
        if decision == "ALLOW": marker = "\033[92m[ALLOW]\033[0m"
        elif decision == "DENY": marker = "\033[91m[DENY ]\033[0m"
        elif decision == "WAIT": marker = "\033[93m[WAIT ]\033[0m"
        else: marker = "\033[90m[PASS ]\033[0m"
        
        is_mcp = server != "noise"
        traffic_type = "Encrypted MCP" if is_mcp else "Normal Traffic"
        
        print(f"\n[\033[96mML Firewall\033[0m] Traffic: {traffic_type} | Server: {server} | Role: {role}")
        print(f"  └─ {marker} {reason}")
        
    elif source == "TLS Proxy":
        role = entry.get("role", "unknown")
        method = entry.get("method", "unknown")
        tool = entry.get("tool", "")
        server = entry.get("server", "unknown")
        decision = entry.get("decision", "PASS")
        reason = entry.get("reason", "")
        
        if decision == "ALLOW": marker = "\033[92m[ALLOW]\033[0m"
        elif decision == "DENY": marker = "\033[91m[DENY ]\033[0m"
        else: marker = "\033[90m[PASS ]\033[0m"
        
        action = f"{method}/{tool}" if tool else method
        
        print(f"\n[\033[95mTLS Proxy\033[0m] App-Layer Access | Server: {server} | Role: {role}")
        print(f"  ├─ Action: {action}")
        print(f"  └─ {marker} {reason}")

def main():
    print("=" * 70)
    print("  LIVE ENCRYPTED RBAC MONITOR (Dual-Layer)")
    print("  Monitoring ML Firewall & TLS Proxy logs...")
    print("=" * 70)

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
    os.system("")
    main()
