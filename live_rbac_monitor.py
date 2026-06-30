import os
import sys
import time
import json

ML_LOG = os.path.join(os.path.dirname(__file__), "logs", "encrypted_rbac_audit.jsonl")
PROXY_LOG = os.path.join(os.path.dirname(__file__), "logs", "rbac_audit.jsonl")

def tail_file(path):
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "a") as f:
            pass
    f = open(path, "r", encoding="utf-8")
    f.seek(0, 2)
    return f

def process_ml_line(line):
    entry = json.loads(line.strip())
    source_ip = entry.get("source_ip", "unknown")
    role = entry.get("role", "unknown")
    server = entry.get("predicted_server", "unknown")
    confidence = entry.get("confidence", 0.0)
    decision = entry.get("decision", "PASS")
    reason = entry.get("reason", "")
    
    if decision == "ALLOW":
        marker = "\033[92m[ALLOW]\033[0m" # Green
    elif decision == "DENY":
        marker = "\033[91m[DENY ]\033[0m" # Red
    elif decision == "WAIT":
        marker = "\033[93m[WAIT ]\033[0m" # Yellow
    else:
        marker = "\033[90m[PASS ]\033[0m" # Gray
        
    print(f"  \033[36m[LAYER 4 ML]\033[0m Source IP: {source_ip:<15} | Role: {role:<10}")
    print(f"  Prediction: server='{server}' (confidence: {confidence*100:.1f}%)")
    print(f"  RBAC Decision: {marker} {reason}")
    print(f"  {'_' * 60}")

def process_proxy_line(line):
    entry = json.loads(line.strip())
    client_ip = entry.get("client_ip", "unknown")
    role = entry.get("role", "unknown")
    server = entry.get("server", "unknown")
    method = entry.get("method", "")
    tool = entry.get("tool", "")
    decision = entry.get("decision", "PASS")
    reason = entry.get("reason", "")
    
    if decision == "ALLOW":
        marker = "\033[92m[ALLOW]\033[0m" # Green
    elif decision == "DENY":
        marker = "\033[91m[DENY ]\033[0m" # Red
    else:
        marker = "\033[90m[PASS ]\033[0m" # Gray
        
    print(f"  \033[35m[LAYER 7 TLS]\033[0m Source IP: {client_ip:<15} | Role: {role:<10}")
    print(f"  Request: server='{server}' | method='{method}' | tool='{tool}'")
    print(f"  RBAC Decision: {marker} {reason}")
    print(f"  {'_' * 60}")

def main():
    print()
    print("=" * 70)
    print("  LIVE RBAC MONITOR - Multi-Layer Inspection")
    print("=" * 70)
    print("  Monitoring live traffic flows...")
    print("  \033[36m[LAYER 4 ML]\033[0m  Decisions made by ML Firewall WITHOUT Decryption")
    print("  \033[35m[LAYER 7 TLS]\033[0m Decisions made by TLS Proxy WITH Decryption")
    print("-" * 70)

    f_ml = tail_file(ML_LOG)
    f_proxy = tail_file(PROXY_LOG)

    while True:
        line_ml = f_ml.readline()
        line_pr = f_proxy.readline()
        
        handled = False
        if line_ml:
            try:
                process_ml_line(line_ml)
            except Exception: pass
            handled = True
            
        if line_pr:
            try:
                process_proxy_line(line_pr)
            except Exception: pass
            handled = True
            
        if not handled:
            time.sleep(0.1)

if __name__ == "__main__":
    try:
        # Enable ANSI escape codes on Windows
        os.system("")
        main()
    except KeyboardInterrupt:
        print("\nExiting Live Monitor...")
        sys.exit(0)
