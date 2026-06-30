import os
import sys
import time
import json

LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "encrypted_rbac_audit.jsonl")

def main():
    print()
    print("=" * 70)
    print("  LIVE ENCRYPTED RBAC MONITOR - Access Control WITHOUT Decryption")
    print("=" * 70)
    print("  Monitoring live traffic flows from ML Firewall...")
    print("-" * 70)

    if not os.path.exists(os.path.dirname(LOG_PATH)):
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "a") as f:
            pass

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            try:
                entry = json.loads(line.strip())
                source_ip = entry.get("source_ip", "unknown")
                role = entry.get("role", "unknown")
                server = entry.get("predicted_server", "unknown")
                confidence = entry.get("confidence", 0.0)
                decision = entry.get("decision", "PASS")
                reason = entry.get("reason", "")
                
                if decision == "ALLOW":
                    marker = "\033[92m[ALLOW]\033[0m"
                elif decision == "DENY":
                    marker = "\033[91m[DENY ]\033[0m"
                elif decision == "WAIT":
                    marker = "\033[93m[WAIT ]\033[0m"
                else:
                    marker = "\033[90m[PASS ]\033[0m"
                    
                is_mcp = server != "noise"
                traffic_type = "Encrypted MCP" if is_mcp else "Normal Traffic"
                
                print(f"  Source IP: {source_ip:<15} | Traffic: {traffic_type}")
                print(f"  Prediction: server='{server}' | Role: {role}")
                print(f"  RBAC Decision: {marker} {reason}")
                print(f"  {'_' * 60}")
                
            except Exception as e:
                pass

if __name__ == "__main__":
    try:
        os.system("")
        main()
    except KeyboardInterrupt:
        print("\nExiting Live Monitor...")
        sys.exit(0)
