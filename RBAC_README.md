# Encrypted RBAC: Layer 4 Access Control

Traditional Role-Based Access Control (RBAC) relies on Layer 7 proxies. These proxies must decrypt TLS connections, parse HTTP headers, extract API keys, and read JSON payloads to determine if a user has permission to perform an action. This introduces significant latency, creates a single point of failure, and compromises payload privacy.

**Encrypted RBAC** represents a paradigm shift. We enforce strict Access Control directly at the Transport Layer (Layer 4) without ever decrypting the traffic.

---

## 🏗️ How It Works (Zero-Decryption Architecture)

To perform access control, a firewall needs two pieces of information:
1. **Who is the user?** (Identity)
2. **What are they trying to do?** (Target)

### 1. Identity Resolution (TCP Headers)
Even in fully encrypted HTTPS/TLS connections, the underlying IP packet headers remain unencrypted so routers can deliver them. The Rust Live Analyzer extracts the **Source IP Address** directly from the TCP header. 
This IP is mapped to a predefined security role using Zero-Trust principles (unknown IPs default to `readonly`).

### 2. Target Prediction (Machine Learning)
Instead of decrypting the payload to read the JSON-RPC method, the ML Firewall analyzes the metadata of the encrypted packet flow:
* Inter-arrival Times (IAT)
* Packet Sizes
* Traffic Direction (Up/Down)

The XGBoost Early-Classification model predicts which MCP server the client is communicating with (e.g., `github`, `filesystem`, `noise`) based purely on these timing and sizing fingerprints.

### 3. The Decision Engine
The Python FastFlow API (`api.py`) combines the Identity and the Prediction:
* **Example:** IP `10.11.0.40` is mapped to `readonly`. The ML model predicts the traffic is targeting the `filesystem` server. The policy engine instantly returns **DENY** because `readonly` users cannot access the filesystem.
* The connection is dropped at the network layer before it ever reaches the application server.

---

## 🛡️ Confidence Gating

Machine Learning models operate on probabilities. To prevent falsely blocking a legitimate user early in a connection stream, the Encrypted RBAC engine utilizes **Confidence Gating**:
* If the ML prediction confidence is `< 40%`, the firewall returns a **WAIT** signal.
* The Rust kernel module keeps the connection open and captures more packets.
* Once the packet threshold provides enough features to push the confidence above the threshold, the firewall executes the **ALLOW** or **DENY** rule.

---

## 🚀 Running the Live Demo

The project includes a fully integrated real-time demonstration. 

1. Ensure **Npcap** is installed on your Windows machine (with or without WinPcap API compatibility).
2. Run the main orchestration script as **Administrator**:
   ```powershell
   .\start_demo.ps1
   ```
3. The script will orchestrate:
   - Docker backend servers
   - The FastFlow ML API (`api.py`)
   - Simulated traffic clients (`full` admin, `analyst` restricted, and `noise`)
   - The native Rust packet capture engine (`live-analyzer.exe`) in the background.

The foreground terminal will launch the **Live Encrypted RBAC Monitor**, streaming real-time `[ALLOW]`, `[DENY]`, `[WAIT]`, and `[PASS]` decisions as the firewall classifies the encrypted traffic live off the wire.

### Simulated Fallback
If Npcap is missing or you are not running as Administrator, `start_demo.ps1` will seamlessly fall back to `rust_simulator.py`. This streams raw dataset features to the ML API to guarantee the presentation runs flawlessly regardless of environment constraints.

---

## 📊 Security Auditing

Because Layer 4 drops happen before the application layer logs a request, the ML API maintains a strict, unified security audit trail.

Run the audit report generator to view a formatted breakdown of all network-layer policy decisions:
```powershell
proxy\.venv\Scripts\python.exe proxy\audit_report.py
```

### Sample Output:
```
  Traffic Breakdown: 181164 Noise (PASS), 29398 Pending (WAIT)
  Policy Decisions : 2276 total
  ████████████████████████████████████████
  ALLOWED: 1077 (47%)  DENIED: 1199 (53%)

  ── Policy Violations (Blocked at Network Layer) ──
    ✗ [06:22:56] IP: 10.11.0.40 | Role: readonly → filesystem (conf: 55.6%)
```
