# Role-Based Access Control (RBAC) & Payload Inspection

This document details the new RBAC Proxy integration for the ML Firewall project. It explains the new features, the architectural changes, and exactly how to run the demonstrations for your presentation.

---

## 🌟 New Features Added

### 1. 🛡️ Three-Tier Role Hierarchy (Zero-Trust)
Instead of a simple "allow/deny all" model, the proxy now enforces an industry-grade role hierarchy:
- **`FULL` Role**: (Admin) Has unrestricted access to all MCP tools, methods, and servers.
- **`ANALYST` Role**: (Data Analyst) Can search, read files, and create entities, but is **explicitly denied** from using destructive tools like `write_file` or `delete_entities`.
- **`READONLY` Role**: Can only perform safe read operations. All write/delete operations are blocked.
- **Zero-Trust Default**: If a client connects without a recognized API key or IP address, they are automatically downgraded to the `READONLY` role.

### 2. 🔑 API Key Authentication
The system no longer relies purely on IP addresses (which can be spoofed). It now uses API keys passed via the `X-MCP-API-Key` HTTP header. 
- The **Groq Client** now automatically sends an admin API key.
- A new **Restricted Client** runs alongside it using an Analyst API key.
- API keys strictly override IP-based rules.

### 3. 🔍 Deep Payload & Server Inspection
The proxy no longer just logs "Port 13000". It intercepts the HTTP payload in real-time, inspects the JSON-RPC body, and logs:
- The **exact MCP Server** being accessed (e.g., `github`, `fetch`, `filesystem`).
- The **exact tool** being called (e.g., `search_repositories`).
- The **JSON arguments** being passed to the tool (e.g., `{"query": "MCP server"}`).

### 4. 📊 Security Audit Reporting
A new automated reporting script analyzes the proxy logs and generates a visual security audit report showing exactly how many requests were allowed/denied, broken down by role, server, and tool.

---

## 🏗️ Architectural Changes

1. **`proxy/tls_proxy.py`**: Completely rewritten to include the `PolicyEngine`. It intercepts the JSON payload, checks the API key, matches the tool against the `tool_policy.yaml`, and either forwards the request or returns a `403 Forbidden` response.
2. **`proxy/tool_policy.yaml`**: A new declarative configuration file where the roles and their explicit permissions are defined.
3. **`groq-client/groq_mcp_client.py`**: Updated to inject the `X-MCP-API-Key` header into every outbound POST request.
4. **`groq-client/restricted_mcp_client.py`**: A brand new test client that intentionally tries to run malicious/destructive operations (like deleting files) to prove that the firewall blocks them.
5. **`proxy/audit_report.py`**: A new script to parse the `rbac_audit.jsonl` and `payload_inspection.jsonl` logs and output a clean summary.

---

## 🚀 How to Run the Demos

There are two ways to demonstrate the system to your mentor.

### Option 1: The Live Integrated Demo (Full Architecture)
This shows the RBAC proxy working alongside Docker, the ML Firewall, and the Groq client in real-time.

1. **Start the containers** (if not already running):
   ```powershell
   docker compose up -d mcp-servers noise-server
   ```
2. **Launch the Demo** (Run as Administrator):
   ```powershell
   .\start_demo.ps1
   ```
   *Note: If the Rust TUI fails to start, the script will automatically drop into the **RBAC Live Monitor**, which streams proxy decisions (ALLOW/DENY) live to your screen.*
3. **Stop the Demo**: Press `Ctrl+C`.
4. **View the Results**:
   ```powershell
   proxy\.venv\Scripts\python.exe proxy\audit_report.py
   ```

### Option 2: The Standalone Demo (Fast & Clean)
If you just want to explain the RBAC logic without starting Docker or worrying about the rest of the pipeline, use the standalone demo. It spins up a mock backend, tests 5 different security scenarios in 30 seconds, and shuts down safely.

1. **Run the Standalone Demo**:
   ```powershell
   proxy\.venv\Scripts\python.exe proxy\standalone_demo.py
   ```
2. **View the Results**:
   ```powershell
   proxy\.venv\Scripts\python.exe proxy\audit_report.py
   ```

---

## 🗣️ Talking Points for Your Mentor

When presenting this to your mentor, emphasize these key points:

1. **Defense in Depth**: Explain that the Rust ML Analyzer operates at **Layer 4** (Network Transport layer, looking at packet timings and sizes), while this RBAC Proxy operates at **Layer 7** (Application layer). Together, they provide a complete "Defense in Depth" strategy.
2. **Granular Control**: We aren't just blocking IP addresses. We are inspecting the JSON payload itself. This means we can allow a Data Analyst to access the `filesystem` server to `read_file`, but actively block them if they try to call `write_file` on that exact same server.
3. **Compliance & Auditing**: Every single decision the proxy makes is logged to `rbac_audit.jsonl` and `payload_inspection.jsonl`. Emphasize that in enterprise environments, having an immutable audit log of *who* accessed *what tool* with *what payload* is critical for compliance.
