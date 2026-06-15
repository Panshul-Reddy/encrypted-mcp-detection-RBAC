# MCP Tool-Level Access Control (RBAC)

## Overview

As part of the **Encrypted MCP Payload Detection** project, we have implemented a **Role-Based Access Control (RBAC)** engine. While the core ML firewall operates on encrypted packets at the wire level (Layer 4), this new RBAC engine operates at the **Application Layer (Layer 7)** inside the TLS Proxy, where TLS is terminated.

This engine inspects the decrypted JSON-RPC payloads of MCP traffic and enforces granular, tool-level access control. This ensures that even if a client is authorized to communicate with the MCP server, they can only execute specific tools they are permitted to use (e.g., allowing `read_file` but blocking `write_file`).

---

## How It Works

The system intercepts `POST /messages` requests and evaluates the JSON-RPC payload:

1. **Client Identity Resolution:**
   The proxy determines the client's identity and assigns a role. It checks in the following order:
   - **API Key:** Extracted from the `X-MCP-API-Key` HTTP header (Highest Priority).
   - **Source IP Address:** Extracted from the TCP connection.
   - **Default Role:** Applied if no API key or IP matches.

2. **Policy Evaluation:**
   Based on the assigned role, the proxy checks `tool_policy.yaml` to see if the requested JSON-RPC `method` is allowed.
   - If the method is `tools/call`, it additionally inspects the `params.name` to see if the specific tool is allowed.

3. **Enforcement:**
   - **ALLOW:** The request is forwarded to the backend MCP server.
   - **DENY:** The proxy intercepts the request and instantly returns an HTTP 403 Forbidden with a JSON-RPC error message detailing why the request was blocked.

---

## Policy Configuration (`proxy/tool_policy.yaml`)

The security rules are defined in `proxy/tool_policy.yaml`. It contains two main sections: `roles` and `clients`.

### Roles

Roles define what a client is allowed to do. We currently define two primary roles:

*   **`readonly`:** Allowed to use standard MCP methods (like `tools/list`, `ping`, `initialize`) but restricted to read-only tools during `tools/call`.
    *   **Allowed Tools:** `list_directory`, `read_file`, `get_file_info`, `search_repositories`, `search`, `fetch`, `tavily-search`.
    *   **Blocked Tools:** Any tool that modifies state, such as `create_entities`, `write_file`, `delete_entities`.
*   **`full`:** Allowed to use all methods and all tools (defined using the wildcard `*`).

### Client Mapping

Clients are mapped to roles:
```yaml
clients:
  by_api_key:
    "full-access-key-001": "full"
    "readonly-key-001": "readonly"
  by_ip:
    "10.11.0.30": "full"       # groq-client
    "10.11.0.40": "readonly"   # noise-client
  default_role: "readonly"     # Zero-trust fallback
```

---

## File Structure & Components

*   **`proxy/tls_proxy.py`**: The main proxy server. It contains the `PolicyEngine` class which parses requests, maps roles, and enforces the rules.
*   **`proxy/tool_policy.yaml`**: The declarative configuration file for roles and client mappings.
*   **`proxy/test_policy.py`**: An automated test suite with 25 unit test cases validating all combinations of roles, IPs, API keys, methods, and tools.
*   **`proxy/standalone_demo.py`**: A live interactive demo script that runs without Docker, showing the RBAC enforcement in real-time.
*   **`proxy/manual_test.py`**: A helper script to send manual test requests to a running proxy.

---

## How to Test and Run the Demo

### 1. Run Automated Tests
To verify that the policy engine logic is sound and all rules are working correctly, run the automated test suite:
```powershell
cd proxy
..\proxy\.venv\Scripts\python.exe test_policy.py
```
*You should see 25/25 tests pass successfully.*

### 2. Run the Standalone Live Demo
We created a lightweight standalone demo that does **not** require Docker. It starts a mock backend, the TLS proxy, and sends a sequence of test requests showing ALLOW and DENY actions.

```powershell
cd proxy
..\proxy\.venv\Scripts\python.exe standalone_demo.py
```
**What you will see:**
*   A "Full-Access" client executing both read and write tools successfully (`✓ ALLOWED`).
*   A "Readonly" client executing read tools successfully, but getting blocked with HTTP 403 when trying to use `write_file` or `create_entities` (`✗ BLOCKED`).
*   An unknown client getting restricted to the default `readonly` role.
*   An API key successfully overriding a permissive IP address.

### 3. Integration with the Full Docker Demo
The RBAC engine is fully integrated into the main `tls_proxy.py`. If you run the main project demo (`start_demo.ps1` or `start_demo.sh`), the proxy will automatically enforce `tool_policy.yaml` on all traffic between the clients and the MCP servers inside Docker!
