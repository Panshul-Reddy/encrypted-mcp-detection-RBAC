"""
Mid-Stream TLS Proxy with MCP Tool-Level Access Control (RBAC)

This module implements an inline TLS proxy with two complementary security layers:

1. ML-BASED DETECTION (unchanged): The proxy forwards encrypted packets bidirectionally,
   permitting the Rust core to observe network traffic characteristics on the wire
   WITHOUT decryption. Upon receiving a positive identification of anomalous traffic
   from the ML inference engine, the proxy terminates the TCP stream via the UDP
   control protocol (KILL command).

2. RBAC POLICY ENGINE (new): Operating at the application layer INSIDE the proxy —
   where TLS has already been terminated by design — this engine inspects JSON-RPC
   payloads to enforce tool-level access control. Clients are mapped to roles
   (e.g., "readonly" vs "full") based on source IP or API key, and each role defines
   which MCP methods and tools are permitted.

These two layers are complementary:
- The ML firewall detects anomalous traffic patterns from encrypted wire observations.
- The RBAC engine enforces authorization rules at the application layer.
Neither requires changes to the other; both operate independently.
"""

import argparse
import asyncio
import json
import os
import ssl
import sys
import time
from collections import defaultdict

# ─── Optional: pyyaml for policy file ────────────────────────────────────────
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# =============================================================================
# Server Name Mapping (backend port → human-readable name)
# =============================================================================

SERVER_NAMES = {
    3000: "fetch",
    3001: "memory",
    3002: "filesystem",
    3003: "github",
    3004: "exa",
    3005: "tavily",
}


# =============================================================================
# Policy Engine
# =============================================================================

class PolicyEngine:
    """
    Evaluates MCP JSON-RPC requests against a declarative YAML policy.

    Determines whether a given client (identified by source IP or API key)
    is authorized to invoke a specific MCP method or tool.

    The policy file defines:
      - Roles: named permission sets (e.g., "readonly", "full")
      - Client mappings: IP → role, API key → role, default role

    Evaluation logic:
      1. Resolve client identity to a role (API key > IP > default)
      2. Check if the JSON-RPC method is allowed for that role
      3. If method is "tools/call", also check if the tool name is allowed
    """

    def __init__(self, policy_path=None):
        self.policy_path = policy_path
        self.roles = {}
        self.ip_map = {}
        self.api_key_map = {}
        self.default_role = "readonly"
        self.rate_limits = {}       # role_name -> max requests/minute
        self.request_counts = defaultdict(list)  # client_key -> [timestamps]
        self.audit_log_path = None
        self.payload_log_path = None

        if policy_path:
            self._load_policy()

    def _load_policy(self):
        """Load and parse the YAML policy file."""
        if not HAS_YAML:
            print("[policy] WARNING: pyyaml not installed — cannot load policy file. "
                  "All requests will be forwarded.", file=sys.stderr)
            self._set_permissive()
            return

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            self.roles = config.get("roles", {})
            clients = config.get("clients", {})
            self.ip_map = clients.get("by_ip", {})
            self.api_key_map = clients.get("by_api_key", {})
            self.default_role = clients.get("default_role", "readonly")

            # Extract rate limits from role definitions
            for rname, rdef in self.roles.items():
                if isinstance(rdef, dict) and "rate_limit" in rdef:
                    self.rate_limits[rname] = rdef["rate_limit"]

            print(f"[policy] Loaded policy from {self.policy_path}", file=sys.stderr)
            print(f"[policy]   Roles defined: {list(self.roles.keys())}", file=sys.stderr)
            print(f"[policy]   IP rules: {len(self.ip_map)}", file=sys.stderr)
            print(f"[policy]   API key rules: {len(self.api_key_map)}", file=sys.stderr)
            print(f"[policy]   Default role: {self.default_role}", file=sys.stderr)
        except Exception as e:
            print(f"[policy] ERROR loading policy from {self.policy_path}: {e}",
                  file=sys.stderr)
            self._set_deny_all()

    def _set_permissive(self):
        """
        DEV/TEST ONLY — allow everything. 
        Called only when explicitly no policy path is provided.
        On YAML parse errors, _load_policy calls _set_deny_all() instead.
        """
        self.roles = {"full": {"allowed_methods": "*", "allowed_tools": "*"}}
        self.ip_map = {}
        self.api_key_map = {}
        self.default_role = "full"

    def _set_deny_all(self):
        """Fail CLOSED — deny everything on policy load error."""
        self.roles = {"deny_all": {"allowed_methods": [], "allowed_tools": []}}
        self.ip_map = {}
        self.api_key_map = {}
        self.default_role = "deny_all"

    def reload(self):
        """Hot-reload the policy file."""
        print("[policy] Reloading policy file...", file=sys.stderr)
        self._load_policy()

    def _resolve_role(self, client_ip, api_key):
        """
        Resolve a client to a role name.
        Priority: API key → source IP → default role.
        """
        if api_key and api_key in self.api_key_map:
            return self.api_key_map[api_key]
        if client_ip and client_ip in self.ip_map:
            return self.ip_map[client_ip]
        return self.default_role

    def set_audit_log(self, path):
        """Set the path for the JSON Lines audit log."""
        self.audit_log_path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        print(f"[policy] Audit log: {path}", file=sys.stderr)

    def set_payload_log(self, path):
        """Set the path for the payload inspection JSONL log."""
        self.payload_log_path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        print(f"[policy] Payload inspection log: {path}", file=sys.stderr)

    def _audit(self, client_ip, client_port, dst_port, api_key, role, method, tool, decision, reason,
               server_name="", tool_args=None):
        """Write one audit entry to the JSONL log."""
        if not self.audit_log_path:
            return
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ip": client_ip,
            "client_port": client_port,
            "dst_port": dst_port,
            "api_key": (api_key[:8] + "...") if api_key and len(api_key) > 8 else (api_key or ""),
            "role": role,
            "method": method,
            "tool": tool or "",
            "server": server_name,
            "decision": decision,
            "reason": reason,
        }
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except Exception:
            pass

    def log_payload(self, client_ip, client_port, dst_port, role, server_name, method, tool, tool_args, decision):
        """Write detailed payload inspection entry to the JSONL log."""
        if not getattr(self, 'payload_log_path', None):
            return
        # Truncate large arguments for readability
        args_summary = ""
        if tool_args and isinstance(tool_args, dict):
            args_summary = json.dumps(tool_args, separators=(",", ":"), default=str)
            if len(args_summary) > 300:
                args_summary = args_summary[:300] + "..."
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ip": client_ip,
            "client_port": client_port,
            "dst_port": dst_port,
            "role": role,
            "server": server_name,
            "method": method,
            "tool": tool or "",
            "arguments": args_summary,
            "decision": decision,
        }
        try:
            with open(self.payload_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except Exception:
            pass

    def _check_rate_limit(self, client_key, role_name):
        """Check if client has exceeded their role's rate limit. Returns (ok, reason)."""
        limit = self.rate_limits.get(role_name, 0)
        if limit <= 0:
            return True, ""

        now = time.time()
        window = 60.0  # 1-minute window
        # Clean old timestamps
        self.request_counts[client_key] = [
            ts for ts in self.request_counts[client_key] if now - ts < window
        ]
        if len(self.request_counts[client_key]) >= limit:
            return False, f"Rate limit exceeded for role '{role_name}' ({limit}/min)"
        self.request_counts[client_key].append(now)
        return True, ""

    def _record_rate_limit(self, client_key: str):
        """
        No-op stub — timestamps are already appended inside _check_rate_limit().
        This method exists only because evaluate() calls it after an ALLOW decision
        on wildcard-tool roles, but the recording already happened upstream.
        """
        pass

    def evaluate(self, client_ip, client_port, api_key, rpc_method, tool_name, local_port=None):
        """
        Evaluate whether a client may invoke a given MCP method/tool.
        """
        role_name = self._resolve_role(client_ip, api_key)
        
        # If unresolved (or defaulted) and on loopback, use the port-based role
        if role_name == self.default_role and client_ip == "127.0.0.1" and local_port:
            port_role_map = {8440:"full", 8441:"analyst", 8442:"analyst",
                             8443:"readonly", 8444:"readonly", 8445:"readonly"}
            role_name = port_role_map.get(local_port, self.default_role)

        # ── Step 0: Check rate limit ──
        client_key = f"{client_ip}:{api_key or 'nokey'}"
        rate_ok, rate_reason = self._check_rate_limit(client_key, role_name)
        if not rate_ok:
            self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", rate_reason)
            return False, rate_reason

        role = self.roles.get(role_name)

        if role is None:
            self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", f"Unknown role '{role_name}'")
            return False, f"Unknown role '{role_name}'"

        # ── Step 1: Check method-level access ──
        allowed_methods = role.get("allowed_methods", [])

        if allowed_methods == "*":
            method_ok = True
        elif isinstance(allowed_methods, list):
            method_ok = False
            for pattern in allowed_methods:
                if pattern.endswith("/*"):
                    # Wildcard prefix match (e.g., "notifications/*")
                    prefix = pattern[:-2]
                    if rpc_method.startswith(prefix):
                        method_ok = True
                        break
                elif pattern == rpc_method:
                    method_ok = True
                    break
        else:
            method_ok = False

        if not method_ok:
            self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", f"Role '{role_name}' cannot invoke method '{rpc_method}'")
            return False, f"Role '{role_name}' cannot invoke method '{rpc_method}'"

        # ── Step 2: For tools/call, check tool-level access ──
        if rpc_method == "tools/call" and tool_name:
            # Check explicit deny list first (takes priority)
            denied_tools = role.get("denied_tools", [])
            if isinstance(denied_tools, list) and tool_name in denied_tools:
                reason = f"Tool '{tool_name}' is explicitly denied for role '{role_name}'"
                self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", reason)
                return False, reason

            allowed_tools = role.get("allowed_tools", [])

            if allowed_tools == "*":
                self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "ALLOW", f"Role '{role_name}' — full tool access")
                self._record_rate_limit(client_key)
                return True, f"Role '{role_name}' — full tool access"
            elif isinstance(allowed_tools, list):
                if tool_name in allowed_tools:
                    self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "ALLOW", f"Tool '{tool_name}' allowed for role '{role_name}'")
                    self._record_rate_limit(client_key)
                    return True, f"Tool '{tool_name}' allowed for role '{role_name}'"
                else:
                    self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", f"Role '{role_name}' cannot use tool '{tool_name}'")
                    return False, (f"Role '{role_name}' cannot use tool '{tool_name}' "
                                   f"(allowed: {', '.join(allowed_tools)})")
            else:
                self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "DENY", f"Role '{role_name}' has no tool access configured")
                return False, f"Role '{role_name}' has no tool access configured"

        self._audit(client_ip, client_port, local_port, api_key, role_name, rpc_method, tool_name, "ALLOW", f"Method '{rpc_method}' allowed for role '{role_name}'")
        self._record_rate_limit(client_key)
        return True, f"Method '{rpc_method}' allowed for role '{role_name}'"


# =============================================================================
# HTTP Request Parser (lightweight, no external deps)
# =============================================================================

class HttpRequest:
    """A parsed HTTP/1.1 request extracted from raw TCP bytes."""
    __slots__ = ("method", "path", "version", "headers", "body", "raw")

    def __init__(self):
        self.method = ""
        self.path = ""
        self.version = ""
        self.headers = {}   # lowercase keys
        self.body = b""
        self.raw = b""      # complete raw bytes for forwarding to backend


async def read_http_request(reader):
    """
    Read and parse one complete HTTP/1.1 request from an asyncio StreamReader.
    Returns an HttpRequest, or None if the connection was closed or unparseable.
    """
    req = HttpRequest()
    header_buf = b""

    # Accumulate bytes until we find the header/body separator
    while b"\r\n\r\n" not in header_buf:
        chunk = await reader.read(8192)
        if not chunk:
            return None  # Connection closed
        header_buf += chunk
        if len(header_buf) > 65536:
            return None  # Header too large — reject

    # Split header section from any body bytes already read
    sep_idx = header_buf.index(b"\r\n\r\n")
    header_section = header_buf[:sep_idx]
    body_start = header_buf[sep_idx + 4:]

    # Parse the request line (e.g., "POST /messages?sessionId=abc HTTP/1.1")
    lines = header_section.decode("utf-8", errors="replace").split("\r\n")
    if not lines:
        return None

    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None

    req.method = parts[0].upper()
    req.path = parts[1]
    req.version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    # Parse headers (case-insensitive keys)
    for line in lines[1:]:
        colon = line.find(":")
        if colon > 0:
            key = line[:colon].strip().lower()
            val = line[colon + 1:].strip()
            req.headers[key] = val

    # Read the remaining body bytes based on Content-Length
    content_length = int(req.headers.get("content-length", "0"))
    req.body = body_start

    while len(req.body) < content_length:
        remaining = content_length - len(req.body)
        chunk = await reader.read(min(8192, remaining))
        if not chunk:
            break
        req.body += chunk

    # Store the complete raw request for forwarding
    req.raw = header_section + b"\r\n\r\n" + req.body
    return req


# =============================================================================
# Connection Tracking & KILL Protocol (preserved from original)
# =============================================================================

# Maps client endpoints (ip:port) to their StreamWriter for mid-stream kills.
active_connections = {}


class ControlProtocol(asyncio.DatagramProtocol):
    """
    UDP Datagram Protocol handler for out-of-band control directives.
    Listens for 'KILL <ip>:<port>' commands from the Rust ML analyzer
    and severs the matching TCP connections.
    """
    def datagram_received(self, data, addr):
        msg = data.decode().strip()
        print(f"[control] Received command: {msg}", file=sys.stderr)
        if msg.startswith("KILL "):
            target = msg.split(" ")[1]
            if target in active_connections:
                print(f"[control] Executing Mid-Stream KILL on {target}",
                      file=sys.stderr)
                try:
                    writer = active_connections[target]
                    writer.close()
                except Exception as e:
                    print(f"[control] Error closing {target}: {e}",
                          file=sys.stderr)
            else:
                print(f"[control] Target {target} not found in active connections.",
                      file=sys.stderr)


# =============================================================================
# Proxy Core
# =============================================================================

async def pipe(reader, writer, client_key):
    """Bidirectional byte pipe between two asyncio streams."""
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def build_http_403(rpc_id, reason):
    """
    Construct a raw HTTP 403 response carrying a JSON-RPC error.
    Returned to the client when a policy denies the request.
    """
    error_body = json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": -32001,
            "message": f"Access denied: {reason}"
        }
    }, separators=(",", ":")).encode("utf-8")

    return (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(error_body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) + error_body


async def handle_client(client_r, client_w, backend_host, backend_port, policy):
    """
    Handle an incoming client connection with RBAC policy enforcement.

    Flow:
      1. Read and parse the HTTP request from the TLS-terminated stream.
      2. For POST /messages (MCP JSON-RPC): parse the payload, evaluate the
         policy, and either forward to the backend or return 403.
      3. For GET /sse and all other requests: forward unconditionally
         (these are read-only by nature — session init, SSE event stream).
      4. Pipe remaining data bidirectionally (preserving the KILL mechanism).
    """
    peer = client_w.get_extra_info("peername")
    if peer:
        client_key = f"{peer[0]}:{peer[1]}"
        client_ip = peer[0]
    else:
        client_key = "unknown"
        client_ip = "unknown"

    server_name = SERVER_NAMES.get(backend_port, f"port-{backend_port}")
    active_connections[client_key] = client_w
    print(f"[proxy] Connection from {client_key} → {server_name} ({backend_host}:{backend_port})",
          file=sys.stderr)

    # ── Parse the incoming HTTP request ──────────────────────────────────
    req = await read_http_request(client_r)
    if req is None:
        print(f"[proxy] No valid HTTP request from {client_key} — closing",
              file=sys.stderr)
        try:
            client_w.close()
        except Exception:
            pass
        active_connections.pop(client_key, None)
        return

    # ── Policy Enforcement (only for POST /messages) ─────────────────────
    if req.method == "POST" and "/messages" in req.path:
        rpc_method = ""
        tool_name = ""
        tool_args = None
        rpc_id = None

        try:
            payload = json.loads(req.body)
            rpc_method = payload.get("method", "")
            rpc_id = payload.get("id")
            params = payload.get("params", {})
            if isinstance(params, dict):
                tool_name = params.get("name", "")
                tool_args = params.get("arguments", None)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Unparseable body — will be denied for readonly roles since
            # "__unparseable__" won't match any allowed method list.
            rpc_method = "__unparseable__"

        api_key = req.headers.get("x-mcp-api-key", "")
        
        # Get the listening port they connected to
        local_port = client_w.get_extra_info('sockname')[1] if client_w.get_extra_info('sockname') else None
        
        role_name = policy._resolve_role(client_ip, api_key)
        if role_name == policy.default_role and client_ip == "127.0.0.1" and local_port:
            port_role_map = {8440:"full", 8441:"analyst", 8442:"analyst", 8443:"readonly", 8444:"readonly", 8445:"readonly"}
            role_name = port_role_map.get(local_port, policy.default_role)

        allowed, reason = policy.evaluate(client_ip, client_port, api_key, rpc_method, tool_name, local_port=local_port)

        # Log payload details (server name, tool, arguments)
        decision_str = "ALLOW" if allowed else "DENY"
        policy.log_payload(client_ip, client_port, local_port, role_name, server_name, rpc_method,
                           tool_name, tool_args, decision_str)

        if not allowed:
            # ── DENY: return 403 without forwarding to backend ──
            response_bytes = build_http_403(rpc_id, reason)
            try:
                client_w.write(response_bytes)
                await client_w.drain()
            except Exception:
                pass

            tool_suffix = f"/{tool_name}" if tool_name else ""
            print(f"[policy] DENY  {client_key} | {server_name} | {rpc_method}{tool_suffix} | {reason}",
                  file=sys.stderr)

            try:
                client_w.close()
            except Exception:
                pass
            active_connections.pop(client_key, None)
            return

        tool_suffix = f"/{tool_name}" if tool_name else ""
        print(f"[policy] ALLOW {client_key} | {server_name} | {rpc_method}{tool_suffix}",
              file=sys.stderr)
    else:
        # GET /sse, OPTIONS, etc. — always pass through (inherently read-only)
        print(f"[policy] PASS  {client_key} | {server_name} | {req.method} {req.path}",
              file=sys.stderr)

    # ── Forward to Backend ───────────────────────────────────────────────
    try:
        back_r, back_w = await asyncio.open_connection(backend_host, backend_port)
    except Exception as e:
        print(f"[proxy] Backend connection failed ({backend_host}:{backend_port}): {e}",
              file=sys.stderr)
        try:
            client_w.close()
        except Exception:
            pass
        active_connections.pop(client_key, None)
        return

    # Send the complete, buffered HTTP request to the backend
    try:
        back_w.write(req.raw)
        await back_w.drain()
    except Exception as e:
        print(f"[proxy] Failed to forward request to backend: {e}", file=sys.stderr)
        try:
            client_w.close()
            back_w.close()
        except Exception:
            pass
        active_connections.pop(client_key, None)
        return

    # Pipe remaining data bidirectionally (handles SSE streams, responses, etc.)
    await asyncio.gather(
        pipe(client_r, back_w, client_key),
        pipe(back_r, client_w, client_key),
    )
    active_connections.pop(client_key, None)
    print(f"[proxy] Connection closed {client_key}", file=sys.stderr)


async def serve_port(listen_port, backend_port, cert, key,
                     backend_host="10.11.0.10", policy=None):
    """Start a TLS-terminating proxy listener on a given port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    handler = lambda r, w: handle_client(r, w, backend_host, backend_port, policy)
    server = await asyncio.start_server(handler, "0.0.0.0", listen_port, ssl=ctx)
    print(f"[proxy] TLS listening on :{listen_port} → backend {backend_host}:{backend_port}",
          file=sys.stderr)
    async with server:
        await server.serve_forever()


# =============================================================================
# Main Entrypoint
# =============================================================================

async def main():
    parser = argparse.ArgumentParser(
        description="MCP TLS Proxy with Tool-Level Access Control (RBAC)"
    )
    parser.add_argument("--cert", required=True,
                        help="Path to TLS certificate file")
    parser.add_argument("--key", required=True,
                        help="Path to TLS private key file")
    parser.add_argument("--backend-host", default="10.11.0.10",
                        help="Backend MCP server host (default: 10.11.0.10)")
    parser.add_argument("--mappings", required=True,
                        help="Port mappings, e.g. 8440:3000,8441:3001")
    parser.add_argument("--control-port", type=int, default=9999,
                        help="UDP port for KILL commands (default: 9999)")
    parser.add_argument("--policy", default=None,
                        help="Path to tool_policy.yaml for RBAC enforcement. "
                             "If omitted, all requests are forwarded (backward compatible).")
    args = parser.parse_args()

    # ── Load Policy Engine ───────────────────────────────────────────────
    if args.policy and os.path.exists(args.policy):
        policy = PolicyEngine(args.policy)
        if not policy.roles or policy.default_role == "deny_all":
            print("[policy] FATAL: Policy file loaded but has no valid roles. "
                  "Refusing to start in deny_all mode — check tool_policy.yaml structure.",
                  file=sys.stderr)
            sys.exit(1)
    else:
        if args.policy:
            print(f"[policy] FATAL: Policy file not found at {args.policy}. "
                  "Cannot start without a valid policy (fail-closed).",
                  file=sys.stderr)
            sys.exit(1)
        print("[policy] No --policy flag provided. Running in allow-all mode (dev only).",
              file=sys.stderr)
        policy = PolicyEngine()
        policy._set_permissive()

    # ── Set up audit logging ──────────────────────────────────────────────
    logs_dir = os.path.join(os.path.dirname(args.policy or "."), "..", "logs")
    logs_dir = os.path.abspath(logs_dir)
    policy.set_audit_log(os.path.join(logs_dir, "rbac_audit.jsonl"))
    policy.set_payload_log(os.path.join(logs_dir, "payload_inspection.jsonl"))

    # ── Start UDP control server (KILL protocol for ML firewall) ─────────
    loop = asyncio.get_running_loop()
    print(f"[control] Starting UDP control server on port {args.control_port}",
          file=sys.stderr)
    await loop.create_datagram_endpoint(
        lambda: ControlProtocol(),
        local_addr=("0.0.0.0", args.control_port)
    )

    # ── Start proxy listeners ────────────────────────────────────────────
    tasks = []
    mappings = args.mappings.split(",")
    for m in mappings:
        parts = m.split(":")
        if len(parts) == 3:
            listen_p, b_host, backend_p = int(parts[0]), parts[1], int(parts[2])
        else:
            listen_p, b_host, backend_p = int(parts[0]), args.backend_host, int(parts[1])
        tasks.append(asyncio.create_task(serve_port(listen_p, backend_p, args.cert, args.key, b_host, policy=policy)))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
