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

# ─── Optional: pyyaml for policy file ────────────────────────────────────────
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


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

            print(f"[policy] Loaded policy from {self.policy_path}", file=sys.stderr)
            print(f"[policy]   Roles defined: {list(self.roles.keys())}", file=sys.stderr)
            print(f"[policy]   IP rules: {len(self.ip_map)}", file=sys.stderr)
            print(f"[policy]   API key rules: {len(self.api_key_map)}", file=sys.stderr)
            print(f"[policy]   Default role: {self.default_role}", file=sys.stderr)
        except Exception as e:
            print(f"[policy] ERROR loading policy from {self.policy_path}: {e}",
                  file=sys.stderr)
            self._set_permissive()

    def _set_permissive(self):
        """Fall back to allow-all mode (backward compatible)."""
        self.roles = {"full": {"allowed_methods": "*", "allowed_tools": "*"}}
        self.ip_map = {}
        self.api_key_map = {}
        self.default_role = "full"

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

    def evaluate(self, client_ip, api_key, rpc_method, tool_name):
        """
        Evaluate whether a client may invoke a given MCP method/tool.

        Args:
            client_ip:  Source IP address of the client.
            api_key:    Value of the X-MCP-API-Key header (may be empty).
            rpc_method: JSON-RPC method string (e.g., "tools/call", "tools/list").
            tool_name:  Tool name from params.name (only relevant for "tools/call").

        Returns:
            (allowed: bool, reason: str)
        """
        role_name = self._resolve_role(client_ip, api_key)
        role = self.roles.get(role_name)

        if role is None:
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
            return False, f"Role '{role_name}' cannot invoke method '{rpc_method}'"

        # ── Step 2: For tools/call, check tool-level access ──
        if rpc_method == "tools/call" and tool_name:
            allowed_tools = role.get("allowed_tools", [])

            if allowed_tools == "*":
                return True, f"Role '{role_name}' — full tool access"
            elif isinstance(allowed_tools, list):
                if tool_name in allowed_tools:
                    return True, f"Tool '{tool_name}' allowed for role '{role_name}'"
                else:
                    return False, (f"Role '{role_name}' cannot use tool '{tool_name}' "
                                   f"(allowed: {', '.join(allowed_tools)})")
            else:
                return False, f"Role '{role_name}' has no tool access configured"

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
            "code": -32600,
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

    active_connections[client_key] = client_w
    print(f"[proxy] Connection from {client_key} → {backend_host}:{backend_port}",
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
        rpc_id = None

        try:
            payload = json.loads(req.body)
            rpc_method = payload.get("method", "")
            rpc_id = payload.get("id")
            params = payload.get("params", {})
            if isinstance(params, dict):
                tool_name = params.get("name", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Unparseable body — will be denied for readonly roles since
            # "__unparseable__" won't match any allowed method list.
            rpc_method = "__unparseable__"

        api_key = req.headers.get("x-mcp-api-key", "")
        allowed, reason = policy.evaluate(client_ip, api_key, rpc_method, tool_name)

        if not allowed:
            # ── DENY: return 403 without forwarding to backend ──
            response_bytes = build_http_403(rpc_id, reason)
            try:
                client_w.write(response_bytes)
                await client_w.drain()
            except Exception:
                pass

            tool_suffix = f"/{tool_name}" if tool_name else ""
            print(f"[policy] DENY  {client_key} | {rpc_method}{tool_suffix} | {reason}",
                  file=sys.stderr)

            try:
                client_w.close()
            except Exception:
                pass
            active_connections.pop(client_key, None)
            return

        tool_suffix = f"/{tool_name}" if tool_name else ""
        print(f"[policy] ALLOW {client_key} | {rpc_method}{tool_suffix}",
              file=sys.stderr)
    else:
        # GET /sse, OPTIONS, etc. — always pass through (inherently read-only)
        print(f"[policy] PASS  {client_key} | {req.method} {req.path}",
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
    else:
        if args.policy:
            print(f"[policy] WARNING: Policy file not found at {args.policy}",
                  file=sys.stderr)
        print("[policy] No policy loaded — all requests will be forwarded "
              "(backward compatible mode)", file=sys.stderr)
        policy = PolicyEngine()  # No path → permissive defaults
        policy._set_permissive()

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
    for mapping in args.mappings.split(","):
        listen_p, backend_p = mapping.split(":")
        tasks.append(asyncio.create_task(
            serve_port(int(listen_p), int(backend_p),
                       args.cert, args.key, args.backend_host, policy)
        ))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
