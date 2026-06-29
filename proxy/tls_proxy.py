"""
Mid-Stream TLS Proxy (Enforcement Node)

This module implements a lightweight inline TLS proxy utilizing Python's asyncio framework. 
It forwards encrypted packets bidirectionally without decryption, permitting the Rust core to 
observe network traffic characteristics. 

The proxy runs an out-of-band UDP control server on port 9999. Upon receiving a positive 
identification of anomalous traffic from the machine learning inference engine, it instantly 
terminates the specified TCP stream, acting as an intelligent firewall.
"""

import argparse
import asyncio
import ssl
import sys
import os

# Dictionary to maintain references to active TCP connections.
# Maps client endpoints (ip:port) to their respective StreamWriter objects.
active_connections = {}

class ControlProtocol(asyncio.DatagramProtocol):
    """
    UDP Datagram Protocol handler for processing out-of-band control directives.
    Listens for 'KILL <ip>:<port>' commands and severs matching connections.
    """
    def datagram_received(self, data, addr):
        msg = data.decode().strip()
        print(f"[control] Received command: {msg}", file=sys.stderr)
        if msg.startswith("KILL "):
            target = msg.split(" ")[1]
            if target in active_connections:
                print(f"[control] Executing Mid-Stream KILL on {target}", file=sys.stderr)
                try:
                    writer = active_connections[target]
                    writer.close()
                except Exception as e:
                    print(f"[control] Error closing {target}: {e}", file=sys.stderr)
            else:
                print(f"[control] Target {target} not found in active connections.", file=sys.stderr)

async def pipe(reader, writer, client_key):
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
        except:
            pass

async def handle_client(client_r, client_w, backend_host, backend_port):
    peer = client_w.get_extra_info('peername')
    if peer:
        client_key = f"{peer[0]}:{peer[1]}"
    else:
        client_key = "unknown"

    active_connections[client_key] = client_w
    print(f"[proxy] Connection accepted from {client_key} -> {backend_host}:{backend_port}", file=sys.stderr)

    try:
        back_r, back_w = await asyncio.open_connection(backend_host, backend_port)
    except Exception as e:
        print(f"[proxy] Failed to connect to backend {backend_host}:{backend_port}: {e}", file=sys.stderr)
        client_w.close()
        active_connections.pop(client_key, None)
        return

    await asyncio.gather(
        pipe(client_r, back_w, client_key),
        pipe(back_r, client_w, client_key),
    )
    active_connections.pop(client_key, None)
    print(f"[proxy] Connection closed {client_key}", file=sys.stderr)


async def serve_port(listen_port, backend_port, cert, key, backend_host="10.11.0.10"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    handler = lambda r, w: handle_client(r, w, backend_host, backend_port)
    server = await asyncio.start_server(handler, '0.0.0.0', listen_port, ssl=ctx)
    print(f"[proxy] TLS listening on {listen_port} -> backend {backend_host}:{backend_port}", file=sys.stderr)
    async with server:
        await server.serve_forever()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--backend-host", default="10.11.0.10")
    parser.add_argument("--mappings", required=True, help="8440:3000,8441:3001")
    parser.add_argument("--control-port", type=int, default=9999)
    args = parser.parse_args()

    # Start UDP control server
    loop = asyncio.get_running_loop()
    print(f"[control] Starting UDP control server on port {args.control_port}", file=sys.stderr)
    await loop.create_datagram_endpoint(
        lambda: ControlProtocol(),
        local_addr=('0.0.0.0', args.control_port)
    )

    tasks = []
    mappings = args.mappings.split(",")
    for m in mappings:
        parts = m.split(":")
        if len(parts) == 3:
            listen_p, b_host, backend_p = int(parts[0]), parts[1], int(parts[2])
        else:
            listen_p, b_host, backend_p = int(parts[0]), args.backend_host, int(parts[1])
        tasks.append(asyncio.create_task(serve_port(listen_p, backend_p, args.cert, args.key, b_host)))

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
