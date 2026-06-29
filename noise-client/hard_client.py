"""
Adversarial Noise Generator Client

This module orchestrates concurrent, randomized network patterns designed to simulate 
authentic WAN latency jitter, fragmentation, and sophisticated evasion techniques. 
It exercises the machine learning inference models with challenging negative-class 
traffic, including REST polling, WebSocket streams, chunked HTTP/1.1 transfers, and 
non-MCP JSON-RPC over HTTPS.
"""

import asyncio
import json
import math
import os
import random
import ssl
import time

import httpx
from httpx_sse import aconnect_sse
import websockets

# Configuration

NOISE_SERVER = os.environ.get("NOISE_SERVER", "https://10.10.0.20:9443")
WS_SERVER    = NOISE_SERVER.replace("https://", "wss://")

# SSL context: disable verification for the self-signed lab certificate.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

# httpx client factory: reuse across pattern threads.
def make_client(**kwargs) -> httpx.AsyncClient:
    headers = kwargs.pop("headers", {})
    headers["X-Padding"] = "A" * random.randint(10, 1000)
    return httpx.AsyncClient(verify=False, timeout=60.0, headers=headers, **kwargs)

# Timing primitives

def lognormal(mu: float, sigma: float, floor: float = 0.0) -> float:
    return max(floor, random.lognormvariate(math.log(max(mu, 0.01)), sigma))

def poisson_wait(rate: float) -> float:
    return random.expovariate(rate)

# Pattern 1: REST polling
# Periodic small-to-medium REST calls. Three sub-patterns run concurrently:
#   a) fast endpoint polling: sub-5 ms, tiny responses, high frequency
#   b) data fetch: medium latency, variable size
#   c) bimodal queue polling: sometimes empty (204), sometimes batched

async def pattern_rest_polling() -> None:
    """Steady REST polling with short-lived connections and varied response sizes."""

    async def fast_poller():
        async with make_client() as client:
            while True:
                try:
                    await client.get(f"{NOISE_SERVER}/api/fast")
                except Exception as e:
                    print(f"[rest:fast] {e}")
                await asyncio.sleep(poisson_wait(0.5))  # Approximately 2 s mean.

    async def data_fetcher():
        sizes = ["small", "medium", "large", "xlarge"]
        weights = [4, 3, 2, 1]
        async with make_client() as client:
            while True:
                size = random.choices(sizes, weights=weights, k=1)[0]
                try:
                    await client.get(f"{NOISE_SERVER}/api/data", params={"size": size})
                except Exception as e:
                    print(f"[rest:data] {e}")
                await asyncio.sleep(lognormal(8.0, 1.2, 1.0))

    async def queue_poller():
        async with make_client() as client:
            while True:
                try:
                    await client.get(f"{NOISE_SERVER}/api/poll")
                except Exception as e:
                    print(f"[rest:poll] {e}")
                await asyncio.sleep(poisson_wait(0.25))  # Approximately 4 s mean.

    async def submit_poster():
        """POST with payloads to exercise client-to-server byte asymmetry."""
        payloads = [
            {"type": "metric", "value": random.random(), "tags": {"env": "prod"}},
            {"type": "event",  "data": "x" * random.randint(100, 2000)},
            {"type": "log",    "level": "info", "msg": "health check passed",
             "trace": "abc123"},
        ]
        async with make_client() as client:
            while True:
                payload = random.choice(payloads)
                try:
                    await client.post(f"{NOISE_SERVER}/api/submit", json=payload)
                except Exception as e:
                    print(f"[rest:submit] {e}")
                await asyncio.sleep(lognormal(12.0, 1.5, 2.0))

    await asyncio.gather(fast_poller(), data_fetcher(), queue_poller(), submit_poster())


# Pattern 2: WebSocket stream
# This transport pattern is a critical negative class. It maintains a long-lived
# WSS connection with server-initiated push and client-initiated messages, but
# differs in message rate, size distribution, and turn-taking pattern.

async def pattern_websocket_stream() -> None:
    """Maintain a pool of 2–4 concurrent WSS connections."""

    async def one_ws_session() -> None:
        # Session duration: 30s–3min (lognormal)
        duration = lognormal(90.0, 0.8, 30.0)
        end_time = time.monotonic() + duration

        uri = f"{WS_SERVER}/ws"
        try:
            async with websockets.connect(uri, ssl=SSL_CTX,
                                           ping_interval=20,
                                           ping_timeout=10) as ws:
                print(f"[ws] connected duration={duration:.0f}s")

                async def sender():
                    """Send client messages at random intervals."""
                    msg_types = ["subscribe", "query", "ping", "config"]
                    while time.monotonic() < end_time:
                        await asyncio.sleep(lognormal(5.0, 1.0, 0.5))
                        if ws.closed:
                            break
                        msg = json.dumps({
                            "type": random.choice(msg_types),
                            "id":   random.randint(1000, 9999),
                            "ts":   time.monotonic(),
                        })
                        try:
                            await ws.send(msg)
                        except Exception:
                            break

                async def receiver():
                    """Consume incoming messages without further processing."""
                    async for msg in ws:
                        if time.monotonic() >= end_time:
                            break
                        _ = msg  # Consume the message without further processing.

                try:
                    await asyncio.wait_for(
                        asyncio.gather(sender(), receiver()),
                        timeout=duration + 5,
                    )
                except (asyncio.TimeoutError, Exception):
                    pass
        except Exception as e:
            print(f"[ws] error: {e}")

        # Short gap before reconnecting.
        await asyncio.sleep(lognormal(3.0, 0.8, 0.5))

    # Run two concurrent WebSocket sessions in a loop.
    async def ws_loop():
        while True:
            await one_ws_session()

    await asyncio.gather(ws_loop(), ws_loop())


# Pattern 3: Chunked stream
# Long-lived HTTP/1.1 connection receiving a chunked body over 5–30 seconds.
# This differs from SSE because it uses no event framing, carries raw binary
# chunks, and does not provide a bidirectional channel.

async def pattern_chunked_stream() -> None:
    """Repeatedly connect to the chunked endpoint, drain the stream, and reconnect."""
    while True:
        try:
            async with make_client() as client:
                async with client.stream("GET", f"{NOISE_SERVER}/stream/chunked") as resp:
                    bytes_recv = 0
                    async for chunk in resp.aiter_bytes(chunk_size=4096):
                        bytes_recv += len(chunk)
                print(f"[chunked] done bytes={bytes_recv}")
        except Exception as e:
            print(f"[chunked] error: {e}")

        # Reconnect gap: log-normal distribution with an approximately 5 s mean.
        await asyncio.sleep(lognormal(5.0, 1.0, 1.0))


# Pattern 4: SSE stream
# This is the most challenging negative class. The SSE transport matches the MCP
# channel format, but it has no POST channel, a different event rate, and no JSON-RPC structure.

async def pattern_sse_stream() -> None:
    """Subscribe to noise-server SSE for 30–120 seconds and reconnect with backoff."""
    consecutive_errors = 0

    while True:
        duration = lognormal(60.0, 0.7, 30.0)
        print(f"[sse] connecting duration={duration:.0f}s")

        try:
            async with make_client() as client:
                async with aconnect_sse(
                    client, "GET", f"{NOISE_SERVER}/stream/sse"
                ) as event_source:
                    start    = time.monotonic()
                    ev_count = 0
                    async for sse in event_source.aiter_sse():
                        ev_count += 1
                        if time.monotonic() - start >= duration:
                            break
            consecutive_errors = 0
            print(f"[sse] done events={ev_count}")
        except Exception as e:
            consecutive_errors += 1
            print(f"[sse] error: {e}")

        # Apply backoff after repeated errors.
        gap = lognormal(8.0, 1.0, 2.0) * min(consecutive_errors + 1, 5)
        await asyncio.sleep(gap)


# Pattern 5: Burst requests
# Simulate single-page application page loads, pipeline fan-outs, and batch queries.
# Many near-simultaneous short TLS connections differ significantly from MCP's
# one persistent SSE connection and sequential POST structure.

async def pattern_burst_requests() -> None:
    """Generate concurrent request bursts, then idle to simulate page navigation."""

    async def single_request(client: httpx.AsyncClient, endpoint: str, **kwargs) -> None:
        try:
            await client.get(f"{NOISE_SERVER}{endpoint}", **kwargs)
        except Exception:
            pass

    while True:
        # Burst size: 3–12 near-simultaneous requests
        burst_size = random.randint(3, 12)
        sizes      = random.choices(["small","medium","large"], weights=[5,3,1], k=burst_size)

        async with make_client() as client:
            tasks = []
            for size in sizes:
                endpoint = random.choice([
                    f"/api/data?size={size}",
                    "/api/fast",
                    "/api/poll",
                ])
                # Stagger requests within the burst so they are not perfectly simultaneous.
                await asyncio.sleep(random.uniform(0.01, 0.15))
                tasks.append(asyncio.create_task(single_request(client, endpoint)))

            await asyncio.gather(*tasks, return_exceptions=True)

        # Simulate page-reading time with a log-normal idle period before the next burst.
        await asyncio.sleep(lognormal(15.0, 1.0, 3.0))


# Pattern 6: JSON-RPC over HTTPS (Hard Negative for MCP)
# This is the most challenging negative case for the classifier. It mirrors MCP's
# HTTPS + JSON-RPC 2.0 request-response cadence with similar timing distributions,
# session lengths, and payload structure — but uses non-MCP method names and
# lacks the SSE channel that real MCP traffic has.

async def pattern_jsonrpc() -> None:
    """Run JSON-RPC sessions that mimic MCP's request-response cadence."""

    METHODS = [
        ("system.status", lambda: {}),
        ("data.query",    lambda: {"limit": random.choice([10, 50, 100, 200])}),
        ("config.get",    lambda: {"key": random.choice(["default", "security", "limits", "features"])}),
        ("job.submit",    lambda: {"type": random.choice(["process", "export", "backup", "index"])}),
        ("metrics.fetch", lambda: {"window_m": random.choice([15, 30, 60, 120])}),
        ("echo",          lambda: {"ping": True, "seq": random.randint(1, 99999)}),
    ]

    # Weights: system.status and data.query are the most common (like MCP's
    # health_check and query_logs), heavier methods are less frequent.
    WEIGHTS = [4, 3, 2, 1, 2, 3]

    req_id = 0

    async def run_jsonrpc_session():
        """One session: 4-12 JSON-RPC calls with MCP-like think times."""
        nonlocal req_id
        n_calls = random.randint(4, 12)

        async with make_client() as client:
            # Optionally start with a status check (like MCP's list_tools discovery)
            if random.random() < 0.35:
                req_id += 1
                try:
                    await client.post(f"{NOISE_SERVER}/jsonrpc", json={
                        "jsonrpc": "2.0",
                        "method": "system.status",
                        "params": {},
                        "id": req_id,
                    })
                except Exception as e:
                    print(f"[jsonrpc] status error: {e}")
                await asyncio.sleep(lognormal(2.5, 0.9, 0.5))

            for _ in range(n_calls):
                method, args_fn = random.choices(METHODS, weights=WEIGHTS, k=1)[0]
                req_id += 1
                try:
                    await client.post(f"{NOISE_SERVER}/jsonrpc", json={
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": args_fn(),
                        "id": req_id,
                    })
                except Exception as e:
                    print(f"[jsonrpc:{method}] {e}")
                    break

                # MCP-like think time between calls
                await asyncio.sleep(lognormal(3.5, 1.3, 0.3))

    while True:
        await run_jsonrpc_session()
        # Inter-session idle: similar to MCP client's inter-session gap
        idle = lognormal(8.0, 0.6, 1.0)
        await asyncio.sleep(idle)


# Main

async def main() -> None:
    print("[noise] Starting noise generator; target:", NOISE_SERVER)
    print("[noise] Patterns: rest_polling | websocket_stream | chunked_stream |"
          " sse_stream | burst_requests | jsonrpc")

    # Stagger pattern startup to avoid simultaneous initialization at time zero.
    patterns = [
        ("sse_stream",       pattern_sse_stream),
        ("jsonrpc",          pattern_jsonrpc),
    ]

    tasks = []
    for name, fn in patterns:
        await asyncio.sleep(random.uniform(0.5, 3.0))
        print(f"[noise] Starting pattern: {name}")
        tasks.append(asyncio.create_task(fn()))

    print(f"[noise] All {len(tasks)} patterns active")
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())