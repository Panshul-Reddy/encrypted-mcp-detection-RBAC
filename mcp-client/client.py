import asyncio
import json
import math
import os
import random

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client

# Configuration

SERVER_URL   = os.environ.get("MCP_SERVER_URL", "https://10.10.0.10:8443/sse")
WORKER_SEED  = int(os.environ.get("WORKER_SEED", "0"))
SESSION_MODE = os.environ.get("SESSION_MODE", "mixed")

# Disable SSL verification for the lab self-signed certificate.
# sse_client() does not forward a verify argument, but it accepts an
# httpx_client_factory callback with the same arguments as McpHttpClientFactory.
# Define a dedicated AsyncClient factory for this example.

def create_httpx_client(headers=None, timeout=None, auth=None):
    return httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(None, connect=10.0),
        auth=auth,
        verify=False,
    )

# Timing primitives

def lognormal(mu: float, sigma: float, floor: float = 0.0) -> float:
    """Return a log-normal wait time with a predominantly short tail."""
    return max(floor, random.lognormvariate(math.log(max(mu, 0.01)), sigma))

def poisson_wait(rate: float) -> float:
    """Return an exponential inter-arrival time with mean 1/rate seconds."""
    return random.expovariate(rate)

# Tool catalogue
# Each entry is (tool_name, args_factory, call_weight).
# Weights drive random selection; higher values are selected more often.
# submit_job and poll_job are excluded here because they are invoked through _async_job_pair.

def _level():    return random.choice(["INFO", "WARN", "ERROR", "DEBUG", "ALL"])
def _service():  return random.choice(["auth", "api-gateway", "db-proxy", "scheduler", None])
def _kv_key():
    prefix = random.choice(["session", "config", "cache", "lock", "feature"])
    if prefix == "session":
        return f"session:{random.randint(0, 99):03d}"
    return f"{prefix}:{random.randint(0, 0xFFFF):04x}"

TOOL_CATALOGUE = [
    # Fast, small responses from the key-value backend
    ("kv_get",          lambda: {"key": _kv_key()},                                        5),
    ("kv_set",          lambda: {"key": f"tmp:{random.randint(0,999):03d}",
                                  "value": f"v_{random.randint(1000,9999)}",
                                  "ttl":   random.randint(30, 3600)},                      3),
    # Fast, small health checks
    ("health_check",    lambda: {"verbose": random.choice([True, False])},                  3),
    # Medium-latency SQL operations
    ("query_logs",      lambda: {"limit":   random.choice([10, 50, 100, 500]),
                                  "level":   _level(),
                                  "service": _service()},                                   3),
    ("get_user",        lambda: {"username": f"user_{random.randint(0, 499)}"},             2),
    ("search_documents",lambda: {"query": random.choice(["auth","error","config",
                                                          "deploy","api","audit"]),
                                  "limit": random.randint(5, 20)},                          2),
    ("list_tables",     lambda: {},                                                          1),
    ("update_record",   lambda: {"table": "logs",
                                  "id":    random.randint(1, 500),
                                  "field": "message",
                                  "value": f"updated_{random.randint(1000,9999)}"},         1),
    # Medium-latency filesystem operations
    ("list_directory",  lambda: {"dir_path": random.choice(["/","config","data",
                                                              "logs","scripts"])},           2),
    ("read_file",       lambda: {"file_path": random.choice([
                                    "config/app.json", "config/services.yaml",
                                    "README.md", "logs/app.log", "scripts/deploy.sh"])},    2),
    # Medium-to-large queue polling with bimodal responses
    ("queue_poll",      lambda: {"max_items":    random.choice([1, 5, 10, 20]),
                                  "topic_filter": random.choice([None, "user.",
                                                                  "payment.", None])},       3),
    # Streaming via SSE notifications
    ("stream_logs",     lambda: {"limit":       random.choice([20, 50, 100]),
                                  "chunk_size":  random.choice([3, 5, 10]),
                                  "interval_ms": random.choice([80, 120, 200]),
                                  "level":       _level()},                                 2),
    # Streaming shell output
    ("run_shell",       lambda: {"command":     random.choice(["ps","df","uptime",
                                                                "free","find","wc_logs"]),
                                  "chunk_lines": random.choice([3, 5, 8])},                 2),
    # Large-payload blob retrieval
    ("fetch_blob",      lambda: {"artifact": random.choice(["log_archive","config_snapshot",
                                                              "metrics_dump","audit_export"]),
                                  "max_kb":   random.choice([10, 25, 50, 100])},            2),
    # Heavy report generation with larger payloads
    ("generate_report", lambda: {"report_type": random.choice(["summary","audit",
                                                                "compliance","activity"]),
                                  "days": random.choice([7, 14, 30])},                      1),
    # Outbound HTTP with external round-trip-time variance
    ("fetch_url",       lambda: {"url": random.choice([
                                    "https://httpbin.org/get",
                                    "https://jsonplaceholder.typicode.com/users",
                                    "https://hacker-news.firebaseio.com/v0/topstories.json",
                                ])},                                                         1),
]

_TOOL_NAMES   = [t[0] for t in TOOL_CATALOGUE]
_TOOL_ARGS    = {t[0]: t[1] for t in TOOL_CATALOGUE}
_TOOL_WEIGHTS = [t[2] for t in TOOL_CATALOGUE]

def pick_tool() -> str:
    return random.choices(_TOOL_NAMES, weights=_TOOL_WEIGHTS, k=1)[0]

# Asynchronous job pair

async def _async_job_pair(session: ClientSession) -> None:
    """
    Submit a job, wait for think time, then poll until completion.

    This produces a distinctive two-burst pattern:
      burst 1: small submit request and response
      gap:     think time while the job runs
      burst 2: repeated small poll requests, with the last poll returning the full result
    """
    result = await session.call_tool("submit_job", {
        "job_type": random.choice(["etl", "report", "index", "backup",
                                   "aggregate", "export"]),
        "priority": random.choice(["low", "normal", "high"]),
    })
    try:
        data   = json.loads(result.content[0].text)
        job_id = data.get("job_id")
        est_ms = data.get("estimated_ms", 4000)
    except Exception:
        return

    if not job_id:
        return

    # Wait approximately half the estimated duration before the first poll.
    await asyncio.sleep(lognormal(est_ms / 2000, 0.5, 0.5))

    for _ in range(10):
        poll = await session.call_tool("poll_job", {"job_id": job_id})
        try:
            state = json.loads(poll.content[0].text)
            if state.get("status") in ("done", "error", "unknown_job"):
                break
        except Exception:
            break
        # Back off between polls.
        await asyncio.sleep(lognormal(2.5, 0.6, 0.5))

# Session modes

async def run_interactive(session: ClientSession) -> None:
    """
    Human-paced mode with log-normal think times and 4–12 tool calls.
    Some sessions begin with list_tools for tool discovery.
    Approximately 20% of sessions include one asynchronous job pair.
    """
    if random.random() < 0.35:
        await session.list_tools()
        await asyncio.sleep(lognormal(2.5, 0.9, 0.5))

    n_calls = random.randint(4, 12)
    job_inserted = False

    for i in range(n_calls):
        # Insert at most one asynchronous job pair, typically in the middle of the session.
        if not job_inserted and i > 0 and random.random() < 0.20:
            await _async_job_pair(session)
            job_inserted = True
            await asyncio.sleep(lognormal(3.0, 1.0, 0.5))
            continue

        tool = pick_tool()
        await session.call_tool(tool, _TOOL_ARGS[tool]())
        await asyncio.sleep(lognormal(3.5, 1.3, 0.3))


async def run_bot(session: ClientSession) -> None:
    """
    Automated agent mode with Poisson-distributed inter-arrival times and a repetitive set of 2–3 tools.
    This simulates monitoring or continuous integration agents: health checks, queue polls, and log queries.
    """
    # Automated agents use a small, specialized tool subset that they repeat.
    bot_subset = random.choices(_TOOL_NAMES, weights=_TOOL_WEIGHTS, k=3)
    n_calls    = random.randint(8, 20)

    for _ in range(n_calls):
        tool = random.choice(bot_subset)
        await session.call_tool(tool, _TOOL_ARGS[tool]())
        await asyncio.sleep(poisson_wait(random.uniform(0.8, 2.5)))


async def run_burst(session: ClientSession) -> None:
    """
    Rapid sequence of tool calls with minimal gaps, followed by session termination.
    This pattern simulates a pipeline runner or batch job that executes many tools quickly.
    """
    n_calls = random.randint(5, 15)
    for _ in range(n_calls):
        tool = pick_tool()
        await session.call_tool(tool, _TOOL_ARGS[tool]())
        await asyncio.sleep(random.uniform(0.03, 0.35))

# Session runner

_MODE_FNS = {
    "interactive": run_interactive,
    "bot":         run_bot,
    "burst":       run_burst,
}

def _pick_mode(base: str) -> str:
    if base == "mixed":
        return random.choices(
            ["interactive", "bot", "burst"],
            weights=[0.50, 0.30, 0.20], k=1,
        )[0]
    return base


async def run_session(worker_id: int, base_mode: str) -> None:
    mode = _pick_mode(base_mode)
    print(f"[W{worker_id}] start  mode={mode}")
    try:
        async with sse_client(
            SERVER_URL,
            timeout=None,
            httpx_client_factory=create_httpx_client,
        ) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await _MODE_FNS[mode](session)
        print(f"[W{worker_id}] done   mode={mode}")
    except Exception as e:
        print(f"[W{worker_id}] error  mode={mode}: {e}")


async def worker(worker_id: int, base_mode: str) -> None:
    while True:
        await run_session(worker_id, base_mode)
        # Inter-session idle: log-normal distribution with an approximately 8 s mean and a heavy tail.
        idle = lognormal(8.0, 1.6, 1.0)
        print(f"[W{worker_id}] idle   {idle:.1f}s")
        await asyncio.sleep(idle)


async def main() -> None:
    random.seed(WORKER_SEED)
    n_workers = 4
    tasks     = []
    for i in range(n_workers):
        # Stagger startup so workers do not all reach the server simultaneously.
        await asyncio.sleep(random.uniform(0.5, 3.5))
        tasks.append(asyncio.create_task(worker(i, SESSION_MODE)))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())