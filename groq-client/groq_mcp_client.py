"""
MCP Groq Client (Traffic Generator)

This programmatic client leverages the Groq LLM API to continually orchestrate
randomized, dynamic tool calls against the protected MCP infrastructure. It is
engineered to generate authentic temporal traffic bursts representing the positive
class (legitimate MCP activity) for the machine learning datasets and live inference.

Added multi-turn session support (run_multiturn_session) and a
per-tool targeted prompt corpus. The previous single-turn pattern caused 95%+ of
MCP flows to have exactly 7 packets — a data artifact from the single tools/list
+ tools/call handshake. Multi-turn sessions keep the SSE connection alive across
multiple LLM rounds, generating realistic variable-length flows.

TOOL_TARGETED_PROMPTS biases traffic toward fetch/memory/filesystem/
github which were previously underrepresented (209–216 flows vs 539–585 for exa/tavily).
"""

import openai
import httpx
from httpx_sse import connect_sse
import threading
import time
import random
import os
import math
import json

def lognormal(mu: float, sigma: float, floor: float = 0.0) -> float:
    return max(floor, random.lognormvariate(math.log(max(mu, 0.01)), sigma))

import string

# A small corpus of words for realistic search queries
WORDS = ["AI", "machine", "learning", "python", "docker", "mcp", "agent", "security",
         "encryption", "api", "network", "linux", "cloud", "data", "model", "inference",
         "training", "kubernetes", "database", "sql"]

def random_string(min_len: int, max_len: int) -> str:
    return " ".join(random.choices(WORDS, k=random.randint(2, 6)))

def random_url() -> str:
    endpoints = [
        f"https://httpbin.org/bytes/{random.randint(100, 15000)}",
        f"https://httpbin.org/uuid",
        f"https://httpbin.org/json",
        f"https://httpbin.org/get",
        f"https://loripsum.net/api/{random.randint(1, 5)}/short",
        "https://en.wikipedia.org/wiki/Special:Random"
    ]
    return random.choice(endpoints)




# Configuration
VM1_IP = os.environ.get("VM1_IP", "10.10.0.5")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "dummy")

SERVERS = {
    "fetch":      f"https://{VM1_IP}:8440",
    "memory":     f"https://{VM1_IP}:8441",
    "filesystem": f"https://{VM1_IP}:8442",
    "github":     f"https://{VM1_IP}:8443",
    "exa":        f"https://{VM1_IP}:8444",
    "tavily":     f"https://{VM1_IP}:8445",
}

client = openai.OpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1"
)

sessions = {}

# We define the tools for Groq to natively use.
GROQ_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files in a given directory path",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "The absolute path to the directory (e.g. /tmp/mcp-test)"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_entities",
            "description": "Store conceptual entities in the memory graph",
            "parameters": {
                "type": "object",
                "properties": {
                    "entities": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "entityType": {"type": "string"},
                                "observations": {"type": "array", "items": {"type": "string"}}
                            },
                            "required": ["name", "entityType", "observations"]
                        }
                    }
                },
                "required": ["entities"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch",
            "description": "Fetch the contents of a URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The full HTTP URL to fetch"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_repositories",
            "description": "Search GitHub repositories",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query for repositories"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Perform an Exa internet search for news or topics",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query string"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tavily-search",
            "description": "Perform a Tavily AI internet search",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query"} 
                },
                "required": ["query"]
            }
        }
    }
]

# Map functions to their respective MCP server name
TOOL_SERVER_MAP = {
    "list_directory": "filesystem",
    "create_entities": "memory",
    "fetch": "fetch",
    "search_repositories": "github",
    "search": "exa",
    "tavily-search": "tavily"
}

def get_session(server_name):
    url = SERVERS[server_name]
    max_retries = 20
    import time
    for attempt in range(max_retries):
        try:
            client = httpx.Client(verify=False, timeout=60.0)
            with connect_sse(client, "GET", f"{url}/sse") as event_source:
                for sse in event_source.iter_sse():
                    if sse.data.startswith("/messages?sessionId="):
                        session_id = sse.data.split("sessionId=")[1]
                        sessions[server_name] = {
                            "url": url,
                            "session_id": session_id,
                            "client": client
                        }
                        print(f"[{server_name}] Session: {session_id}")
            break
        except Exception as e:
            print(f"[{server_name}] Failed (attempt {attempt+1}/{max_retries}): {e}")
            time.sleep(3)

def start_sessions():
    threads = []
    for name in SERVERS:
        t = threading.Thread(target=get_session, args=(name,), daemon=True)
        t.start()
        threads.append(t)
    timeout = 120
    start = time.time()
    while len(sessions) < len(SERVERS) and time.time() - start < timeout:
        time.sleep(0.2)
    print(f"Connected to {len(sessions)} servers")

# A persistent session for POST requests to reuse TCP connections.
# This prevents every single tool call from being a separate 7-packet flow,
# making the MCP traffic properly persistent like the adversarial noise.
http_session = httpx.Client(verify=False)

def call_mcp_tool(server_name, method, params={}):
    if server_name not in sessions:
        return None
    s = sessions[server_name]
    payload = {
        "jsonrpc": "2.0",
        "id": random.randint(1, 9999),
        "method": method,
        "params": params
    }
    url = f"{s['url']}/messages?sessionId={s['session_id']}"
    
    # Add random padding to headers to fix TLS Application Data size leakage
    headers = {
        "Content-Type": "application/json",
        "X-Padding": "A" * random.randint(10, 1000)
    }
    try:
        r = http_session.post(url, json=payload,
                         headers=headers,
                         timeout=10)
        return r.status_code
    except Exception as e:
        return str(e)

def _dispatch_tool_calls(tool_calls):
    """Execute a list of LLM-requested tool calls against MCP servers.

    Returns a list of (tool_call_id, tool_name, result_str) for feeding back
    into the next LLM message turn.
    """
    results = []
    for tc in tool_calls:
        func_name = tc.function.name
        try:
            args = json.loads(tc.function.arguments)
        except json.JSONDecodeError:
            args = {}

        server = TOOL_SERVER_MAP.get(func_name)
        if server:
            time.sleep(lognormal(3.5, 1.3, 0.3))
            print(f"    -> Dispatching {func_name} to {server} with args {args}")
            status = call_mcp_tool(server, "tools/call", {
                "name": func_name,
                "arguments": args
            })
            print(f"    <- Response status: {status}")
            results.append((tc.id, func_name, f"status={status}"))
        else:
            print(f"    -> Unknown function {func_name}")
    return results


def run_claude_session(prompt, servers_to_use):
    """Single-turn session: tools/list discovery + one LLM call + tool dispatching."""
    print(f"\n--- Groq prompt: {prompt[:60]}...")

    # Generate base MCP traffic via tools/list (protocol discovery)
    for server in servers_to_use:
        status = call_mcp_tool(server, "tools/list", {})
        print(f"  [{server}] tools/list -> {status}")

    try:
        if GROQ_API_KEY != "dummy":
            message = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                max_tokens=500,
                messages=[
                    {"role": "system", "content": "You are a helpful AI assistant connected to various tools. You MUST use tools when relevant."},
                    {"role": "user", "content": prompt}
                ],
                tools=GROQ_TOOLS,
                tool_choice="auto"
            )
            response = message.choices[0].message

            if response.tool_calls:
                print(f"  LLM triggered {len(response.tool_calls)} tool calls!")
                _dispatch_tool_calls(response.tool_calls)
            else:
                print(f"  LLM response (no tools): {str(response.content)[:100]}...")
        else:
            print("  LLM simulation (dummy key)")
            time.sleep(lognormal(2.5, 0.9, 0.5))
            _fallback_dummy_tool(prompt)

    except Exception as e:
        print(f"  LLM error: {e}")


def run_multiturn_session(prompt, servers_to_use):
    """Multi-turn session: runs two full LLM rounds with tool results fed back.

    This addresses Issue 1 (7-packet artifact): the single-turn pattern caused
    one tools/list + one tools/call, producing a short predictable TLS handshake.
    Multi-turn keeps the HTTP/SSE context alive across multiple request-response
    cycles, generating realistic variable-length flows with 10-30+ packets.

    Round 1: LLM sees user prompt → requests tool calls → we dispatch them.
    Round 2: LLM sees tool results → requests follow-up tool calls → we dispatch.
    """
    print(f"\n--- [MULTI-TURN] Groq prompt: {prompt[:60]}...")

    # Protocol discovery traffic
    for server in servers_to_use:
        status = call_mcp_tool(server, "tools/list", {})
        print(f"  [{server}] tools/list -> {status}")

    if GROQ_API_KEY == "dummy":
        print("  [MULTI-TURN] LLM simulation (dummy key)")
        time.sleep(lognormal(3.0, 0.8, 0.5))
        _fallback_dummy_tool(prompt)
        time.sleep(lognormal(2.0, 0.8, 0.5))
        _fallback_dummy_tool("store results in memory")
        return

    try:
        messages = [
            {"role": "system", "content": (
                "You are a helpful AI assistant with access to tools. "
                "Always use tools to complete the task. After getting results, "
                "store important findings in memory using create_entities."
            )},
            {"role": "user", "content": prompt}
        ]

        # ── Round 1 ──────────────────────────────────────────────────────────
        print("  [Round 1] Calling LLM...")
        r1 = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=600,
            messages=messages,
            tools=GROQ_TOOLS,
            tool_choice="auto"
        )
        r1_msg = r1.choices[0].message

        if not r1_msg.tool_calls:
            print(f"  [Round 1] No tool calls: {str(r1_msg.content)[:100]}")
            return

        print(f"  [Round 1] LLM triggered {len(r1_msg.tool_calls)} tool calls!")
        tool_results = _dispatch_tool_calls(r1_msg.tool_calls)

        # Feed round-1 results back into the message history
        messages.append({"role": "assistant", "content": r1_msg.content, "tool_calls": r1_msg.tool_calls})
        for tc_id, tc_name, result_str in tool_results:
            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "name": tc_name,
                "content": result_str,
            })

        # Inter-turn human-like pause
        time.sleep(lognormal(2.5, 0.8, 0.5))

        # ── Round 2 ──────────────────────────────────────────────────────────
        print("  [Round 2] Calling LLM with tool results...")
        r2 = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=500,
            messages=messages,
            tools=GROQ_TOOLS,
            tool_choice="auto"
        )
        r2_msg = r2.choices[0].message

        if r2_msg.tool_calls:
            print(f"  [Round 2] LLM triggered {len(r2_msg.tool_calls)} follow-up tool calls!")
            _dispatch_tool_calls(r2_msg.tool_calls)
        else:
            print(f"  [Round 2] Final response: {str(r2_msg.content)[:120]}")

    except Exception as e:
        print(f"  [MULTI-TURN] LLM error: {e}")


def _fallback_dummy_tool(prompt):
    """Heuristic fallback tool dispatch when running with a dummy Groq key."""
    prompt_l = prompt.lower()
    if "file" in prompt_l or "directory" in prompt_l or "list" in prompt_l:
        dirs = ["/tmp/mcp-test", "/var/log", "/etc/nginx", "/home/user/docs",
                "/opt/app/data/" + random_string(5, 10)]
        call_mcp_tool("filesystem", "tools/call", {
            "name": "list_directory",
            "arguments": {"path": random.choice(dirs)}
        })
    elif "remember" in prompt_l or "store" in prompt_l or "memory" in prompt_l or "entity" in prompt_l:
        call_mcp_tool("memory", "tools/call", {
            "name": "create_entities",
            "arguments": {"entities": [{
                "name": random_string(5, 15).strip(),
                "entityType": random.choice(["person", "concept", "task", "note", "organization"]),
                "observations": [random_string(10, 100)]
            }]}
        })
    elif "fetch" in prompt_l or "url" in prompt_l or "http" in prompt_l:
        call_mcp_tool("fetch", "tools/call", {
            "name": "fetch",
            "arguments": {"url": random_url()}
        })
    elif "github" in prompt_l or "repositor" in prompt_l or "repo" in prompt_l:
        call_mcp_tool("github", "tools/call", {
            "name": "search_repositories",
            "arguments": {"query": random_string(3, 8)}
        })
    elif "exa" in prompt_l or "search" in prompt_l:
        call_mcp_tool("exa", "tools/call", {
            "name": "search",
            "arguments": {"query": random_string(3, 8)}
        })
    elif "tavily" in prompt_l:
        call_mcp_tool("tavily", "tools/call", {
            "name": "tavily-search",
            "arguments": {"query": random_string(3, 8)}
        })
    else:
        # Default: pick a random tool
        tool = random.choice(list(TOOL_SERVER_MAP.keys()))
        server = TOOL_SERVER_MAP[tool]
        if tool == "list_directory":
            args = {"path": "/tmp/mcp-test"}
        elif tool == "create_entities":
            args = {"entities": [{"name": "test", "entityType": "concept", "observations": ["auto-generated"]}]}
        elif tool == "fetch":
            args = {"url": random_url()}
        else:
            args = {"query": random_string(3, 6)}
        call_mcp_tool(server, "tools/call", {"name": tool, "arguments": args})


# ── Prompt corpora ────────────────────────────────────────────────────────────

SHORT_PROMPTS = [
    "List the files in my /tmp/mcp-test directory",
    "What tools do you have available?",
    "Store this note: meeting at 3pm",
    "Fetch the content of https://httpbin.org/uuid",
    "List my GitHub repositories",
    "Search GitHub for MCP server examples",
    "Find documentation for Python requests library",
    "Search the web for recent news about AI agents",
    "Find examples of MCP server implementations",
    "Can you check what's in /var/log?",
    "Save the entity 'Groq' as an 'organization' with observation 'fast inference API'",
]

# Multi-tool long prompts for multi-turn sessions — 60% of traffic
LONG_PROMPTS = [
    "List all files in /tmp/mcp-test, then fetch https://httpbin.org/json, and finally store the summary in memory.",
    "Check what tools are available, search Exa for latest LLM news, and store the findings in memory.",
    "Fetch https://httpbin.org/uuid, store a summary in memory, and list what's stored.",
    "Search GitHub for 'network intrusion detection' repos, then store the top result as an entity in memory.",
    "List /var/log directory, fetch https://httpbin.org/get, and remember the results as 'system-scan'.",
    "Fetch https://httpbin.org/bytes/512, then search GitHub for 'machine learning security' and store both results.",
    "Search Exa for 'packet classification neural network', store results in memory, then list /tmp/mcp-test.",
    "Search Tavily for 'TLS fingerprinting techniques', then store the key findings in memory.",
    "List /etc/nginx directory contents, then fetch https://httpbin.org/json and store both results as entities.",
    "Search GitHub for 'traffic analysis tools', list /tmp/mcp-test, and store findings as 'recon-session'.",
]

# Per-tool targeted prompts biased toward underrepresented classes.
# fetch/memory/filesystem/github had 209–216 flows vs 539–585 for exa/tavily.
TOOL_TARGETED_PROMPTS = {
    "fetch": [
        f"Fetch the content of {random_url()} and tell me what you find." for _ in range(5)
    ] + [
        "Fetch https://httpbin.org/uuid and extract the UUID.",
        "Retrieve the JSON from https://httpbin.org/json.",
        "Fetch https://httpbin.org/get and summarise the response headers.",
        "Get the content of https://httpbin.org/bytes/1024.",
        "Fetch https://loripsum.net/api/1/short and return the text.",
    ],
    "filesystem": [
        "List all files in /tmp/mcp-test directory.",
        "What files are in /var/log?",
        "Check the contents of /etc/nginx directory.",
        "List the /home/user/docs directory.",
        "Show me what's in /opt/app/data/.",
        "List files under /tmp/mcp-test and tell me if any are logs.",
        "What is in the /var/log/nginx directory?",
        "Check /etc for any configuration files.",
    ],
    "memory": [
        "Store the concept 'MCP' as a 'protocol' with observation 'Model Context Protocol for AI tools'.",
        "Remember that 'Docker' is a 'tool' with observation 'container runtime used in production'.",
        "Save entity 'Python' as 'language' with observation 'primary scripting language for ML pipelines'.",
        "Store 'network security' as a 'domain' with observation 'focus area for this project'.",
        "Create entity 'Groq' of type 'service' with observation 'fast LLM inference API'.",
        "Remember: 'TLS' is a 'protocol' with observation 'encrypts MCP traffic between client and server'.",
        "Store 'ExtraTrees' as a 'model' with observation 'ensemble method for traffic classification'.",
        "Create entity 'pcap' of type 'file_format' with observation 'packet capture used for training data'.",
    ],
    "github": [
        "Search GitHub for repositories about 'network packet analysis'.",
        "Find GitHub repos for 'machine learning intrusion detection'.",
        "Search GitHub for 'MCP server implementation'.",
        "Look for GitHub repositories tagged 'traffic classification'.",
        "Search GitHub for 'TLS fingerprinting'.",
        "Find repos on GitHub about 'encrypted traffic analysis'.",
        "Search GitHub for 'rust network analysis tools'.",
        "Look for 'python pcap parser' repositories on GitHub.",
    ],
}


if __name__ == "__main__":
    print("Starting sessions with all MCP servers...")
    start_sessions()

    if not sessions:
        print("No sessions established. Check VM1 servers are running.")
        exit(1)

    loop_count = 0
    while True:
        loop_count += 1
        print(f"\n=== Loop {loop_count} ===")

        # 40% short single-tool sessions, 60% multi-turn long sessions.
        # This addresses the previous class imbalance: the 11 short + 3 long ratio
        # meant ~78% of traffic was short-session, causing the 7-packet artifact.

        # ── Targeted short sessions (biased toward underrepresented classes) ─
        print(f"\nRunning TARGETED short sessions...")
        for tool_type, prompts in TOOL_TARGETED_PROMPTS.items():
            prompt = random.choice(prompts)
            servers = [s for s in sessions.keys() if s == tool_type or s in list(sessions.keys())[:2]]
            # Primary server is the targeted one; add one more for tools/list diversity
            primary = tool_type if tool_type in sessions else random.choice(list(sessions.keys()))
            secondary = random.choice([s for s in sessions.keys() if s != primary])
            run_claude_session(prompt, [primary, secondary])
            time.sleep(lognormal(4.0, 1.0, 0.5))

        # ── General short sessions ────────────────────────────────────────────
        print(f"\nRunning SHORT-LIVED flows ({len(SHORT_PROMPTS)} prompts)...")
        for prompt in SHORT_PROMPTS:
            servers = random.sample(list(sessions.keys()), k=min(2, len(sessions)))
            run_claude_session(prompt, servers)
            time.sleep(lognormal(4.0, 1.0, 0.5))

        # ── Multi-turn long sessions (majority of traffic) ────────────────────
        print(f"\nRunning MULTI-TURN LONG flows ({len(LONG_PROMPTS)} prompts)...")
        for prompt in LONG_PROMPTS:
            servers = list(sessions.keys())
            run_multiturn_session(prompt, servers)
            time.sleep(lognormal(6.0, 0.8, 1.0))
