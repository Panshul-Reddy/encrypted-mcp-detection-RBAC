"""
MCP Groq Client (Traffic Generator)

This programmatic client leverages the Groq LLM API to continually orchestrate 
randomized, dynamic tool calls against the protected MCP infrastructure. It is 
engineered to generate authentic temporal traffic bursts representing the positive 
class (legitimate MCP activity) for the machine learning datasets and live inference.
"""

import openai
import requests
import threading
import time
import random
import urllib3
import os
import math

def lognormal(mu: float, sigma: float, floor: float = 0.0) -> float:
    return max(floor, random.lognormvariate(math.log(max(mu, 0.01)), sigma))

import string

# A small corpus of words for realistic search queries
WORDS = ["AI", "machine", "learning", "python", "docker", "mcp", "agent", "security", "encryption", "api", "network", "linux", "cloud", "data", "model", "inference", "training", "kubernetes", "database", "sql"]

def random_string(min_len: int, max_len: int) -> str:
    return " ".join(random.choices(WORDS, k=random.randint(2, 6)))

def random_url() -> str:
    # httpbin.org/bytes/N returns exactly N random bytes, guaranteeing massive payload variance!
    # loripsum.net returns random paragraphs of text
    endpoints = [
        f"https://httpbin.org/bytes/{random.randint(100, 15000)}",
        f"https://loripsum.net/api/{random.randint(1, 5)}/short",
        "https://en.wikipedia.org/wiki/Special:Random"
    ]
    return random.choice(endpoints)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def get_session(server_name):
    url = SERVERS[server_name]
    max_retries = 20
    import time
    for attempt in range(max_retries):
        try:
            response = requests.get(f"{url}/sse", stream=True,
                                   timeout=30, verify=False)
            if response.status_code != 200:
                print(f"[{server_name}] HTTP {response.status_code}, retrying...")
                time.sleep(3)
                continue
            for line in response.iter_lines():
                if line:
                    decoded = line.decode("utf-8")
                    if decoded.startswith("data: /messages?sessionId="):
                        session_id = decoded.split("sessionId=")[1]
                        sessions[server_name] = {
                            "url": url,
                            "session_id": session_id
                        }
                        print(f"[{server_name}] Session: {session_id}")
                        for _ in response.iter_lines():
                            pass
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
    try:
        r = requests.post(url, json=payload,
                         headers={"Content-Type": "application/json"},
                         timeout=10, verify=False)
        return r.status_code
    except Exception as e:
        return str(e)

def run_claude_session(prompt, servers_to_use):
    print(f"\n--- Claude prompt: {prompt[:50]}...")
    for server in servers_to_use:
        status = call_mcp_tool(server, "tools/list", {})
        print(f"  [{server}] tools/list -> {status}")

    try:
        # We only call the LLM if we have a real key, otherwise we just simulate tool calls to generate traffic
        if GROQ_API_KEY != "dummy":
            message = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            response = message.choices[0].message.content
            print(f"  LLM response: {response[:100]}...")
        else:
            print("  LLM simulation (dummy key)")
            time.sleep(lognormal(2.5, 0.9, 0.5))

    except Exception as e:
        print(f"  LLM error: {e}")

    # Generate specific tool traffic
    if "file" in prompt.lower() or "directory" in prompt.lower():
        time.sleep(lognormal(3.5, 1.3, 0.3))
        dirs = ["/tmp/mcp-test", "/var/log", "/etc/nginx", "/home/user/docs", "/opt/app/data/" + random_string(5, 10)]
        call_mcp_tool("filesystem", "tools/call", {
            "name": "list_directory",
            "arguments": {"path": random.choice(dirs)}
        })
    if "remember" in prompt.lower() or "store" in prompt.lower():
        time.sleep(lognormal(3.5, 1.3, 0.3))
        call_mcp_tool("memory", "tools/call", {
            "name": "create_entities",
            "arguments": {"entities": [{
                "name": random_string(5, 15).strip(),
                "entityType": random.choice(["person", "concept", "task", "note", "organization"]),
                "observations": [random_string(10, 100)]
            }]}
        })
    if "fetch" in prompt.lower() or "url" in prompt.lower():
        time.sleep(lognormal(3.5, 1.3, 0.3))
        call_mcp_tool("fetch", "tools/call", {
            "name": "fetch",
            "arguments": {"url": random_url()}
        })
    if "github" in prompt.lower():
        time.sleep(lognormal(3.5, 1.3, 0.3))
        call_mcp_tool("github", "tools/call", {
            "name": "search_repositories",
            "arguments": {"query": random_string(10, 40)}
        })
    if "search" in prompt.lower() or "news" in prompt.lower():
        time.sleep(lognormal(3.5, 1.3, 0.3))
        query = random_string(15, 60)
        call_mcp_tool("exa", "tools/call", {
            "name": "search",
            "arguments": {"query": query}
        })
        time.sleep(lognormal(2.0, 0.8, 0.2))
        call_mcp_tool("tavily", "tools/call", {
            "name": "tavily-search",
            "arguments": {"query": query}
        })

SHORT_PROMPTS = [
    "List the files in my directory",
    "What tools do you have available?",
    "Store this note: meeting at 3pm",
    "Fetch the content of example.com",
    "List my GitHub repositories",
    "Search GitHub for MCP server examples",
    "Find documentation for Python requests library",
    "Search the web for recent news about AI agents",
    "Find examples of MCP server implementations",
]

LONG_PROMPTS = [
    "List all files, read each one, store their names in memory, then confirm what you stored",
    "Check what tools are available across all servers, then use each tool once and report results",
    "Fetch example.com, store a summary in memory, list what you stored, then verify it",
]

if __name__ == "__main__":
    print("Starting sessions with all MCP servers...")
    start_sessions()

    if not sessions:
        print("No sessions established. Check VM1 servers are running.")
        exit(1)

    # Loop infinitely for dataset generation
    while True:
        print(f"\nRunning SHORT-LIVED flows ({len(SHORT_PROMPTS)} prompts)...")
        for prompt in SHORT_PROMPTS:
            servers = random.sample(list(sessions.keys()), k=min(2, len(sessions)))
            run_claude_session(prompt, servers)
            time.sleep(lognormal(4.0, 1.0, 0.5))

        print(f"\nRunning LONG-LIVED flows ({len(LONG_PROMPTS)} prompts)...")
        for prompt in LONG_PROMPTS:
            servers = list(sessions.keys())
            run_claude_session(prompt, servers)
            time.sleep(lognormal(8.0, 0.6, 1.0))
