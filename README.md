# Encrypted MCP Payload Detection & Application-Layer RBAC

## Overview

Welcome to the unified repository for **Encrypted Model Context Protocol (MCP) Payload Detection and Role-Based Access Control (RBAC)**. As machine learning systems and Large Language Model (LLM) integrations become increasingly embedded in modern infrastructure, securing these AI-to-tool communication channels is of paramount importance. 

This project tackles MCP security through two distinct, complementary security layers that operate simultaneously:
1. **ML-Based Detection (Layer 4):** A progressive machine learning pipeline that classifies anomalous MCP traffic purely from encrypted packet heuristics on the wire, without requiring TLS decryption.
2. **Application-Layer RBAC Engine (Layer 7):** A granular, policy-driven access control proxy that inspects unencrypted JSON-RPC payloads to enforce strict tool-level least privilege, utilizing API keys and role mapping.

---

## Prerequisites

Before running the system, ensure you have the following installed:
* **Docker Desktop**: Required for running the backend MCP tool servers.
* **Rust & Cargo**: Required to compile the High-Speed Feature Extractor and Live TUI (`rust-extractor`).
* **Python 3.10+**: Required for the ML Inference API, Proxy, and Traffic Generators.
* **Npcap (Windows)**: Required for `libpcap` to bind to the network interface in promiscuous mode (make sure Npcap SDK is installed and added to your `$env:LIB`).

---

## System Architecture

### 1. Application-Layer RBAC Engine (Native TLS Proxy)
Located in `proxy/`.
To enforce tool-level access control, we implement a declarative, policy-driven Mid-Stream TLS proxy. 
* **Identity Resolution:** The proxy maps incoming connections to a role (e.g., `full` or `readonly`) based on the `X-MCP-API-Key` header or the Source IP.
* **Granular Policy Enforcement:** Evaluates incoming JSON-RPC payloads against `tool_policy.yaml`. The engine accurately extracts the nested MCP tool name from the JSON body (handling canonical aliases) and strictly verifies it against the role's allowed methods and tool lists. 
* **Zero-Trust Defaults:** Unauthorized attempts immediately return an HTTP 403, and any unrecognized role strictly defaults to DENY.

### 2. High-Speed Feature Extractor (Rust Core)
Located in `rust-extractor/`. 
Operating in promiscuous mode, this data acquisition engine performs line-rate packet capture, TCP stream reassembly, and TLS unencrypted header parsing. It extracts a comprehensive **115-dimension feature vector** per flow, analyzing flow durations, packet counts, inter-arrival time statistics, and initial N-packet sequences.

### 3. FastFlow Inference API (Machine Learning Engine)
Located in `classifier/`.
This asynchronous Python API serves pre-trained tree-ensemble models:
* **Progressive Confidence Evaluation:** The Rust core emits feature vectors at predefined packet milestones (N = [3, 5, 8, 10, 15, 20]). The system uses a **Dynamic Confidence Threshold** that scales progressively. If confidence is insufficient, it returns a `WAIT` directive to accumulate more packets.
* **Mid-Stream Kill:** Upon confirming anomalous activity, a terminal command is dispatched to the Proxy on UDP port 9999, instantaneously triggering a socket termination before the LLM can receive the unauthorized data.

### 4. Live Terminal Dashboard (TUI)
Located in `rust-extractor/src/tui.rs`.
A gorgeous terminal dashboard that fuses data from both security layers into a single pane of glass. It correlates the wire-level ML classification statistics (Label, Confidence, Packets) alongside the L7 RBAC inspection metadata (Server, Role, Accessed Tool, ALLOW/DENY Decisions).

---

## Model Training Methodology

Because the models require the full 115-dimension feature shapes and are extremely large when saved (`~200MB` each), **they are not checked into version control**. You must generate them locally.

1. **Dataset Generation:** The `dataset_hard.csv` contains realistic WAN latency jitter, adversarial JSON-RPC payloads, and official MCP server traffic.
2. **Early-Sequence Models:** The training script compares Random Forest, Extra Trees, and HistGradientBoosting candidates across multiple sequence thresholds. 
3. **Compilation:** The resulting models are saved as `.joblib` files to the `classifier/models/` directory for fast loading.

---

## Live Demo Guide (Windows PowerShell)

We provide an automated orchestration script (`start_demo.ps1`) to launch all services, orchestrate traffic, and run the real-time TUI dashboard.

### 1. Train the Models (First Run Only)
Before running the demo for the first time, you must train the progressive ML models using the provided dataset.
```powershell
cd classifier
.\.venv\Scripts\python.exe train.py
cd ..
```
*This will generate `n3.joblib`, `n5.joblib`, etc. inside `classifier/models/`.*

### 2. Execute the Demo
Execute the orchestration script from the project root:
```powershell
.\start_demo.ps1
```

**What the Script Orchestrates:**
1. **Docker Infrastructure:** Initializes the backend MCP servers (`fetch`, `memory`, `filesystem`, `tavily`, `exa`) and Noise servers.
2. **FastFlow API:** Runs the FastAPI model server on port `5050`.
3. **Native TLS Proxy:** Binds to the loopback adapter and loads the strict `tool_policy.yaml` configuration.
4. **Traffic Generators:** 
   - `groq-client` (Role: `full`): Generates legitimate MCP tool traffic that succeeds.
   - `restricted-client` (Role: `readonly`): Connects with a restricted API key and intentionally attempts both safe read operations (which are ALLOWED) and restricted write operations (which are DENIED), demonstrating the RBAC engine in real-time.
   - `noise-client`: Generates adversarial web traffic to test ML evasion resilience.
5. **Rust Live Analyzer:** Compiles and runs the Rust core, attaching to the Npcap loopback adapter to feed the ML API and render the dashboard.

### 3. Cleanup
If processes hang or you need to restart the demo cleanly, run:
```powershell
taskkill /F /IM live-analyzer.exe /T -ErrorAction SilentlyContinue
taskkill /F /IM python.exe /T -ErrorAction SilentlyContinue
```
