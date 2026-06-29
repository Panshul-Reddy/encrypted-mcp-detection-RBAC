# Encrypted MCP Payload Detection & Layer 4 RBAC

## Overview

Welcome to the unified repository for **Encrypted Model Context Protocol (MCP) Payload Detection and Role-Based Access Control (RBAC)**. As machine learning systems and Large Language Model (LLM) integrations become increasingly embedded in modern infrastructure, securing these AI-to-tool communication channels is of paramount importance. 

This project addresses the critical challenge of classifying, policing, and intercepting unauthorized MCP traffic in real-time. It operates **exclusively on encrypted streams** without the necessity of TLS decryption. We achieve this through a combination of rigorous data engineering, low-latency feature extraction in Rust, and specialized early-packet sequence models deployed via Python, culminating in a dynamic Layer 4 RBAC enforcement engine.

---

## Prerequisites

Before running the system, ensure you have the following installed:
* **Docker Desktop**: Required for running the backend MCP and Noise servers.
* **Rust & Cargo**: Required to compile the High-Speed Feature Extractor (`rust-extractor`).
* **Python 3.10+**: Required for the ML Inference API, Proxy, and Traffic Generators.
* **Npcap (Windows)**: Required for `libpcap` to bind to the network interface in promiscuous mode (make sure Npcap SDK is installed and added to your `$env:LIB`).

---

## System Architecture

To achieve line-rate processing and preserve bidirectional traffic features without introducing latency, we implement a highly decoupled architecture:

### 1. High-Speed Feature Extractor (Rust Core)
Located in `rust-extractor/`. 
The core data acquisition engine is implemented in Rust. It operates in promiscuous mode, performing line-rate packet capture, TCP stream reassembly, and TLS unencrypted header parsing. It extracts a comprehensive **115-dimension feature vector** per flow, encompassing:
* **Flow Metadata:** Flow durations, byte and packet counts, and directional ratios.
* **Timing Statistics:** Inter-Arrival Time (IAT) statistical moments (mean, standard deviation, minimum, maximum).
* **TLS Parsing:** Application Data lengths inferred from unencrypted 5-byte headers.
* **N-Packet Sequences:** Fixed-length arrays tracking the size, directionality, and IAT of the initial 20 packets.

*(Note: Payload Entropy calculations were removed from the feature set as they were deemed ineffective for differentiating between uniformly encrypted TLS cipher suites).*

### 2. FastFlow Inference API (Machine Learning Engine)
Located in `classifier/`.
This component serves as the asynchronous inference engine. Implemented as a Python API, it serves pre-trained tree-ensemble models:
* **Threshold Buffering:** The Rust core emits feature vectors strictly at predefined packet milestones: N = [3, 5, 8, 10, 15, 20].
* **Progressive Confidence Evaluation:** The API routes incoming requests to the corresponding N-packet model. The system uses a **Dynamic Confidence Threshold** that scales progressively (e.g., requires 35% confidence at N=3, up to 60% at N=20). If confidence is insufficient, it returns a `WAIT` directive to accumulate more packets.

### 3. Layer 4 Encrypted RBAC Engine
The prediction results are passed through the RBAC engine, which maps source IPs (or in the demo environment, simulated roles based on flow timing) to predefined security roles (`analyst`, `restricted`, `full`). 
* If a flow attempts to access a tool/server they do not have authorization for, the system issues a **DENY** decision.
* A terminal command is dispatched to the Proxy on UDP port 9999, which instantaneously triggers a **Mid-Stream Kill**, terminating the TCP socket before the LLM can receive the unauthorized data.

---

## Model Training Methodology

Because the models require the full 115-dimension feature shapes and are extremely large when saved (`~200MB` each), **they are not checked into version control**. You must generate them locally.

1. **Dataset Generation:** The `dataset_hard.csv` contains realistic WAN latency jitter, adversarial JSON-RPC payloads, and official MCP server traffic.
2. **Early-Sequence Models:** The training script compares Random Forest, Extra Trees, and HistGradientBoosting candidates across multiple sequence thresholds (N=3 to N=20). 
3. **Compilation:** The resulting highly accurate models are saved as `.joblib` files to the `classifier/models/` directory for fast loading by the FastFlow API.

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
1. **Docker Infrastructure:** Initializes the backend MCP (`fetch`, `memory`, `filesystem`, `tavily`, `exa`) and Noise servers.
2. **FastFlow API:** Runs the FastAPI model server on port `5050`.
3. **Native TLS Proxy:** Binds natively to loopback to route traffic to the Docker containers.
4. **Traffic Generators:** 
   - `groq-client` generates legitimate MCP `tools/call` patterns.
   - `restricted-client` generates unauthorized tool calls to simulate an internal threat.
   - `noise-client` generates adversarial web traffic to test evasion resilience.
5. **Rust Live Analyzer:** Compiles and runs the Rust core, attaching to the Npcap loopback adapter to feed the ML API.
6. **Live RBAC Monitor:** Launches a sleek terminal monitor reading from `logs/encrypted_rbac_audit.jsonl` to display real-time ALLOW/DENY decisions!

### 3. Cleanup
If processes hang or you need to restart the demo, run:
```powershell
taskkill /F /IM live-analyzer.exe /T -ErrorAction SilentlyContinue
taskkill /F /IM python.exe /T -ErrorAction SilentlyContinue
```
