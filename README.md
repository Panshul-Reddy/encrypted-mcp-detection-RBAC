# Encrypted MCP Payload Detection: Architecture and Implementation

## Overview

Welcome to the unified repository for **Encrypted Model Context Protocol (MCP) Payload Detection**. As machine learning systems and Large Language Model (LLM) integrations become increasingly embedded in modern infrastructure, securing these AI-to-tool communication channels is of paramount importance. 

This project addresses the critical challenge of classifying and intercepting unauthorized or adversarial MCP traffic in real-time, relying exclusively on encrypted streams without the necessity of TLS decryption. We achieve this through a combination of rigorous data engineering, low-latency feature extraction in Rust, and specialized early-packet sequence models deployed via Python, enabling the system to identify and terminate malicious flows mid-stream.

---

## Prerequisites

Before running the system, ensure you have the following installed:
* **Docker & Docker Compose**: Required for running the backend MCP and Noise servers.
* **Rust & Cargo**: Required to compile the High-Speed Feature Extractor (`rust-extractor`).
* **Python 3.10+**: Required for the ML Inference API, Proxy, and Traffic Generators.
* **`uv` (or `pip`)**: Recommended for ultra-fast Python environment resolution.
* **Root/Sudo Privileges**: Required for `libpcap` to bind to the network interface in promiscuous mode.

---

## Tripartite System Architecture

To achieve line-rate processing and preserve bidirectional traffic features without introducing latency, we implement a highly decoupled, three-tier architecture:

### 1. High-Speed Feature Extractor (Rust Core)
Located in `capture/` and `rust-extractor/`. 
The core data acquisition engine is implemented in Rust. It operates in promiscuous mode on the network bridge, performing line-rate packet capture, TCP stream reassembly, and TLS unencrypted header parsing. It extracts a comprehensive feature vector per flow, encompassing:
* **Flow Metadata:** Flow durations, byte and packet counts, and directional ratios.
* **Timing Statistics:** Inter-Arrival Time (IAT) statistical moments (mean, standard deviation, minimum, maximum).
* **TLS Parsing:** Application Data lengths inferred from unencrypted 5-byte headers.
* **Payload Entropy:** Shannon entropy calculations derived from the first 64 bytes of TCP payloads.
* **N-Packet Sequences:** Fixed-length arrays tracking the size, directionality, and IAT of the initial 20 packets.

*Rationale: Native Python packet processing (e.g., via Scapy) introduces prohibitive latency for line-rate TCP reassembly. Centralizing feature extraction in Rust ensures deterministic, low-latency performance.*

### 2. FastFlow Inference API (Machine Learning Engine)
Located in `classifier/`.
This component serves as the asynchronous inference engine. Implemented as a Python API, it serves pre-trained XGBoost sequence models with the following optimizations:
* **Threshold Buffering:** The Rust core emits feature vectors strictly at predefined packet milestones: N = [3, 5, 8, 10, 15, 20].
* **Progressive Confidence Evaluation:** The API routes incoming requests to the corresponding N-packet model. If the classification confidence exceeds the requisite threshold (>85%), a terminal classification is returned. If confidence is insufficient, the system returns an `UNKNOWN_WAIT` directive, instructing the Rust core to accumulate further packets before issuing subsequent queries.

### 3. Mid-Stream TLS Proxy (Enforcement Node)
Located in `proxy/`.
A lightweight inline TLS proxy engineered for **Mid-Stream Termination**. It forwards packets uninterrupted, permitting the Rust core to observe bidirectional traffic characteristics including server responses. Upon receiving a positive identification of anomalous or malicious traffic from the FastFlow API, an out-of-band termination command is issued to the proxy, which instantaneously severs the active TCP connection.

---

## Data Engineering and the Unified Docker Environment

Developing a robust, resilient model necessitates a highly diverse and representative dataset. We have architected an orchestrated Docker environment to simulate realistic network conditions and mitigate loopback overfitting.

* **Positive Class (MCP Traffic):** Official MCP servers (Fetch, Memory, Filesystem) are deployed behind an NGINX reverse proxy (`nginx/`, `mcp-servers/`). A programmatic client (`groq-client/`) continuously executes randomized, LLM-driven tool calls to generate realistic temporal traffic bursts.
* **Negative Class (Noise and Adversarial Traffic):** To introduce authentic Wide Area Network (WAN) latency jitter and Maximum Transmission Unit (MTU) fragmentation, payloads are fetched from public APIs (`noise-client/`, `noise-server/`). Furthermore, adversarial JSON-RPC generators are deployed to emit compliant JSON-RPC 2.0 structures over Server-Sent Events (SSE), intentionally simulating sophisticated evasion techniques.
* **Deterministic Labeling:** Establishing ground truth for encrypted traffic is historically challenging. This is addressed by isolating respective services on designated ports (e.g., Fetch=8440, Memory=8441). The Rust dataset exporter utilizes these deterministic destinations to accurately label the resulting `dataset.csv`.

---

## Model Training Methodology

The machine learning strategy avoids processing raw packet captures through deep learning networks, which is prone to overfitting. Instead, the approach relies on meticulously engineered features and early-sequence classifiers.

* **Multi-Class Objectives:** Traffic is classified across five distinct categories: `[Noise, MCP-Fetch, MCP-Memory, MCP-Filesystem, MCP-GitHub]`.
* **Early-Sequence Models:** Distinct XGBoost estimators are trained for truncated packet sequences. For instance, an N=5 model evaluates exclusively the first five packets, whereas an N=10 model evaluates ten. This architecture facilitates split-second classification prior to full payload transmission, preserving bandwidth and proactively neutralizing threats.

---

## Operational Guidelines & Live Demo Guide

Due to how Docker handles networking, the setup for live traffic interception differs significantly depending on the host operating system.

### OS-Specific Architecture Requirements

**macOS & Windows (Docker Desktop):**
Docker runs inside a lightweight Linux virtual machine. Traffic sent between two Docker containers remains within that VM's bridge network and is invisible to host packet sniffers (e.g., Wireshark or `libpcap`). 
To bypass this limitation, we utilize **Loopback Interception**: The backend servers and `tls-proxy` run inside Docker, while the clients (traffic generators) run natively on the host OS. This routes traffic across the host's loopback interface (`lo0` on macOS), allowing the Rust analyzer to capture it before entering the Docker VM.

**Linux (Native Docker):**
Docker runs natively on the host kernel. Container-to-container traffic can be sniffed directly by attaching the Rust analyzer to the specific Docker bridge interface (e.g., `br-<network_id>`).

---

### Phase 1: Environment Setup & Dataset Generation

1. **Start the Backend Infrastructure:**
   Ensure Python virtual environments are configured, then start the proxy and backend servers.
   ```bash
   docker compose up -d tls-proxy mcp-servers noise-server
   ```

2. **(Optional) Generate the Dataset:**
   To train models from scratch, execute the dataset generator. *(Note: On macOS/Windows, this script configures clients to run natively over loopback).*
   ```bash
   ./generate_dataset.sh
   ```

3. **Train the Models:**
   Navigate to the `classifier/` directory to train the XGBoost models across all packet thresholds (N=3, 5, 8, 10, etc.).
   ```bash
   cd classifier/
   source .venv/bin/activate
   pip install -r requirements.txt
   python train.py --dataset ../dataset.csv
   ```

---

### Phase 2: Live Inference & Mid-Stream Kill Demo

To observe the firewall identifying and terminating unauthorized traffic mid-stream, we provide an automated orchestration script. This script automatically builds the Rust binaries, configures Python environments, and launches all background services (Docker, Inference API, TLS Proxy, and Traffic Generators) before attaching the Rust TUI to the loopback interface.

**Execution:**
Execute the orchestration script from the project root:
```bash
chmod +x start_demo.sh
./start_demo.sh
```

**What the Script Orchestrates:**
1. **Docker Infrastructure:** Initializes the backend MCP and Noise servers.
2. **FastFlow API:** Runs the FastAPI model server on port `5050` (logs to `classifier/api.log`).
3. **Native TLS Proxy:** Binds natively to the host to circumvent Docker NAT limitations on macOS/Windows, allowing precise source IP tracking (logs to `proxy/proxy.log`).
4. **Traffic Generators:** 
   - `groq-client` generates legitimate MCP `tools/call` patterns.
   - `noise-client` generates adversarial traffic (WSS, REST polling) against the proxy endpoints.
5. **Rust Live Analyzer:** Prompts for superuser privileges to bind `libpcap` to the loopback interface (`lo0`) and renders the real-time TUI dashboard.

**Observation:**
1. As the script runs, active flows will instantly populate in the Rust TUI.
2. The ML inference engine will label anomalous flows (from the `noise-client`) as `NOISE`.
3. The Rust analyzer will transmit a UDP command to the native proxy.
4. The background proxy instantly severs the socket mid-stream. (You can verify this by running `tail -f proxy/proxy.log` in a separate terminal to view the `[control] Executing Mid-Stream KILL` events).
5. Exiting the Rust TUI (via `Ctrl+C` or `q`) will trigger a clean shutdown of all background services.

### Why an ML Firewall? (The Reverse Proxy Problem)
Traditional port-based firewalls easily fall victim to reverse proxy encapsulation. If a standard firewall is positioned behind a TLS-terminating proxy (like Nginx), it sees all traffic arriving on the same local proxy port. 

If an attacker launches a malicious polling script against the proxy's open HTTP port (e.g., `8440`), a traditional firewall evaluates the destination port, concludes that `8440` is authorized, and lets the attack through blindly. 

Our **Machine Learning Firewall** bypasses this entirely. By executing deep packet cadence analysis (inter-arrival times, payload byte entropy, request/response pacing), the AI completely ignores the port number. It dynamically identifies that the underlying application-layer sequence is anomalous and terminates the flow mid-stream—providing zero-trust security even when traffic is fully encapsulated behind an edge proxy!
