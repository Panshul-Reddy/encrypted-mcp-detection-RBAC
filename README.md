# Encrypted MCP Payload Detection

## Overview

This project implements a detection system for identifying encrypted Model Context Protocol (MCP) traffic without requiring cryptographic decryption. The system generates realistic network traffic patterns through a multi-container Docker deployment and captures packet-level data for analysis.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Components](#components)

## Features

- **Comprehensive MCP Client**: Supports 18 distinct tools simulating realistic client behavior with multiple session modes (interactive, bot, burst, and mixed)
- **Backend Simulation**: SQLite-backed server with in-memory key-value store, message queue, and asynchronous job handling
- **Realistic Traffic Generation**: Diverse noise patterns including REST polling, WebSocket streams, chunked transfers, and Server-Sent Events (SSE)
- **Passive Capture**: Host-mode network capture with tcpdump for encrypted traffic analysis
- **Containerized Deployment**: Docker Compose orchestration for reproducible multi-component environments

## Architecture

The system consists of four interconnected Docker containers:

1. **mcp-client** — MCP client container that communicates with the MCP server via SSE connections
2. **mcp-server** — MCP server container executing tool handlers and managing backend state via SQLite
3. **noise-client** — Traffic generation container producing non-MCP network patterns to simulate real-world interference
4. **network-tap** — Passive packet capture container recording encrypted traffic as PCAP data

This multi-container architecture generates network traffic that closely resembles production environments while remaining fully controlled and reproducible.

## Installation

### Prerequisites

- Docker and Docker Compose
- Unix-based system (macOS, Linux)

### Setup

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd hpe
   ```

2. Build and start the containers:

   ```bash
   docker-compose up --build
   ```

The deployment will automatically initialize the SQLite database, generate certificates, and begin traffic capture.

## Usage

The system operates through Docker Compose orchestration. All containers start automatically and run in coordination:

```bash
# Start all containers in the background
docker-compose up -d

# View container logs
docker-compose logs -f

# Stop all containers
docker-compose down
```

Captured PCAP data will be persisted in the `./capture` directory for downstream analysis and anomaly detection processing.

## Components

### MCP Client

The MCP client (`mcp-client/`) simulates realistic client behavior and communicates with the MCP server.

**Key Features:**

- 18 distinct tools covering key-value operations, logging, user queries, document search, database operations, shell execution, job submission, and blob/URL fetching
- Three session modes:
  - **Interactive**: Single-action requests mimicking user interaction
  - **Bot**: Automated sequences and bulk operations
  - **Burst**: Time-compressed tool sequences and batch submissions
- Realistic timing profiles using random think times, log-normal and Poisson timers, and jitter
- SSL/TLS handling with self-signed certificate support and connection retry logic

**Files:**

- `client.py`: Core MCP client implementation with tool definitions and session orchestration
- `run.sh`: Proxy initialization script
- `Dockerfile`: Container image build configuration
- `requirements.txt`: Python dependencies

### MCP Server

The MCP server (`mcp-server/`) provides tool handlers and backend simulation.

**Key Features:**

- HTTPS server running on port 8443 with self-signed certificate generation
- In-memory key-value store with event generation and burst patterns
- SQLite database seeded with logs, users, documents, and sandbox file structures
- 18 tool implementations with configurable latency profiles and payload sizing
- Server-Sent Events (SSE) channel for asynchronous notifications
- Asynchronous job lifecycle management with state transitions and large result payloads

**Files:**

- `server.js`: Tool handler implementation and backend simulation logic
- `Dockerfile`: Container image build and database/certificate initialization
- `package.json`: Node.js package dependencies

### Noise Client

The noise client (`noise-client/`) generates non-MCP traffic patterns that simulate real-world network interference.

**Traffic Patterns:**

- `pattern_rest_polling`: Fast endpoint polling with data fetching and queue operations
- `pattern_websocket_stream`: Long-lived WebSocket sessions with bidirectional messaging
- `pattern_chunked_stream`: HTTP chunked transfer encoding with reconnection handling
- `pattern_sse_stream`: Server-Sent Events consumption from external sources
- `pattern_burst_requests`: Short fan-out bursts with idle periods

**Files:**

- `client.py`: Pattern implementation and traffic generation logic
- `Dockerfile`: Container image build configuration
- `requirements.txt`: Python dependencies

### Noise Server

The noise server (`noise-server/`) provides structured noise endpoints and push mechanisms.

**Capabilities:**

- Pre-generated payloads at multiple sizes (tiny, small, medium, large, xlarge)
- REST endpoints for polling and data submission (/api/fast, /api/data, /api/submit, /api/poll)
- HTTP chunked transfer endpoint (/stream/chunked)
- Server-Sent Events feed (/stream/sse) with internal push mechanics
- WebSocket endpoint (/ws) for real-time message exchange

**Files:**

- `server.js`: Endpoint and push mechanism implementation
- `Dockerfile`: Container image build configuration
- `package.json`: Node.js package dependencies

### Network Tap

The network tap (`network-tap`) provides passive packet capture for all container traffic.

**Configuration:**

- Base image: `nicolaka/netshoot` (includes tcpdump, tshark, nmap)
- Network mode: Host mode for access to virtual bridge interfaces
- Capture filter: TCP ports 8443 (MCP server) and 443 (external APIs)
- Output: PCAP file persisted to `./capture/dataset.pcap`
- Volume mount: `./capture` directory for persistent storage across container lifecycle
