#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# ==============================================================================
# FastFlow Live Demo Environment Setup
# ==============================================================================

# --- Colors & Formatting ---
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BOLD='\033[1m'
RESET='\033[0m'

# --- Configuration ---
PYTHON_SERVICES=("classifier" "proxy" "groq-client" "noise-client")
TARGET_PORTS=(5050 8440 8441 8442 8443 8444 8445 9999)
declare -a PIDS

# --- Helper Functions ---

log_info() { echo -e "${BLUE}ℹ️  ${1}${RESET}"; }
log_success() { echo -e "${GREEN}✓  ${1}${RESET}"; }
log_warn() { echo -e "${YELLOW}⚠️  ${1}${RESET}"; }
log_error() { echo -e "${RED}❌ ${1}${RESET}"; }
log_step() { echo -e "\n${BOLD}${BLUE}=== ${1} ===${RESET}"; }

cleanup() {
    echo -e "\n"
    log_warn "Stopping all background services..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -15 "$pid" 2>/dev/null || true
        fi
    done
    log_success "All services stopped."
    exit 0
}

# Trap Ctrl+C (SIGINT/SIGTERM) to clean up all background processes
trap cleanup SIGINT SIGTERM

setup_python_env() {
    local dir=$1
    log_info "Setting up Python environment in ${BOLD}$dir${RESET}..."
    pushd "$dir" > /dev/null
    
    if [ ! -d ".venv" ]; then
        if command -v uv &> /dev/null; then
            uv venv > /dev/null || { log_error "Failed to create venv in $dir"; exit 1; }
        else
            python3 -m venv .venv || { log_error "Failed to create venv in $dir"; exit 1; }
        fi
    fi
    
    source .venv/bin/activate
    
    if [ -f "requirements.txt" ]; then
        if command -v uv &> /dev/null; then
            uv pip install -r requirements.txt > /dev/null 2>&1 || { log_error "Dependencies failed to install in $dir"; exit 1; }
        else
            pip install -r requirements.txt > /dev/null 2>&1 || { log_error "Dependencies failed to install in $dir"; exit 1; }
        fi
    else
        log_info "No requirements.txt found in $dir, skipping pip install."
    fi
    
    deactivate
    popd > /dev/null
    log_success "Environment ready for $dir"
}

start_service() {
    local dir=$1
    local name=$2
    local log_file=$3
    shift 3
    local cmd=("$@")

    pushd "$dir" > /dev/null
    source .venv/bin/activate
    
    "${cmd[@]}" > "$log_file" 2>&1 &
    local pid=$!
    PIDS+=($pid)
    
    deactivate
    popd > /dev/null
    
    if [ "$name" == "Native TLS Proxy" ]; then
        log_success "$name running (PID: $pid) - Check $dir/$log_file for connection kills!"
    else
        log_success "$name running (PID: $pid)"
    fi
}

# ==============================================================================
# Main Execution
# ==============================================================================

LOG_DIR="/tmp/fastflow_logs"
mkdir -p "$LOG_DIR"

log_step "1. Pre-Flight Checks & Python Environments"

if ! docker info > /dev/null 2>&1; then
    log_error "Docker daemon is not running! Please start Docker Desktop first."
    exit 1
fi

for service in "${PYTHON_SERVICES[@]}"; do
    setup_python_env "$service"
done

log_step "2. Starting Docker Infrastructure"
log_info "Starting backend containers (mcp-servers, noise-server)..."
docker compose up -d mcp-servers noise-server
if [ $? -ne 0 ]; then
    log_error "Failed to start Docker containers."
    exit 1
fi
log_success "Docker containers are up."

log_step "3. Starting Native Python Services"

log_info "Cleaning up existing processes on target ports..."
PORT_ARGS=()
for port in "${TARGET_PORTS[@]}"; do
    PORT_ARGS+=("-i:$port")
done
if [ ${#PORT_ARGS[@]} -gt 0 ]; then
    lsof -t "${PORT_ARGS[@]}" 2>/dev/null | xargs kill -9 2>/dev/null || true
fi

log_info "All logs are being written to ${BOLD}${LOG_DIR}${RESET}"

# Start services using the helper
start_service "classifier" "FastFlow API" "$LOG_DIR/api.log" uvicorn api:app --port 5050
start_service "proxy" "Native TLS Proxy" "$LOG_DIR/proxy.log" python3 tls_proxy.py --cert ../nginx/ssl/mcp.crt --key ../nginx/ssl/mcp.key --mappings "8440:3000,8441:3001,8442:3002,8443:3003,8444:3004,8445:3005,9443:9444" --backend-host 127.0.0.1

export VM1_IP=127.0.0.1
start_service "groq-client" "Groq Traffic Generator" "$LOG_DIR/groq.log" python3 groq_mcp_client.py

# Export variables for native python processes
export VM1_IP="127.0.0.1"
export NOISE_SERVER="https://127.0.0.1:9443"
start_service "noise-client" "Noise Attacker" "$LOG_DIR/noise.log" python3 client.py

log_step "4. Building Rust Live Analyzer"
pushd rust-extractor > /dev/null
log_info "Compiling Rust project (release mode)..."
cargo build --release
popd > /dev/null
log_success "Build complete."

log_step "5. Starting Rust Live Analyzer TUI"
log_warn "Requires sudo for promiscuous packet capture on lo0."
log_info "Press Ctrl+C at any time to safely shutdown ALL services."
echo ""

cd rust-extractor
# Run the compiled binary directly
sudo target/release/live-analyzer --interface lo0 --inference-url http://localhost:5050

# If the Rust binary exits naturally (e.g. user pressed 'q' in TUI), trigger the trap manually
kill -SIGINT $$
