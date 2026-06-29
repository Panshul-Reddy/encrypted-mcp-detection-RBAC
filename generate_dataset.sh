#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

function cleanup {
    echo "Stopping Docker Lab..."
    cd "$SCRIPT_DIR"
    docker compose down
    
    echo "Extracting features from PCAP files to CSV using Rust..."
    if [ -d "rust-extractor" ]; then
        cd rust-extractor
        # Decompress any rotated gzipped pcaps first so the shell glob doesn't miss them
        gunzip ../capture/*.gz 2>/dev/null || true
        # Using 2>/dev/null to ignore "no matches found" if no pcaps exist yet
        cargo run --release -- --no-tui --replay ../capture/*.pcap --export-csv ../dataset.csv || true
    fi
    
    echo "Dataset generation complete: dataset.csv"
}

# Trap EXIT and SIGINT (Ctrl+C) to ensure cleanup runs
trap cleanup EXIT INT

echo "Starting Unified Docker Lab for Bulk Data Generation..."
# Run docker compose in detached mode so the script can continue
docker compose up --build -d

# Optionally, you can stream logs to the file in the background if you need them:
docker compose logs -f > /tmp/hpe_unified_logs.txt 2>&1 &

DURATION=${1:-1800}
echo "Generating traffic for ${DURATION} seconds... (Hit Ctrl+C to stop early)"
# Realistic MCP flow estimate: ~2,500–4,500 total flows (groq-client + chaos-client)
# constrained by Groq API rate limits (~30 req/min) and lognormal inter-call delays.
sleep $DURATION
