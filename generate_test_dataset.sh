#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

function cleanup {
    echo "Stopping Docker Lab..."
    cd "$SCRIPT_DIR"
    docker compose -f docker-compose.yml -f docker-compose.test.yml down
    
    echo "Extracting features from PCAP files to CSV using Rust..."
    if [ -d "rust-extractor" ]; then
        cd rust-extractor
        # Decompress any rotated gzipped pcaps first so the shell glob doesn't miss them
        gunzip ../capture_test/*.gz 2>/dev/null || true
        # Using 2>/dev/null to ignore "no matches found" if no pcaps exist yet
        cargo run --release -- --no-tui --replay ../capture_test/*.pcap --export-csv ../dataset_hard.csv || true
    fi
    
    echo "Hard Negative Dataset generation complete: dataset_hard.csv"
}

# Trap EXIT and SIGINT (Ctrl+C) to ensure cleanup runs
trap cleanup EXIT INT

# Clean capture directory first so we only get fresh traffic
mkdir -p capture_test
# We will keep old pcaps so they are not deleted.

echo "Starting Unified Docker Lab for Hard Negative Data Generation..."
# Run docker compose in detached mode so the script can continue
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build --force-recreate -d

# Optionally, you can stream logs to the file in the background if you need them:
docker compose -f docker-compose.yml -f docker-compose.test.yml logs -f > /tmp/hpe_unified_test_logs.txt 2>&1 &

DURATION=${1:-600}
echo "Generating hard negative noise and pure MCP traffic for ${DURATION} seconds... (Hit Ctrl+C to stop early)"
sleep $DURATION
