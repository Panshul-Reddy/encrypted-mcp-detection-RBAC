#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- Colors & Formatting ---
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n${BOLD}${RED}=== 🌪️  FASTFLOW CHAOS AGENT 🌪️  ===${RESET}\n"

# Verify environment
if [ -z "$GROQ_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  WARNING: GROQ_API_KEY is not set.${RESET}"
    echo -e "The Chaos Agent requires a valid Groq API key to dynamically generate zero-day prompts."
    echo -e "Please run: ${BOLD}export GROQ_API_KEY='your-key-here'${RESET} and try again.\n"
    exit 1
fi

export VM1_IP="127.0.0.1"
DIR="groq-client"

echo -e "${BLUE}ℹ️  Activating environment in ${BOLD}$DIR${RESET}..."
pushd "$DIR" > /dev/null

if [ ! -d ".venv" ]; then
    echo -e "${RED}❌ Environment not found. Please run ./start_demo.sh first to build the lab.${RESET}"
    exit 1
fi

source .venv/bin/activate

echo -e "${GREEN}✓  Launching Zero-Day Traffic Generator...${RESET}\n"
python3 chaos_mcp_client.py

deactivate
popd > /dev/null
