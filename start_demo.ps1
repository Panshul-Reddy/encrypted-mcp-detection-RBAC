# ==============================================================================
# FastFlow Live Demo - Windows PowerShell Edition
# ==============================================================================
# This script orchestrates all services for the live ML firewall demo.
# NOTE: Must be run as Administrator for Npcap packet capture.
# ==============================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Colors ---
function Log-Info    { param($msg) Write-Host "  [INFO]  $msg" -ForegroundColor Cyan }
function Log-Success { param($msg) Write-Host "  [OK]    $msg" -ForegroundColor Green }
function Log-Warn    { param($msg) Write-Host "  [WARN]  $msg" -ForegroundColor Yellow }
function Log-Error   { param($msg) Write-Host "  [ERROR] $msg" -ForegroundColor Red }
function Log-Step    { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Magenta }

# --- Ensure Rust is on PATH ---
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
$env:LIB  = "$env:USERPROFILE\npcap-sdk\Lib\x64;$env:LIB"

# Load .env file
$envFile = Join-Path $ProjectRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
    Log-Success "Loaded .env file"
}

# Track background processes for cleanup
$script:bgJobs = @()

function Cleanup {
    Log-Warn "Stopping all background services..."
    foreach ($job in $script:bgJobs) {
        try {
            Stop-Process -Id $job -Force -ErrorAction SilentlyContinue
            # Also kill child processes
            Get-CimInstance Win32_Process -Filter "ParentProcessId=$job" -ErrorAction SilentlyContinue | 
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
    Log-Success "All services stopped."
}

# ==============================================================================
# Phase 1: Pre-Flight Checks
# ==============================================================================
Log-Step "1. Pre-Flight Checks"

# Check Docker
try {
    docker info 2>$null | Out-Null
    Log-Success "Docker is running"
} catch {
    Log-Error "Docker is not running! Start Docker Desktop first."
    exit 1
}

# Check Rust binary
$rustBinary = Join-Path $ProjectRoot "rust-extractor\target\release\live-analyzer.exe"
if (-not (Test-Path $rustBinary)) {
    Log-Error "Rust binary not found. Run 'cargo build --release' in rust-extractor/ first."
    exit 1
}
Log-Success "Rust binary found: live-analyzer.exe"

# Check admin (needed for Npcap)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log-Warn "NOT running as Administrator. Packet capture may fail."
    Log-Warn "Consider: Right-click PowerShell -> Run as Administrator"
}

# ==============================================================================
# Phase 2: Docker Infrastructure
# ==============================================================================
Log-Step "2. Docker Infrastructure"

Log-Info "Starting backend containers (mcp-servers, noise-server)..."
Push-Location $ProjectRoot
docker compose up -d mcp-servers noise-server
Pop-Location

Start-Sleep -Seconds 3
docker ps --format "table {{.Names}}`t{{.Status}}`t{{.Ports}}" --filter "name=mcp" --filter "name=noise"
Log-Success "Docker containers are up."

# ==============================================================================
# Phase 3: Native Python Services
# ==============================================================================
Log-Step "3. Starting Native Python Services"

$logDir = Join-Path $ProjectRoot "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Log-Info "Logs will be written to $logDir"

# --- 3a. FastFlow Inference API (classifier) ---
Log-Info "Starting FastFlow Inference API on port 5050..."
$classifierVenv = Join-Path $ProjectRoot "classifier\.venv\Scripts"
$apiLog = Join-Path $logDir "api.log"
$proc = Start-Process -FilePath (Join-Path $classifierVenv "python.exe") `
    -ArgumentList "-m", "uvicorn", "api:app", "--port", "5050", "--host", "0.0.0.0" `
    -WorkingDirectory (Join-Path $ProjectRoot "classifier") `
    -RedirectStandardOutput $apiLog `
    -RedirectStandardError (Join-Path $logDir "api_err.log") `
    -PassThru -WindowStyle Hidden
$script:bgJobs += $proc.Id
Log-Success "FastFlow API running (PID: $($proc.Id)) - logs: $apiLog"

Start-Sleep -Seconds 3

# --- 3b. Native TLS Proxy ---
Log-Info "Starting Native TLS Proxy (ports 8440-8445)..."
$proxyVenv = Join-Path $ProjectRoot "proxy\.venv\Scripts"
$proxyLog = Join-Path $logDir "proxy.log"
$proxyArgs = "tls_proxy.py --cert `"$(Join-Path $ProjectRoot 'nginx\ssl\mcp.crt')`" --key `"$(Join-Path $ProjectRoot 'nginx\ssl\mcp.key')`" --mappings 8440:3000,8441:3001,8442:3002,8443:3003,8444:3004,8445:3005 --backend-host 127.0.0.1 --policy `"$(Join-Path $ProjectRoot 'proxy\tool_policy.yaml')`""
$proc = Start-Process -FilePath (Join-Path $proxyVenv "python.exe") `
    -ArgumentList $proxyArgs.Split(" ") `
    -WorkingDirectory (Join-Path $ProjectRoot "proxy") `
    -RedirectStandardOutput $proxyLog `
    -RedirectStandardError (Join-Path $logDir "proxy_err.log") `
    -PassThru -WindowStyle Hidden
$script:bgJobs += $proc.Id
Log-Success "TLS Proxy running (PID: $($proc.Id)) - Check $proxyLog for KILL events!"

Start-Sleep -Seconds 2

# --- 3c. Groq Traffic Generator ---
Log-Info "Starting Groq MCP Traffic Generator..."
$env:VM1_IP = "127.0.0.1"
$groqVenv = Join-Path $ProjectRoot "groq-client\.venv\Scripts"
$groqLog = Join-Path $logDir "groq.log"
$proc = Start-Process -FilePath (Join-Path $groqVenv "python.exe") `
    -ArgumentList "groq_mcp_client.py" `
    -WorkingDirectory (Join-Path $ProjectRoot "groq-client") `
    -RedirectStandardOutput $groqLog `
    -RedirectStandardError (Join-Path $logDir "groq_err.log") `
    -PassThru -WindowStyle Hidden `
    -Environment @{ VM1_IP="127.0.0.1"; GROQ_API_KEY=$env:GROQ_API_KEY }
$script:bgJobs += $proc.Id
Log-Success "Groq Traffic Generator running (PID: $($proc.Id))"

# --- 3d. Noise Attacker ---
Log-Info "Starting Noise Attacker..."
$env:NOISE_SERVER = "https://127.0.0.1:9443"
$noiseVenv = Join-Path $ProjectRoot "noise-client\.venv\Scripts"
$noiseLog = Join-Path $logDir "noise.log"
$proc = Start-Process -FilePath (Join-Path $noiseVenv "python.exe") `
    -ArgumentList "client.py" `
    -WorkingDirectory (Join-Path $ProjectRoot "noise-client") `
    -RedirectStandardOutput $noiseLog `
    -RedirectStandardError (Join-Path $logDir "noise_err.log") `
    -PassThru -WindowStyle Hidden `
    -Environment @{ NOISE_SERVER="https://127.0.0.1:9443" }
$script:bgJobs += $proc.Id
Log-Success "Noise Attacker running (PID: $($proc.Id))"

# ==============================================================================
# Phase 4: Rust Live Analyzer TUI
# ==============================================================================
Log-Step "4. Launching Rust Live Analyzer"

Log-Warn "The TUI requires Npcap access (Administrator privileges)."
Log-Info "Press 'q' or Ctrl+C in the TUI to safely shutdown ALL services."
Log-Info ""
Log-Info "Monitor proxy kills:  Get-Content $proxyLog -Wait"
Log-Info "Monitor API logs:     Get-Content $apiLog -Wait"
Log-Info ""

# List interfaces for user to pick
Log-Info "Available network interfaces:"
& $rustBinary --list-interfaces 2>$null

Write-Host ""
Write-Host "Starting live analyzer on the Npcap Loopback Adapter..." -ForegroundColor Yellow
Write-Host "  (If no loopback adapter, use Wi-Fi or the adapter carrying Docker traffic)" -ForegroundColor DarkGray
Write-Host ""

try {
    # Npcap installs a loopback adapter called "\Device\NPF_Loopback" or "Npcap Loopback Adapter"
    # Try common Windows interface names
    & $rustBinary --interface "\Device\NPF_Loopback" --inference-url http://localhost:5050
} catch {
    Log-Warn "Loopback failed. Trying with adapter list..."
    & $rustBinary --list-interfaces
} finally {
    # Cleanup all services when TUI exits
    Cleanup
}
