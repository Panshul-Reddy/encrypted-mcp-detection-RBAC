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

# Kill any leftover processes from previous runs
$portsToClean = @(5050, 9999)
foreach ($p in $portsToClean) {
    Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue |
        Select-Object OwningProcess -Unique |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
}
Get-NetUDPEndpoint -LocalPort 9999 -ErrorAction SilentlyContinue |
    Select-Object OwningProcess -Unique |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

# Kill any dangling Rust analyzers from previous background runs
try {
    taskkill /F /IM live-analyzer.exe 2>$null
} catch {}

Start-Sleep -Seconds 1

# Check Docker — temporarily relax error handling since docker info writes to stderr
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $dockerOut = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Log-Success "Docker is running"
    } else {
        throw "docker info exited with code $LASTEXITCODE"
    }
} catch {
    Log-Error "Docker is not running! Start Docker Desktop first."
    $ErrorActionPreference = $savedEAP
    exit 1
}
$ErrorActionPreference = $savedEAP

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
$proxyArgs = "tls_proxy.py --cert `"$(Join-Path $ProjectRoot 'nginx\ssl\mcp.crt')`" --key `"$(Join-Path $ProjectRoot 'nginx\ssl\mcp.key')`" --mappings 8440:3000,8441:3001,8442:3002,8443:3003,8444:3004,8445:3005,8446:9444 --backend-host 127.0.0.1"
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
Log-Info "Starting Groq MCP Traffic Generator (role: full)..."
$env:VM1_IP = "127.0.0.1"
$env:MCP_API_KEY = "full-access-key-001"
$groqVenv = Join-Path $ProjectRoot "groq-client\.venv\Scripts"
$groqLog = Join-Path $logDir "groq.log"
$proc = Start-Process -FilePath (Join-Path $groqVenv "python.exe") `
    -ArgumentList "groq_mcp_client.py", "--proxy-port", "8440" `
    -WorkingDirectory (Join-Path $ProjectRoot "groq-client") `
    -RedirectStandardOutput $groqLog `
    -RedirectStandardError (Join-Path $logDir "groq_err.log") `
    -PassThru -WindowStyle Hidden
$script:bgJobs += $proc.Id
Log-Success "Groq Traffic Generator running (PID: $($proc.Id)) [FULL access]"

# --- 3d. Noise Attacker ---
Log-Info "Starting Noise Attacker..."
$env:NOISE_SERVER = "https://127.0.0.1:9443"
$noiseVenv = Join-Path $ProjectRoot "noise-client\.venv\Scripts"
$noiseLog = Join-Path $logDir "noise.log"
$proc = Start-Process -FilePath (Join-Path $noiseVenv "python.exe") `
    -ArgumentList "client.py", "--proxy-port", "8446" `
    -WorkingDirectory (Join-Path $ProjectRoot "noise-client") `
    -RedirectStandardOutput $noiseLog `
    -RedirectStandardError (Join-Path $logDir "noise_err.log") `
    -PassThru -WindowStyle Hidden
$script:bgJobs += $proc.Id
Log-Success "Noise Attacker running (PID: $($proc.Id))"

# --- 3e. Restricted Readonly Client (RBAC Demo) ---
Log-Info "Starting Restricted Readonly Client (role: readonly)..."
$env:MCP_API_KEY = "readonly-key-001"
$env:ROLE_LABEL = "readonly"
$env:LOOP_COUNT = "5"
$restrictedLog = Join-Path $logDir "restricted_client.log"
$proc = Start-Process -FilePath (Join-Path $groqVenv "python.exe") `
    -ArgumentList "restricted_mcp_client.py", "--proxy-port", "8441" `
    -WorkingDirectory (Join-Path $ProjectRoot "groq-client") `
    -RedirectStandardOutput $restrictedLog `
    -RedirectStandardError (Join-Path $logDir "restricted_err.log") `
    -PassThru -WindowStyle Hidden
$script:bgJobs += $proc.Id
Log-Success "Restricted Client running (PID: $($proc.Id)) [READONLY - writes will be DENIED]"

# ==============================================================================
# Phase 4: Live Encrypted RBAC Monitor
# ==============================================================================
Log-Step "4. Launching Live Encrypted RBAC Monitor"

# Check if Npcap (wpcap.dll) is installed
$npcapDefault = "$env:SystemRoot\System32\wpcap.dll"
$npcapSubdir = "$env:SystemRoot\System32\Npcap\wpcap.dll"
$hasNpcap = $false

if (Test-Path $npcapDefault) {
    $hasNpcap = $true
} elseif (Test-Path $npcapSubdir) {
    $hasNpcap = $true
    # Add Npcap folder to PATH so the Rust binary can find the DLL
    $env:PATH = "$env:SystemRoot\System32\Npcap;$env:PATH"
    Log-Info "Npcap found in subdirectory. Added to PATH."
}

if ($hasNpcap) {
    Log-Info "Npcap detected. Launching native Rust packet capture in FOREGROUND..."
    Write-Host "Services are running. Close the Rust TUI (press 'q') to stop all services.`n" -ForegroundColor Yellow
    
    # Run the Rust TUI natively in the foreground terminal
    try {
        & $rustBinary --interface "\Device\NPF_Loopback" --inference-url "http://localhost:5050"
    } catch {
        Log-Warn "Rust packet capture failed (possibly not running as Admin). Falling back to Simulator..."
        $hasNpcap = $false
    }
}

if (-not $hasNpcap) {
    Log-Warn "Npcap (wpcap.dll) missing or capture failed. Launching Rust Traffic Simulator..."
    $simProc = Start-Process -FilePath "python.exe" `
        -ArgumentList "rust_simulator.py" `
        -WorkingDirectory $ProjectRoot `
        -PassThru -WindowStyle Hidden
    $script:bgJobs += $simProc.Id
    
    Write-Host "Simulator is running. Press Ctrl+C to stop all services.`n" -ForegroundColor Yellow
    try {
        Wait-Event   # keep the main ps1 alive
    } catch {}
}

# Cleanup all services
Cleanup
