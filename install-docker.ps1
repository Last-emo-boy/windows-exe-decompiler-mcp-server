# Rikune - Docker Install Script
# Requires: PowerShell 7.5+, Docker Desktop, Administrator privileges
# Encoding: UTF-8 without BOM

#Requires -RunAsAdministrator

param(
    [Parameter(HelpMessage="Data root directory")]
    [string]$DataRoot,
    
    [Parameter(HelpMessage="Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot,
    
    [Parameter(HelpMessage="Skip Docker image build")]
    [switch]$SkipBuild,
    
    [Parameter(HelpMessage="Enable verbose output")]
    [switch]$EnableVerbose,
    
    [Parameter(HelpMessage="HTTP Proxy URL")]
    [string]$HttpProxy,
    
    [Parameter(HelpMessage="HTTPS Proxy URL")]
    [string]$HttpsProxy,
    
    [Parameter(HelpMessage="Use proxy")]
    [switch]$UseProxy
)

$ColorPrimary = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorInfo = "White"

function Write-Header {
    param([string]$Text)
    Write-Host "`n==================================================" -ForegroundColor $ColorPrimary
    Write-Host "  $Text" -ForegroundColor $ColorPrimary
    Write-Host "==================================================" -ForegroundColor $ColorPrimary
    Write-Host "`n" -NoNewline
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] " -ForegroundColor $ColorSuccess -NoNewline
    Write-Host $Text -ForegroundColor $ColorSuccess
}

function Write-Error-Message {
    param([string]$Text)
    Write-Host "[ERROR] " -ForegroundColor $ColorError -NoNewline
    Write-Host $Text -ForegroundColor $ColorError
}

function Write-Warning-Message {
    param([string]$Text)
    Write-Host "[WARN] " -ForegroundColor $ColorWarning -NoNewline
    Write-Host $Text -ForegroundColor $ColorWarning
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor $ColorInfo
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n[STEP] $Text" -ForegroundColor $ColorPrimary
    Write-Host "-----------------------------------------" -ForegroundColor $ColorPrimary
}

function Resolve-ComposeCommand {
    if ($script:ComposeCommand) {
        return $script:ComposeCommand
    }

    try {
        docker compose version | Out-Null
        $script:ComposeCommand = "docker compose"
        return $script:ComposeCommand
    } catch {
    }

    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        $script:ComposeCommand = "docker-compose"
        return $script:ComposeCommand
    }

    return $null
}

# Main Script
Clear-Host
Write-Header "Rikune - Docker Installer"

Write-Host "This script will:" -ForegroundColor $ColorInfo
Write-Host "  1. Check Docker installation" -ForegroundColor $ColorInfo
Write-Host "  2. Configure proxy (optional)" -ForegroundColor $ColorInfo
Write-Host "  3. Select data storage location" -ForegroundColor $ColorInfo
Write-Host "  4. Create directory structure" -ForegroundColor $ColorInfo
Write-Host "  5. Build Docker image (~10-15 min)" -ForegroundColor $ColorInfo
Write-Host "  6. Configure MCP clients" -ForegroundColor $ColorInfo
Write-Host "  7. Test installation" -ForegroundColor $ColorInfo

$continue = Read-Host "`nContinue? (Y/n)"
if ($continue -eq 'n' -or $continue -eq 'N') {
    Write-Warning-Message "Installation cancelled"
    exit 0
}

Write-Step "Checking Docker"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error-Message "Docker not found"
    Write-Host "Please install Docker Desktop: https://www.docker.com/products/docker-desktop/" -ForegroundColor $ColorError
    exit 1
}

try {
    $dockerVersion = docker --version
    Write-Success "Docker installed: $dockerVersion"
} catch {
    Write-Error-Message "Cannot run Docker"
    exit 1
}

try {
    docker info | Out-Null
    Write-Success "Docker is running"
} catch {
    Write-Error-Message "Docker is not running, please start Docker Desktop"
    exit 1
}

$composeCommand = Resolve-ComposeCommand
if ($composeCommand) {
    Write-Success "Docker Compose available: $composeCommand"
} else {
    Write-Warning-Message "Docker Compose not found. Compose mode will require manual setup."
}

# =============================================================================
# Proxy Configuration Step
# =============================================================================
Write-Step "Proxy Configuration (Optional)"

Write-Host "`nIf you are in mainland China or other network-restricted regions," -ForegroundColor $ColorInfo
Write-Host "it is recommended to use a proxy to accelerate downloads:" -ForegroundColor $ColorInfo
Write-Host "  - Docker Hub image pull" -ForegroundColor $ColorInfo
Write-Host "  - Ghidra download (about 600MB)" -ForegroundColor $ColorInfo
Write-Host "  - Python/Node.js dependencies" -ForegroundColor $ColorInfo
Write-Host "`nCommon proxy tools:" -ForegroundColor $ColorInfo
Write-Host "  - Clash: http://127.0.0.1:7890" -ForegroundColor $ColorInfo
Write-Host "  - V2Ray: http://127.0.0.1:10809" -ForegroundColor $ColorInfo
Write-Host "  - Shadowsocks: http://127.0.0.1:1080" -ForegroundColor $ColorInfo

# Check system proxy
$systemProxy = $null
try {
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = Get-ItemProperty -Path $registryPath -Name "ProxyEnable" -ErrorAction SilentlyContinue
    if ($proxyEnable.ProxyEnable -eq 1) {
        $proxyServer = Get-ItemProperty -Path $registryPath -Name "ProxyServer" -ErrorAction SilentlyContinue
        if ($proxyServer.ProxyServer) {
            $systemProxy = $proxyServer.ProxyServer
            Write-Info "Detected system proxy: $systemProxy"
        }
    }
} catch {
    # Ignore errors
}

# Ask if use proxy
if (-not $UseProxy) {
    Write-Host "`nDo you need to configure a proxy?" -ForegroundColor $ColorPrimary
    if ($systemProxy) {
        Write-Host "  [1] Use system proxy ($systemProxy) - Recommended" -ForegroundColor $ColorSuccess
    } else {
        Write-Host "  [1] Manual proxy configuration" -ForegroundColor $ColorInfo
    }
    Write-Host "  [2] No proxy (direct connection)" -ForegroundColor $ColorInfo
    Write-Host "  [3] Skip (configure later in Docker)" -ForegroundColor $ColorInfo

    $proxyChoice = Read-Host "`nSelect (default: 1)"
    if ([string]::IsNullOrWhiteSpace($proxyChoice)) {
        $proxyChoice = "1"
    }

    if ($proxyChoice -eq "1") {
        if ($systemProxy) {
            # Use system proxy
            $HttpProxy = "http://$systemProxy"
            $HttpsProxy = "http://$systemProxy"
            Write-Success "Using system proxy: $HttpProxy"
        } else {
            # Manual configuration
            Write-Host "`nEnter proxy address:" -ForegroundColor $ColorPrimary
            Write-Host "Format: http://host:port or http://username:password@host:port" -ForegroundColor $ColorInfo

            $manualProxy = Read-Host "Proxy address"
            if (-not [string]::IsNullOrWhiteSpace($manualProxy)) {
                $HttpProxy = $manualProxy
                $HttpsProxy = $manualProxy
                Write-Success "Proxy configured: $HttpProxy"
            } else {
                Write-Warning-Message "No proxy address entered, will use direct connection"
            }
        }
    } elseif ($proxyChoice -eq "2") {
        Write-Info "Will use direct connection (no proxy)"
        # Explicitly set to null
        $HttpProxy = $null
        $HttpsProxy = $null
        $proxyConfigured = $false
    } else {
        Write-Warning-Message "Skipped proxy configuration"
    }
}

# Validate proxy settings
$proxyConfigured = $false
if (-not [string]::IsNullOrWhiteSpace($HttpProxy) -or -not [string]::IsNullOrWhiteSpace($HttpsProxy)) {
    $proxyConfigured = $true
    Write-Host "`nProxy Configuration:" -ForegroundColor $ColorPrimary
    Write-Host "  HTTP_PROXY:  $HttpProxy" -ForegroundColor $ColorInfo
    Write-Host "  HTTPS_PROXY: $HttpsProxy" -ForegroundColor $ColorInfo

    # Check if Clash allows LAN connections
    Write-Host "`nChecking Clash configuration..." -ForegroundColor $ColorInfo
    try {
        $netstatOutput = netstat -an | Select-String ":7890" | Select-String "LISTENING"
        if ($netstatOutput) {
            $listeningAddress = ($netstatOutput | Select-Object -First 1).ToString().Split()[1]
            if ($listeningAddress -eq "0.0.0.0:7890" -or $listeningAddress -eq "*:7890" -or $listeningAddress -like "192.168.*:7890") {
                Write-Success "Clash allows LAN connections ($listeningAddress)"
            } elseif ($listeningAddress -eq "127.0.0.1:7890") {
                Write-Warning-Message "Clash only listens on localhost (127.0.0.1:7890)"
                Write-Host "`nNeed to modify Clash configuration:" -ForegroundColor $ColorPrimary
                Write-Host "  1. Open Clash config file (config.yaml)" -ForegroundColor $ColorInfo
                Write-Host "  2. Set: allow-lan: true" -ForegroundColor $ColorSuccess
                Write-Host "  3. Restart Clash" -ForegroundColor $ColorInfo
                Write-Host "`nOr enable 'Allow LAN' option in Clash for Windows" -ForegroundColor $ColorInfo

                $continue = Read-Host "`nContinue installation? (y/N)"
                if ($continue -ne 'y' -and $continue -ne 'Y') {
                    exit 0
                }
            }
        } else {
            Write-Warning-Message "Clash not detected on port 7890"
        }
    } catch {
        Write-Warning-Message "Cannot check Clash configuration: $($_.Exception.Message)"
    }

    # Convert proxy address: 127.0.0.1 -> host.docker.internal
    $buildHttpProxy = $HttpProxy -replace 'http://127\.0\.0\.1:', 'http://host.docker.internal:'
    $buildHttpsProxy = $HttpsProxy -replace 'http://127\.0\.0\.1:', 'http://host.docker.internal:'

    Write-Host "`nProxy Address Conversion:" -ForegroundColor $ColorPrimary
    Write-Host "  Original: $HttpProxy" -ForegroundColor $ColorInfo
    Write-Host "  Build: $buildHttpProxy (for Docker container)" -ForegroundColor $ColorInfo
}

# Set environment variables (global, for subsequent use)
if ($proxyConfigured) {
    $env:HTTP_PROXY = $HttpProxy
    $env:HTTPS_PROXY = $HttpsProxy
    $env:http_proxy = $HttpProxy
    $env:https_proxy = $HttpsProxy
    Write-Info "Environment variables HTTP_PROXY and HTTPS_PROXY set"
}

Write-Step "Selecting Data Location"

# Always ask for data location
Write-Host "`nMCP Server needs to store the following data:" -ForegroundColor $ColorInfo
Write-Host "  - Sample files" -ForegroundColor $ColorInfo
Write-Host "  - Workspaces (analysis results)" -ForegroundColor $ColorInfo
Write-Host "  - SQLite database" -ForegroundColor $ColorInfo
Write-Host "  - Cache files" -ForegroundColor $ColorInfo
Write-Host "  - Ghidra projects (can be large)" -ForegroundColor $ColorInfo
Write-Host "  - Ghidra logs" -ForegroundColor $ColorInfo
Write-Host "`nRecommended: Store on a drive with sufficient space" -ForegroundColor $ColorInfo

# Get available drives
$disks = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 10GB } | Sort-Object -Property Name

$options = @()
$optionIndex = 1

# Default option (user profile)
$defaultPath = "$env:USERPROFILE\.rikune"
$options += @{
    Index = 0
    Path = $defaultPath
    Description = "User profile (default)"
    Free = "N/A"
}

# Add other drives
foreach ($disk in $disks) {
    if ($disk.Name -ne 'C') {
        $path = "$($disk.Name):\Docker\rikune"
        $freeGB = [math]::Round($disk.Free / 1GB, 1)
        $options += @{
            Index = $optionIndex
            Path = $path
            Description = "$($disk.Name): drive - ${freeGB}GB free"
            Free = $freeGB
        }
        $optionIndex++
    }
}

# Display options
Write-Host "`nAvailable options:" -ForegroundColor $ColorPrimary
foreach ($opt in $options) {
    if ($opt.Index -eq 0) {
        Write-Host "  [$($opt.Index)] $($opt.Description)" -ForegroundColor $ColorInfo
    } else {
        Write-Host "  [$($opt.Index)] $($opt.Description)" -ForegroundColor $ColorSuccess
    }
}

# User selection
$selection = Read-Host "`nEnter option number (default: 0)"
if ([string]::IsNullOrWhiteSpace($selection)) {
    $selection = 0
}

$selectedOption = $options | Where-Object { $_.Index -eq [int]$selection }
if (-not $selectedOption) {
    Write-Error-Message "Invalid selection"
    exit 1
}

$DataRoot = $selectedOption.Path
Write-Success "Selected: $DataRoot"

# Custom path option
$customPath = Read-Host "`nUse custom path? (leave empty to use selected)"
if (-not [string]::IsNullOrWhiteSpace($customPath)) {
    if (-not [System.IO.Path]::IsPathRooted($customPath)) {
        $customPath = Join-Path $ProjectRoot $customPath
    }
    $DataRoot = $customPath
    Write-Success "Using custom path: $DataRoot"
}

Write-Step "Creating Directories"

$directories = @("samples", "workspaces", "data", "cache", "ghidra-projects", "ghidra-logs", "logs", "config", "storage", "qiling-rootfs")
foreach ($dir in $directories) {
    $fullPath = Join-Path $DataRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Success "Created: $fullPath"
    }
}

$dockerRuntimeEnvFile = Join-Path $ProjectRoot ".docker-runtime.env"
"RIKUNE_DATA_ROOT=$($DataRoot -replace '\\', '/')" | Set-Content $dockerRuntimeEnvFile -Encoding UTF8
Write-Success "Compose env file: $dockerRuntimeEnvFile"

Write-Step "Building Docker Image"

Push-Location $ProjectRoot
try {
    if ($SkipBuild) {
        Write-Warning-Message "Skipping Docker image build (--SkipBuild)"
    } else {
        $buildArgs = @("build", "-t", "rikune:latest", "--progress", "plain", ".")

        if ($EnableVerbose) {
            $buildArgs += "--no-cache"
        }

        # Add proxy build arguments if configured
        if ($proxyConfigured) {
            Write-Info "Original proxy: $HttpProxy"
            Write-Info "Build proxy: $buildHttpProxy (for Docker internal)"
            
            $buildArgs += @(
                "--build-arg", "HTTP_PROXY=$buildHttpProxy"
                "--build-arg", "HTTPS_PROXY=$buildHttpsProxy"
                "--build-arg", "http_proxy=$buildHttpProxy"
                "--build-arg", "https_proxy=$buildHttpsProxy"
            )
            
            Write-Info "Added proxy build arguments"
        }

        Write-Info "Running: docker $($buildArgs -join ' ')"
        & docker @buildArgs

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker image built successfully"
            docker images rikune:latest
        } else {
            Write-Error-Message "Docker build failed"
            exit 1
        }
    }
} catch {
    Write-Error-Message "Build error: $($_.Exception.Message)"
    exit 1
} finally {
    Pop-Location
}

Write-Step "Configuring MCP Clients"

Write-Host "`nSelect MCP client to configure:" -ForegroundColor $ColorPrimary
Write-Host "  [1] Claude Desktop" -ForegroundColor $ColorInfo
Write-Host "  [2] GitHub Copilot" -ForegroundColor $ColorInfo
Write-Host "  [3] Codex" -ForegroundColor $ColorInfo
Write-Host "  [4] Qwen" -ForegroundColor $ColorInfo
Write-Host "  [5] Generic config" -ForegroundColor $ColorInfo
Write-Host "  [6] Skip" -ForegroundColor $ColorInfo

$mcpClient = Read-Host "`nSelect (1-6)"

$samplesPath = Join-Path $DataRoot "samples"
$workspacesPath = Join-Path $DataRoot "workspaces"
$dataPath = Join-Path $DataRoot "data"
$cachePath = Join-Path $DataRoot "cache"
$ghidraProjectsPath = Join-Path $DataRoot "ghidra-projects"
$ghidraLogsPath = Join-Path $DataRoot "ghidra-logs"
$logsPath = Join-Path $DataRoot "logs"
$storagePath = Join-Path $DataRoot "storage"
$qilingRootfsPath = Join-Path $DataRoot "qiling-rootfs"

$dockerExecArgs = @(
    "exec", "-i",
    "rikune",
    "node",
    "dist/index.js"
)

$config = @{
    mcpServers = @{
        "rikune" = @{
            command = "docker"
            args = $dockerExecArgs
            env = @{
                NODE_ENV = "production"
                PYTHONUNBUFFERED = "1"
                WORKSPACE_ROOT = "/app/workspaces"
                DB_PATH = "/app/data/database.db"
                CACHE_ROOT = "/app/cache"
                GHIDRA_PROJECT_ROOT = "/ghidra-projects"
                GHIDRA_LOG_ROOT = "/ghidra-logs"
            }
        }
    }
}

switch ($mcpClient) {
    "1" {
        $configDir = "$env:APPDATA\Claude"
        $configFile = Join-Path $configDir "claude_desktop_config.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Claude Desktop config: $configFile"
    }
    "2" {
        $configDir = "$env:APPDATA\GitHub Copilot"
        $configFile = Join-Path $configDir "mcp.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "GitHub Copilot config: $configFile"
    }
    "3" {
        $configDir = "$env:USERPROFILE\.codex"
        $configFile = Join-Path $configDir "mcp.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Codex config: $configFile"
    }
    "4" {
        $configDir = "$env:APPDATA\Qwen"
        $configFile = Join-Path $configDir "mcp.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Qwen config: $configFile"
    }
    "5" {
        $configFile = Join-Path $DataRoot "config\mcp-client-config.json"
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Generic config: $configFile"
    }
    default {
        Write-Warning-Message "Skipped MCP client configuration"
    }
}

Write-Step "Testing Installation"

Write-Host "`nTesting Docker image..." -ForegroundColor $ColorPrimary

$tests = @(
    @{ Name = "Node.js"; Cmd = @("run", "--rm", "--entrypoint", "node", "rikune:latest", "--version") },
    @{ Name = "Python"; Cmd = @("run", "--rm", "--entrypoint", "python3", "rikune:latest", "--version") },
    @{ Name = "Java"; Cmd = @("run", "--rm", "--entrypoint", "java", "rikune:latest", "-version") },
    @{ Name = "Full Stack"; Cmd = @("run", "--rm", "--entrypoint", "/usr/local/bin/validate-docker-full-stack.sh", "rikune:latest") }
)

$passed = 0
foreach ($test in $tests) {
    Write-Host "  Testing $($test.Name)... " -NoNewline
    try {
        $result = docker @($test.Cmd) 2>&1
        if ($LASTEXITCODE -eq 0) {
            $version = ($result | Select-Object -First 1).ToString().Trim()
            Write-Host "OK ($version)" -ForegroundColor $ColorSuccess
            $passed++
        } else {
            Write-Host "FAILED" -ForegroundColor $ColorError
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor $ColorError
    }
}

Write-Host "`nResults: $passed/$($tests.Count) passed" -ForegroundColor $(if ($passed -eq $tests.Count) { $ColorSuccess } else { $ColorWarning })

Write-Header "Installation Complete"

Write-Host "Data Root: $DataRoot" -ForegroundColor $ColorSuccess
Write-Host "Image: rikune:latest" -ForegroundColor $ColorSuccess

Write-Host "`n========================================" -ForegroundColor $ColorPrimary
Write-Host "  API File Server - AUTO-ENABLED" -ForegroundColor $ColorSuccess
Write-Host "========================================" -ForegroundColor $ColorPrimary
Write-Host ""
Write-Host "The HTTP API server is enabled by default on port 18080." -ForegroundColor $ColorInfo
Write-Host "An API key will be auto-generated on first startup." -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "To get your API key after starting the container:" -ForegroundColor $ColorPrimary
Write-Host "  docker logs rikune | grep 'API Key'" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "To upload a sample:" -ForegroundColor $ColorPrimary
Write-Host "  curl -X POST http://localhost:18080/api/v1/samples \" -ForegroundColor $ColorInfo
Write-Host "    -H 'X-API-Key: YOUR_KEY' \" -ForegroundColor $ColorInfo
Write-Host "    -F 'file=@sample.exe'" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "To use a fixed API key (optional):" -ForegroundColor $ColorPrimary
Write-Host "  Set API_KEY environment variable in docker-compose.yml" -ForegroundColor $ColorInfo
Write-Host ""

Write-Host "`nBasic Usage:" -ForegroundColor $ColorPrimary
Write-Host "  docker run --rm -i -v ${samplesPath}:/samples:ro rikune:latest"
Write-Host ""
Write-Host "Or use Docker Compose (recommended):" -ForegroundColor $ColorPrimary
Write-Host "  $(if ($composeCommand) { $composeCommand } else { 'docker compose' }) --env-file .docker-runtime.env up -d mcp-server"
Write-Host ""

$installInfo = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    DataRoot = $DataRoot
    DockerImage = "rikune:latest"
    TestsPassed = $passed
    APIEnabled = $true
    APIPort = 18080
    StorageRoot = $storagePath
    QilingRootfs = $qilingRootfsPath
    ComposeCommand = $composeCommand
    ComposeEnvFile = $dockerRuntimeEnvFile
}
$installInfo | ConvertTo-Json | Set-Content (Join-Path $DataRoot "install-info.json") -Encoding UTF8
Write-Info "Install info saved"
