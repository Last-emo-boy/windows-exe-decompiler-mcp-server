# Windows EXE Decompiler MCP Server - Docker Start Script

param(
    [Parameter(HelpMessage="Data root directory")]
    [string]$DataRoot,

    [Parameter(HelpMessage="Run mode")]
    [ValidateSet("stdio", "compose", "interactive")]
    [string]$Mode = "stdio"
)

function Resolve-ComposeCommand {
    try {
        docker compose version | Out-Null
        return "docker compose"
    } catch {
    }

    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        return "docker-compose"
    }

    return $null
}

function Invoke-ComposeCommand {
    param([string[]]$Arguments)

    $composeCommand = Resolve-ComposeCommand
    if (-not $composeCommand) {
        throw "Docker Compose not found. Install Docker Compose v2+ or docker-compose."
    }

    if ($composeCommand -eq "docker compose") {
        & docker compose @Arguments
    } else {
        & docker-compose @Arguments
    }
}

if (-not $DataRoot) {
    $defaultDataRoot = "$env:USERPROFILE\.windows-exe-decompiler-mcp-server"
    $installInfoFile = Join-Path $defaultDataRoot "install-info.json"

    if (Test-Path $installInfoFile) {
        $installInfo = Get-Content $installInfoFile -Raw | ConvertFrom-Json
        $DataRoot = $installInfo.DataRoot
        Write-Host "Using DataRoot from install-info.json: $DataRoot" -ForegroundColor Cyan
    } else {
        Write-Host "install-info.json not found, using default DataRoot: $defaultDataRoot" -ForegroundColor Yellow
        $DataRoot = $defaultDataRoot
    }
}

$requiredDirs = @(
    "samples",
    "workspaces",
    "data",
    "cache",
    "ghidra-projects",
    "ghidra-logs",
    "logs",
    "storage",
    "qiling-rootfs"
)

foreach ($dir in $requiredDirs) {
    $fullPath = Join-Path $DataRoot $dir
    if (-not (Test-Path $fullPath)) {
        Write-Host "Creating directory: $fullPath" -ForegroundColor Cyan
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }
}

$samplesPath = Join-Path $DataRoot "samples"
$workspacesPath = Join-Path $DataRoot "workspaces"
$dataPath = Join-Path $DataRoot "data"
$cachePath = Join-Path $DataRoot "cache"
$ghidraProjectsPath = Join-Path $DataRoot "ghidra-projects"
$ghidraLogsPath = Join-Path $DataRoot "ghidra-logs"
$logsPath = Join-Path $DataRoot "logs"
$storagePath = Join-Path $DataRoot "storage"
$qilingRootfsPath = Join-Path $DataRoot "qiling-rootfs"

switch ($Mode) {
    "stdio" {
        Write-Host "`nStarting MCP Server (stdio mode)..." -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
        Write-Host "Note: stdio mode keeps --network=none, so HTTP upload/session APIs are not exposed externally." -ForegroundColor Yellow

        docker run --rm -i `
            --network=none `
            --read-only `
            --tmpfs /tmp:rw,noexec,nosuid,size=512m `
            --security-opt no-new-privileges:true `
            --cap-drop=ALL `
            --memory=8g `
            --cpus=2 `
            -v "${samplesPath}:/samples:ro" `
            -v "${workspacesPath}:/app/workspaces" `
            -v "${dataPath}:/app/data" `
            -v "${cachePath}:/app/cache" `
            -v "${ghidraProjectsPath}:/ghidra-projects" `
            -v "${ghidraLogsPath}:/ghidra-logs" `
            -v "${logsPath}:/app/logs" `
            -v "${storagePath}:/app/storage" `
            -v "${qilingRootfsPath}:/opt/qiling-rootfs:ro" `
            -e "WORKSPACE_ROOT=/app/workspaces" `
            -e "DB_PATH=/app/data/database.db" `
            -e "CACHE_ROOT=/app/cache" `
            -e "GHIDRA_PROJECT_ROOT=/ghidra-projects" `
            -e "GHIDRA_LOG_ROOT=/ghidra-logs" `
            -e "AUDIT_LOG_PATH=/app/logs/audit.log" `
            -e "XDG_CONFIG_HOME=/app/logs/.config" `
            -e "XDG_CACHE_HOME=/app/cache/xdg" `
            -e "API_STORAGE_ROOT=/app/storage" `
            windows-exe-decompiler:latest
    }

    "compose" {
        Write-Host "`nStarting Docker Compose..." -ForegroundColor Cyan

        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        Push-Location $scriptPath

        try {
            if (-not (Test-Path "docker-compose.yml")) {
                throw "docker-compose.yml not found"
            }

            $composeEnvFile = Join-Path $scriptPath ".docker-runtime.env"
            "WINDOWS_EXE_DECOMPILER_DATA_ROOT=$($DataRoot -replace '\\', '/')" | Set-Content $composeEnvFile -Encoding UTF8
            Invoke-ComposeCommand @("--env-file", $composeEnvFile, "up", "-d", "mcp-server")

            $composeCommand = Resolve-ComposeCommand
            Write-Host "`nDocker Compose started successfully." -ForegroundColor Green
            Write-Host "  Env file:  $composeEnvFile"
            Write-Host "  Logs:      $composeCommand --env-file $composeEnvFile logs -f mcp-server"
            Write-Host "  Stop:      $composeCommand --env-file $composeEnvFile down"
            Write-Host "  Shell:     $composeCommand --env-file $composeEnvFile exec mcp-server bash"
            Write-Host "  MCP exec:  docker exec -i windows-exe-decompiler-mcp node dist/index.js"
            Write-Host "  Note:      single-container mode keeps one compose container but will launch a client-scoped MCP Node process via docker exec." -ForegroundColor Yellow
            Write-Host "             Keep the compose container memory at 8GB and avoid overlapping heavy client sessions." -ForegroundColor Yellow
        } finally {
            Pop-Location
        }
    }

    "interactive" {
        Write-Host "`nStarting interactive shell..." -ForegroundColor Cyan
        Write-Host "Type 'exit' to leave the container." -ForegroundColor Gray

        docker run --rm -it `
            --network=none `
            -v "${samplesPath}:/samples:ro" `
            -v "${workspacesPath}:/app/workspaces" `
            -v "${dataPath}:/app/data" `
            -v "${cachePath}:/app/cache" `
            -v "${ghidraProjectsPath}:/ghidra-projects" `
            -v "${ghidraLogsPath}:/ghidra-logs" `
            -v "${logsPath}:/app/logs" `
            -v "${storagePath}:/app/storage" `
            -v "${qilingRootfsPath}:/opt/qiling-rootfs:ro" `
            windows-exe-decompiler:latest `
            bash
    }
}
