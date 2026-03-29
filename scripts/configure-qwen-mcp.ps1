# Configure Qwen MCP Client
# Usage: .\scripts\configure-qwen-mcp.ps1
# Config location: ~/.qwen/settings.json (user-level) or ./.qwen/settings.json (project-level)

$ErrorActionPreference = "Stop"

# Configuration
$QwenUserConfigDir = "$env:USERPROFILE\.qwen"
$QwenUserConfigFile = Join-Path $QwenUserConfigDir "settings.json"
$QwenProjectConfigDir = ".qwen"
$QwenProjectConfigFile = Join-Path $QwenProjectConfigDir "settings.json"
$ContainerName = "windows-exe-decompiler-mcp"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Qwen MCP Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if container is running
$container = docker ps --filter "name=$ContainerName" --format "{{.Names}}"
if (-not $container) {
    Write-Host "⚠ Container '$ContainerName' is not running. Starting..." -ForegroundColor Yellow
    docker compose up -d mcp-server
    Start-Sleep -Seconds 5
}

# Create MCP config
$config = @{
    mcpServers = @{
        "windows-exe-decompiler" = @{
            command = "docker"
            args = @(
                "exec",
                "-i",
                $ContainerName,
                "node",
                "dist/index.js"
            )
            env = @{
                NODE_ENV = "production"
                WORKSPACE_ROOT = "/app/workspaces"
                DB_PATH = "/app/data/database.db"
                CACHE_ROOT = "/app/cache"
                GHIDRA_PROJECT_ROOT = "/ghidra-projects"
                GHIDRA_LOG_ROOT = "/ghidra-logs"
            }
            timeout = 300000
        }
    }
}

$configJson = $config | ConvertTo-Json -Depth 10

# Ask user which config to create
Write-Host "Select configuration type:" -ForegroundColor Cyan
Write-Host "  [1] User-level (global) - ~/.qwen/settings.json" -ForegroundColor White
Write-Host "  [2] Project-level - ./.qwen/settings.json" -ForegroundColor White
Write-Host "  [3] Both" -ForegroundColor White

$choice = Read-Host "`nEnter choice (default: 1)"
if ([string]::IsNullOrWhiteSpace($choice)) {
    $choice = "1"
}

# Create user-level config
if ($choice -eq "1" -or $choice -eq "3") {
    if (-not (Test-Path $QwenUserConfigDir)) {
        New-Item -ItemType Directory -Path $QwenUserConfigDir -Force | Out-Null
        Write-Host "✓ Created directory: $QwenUserConfigDir" -ForegroundColor Green
    }
    $configJson | Out-File -FilePath $QwenUserConfigFile -Encoding UTF8
    Write-Host "✓ Created user-level config: $QwenUserConfigFile" -ForegroundColor Green
}

# Create project-level config
if ($choice -eq "2" -or $choice -eq "3") {
    if (-not (Test-Path $QwenProjectConfigDir)) {
        New-Item -ItemType Directory -Path $QwenProjectConfigDir -Force | Out-Null
        Write-Host "✓ Created directory: $QwenProjectConfigDir" -ForegroundColor Green
    }
    $configJson | Out-File -FilePath $QwenProjectConfigFile -Encoding UTF8
    Write-Host "✓ Created project-level config: $QwenProjectConfigFile" -ForegroundColor Green
}

Write-Host "`n✓ Qwen MCP configuration complete!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Restart Qwen Code CLI" -ForegroundColor White
Write-Host "  2. Run: qwen --mcp" -ForegroundColor White
Write-Host "  3. Keep 'docker compose up -d mcp-server' running for the single-container MCP setup" -ForegroundColor White
Write-Host "  4. You should see 'windows-exe-decompiler' tools available" -ForegroundColor White
