param(
    [string]$ServerName = "rikune",
    [string]$ProjectRoot = (Get-Location).Path,
    [string]$NodePath,
    [string]$GhidraPath = "",
    [string]$WorkspaceRoot = "$env:USERPROFILE\\.rikune\\workspaces",
    [string]$DatabasePath = "$env:USERPROFILE\\.rikune\\data\\database.db",
    [string]$CacheRoot = "$env:USERPROFILE\\.rikune\\cache",
    [string]$AuditLogPath = "$env:USERPROFILE\\.rikune\\audit.log",
    [string]$ConfigPath = "$env:USERPROFILE\.codex\config.toml",
    [switch]$NoBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
}

function Convert-ToConfigPath {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    return ([System.IO.Path]::GetFullPath($PathValue) -replace "\\", "/")
}

function Get-NodeExecutable {
    if ($NodePath) {
        if (-not (Test-Path -Path $NodePath)) {
            throw "NodePath does not exist: $NodePath"
        }

        return [System.IO.Path]::GetFullPath($NodePath)
    }

    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if ($null -eq $nodeCommand) {
        throw "Node.js was not found in PATH. Install Node.js or pass -NodePath."
    }

    return $nodeCommand.Source
}

function Resolve-GhidraPath {
    if ($GhidraPath) {
        return $GhidraPath
    }

    if ($env:GHIDRA_PATH) {
        return $env:GHIDRA_PATH
    }

    if ($env:GHIDRA_INSTALL_DIR) {
        return $env:GHIDRA_INSTALL_DIR
    }

    return ""
}

function Resolve-WorkspaceRoot {
    if ($WorkspaceRoot) {
        return $WorkspaceRoot
    }

    if ($env:WORKSPACE_ROOT) {
        return $env:WORKSPACE_ROOT
    }

    return "$env:USERPROFILE\\.rikune\\workspaces"
}

function Resolve-DatabasePath {
    if ($DatabasePath) {
        return $DatabasePath
    }

    if ($env:DB_PATH) {
        return $env:DB_PATH
    }

    return "$env:USERPROFILE\\.rikune\\data\\database.db"
}

function Resolve-CacheRoot {
    if ($CacheRoot) {
        return $CacheRoot
    }

    if ($env:CACHE_ROOT) {
        return $env:CACHE_ROOT
    }

    return "$env:USERPROFILE\\.rikune\\cache"
}

function Resolve-AuditLogPath {
    if ($AuditLogPath) {
        return $AuditLogPath
    }

    if ($env:AUDIT_LOG_PATH) {
        return $env:AUDIT_LOG_PATH
    }

    return "$env:USERPROFILE\\.rikune\\audit.log"
}

function Backup-FileIfNeeded {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    if ($NoBackup -or -not (Test-Path -Path $PathValue)) {
        return $null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = "$PathValue.$timestamp.bak"
    Copy-Item -Path $PathValue -Destination $backupPath -Force
    return $backupPath
}

function Ensure-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $parent = Split-Path -Path $PathValue -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Build-ServerBlock {
    param(
        [Parameter(Mandatory = $true)][string]$NodeExecutableConfig,
        [Parameter(Mandatory = $true)][string]$EntryPathConfig,
        [Parameter(Mandatory = $true)][string]$ProjectRootConfig,
        [Parameter(Mandatory = $true)][string]$WorkspaceRootConfig,
        [Parameter(Mandatory = $true)][string]$DatabasePathConfig,
        [Parameter(Mandatory = $true)][string]$CacheRootConfig,
        [Parameter(Mandatory = $true)][string]$AuditLogPathConfig,
        [string]$GhidraPathConfig
    )

    $lines = @(
        "[mcp_servers.$ServerName]"
        "command = `"$NodeExecutableConfig`""
        "args = [`"$EntryPathConfig`"]"
        "cwd = `"$ProjectRootConfig`""
        "startup_timeout_sec = 30"
        "tool_timeout_sec = 300"
        "enabled = true"
    )

    $envEntries = @(
        "WORKSPACE_ROOT = `"$WorkspaceRootConfig`"",
        "DB_PATH = `"$DatabasePathConfig`"",
        "CACHE_ROOT = `"$CacheRootConfig`"",
        "AUDIT_LOG_PATH = `"$AuditLogPathConfig`""
    )

    if ($GhidraPathConfig) {
        $envEntries += "GHIDRA_PATH = `"$GhidraPathConfig`""
        $envEntries += "GHIDRA_INSTALL_DIR = `"$GhidraPathConfig`""
    }

    $lines += "env = { $($envEntries -join ', ') }"

    return ($lines -join [Environment]::NewLine)
}

function Upsert-ConfigBlock {
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$BlockText
    )

    Ensure-ParentDirectory -PathValue $PathValue

    $existing = ""
    if (Test-Path -Path $PathValue) {
        $existing = Get-Content -Path $PathValue -Raw
    }

    $pattern = "(?ms)^\[mcp_servers\.$([regex]::Escape($ServerName))\]\r?\n.*?(?=^\[|\z)"
    if ($existing -match $pattern) {
        $updated = [regex]::Replace($existing, $pattern, $BlockText + [Environment]::NewLine)
    } else {
        $separator = if ([string]::IsNullOrWhiteSpace($existing)) { "" } else { [Environment]::NewLine + [Environment]::NewLine }
        $updated = $existing.TrimEnd() + $separator + $BlockText + [Environment]::NewLine
    }

    [System.IO.File]::WriteAllText($PathValue, $updated, [System.Text.UTF8Encoding]::new($false))
}

Write-Host "=== Rikune - Codex Install ===" -ForegroundColor Cyan

Write-Step "Step 1: Validate build output"
$projectRootFull = [System.IO.Path]::GetFullPath($ProjectRoot)
$entryPath = Join-Path -Path $projectRootFull -ChildPath "dist/index.js"
if (-not (Test-Path -Path $entryPath)) {
    throw "dist/index.js was not found. Run 'npm run build' from the project root first."
}

$nodeExecutable = Get-NodeExecutable
$ghidraPathResolved = Resolve-GhidraPath
$workspaceRootResolved = Resolve-WorkspaceRoot
$databasePathResolved = Resolve-DatabasePath
$cacheRootResolved = Resolve-CacheRoot
$auditLogPathResolved = Resolve-AuditLogPath

$nodeExecutableConfig = Convert-ToConfigPath -PathValue $nodeExecutable
$entryPathConfig = Convert-ToConfigPath -PathValue $entryPath
$projectRootConfig = Convert-ToConfigPath -PathValue $projectRootFull
$ghidraPathConfig = if ($ghidraPathResolved) { Convert-ToConfigPath -PathValue $ghidraPathResolved } else { "" }
$workspaceRootConfig = Convert-ToConfigPath -PathValue $workspaceRootResolved
$databasePathConfig = Convert-ToConfigPath -PathValue $databasePathResolved
$cacheRootConfig = Convert-ToConfigPath -PathValue $cacheRootResolved
$auditLogPathConfig = Convert-ToConfigPath -PathValue $auditLogPathResolved

Write-Host "Project root: $projectRootConfig" -ForegroundColor Gray
Write-Host "Node path: $nodeExecutableConfig" -ForegroundColor Gray
Write-Host "Server entry: $entryPathConfig" -ForegroundColor Gray
Write-Host "Workspace root: $workspaceRootConfig" -ForegroundColor Gray
Write-Host "Database path: $databasePathConfig" -ForegroundColor Gray
Write-Host "Cache root: $cacheRootConfig" -ForegroundColor Gray
Write-Host "Audit log path: $auditLogPathConfig" -ForegroundColor Gray
if ($ghidraPathConfig) {
    Write-Host "Ghidra path: $ghidraPathConfig" -ForegroundColor Gray
} else {
    Write-Host "No Ghidra path supplied. The config will be written without GHIDRA_PATH." -ForegroundColor Yellow
}

Write-Step "Step 2: Register MCP server with Codex"
& codex mcp add $ServerName -- $nodeExecutableConfig $entryPathConfig
if ($LASTEXITCODE -ne 0) {
    throw "codex mcp add failed."
}
Write-Host "Codex registration completed." -ForegroundColor Green

Write-Step "Step 3: Update Codex config"
$backupPath = Backup-FileIfNeeded -PathValue $ConfigPath
$serverBlock = Build-ServerBlock -NodeExecutableConfig $nodeExecutableConfig -EntryPathConfig $entryPathConfig -ProjectRootConfig $projectRootConfig -WorkspaceRootConfig $workspaceRootConfig -DatabasePathConfig $databasePathConfig -CacheRootConfig $cacheRootConfig -AuditLogPathConfig $auditLogPathConfig -GhidraPathConfig $ghidraPathConfig
Upsert-ConfigBlock -PathValue $ConfigPath -BlockText $serverBlock
Write-Host "Config written: $ConfigPath" -ForegroundColor Green
if ($backupPath) {
    Write-Host "Backup file: $backupPath" -ForegroundColor Gray
}

Write-Step "Step 4: Verify installation"
& codex mcp list

Write-Step "Next steps"
Write-Host "1. Restart Codex if it was already running." -ForegroundColor White
Write-Host "2. Ask Codex to call 'tool.help' or 'workflow.triage'." -ForegroundColor White
Write-Host "3. If native analysis is needed, pass -GhidraPath or set GHIDRA_PATH." -ForegroundColor White
Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
