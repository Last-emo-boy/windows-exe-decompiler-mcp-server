param(
    [string]$ServerName = "windows-exe-decompiler",
    [string]$ProjectRoot = (Get-Location).Path,
    [string]$NodePath,
    [string]$GhidraPath = "",
    [string]$WorkspaceRoot = "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\workspaces",
    [string]$DatabasePath = "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\data\\database.db",
    [string]$CacheRoot = "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\cache",
    [string]$AuditLogPath = "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\audit.log",
    [string]$WorkspaceConfigPath,
    [string]$CopilotCliConfigPath,
    [switch]$SkipWorkspaceConfig,
    [switch]$SkipCopilotCliConfig,
    [switch]$InstallVsCodeUserProfile,
    [switch]$NoBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param(
        [string]$Message
    )

    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
}

function Convert-ToConfigPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    $resolved = [System.IO.Path]::GetFullPath($PathValue)
    return ($resolved -replace "\\", "/")
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $directory = Split-Path -Path $FilePath -Parent
    if ($directory -and -not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
}

function Backup-FileIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    if ($NoBackup -or -not (Test-Path -Path $PathValue)) {
        return $null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = "$PathValue.$timestamp.bak"
    Copy-Item -Path $PathValue -Destination $backupPath -Force
    return $backupPath
}

function Load-JsonConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$RootProperty
    )

    if (-not (Test-Path -Path $PathValue)) {
        return [pscustomobject]@{
            $RootProperty = [pscustomobject]@{}
        }
    }

    $raw = Get-Content -Path $PathValue -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{
            $RootProperty = [pscustomobject]@{}
        }
    }

    $config = $raw | ConvertFrom-Json
    if ($null -eq $config) {
        return [pscustomobject]@{
            $RootProperty = [pscustomobject]@{}
        }
    }

    if (-not ($config.PSObject.Properties.Name -contains $RootProperty)) {
        $config | Add-Member -NotePropertyName $RootProperty -NotePropertyValue ([pscustomobject]@{})
    }

    return $config
}

function Set-NamedProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $existingProperty = $Object.PSObject.Properties[$Name]
    if ($null -ne $existingProperty) {
        $Object.$Name = $Value
        return
    }

    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
}

function Save-JsonConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    Ensure-Directory -FilePath $PathValue
    $json = $Config | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($PathValue, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
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
        throw "Node.js is not available in PATH. Install Node.js or pass -NodePath explicitly."
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

    return "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\workspaces"
}

function Resolve-DatabasePath {
    if ($DatabasePath) {
        return $DatabasePath
    }

    if ($env:DB_PATH) {
        return $env:DB_PATH
    }

    return "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\data\\database.db"
}

function Resolve-CacheRoot {
    if ($CacheRoot) {
        return $CacheRoot
    }

    if ($env:CACHE_ROOT) {
        return $env:CACHE_ROOT
    }

    return "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\cache"
}

function Resolve-AuditLogPath {
    if ($AuditLogPath) {
        return $AuditLogPath
    }

    if ($env:AUDIT_LOG_PATH) {
        return $env:AUDIT_LOG_PATH
    }

    return "$env:USERPROFILE\\.windows-exe-decompiler-mcp-server\\audit.log"
}

Write-Host "=== Windows EXE Decompiler MCP Server - GitHub Copilot Install ===" -ForegroundColor Cyan

Write-Step "Step 1: Validate build output and runtime"
$projectRootFull = [System.IO.Path]::GetFullPath($ProjectRoot)
$distEntry = Join-Path -Path $projectRootFull -ChildPath "dist/index.js"
if (-not (Test-Path -Path $distEntry)) {
    throw "dist/index.js was not found. Run 'npm run build' from the project root first."
}

$nodeExecutable = Get-NodeExecutable
$nodeExecutableConfig = Convert-ToConfigPath -PathValue $nodeExecutable
$distEntryConfig = Convert-ToConfigPath -PathValue $distEntry
$projectRootConfig = Convert-ToConfigPath -PathValue $projectRootFull
$workspaceRootResolved = Resolve-WorkspaceRoot
$workspaceRootConfig = Convert-ToConfigPath -PathValue $workspaceRootResolved
$databasePathResolved = Resolve-DatabasePath
$databasePathConfig = Convert-ToConfigPath -PathValue $databasePathResolved
$cacheRootResolved = Resolve-CacheRoot
$cacheRootConfig = Convert-ToConfigPath -PathValue $cacheRootResolved
$auditLogPathResolved = Resolve-AuditLogPath
$auditLogPathConfig = Convert-ToConfigPath -PathValue $auditLogPathResolved
$ghidraPathResolved = Resolve-GhidraPath
$ghidraPathExists = $ghidraPathResolved -and (Test-Path -Path $ghidraPathResolved)
$ghidraPathConfig = if ($ghidraPathResolved) { Convert-ToConfigPath -PathValue $ghidraPathResolved } else { "" }

Write-Host "Project root: $projectRootConfig" -ForegroundColor Gray
Write-Host "Node path: $nodeExecutableConfig" -ForegroundColor Gray
Write-Host "Server entry: $distEntryConfig" -ForegroundColor Gray
Write-Host "Workspace root: $workspaceRootConfig" -ForegroundColor Gray
Write-Host "Database path: $databasePathConfig" -ForegroundColor Gray
Write-Host "Cache root: $cacheRootConfig" -ForegroundColor Gray
Write-Host "Audit log path: $auditLogPathConfig" -ForegroundColor Gray
if ($ghidraPathConfig -and $ghidraPathExists) {
    Write-Host "Ghidra path: $ghidraPathConfig" -ForegroundColor Gray
} elseif ($ghidraPathConfig) {
    Write-Host "Warning: the Ghidra path does not exist. The script will still write it into the config. Pass -GhidraPath to override it." -ForegroundColor Yellow
} else {
    Write-Host "No Ghidra path supplied. The config will be written without GHIDRA_PATH." -ForegroundColor Yellow
}

if (-not $WorkspaceConfigPath) {
    $WorkspaceConfigPath = Join-Path -Path $projectRootFull -ChildPath ".vscode/mcp.json"
}

if (-not $CopilotCliConfigPath) {
    $copilotConfigRoot = if ($env:XDG_CONFIG_HOME) {
        Join-Path -Path $env:XDG_CONFIG_HOME -ChildPath "copilot"
    } else {
        Join-Path -Path $HOME -ChildPath ".copilot"
    }

    $CopilotCliConfigPath = Join-Path -Path $copilotConfigRoot -ChildPath "mcp-config.json"
}

$workspaceServerConfig = [ordered]@{
    type    = "stdio"
    command = $nodeExecutableConfig
    args    = @($distEntryConfig)
}

if ($ghidraPathConfig) {
    $workspaceServerConfig.env = [ordered]@{
        WORKSPACE_ROOT     = $workspaceRootConfig
        DB_PATH            = $databasePathConfig
        CACHE_ROOT         = $cacheRootConfig
        AUDIT_LOG_PATH     = $auditLogPathConfig
        GHIDRA_PATH        = $ghidraPathConfig
        GHIDRA_INSTALL_DIR = $ghidraPathConfig
    }
} else {
    $workspaceServerConfig.env = [ordered]@{
        WORKSPACE_ROOT = $workspaceRootConfig
        DB_PATH        = $databasePathConfig
        CACHE_ROOT     = $cacheRootConfig
        AUDIT_LOG_PATH = $auditLogPathConfig
    }
}

$copilotCliServerConfig = [ordered]@{
    type    = "local"
    command = $nodeExecutableConfig
    args    = @($distEntryConfig)
    cwd     = $projectRootConfig
    tools   = @("*")
    timeout = 300000
}

if ($ghidraPathConfig) {
    $copilotCliServerConfig.env = [ordered]@{
        WORKSPACE_ROOT     = $workspaceRootConfig
        DB_PATH            = $databasePathConfig
        CACHE_ROOT         = $cacheRootConfig
        AUDIT_LOG_PATH     = $auditLogPathConfig
        GHIDRA_PATH        = $ghidraPathConfig
        GHIDRA_INSTALL_DIR = $ghidraPathConfig
    }
} else {
    $copilotCliServerConfig.env = [ordered]@{
        WORKSPACE_ROOT = $workspaceRootConfig
        DB_PATH        = $databasePathConfig
        CACHE_ROOT     = $cacheRootConfig
        AUDIT_LOG_PATH = $auditLogPathConfig
    }
}

if (-not $SkipWorkspaceConfig) {
    Write-Step "Step 2: Write workspace GitHub Copilot / VS Code MCP config"
    $workspaceBackup = Backup-FileIfNeeded -PathValue $WorkspaceConfigPath
    $workspaceConfig = Load-JsonConfig -PathValue $WorkspaceConfigPath -RootProperty "servers"
    Set-NamedProperty -Object $workspaceConfig.servers -Name $ServerName -Value $workspaceServerConfig
    Save-JsonConfig -PathValue $WorkspaceConfigPath -Config $workspaceConfig

    Write-Host "Workspace config written: $WorkspaceConfigPath" -ForegroundColor Green
    if ($workspaceBackup) {
        Write-Host "Backup file: $workspaceBackup" -ForegroundColor Gray
    }
}

if (-not $SkipCopilotCliConfig) {
    Write-Step "Step 3: Write GitHub Copilot CLI MCP config"
    $cliBackup = Backup-FileIfNeeded -PathValue $CopilotCliConfigPath
    $cliConfig = Load-JsonConfig -PathValue $CopilotCliConfigPath -RootProperty "mcpServers"
    Set-NamedProperty -Object $cliConfig.mcpServers -Name $ServerName -Value $copilotCliServerConfig
    Save-JsonConfig -PathValue $CopilotCliConfigPath -Config $cliConfig

    Write-Host "CLI config written: $CopilotCliConfigPath" -ForegroundColor Green
    if ($cliBackup) {
        Write-Host "Backup file: $cliBackup" -ForegroundColor Gray
    }
}

if ($InstallVsCodeUserProfile) {
    Write-Step "Step 4: Try to install into the VS Code user-level MCP config"
    $codeCommand = Get-Command code -ErrorAction SilentlyContinue
    if ($null -eq $codeCommand) {
        Write-Host "Warning: the 'code' command was not found. Skipping user-level VS Code installation." -ForegroundColor Yellow
    } else {
        $userProfilePayload = [pscustomobject]@{
            name    = $ServerName
            type    = "stdio"
            command = $nodeExecutableConfig
            args    = @($distEntryConfig)
        } | ConvertTo-Json -Depth 10 -Compress

        if ($ghidraPathConfig) {
            $userProfilePayload = [pscustomobject]@{
                name    = $ServerName
                type    = "stdio"
                command = $nodeExecutableConfig
                args    = @($distEntryConfig)
                env     = [pscustomobject]@{
                    GHIDRA_PATH        = $ghidraPathConfig
                    GHIDRA_INSTALL_DIR = $ghidraPathConfig
                }
            } | ConvertTo-Json -Depth 10 -Compress
        }

        & $codeCommand.Source --add-mcp $userProfilePayload
        Write-Host "VS Code --add-mcp was invoked successfully." -ForegroundColor Green
    }
}

Write-Step "Step 5: What to do next"
Write-Host "1. VS Code / GitHub Copilot Chat:" -ForegroundColor Cyan
Write-Host "   Open this workspace. Copilot will read .vscode/mcp.json. Trust the MCP server when VS Code prompts you." -ForegroundColor White
Write-Host "2. GitHub Copilot CLI:" -ForegroundColor Cyan
Write-Host "   Start 'copilot' and run '/mcp list' or '/mcp show $ServerName'." -ForegroundColor White
Write-Host "3. Use -SkipWorkspaceConfig or -SkipCopilotCliConfig if you only want to update one target." -ForegroundColor White
Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
