param(
    [string]$ServerName = "rikune",
    [string]$ProjectRoot = (Get-Location).Path,
    [string]$NodePath,
    [string]$GhidraPath = "",
    [string]$WorkspaceRoot = "$env:USERPROFILE\\.rikune\\workspaces",
    [string]$DatabasePath = "$env:USERPROFILE\\.rikune\\data\\database.db",
    [string]$CacheRoot = "$env:USERPROFILE\\.rikune\\cache",
    [string]$AuditLogPath = "$env:USERPROFILE\\.rikune\\audit.log",
    [ValidateSet("local", "user", "project")]
    [string]$Scope = "user",
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

        [string]$RootProperty
    )

    if (-not (Test-Path -Path $PathValue)) {
        if ($RootProperty) {
            return [pscustomobject]@{
                $RootProperty = [pscustomobject]@{}
            }
        }

        return [pscustomobject]@{}
    }

    $raw = Get-Content -Path $PathValue -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        if ($RootProperty) {
            return [pscustomobject]@{
                $RootProperty = [pscustomobject]@{}
            }
        }

        return [pscustomobject]@{}
    }

    $config = $raw | ConvertFrom-Json
    if ($null -eq $config) {
        if ($RootProperty) {
            return [pscustomobject]@{
                $RootProperty = [pscustomobject]@{}
            }
        }

        return [pscustomobject]@{}
    }

    if ($RootProperty -and -not ($config.PSObject.Properties.Name -contains $RootProperty)) {
        $config | Add-Member -NotePropertyName $RootProperty -NotePropertyValue ([pscustomobject]@{})
    }

    return $config
}

function Save-JsonConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    Ensure-Directory -FilePath $PathValue
    $json = $Config | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($PathValue, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
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

function New-ClaudeServerConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NodeExecutable,

        [Parameter(Mandatory = $true)]
        [string]$EntryPath,

        [Parameter(Mandatory = $true)]
        [string]$ProjectRootValue,

        [Parameter(Mandatory = $true)]
        [string]$WorkspaceRootValue,

        [Parameter(Mandatory = $true)]
        [string]$DatabasePathValue,

        [Parameter(Mandatory = $true)]
        [string]$CacheRootValue,

        [Parameter(Mandatory = $true)]
        [string]$AuditLogPathValue,

        [string]$GhidraPathValue
    )

    $config = [ordered]@{
        command = $NodeExecutable
        args    = @($EntryPath)
        cwd     = $ProjectRootValue
    }

    $config.env = [ordered]@{
        WORKSPACE_ROOT = $WorkspaceRootValue
        DB_PATH = $DatabasePathValue
        CACHE_ROOT = $CacheRootValue
        AUDIT_LOG_PATH = $AuditLogPathValue
    }

    if ($GhidraPathValue) {
        $config.env.GHIDRA_PATH = $GhidraPathValue
        $config.env.GHIDRA_INSTALL_DIR = $GhidraPathValue
    }

    return $config
}

function Ensure-ClaudeProjectEntry {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,

        [Parameter(Mandatory = $true)]
        [string]$ProjectKey
    )

    if (-not ($Config.PSObject.Properties.Name -contains "projects")) {
        $Config | Add-Member -NotePropertyName "projects" -NotePropertyValue ([pscustomobject]@{})
    }

    if (-not ($Config.projects.PSObject.Properties.Name -contains $ProjectKey)) {
        $projectRecord = [pscustomobject]@{
            allowedTools                         = @()
            mcpContextUris                       = @()
            mcpServers                           = [pscustomobject]@{}
            enabledMcpjsonServers                = @()
            disabledMcpjsonServers               = @()
            hasTrustDialogAccepted               = $false
            hasClaudeMdExternalIncludesApproved  = $false
            hasClaudeMdExternalIncludesWarningShown = $false
            exampleFiles                         = @()
        }

        $Config.projects | Add-Member -NotePropertyName $ProjectKey -NotePropertyValue $projectRecord
    } elseif (-not ($Config.projects.$ProjectKey.PSObject.Properties.Name -contains "mcpServers")) {
        $Config.projects.$ProjectKey | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([pscustomobject]@{})
    }
}

function Get-ClaudeConfigPath {
    return Join-Path -Path $HOME -ChildPath ".claude.json"
}

function Get-ProjectConfigPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRootValue
    )

    return Join-Path -Path $ProjectRootValue -ChildPath ".mcp.json"
}

Write-Host "=== Rikune - Claude Install ===" -ForegroundColor Cyan

Write-Step "Step 1: Validate build output and runtime"
$projectRootFull = [System.IO.Path]::GetFullPath($ProjectRoot)
$entryPath = Join-Path -Path $projectRootFull -ChildPath "dist/index.js"
if (-not (Test-Path -Path $entryPath)) {
    throw "dist/index.js was not found. Run 'npm run build' from the project root first."
}

$nodeExecutable = Get-NodeExecutable
$nodeExecutableConfig = Convert-ToConfigPath -PathValue $nodeExecutable
$entryPathConfig = Convert-ToConfigPath -PathValue $entryPath
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
$serverConfig = New-ClaudeServerConfig -NodeExecutable $nodeExecutableConfig -EntryPath $entryPathConfig -ProjectRootValue $projectRootConfig -WorkspaceRootValue $workspaceRootConfig -DatabasePathValue $databasePathConfig -CacheRootValue $cacheRootConfig -AuditLogPathValue $auditLogPathConfig -GhidraPathValue $ghidraPathConfig

Write-Host "Project root: $projectRootConfig" -ForegroundColor Gray
Write-Host "Node path: $nodeExecutableConfig" -ForegroundColor Gray
Write-Host "Server entry: $entryPathConfig" -ForegroundColor Gray
Write-Host "Workspace root: $workspaceRootConfig" -ForegroundColor Gray
Write-Host "Database path: $databasePathConfig" -ForegroundColor Gray
Write-Host "Cache root: $cacheRootConfig" -ForegroundColor Gray
Write-Host "Audit log path: $auditLogPathConfig" -ForegroundColor Gray
Write-Host "Scope: $Scope" -ForegroundColor Gray
if ($ghidraPathConfig -and $ghidraPathExists) {
    Write-Host "Ghidra path: $ghidraPathConfig" -ForegroundColor Gray
} elseif ($ghidraPathConfig) {
    Write-Host "Warning: the Ghidra path does not exist. The script will still write it into the config." -ForegroundColor Yellow
} else {
    Write-Host "No Ghidra path supplied. The config will be written without GHIDRA_PATH." -ForegroundColor Yellow
}

$backupPath = $null

if ($Scope -eq "project") {
    Write-Step "Step 2: Write project-scoped Claude MCP config"
    $configPath = Get-ProjectConfigPath -ProjectRootValue $projectRootFull
    $backupPath = Backup-FileIfNeeded -PathValue $configPath
    $config = Load-JsonConfig -PathValue $configPath -RootProperty "mcpServers"
    Set-NamedProperty -Object $config.mcpServers -Name $ServerName -Value $serverConfig
    Save-JsonConfig -PathValue $configPath -Config $config
    Write-Host "Project config written: $configPath" -ForegroundColor Green
} elseif ($Scope -eq "user") {
    Write-Step "Step 2: Write user-scoped Claude MCP config"
    $configPath = Get-ClaudeConfigPath
    $backupPath = Backup-FileIfNeeded -PathValue $configPath
    $config = Load-JsonConfig -PathValue $configPath -RootProperty "mcpServers"
    Set-NamedProperty -Object $config.mcpServers -Name $ServerName -Value $serverConfig
    Save-JsonConfig -PathValue $configPath -Config $config
    Write-Host "User config written: $configPath" -ForegroundColor Green
} else {
    Write-Step "Step 2: Write local-scoped Claude MCP config"
    $configPath = Get-ClaudeConfigPath
    $backupPath = Backup-FileIfNeeded -PathValue $configPath
    $projectKey = $projectRootConfig
    $config = Load-JsonConfig -PathValue $configPath
    Ensure-ClaudeProjectEntry -Config $config -ProjectKey $projectKey
    Set-NamedProperty -Object $config.projects.$projectKey.mcpServers -Name $ServerName -Value $serverConfig
    Save-JsonConfig -PathValue $configPath -Config $config
    Write-Host "Local config written: $configPath" -ForegroundColor Green
    Write-Host "Project key: $projectKey" -ForegroundColor Gray
}

if ($backupPath) {
    Write-Host "Backup file: $backupPath" -ForegroundColor Gray
}

Write-Step "Step 3: Verify installation with Claude CLI"
$claudeCommand = Get-Command claude -ErrorAction SilentlyContinue
if ($null -eq $claudeCommand) {
    Write-Host "Claude CLI was not found in PATH. The config file was written, but automatic verification was skipped." -ForegroundColor Yellow
    exit 0
}

$verifyLocation = $projectRootFull
if ($Scope -eq "user") {
    $verifyLocation = $env:USERPROFILE
}

Push-Location $verifyLocation
try {
    & $claudeCommand.Source mcp get $ServerName
    if ($LASTEXITCODE -ne 0) {
        throw "Claude could not resolve MCP server '$ServerName' after writing the config."
    }

    if ($Scope -eq "user") {
        Push-Location $projectRootFull
        try {
            $localOverride = & $claudeCommand.Source mcp get $ServerName 2>$null
            if ($LASTEXITCODE -eq 0 -and ($localOverride -join "`n") -match "Scope:\s+Local config") {
                Write-Host ""
                Write-Host "Note: this repository also has a local Claude MCP registration. Inside this repo, Claude will prefer the local scope over the user scope." -ForegroundColor Yellow
            }
        } finally {
            Pop-Location
        }
    }

    Write-Host ""
    Write-Host "Installation complete." -ForegroundColor Green
    Write-Host "Next step: open Claude in this repo and ask it to call 'tool.help' or 'workflow.triage'." -ForegroundColor White
} finally {
    Pop-Location
}
