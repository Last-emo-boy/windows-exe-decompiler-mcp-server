# Upload Sample to Docker Container
# Usage: .\scripts\upload-sample.ps1 -Path "C:\path\to\sample.exe" [-OutputFormat "path"|"json"]

param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the sample file on host system")]
    [string]$Path,
    
    [Parameter(HelpMessage="Output format: 'path' (default) or 'json' for MCP call")]
    [ValidateSet("path", "json")]
    [string]$OutputFormat = "path"
)

$ErrorActionPreference = "Stop"

# Configuration
$SamplesDir = "D:\Docker\decompile-mcp-server\samples"
$ContainerName = "windows-exe-decompiler-mcp"

# Check if file exists
if (-not (Test-Path $Path)) {
    Write-Error "Sample file not found: $Path"
    exit 1
}

# Get filename
$filename = Split-Path $Path -Leaf

# Ensure samples directory exists
if (-not (Test-Path $SamplesDir)) {
    Write-Host "Creating samples directory: $SamplesDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null
}

# Check if container is running
$container = docker ps --filter "name=$ContainerName" --format "{{.Names}}"
if (-not $container) {
    Write-Host "⚠ Container '$ContainerName' is not running. Starting..." -ForegroundColor Yellow
    docker-compose up -d
    Start-Sleep -Seconds 3
}

# Copy file to mounted directory
Write-Host "Uploading sample: $filename" -ForegroundColor Cyan
Copy-Item $Path -Destination "$SamplesDir\$filename" -Force

# Verify upload
if (Test-Path "$SamplesDir\$filename") {
    $fileSize = (Get-Item "$SamplesDir\$filename").Length
    Write-Host "✓ Sample uploaded successfully" -ForegroundColor Green
    Write-Host "  Host path: $SamplesDir\$filename" -ForegroundColor Gray
    Write-Host "  Container path: /samples/$filename" -ForegroundColor Gray
    Write-Host "  File size: $([math]::Round($fileSize / 1KB, 2)) KB" -ForegroundColor Gray
    
    if ($OutputFormat -eq "json") {
        # Output JSON for direct MCP use
        $result = @{
            path = "/samples/$filename"
            filename = $filename
            size = $fileSize
            mcp_call = @{
                tool = "sample.ingest"
                arguments = @{
                    path = "/samples/$filename"
                    filename = $filename
                }
            }
        }
        Write-Host "`nMCP Call JSON:" -ForegroundColor Cyan
        $result | ConvertTo-Json -Depth 10
    } else {
        Write-Host "`nUse this path in sample.ingest:" -ForegroundColor Cyan
        Write-Host "/samples/$filename" -ForegroundColor White
    }
} else {
    Write-Error "Failed to upload sample"
    exit 1
}
