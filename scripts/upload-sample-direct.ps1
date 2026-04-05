# Upload Sample Directly to Docker Container
# Usage: .\scripts\upload-sample-direct.ps1 -Path "C:\path\to\sample.exe"
# This script uploads files directly to the running container without manual copying

param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the sample file on host system")]
    [string]$Path,
    
    [Parameter(HelpMessage="Output format: 'path' (default), 'json', or 'mcp'")]
    [ValidateSet("path", "json", "mcp")]
    [string]$OutputFormat = "path"
)

$ErrorActionPreference = "Stop"

# Configuration
$ContainerName = "rikune"
$SamplesDir = "/samples"

# Check if file exists
if (-not (Test-Path $Path)) {
    Write-Error "Sample file not found: $Path"
    exit 1
}

# Get filename and size
$filename = Split-Path $Path -Leaf
$fileSize = (Get-Item $Path).Length

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Direct Sample Upload to Docker" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "File: $filename" -ForegroundColor White
Write-Host "Size: $([math]::Round($fileSize / 1KB, 2)) KB" -ForegroundColor White
Write-Host ""

# Check if container is running
Write-Host "Checking container status..." -ForegroundColor Gray
$container = docker ps --filter "name=$ContainerName" --format "{{.Names}}"
if (-not $container) {
    Write-Host "⚠ Container '$ContainerName' is not running. Starting..." -ForegroundColor Yellow
    docker-compose up -d
    Start-Sleep -Seconds 5
    
    # Verify container is running
    $container = docker ps --filter "name=$ContainerName" --format "{{.Names}}"
    if (-not $container) {
        Write-Error "Failed to start container"
        exit 1
    }
}
Write-Host "✓ Container is running" -ForegroundColor Green
Write-Host ""

# Upload file using docker exec
Write-Host "Uploading sample to container..." -ForegroundColor Gray

try {
    # Read file as bytes and encode to Base64
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $base64 = [System.Convert]::ToBase64String($bytes)
    
    # Create upload command
    $uploadCmd = "echo '$base64' | base64 -d > '$SamplesDir/$filename'"
    
    # Execute in container
    docker exec -i $ContainerName bash -c $uploadCmd
    
    # Verify upload
    $verifyCmd = "ls -lh '$SamplesDir/$filename'"
    $result = docker exec -i $ContainerName bash -c $verifyCmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Sample uploaded successfully" -ForegroundColor Green
        Write-Host ""
        Write-Host "Container path: $SamplesDir/$filename" -ForegroundColor Cyan
        Write-Host ""
        
        if ($OutputFormat -eq "json") {
            # Output JSON for direct MCP use
            $result = @{
                success = $true
                containerPath = "$SamplesDir/$filename"
                filename = $filename
                size = $fileSize
                uploadedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                mcp_call = @{
                    tool = "sample.ingest"
                    arguments = @{
                        path = "$SamplesDir/$filename"
                        filename = $filename
                        source = "direct_upload"
                    }
                }
            }
            Write-Host "MCP Call JSON:" -ForegroundColor Cyan
            $result | ConvertTo-Json -Depth 10
        } elseif ($OutputFormat -eq "mcp") {
            # Output ready-to-use MCP call
            Write-Host "Ready-to-use MCP Call:" -ForegroundColor Cyan
            Write-Host ""
            Write-Host @"
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "$SamplesDir/$filename",
    "filename": "$filename",
    "source": "direct_upload"
  }
}
"@ -ForegroundColor White
        } else {
            Write-Host "Use this path in sample.ingest:" -ForegroundColor Cyan
            Write-Host "$SamplesDir/$filename" -ForegroundColor White
        }
    } else {
        Write-Error "Failed to verify upload"
        exit 1
    }
} catch {
    Write-Error "Upload failed: $($_.Exception.Message)"
    exit 1
}
