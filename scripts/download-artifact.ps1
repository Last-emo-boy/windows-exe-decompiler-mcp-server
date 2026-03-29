# Download Artifact from MCP Server via HTTP API
# Usage: .\scripts\download-artifact.ps1 -ArtifactId "artifact-id" [-ApiKey "your-api-key"] [-Server "http://localhost:18080"] [-OutputPath "./output"]

param(
    [Parameter(Mandatory=$true, HelpMessage="Artifact ID to download")]
    [string]$ArtifactId,

    [Parameter(HelpMessage="API Key for authentication")]
    [string]$ApiKey,

    [Parameter(HelpMessage="MCP Server API URL")]
    [string]$Server = "http://localhost:18080",

    [Parameter(HelpMessage="Output directory for downloaded artifact")]
    [string]$OutputPath = ".",

    [Parameter(HelpMessage="Download artifact file (not just metadata)")]
    [switch]$DownloadFile
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-ProgressInfo {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-ProgressSuccess {
    param([string]$Message)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-ProgressError {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# =============================================================================
# Main Script
# =============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MCP Server Artifact Download" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Build API URL
$baseUrl = $Server.TrimEnd('/')
$artifactUrl = "$baseUrl/api/v1/artifacts/$ArtifactId"

# Build headers
$headers = @{
    "Accept" = "application/json"
}

if ($ApiKey) {
    $headers["X-API-Key"] = $ApiKey
    Write-ProgressInfo "Using API key authentication"
}

# =============================================================================
# Get Artifact Metadata
# =============================================================================

Write-ProgressInfo "Fetching artifact metadata..."

try {
    $metadataResponse = Invoke-RestMethod -Uri $artifactUrl -Method Get -Headers $headers -ErrorAction Stop
    
    if ($metadataResponse.ok) {
        Write-ProgressSuccess "Artifact found"
        $artifact = $metadataResponse.data
        
        Write-Host ""
        Write-Host "Artifact Details:" -ForegroundColor Yellow
        Write-Host "  ID:          $($artifact.id)"
        Write-Host "  Sample ID:   $($artifact.sample_id)"
        Write-Host "  Type:        $($artifact.type)"
        Write-Host "  SHA256:      $($artifact.sha256)"
        Write-Host "  Created:     $($artifact.created_at)"
        if ($artifact.mime) {
            Write-Host "  MIME Type:   $($artifact.mime)"
        }
        Write-Host ""
        
        # Download file if requested
        if ($DownloadFile) {
            Write-ProgressInfo "Downloading artifact file..."
            
            $downloadUrl = "$artifactUrl?download=true"
            $outputFile = Join-Path $OutputPath $artifact.id
            
            try {
                Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile $outputFile -ErrorAction Stop
                Write-ProgressSuccess "Artifact downloaded to: $outputFile"
                
                # Verify file
                if (Test-Path $outputFile) {
                    $fileSize = (Get-Item $outputFile).Length
                    Write-ProgressInfo "File size: $fileSize bytes"
                }
            } catch {
                Write-ProgressError "Failed to download artifact: $($_.Exception.Message)"
                exit 1
            }
        } else {
            Write-Host "Use -DownloadFile to download the artifact file" -ForegroundColor Gray
        }
        
    } else {
        Write-ProgressError "Artifact not found or error occurred"
        if ($metadataResponse.error) {
            Write-Host "Error: $($metadataResponse.error)" -ForegroundColor Red
        }
        exit 1
    }
} catch {
    $statusCode = $_.Exception.Response.StatusCode
    $statusDesc = $_.Exception.Response.StatusDescription
    
    if ($statusCode -eq 404) {
        Write-ProgressError "Artifact not found: $ArtifactId"
    } elseif ($statusCode -eq 401 -or $statusCode -eq 403) {
        Write-ProgressError "Authentication failed. Check your API key."
    } else {
        Write-ProgressError "Failed to fetch artifact: $statusDesc"
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}

Write-Host ""
Write-Host "Download complete!" -ForegroundColor Green
