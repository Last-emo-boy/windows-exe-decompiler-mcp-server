# Upload Sample to MCP Server via HTTP API
# Usage: .\scripts\upload-api.ps1 -Path "C:\path\to\sample.exe" [-ApiKey "your-api-key"] [-Server "http://localhost:18080"]

param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the sample file on host system")]
    [string]$Path,
    
    [Parameter(HelpMessage="API Key for authentication")]
    [string]$ApiKey,
    
    [Parameter(HelpMessage="MCP Server API URL")]
    [string]$Server = "http://localhost:18080",
    
    [Parameter(HelpMessage="Sample source tag")]
    [string]$Source = "api_upload"
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
Write-Host "  MCP Server Sample Upload (API)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if file exists
if (-not (Test-Path $Path)) {
    Write-ProgressError "Sample file not found: $Path"
    exit 1
}

# Get filename and size
$filename = Split-Path $Path -Leaf
$fileSize = (Get-Item $Path).Length
$fileSizeMB = [math]::Round($fileSize / 1MB, 2)

Write-ProgressInfo "File: $filename"
Write-ProgressInfo "Size: $fileSizeMB MB"
Write-ProgressInfo "Server: $Server"
Write-Host ""

# Check file size limit (500MB)
if ($fileSizeMB -gt 500) {
    Write-ProgressError "File size exceeds 500MB limit"
    exit 1
}

# Load API key from environment if not provided
if (-not $ApiKey) {
    $ApiKey = $env:MCP_API_KEY
    if (-not $ApiKey) {
        Write-ProgressInfo "API Key not provided, attempting anonymous upload..."
    }
}

# Prepare upload
Write-ProgressInfo "Preparing upload..."
$uploadUrl = "$Server/api/v1/samples"

# Create form data
$form = New-Object System.Net.Http.FormDataContent

# Read file as bytes
try {
    $fileBytes = [System.IO.File]::ReadAllBytes($Path)
    $fileStream = New-Object System.IO.MemoryStream(,$fileBytes)
    $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
    $fileContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream")
    
    $form.Add($fileContent, "file", $filename)
    
    # Add metadata
    if ($Source) {
        $form.Add("source", $Source)
    }
} catch {
    Write-ProgressError "Failed to read file: $($_.Exception.Message)"
    exit 1
}

# Upload file
Write-ProgressInfo "Uploading to $uploadUrl..."

try {
    $httpClient = New-Object System.Net.Http.HttpClient
    
    # Add API key header if provided
    if ($ApiKey) {
        $httpClient.DefaultRequestHeaders.Add("X-API-Key", $ApiKey)
    }
    
    # Set timeout (300 seconds for large files)
    $httpClient.Timeout = New-Object System.TimeSpan(0, 5, 0)
    
    # Upload
    $response = $httpClient.PostAsync($uploadUrl, $form).Result
    
    if ($response.IsSuccessStatusCode) {
        $responseContent = $response.Content.ReadAsStringAsync().Result
        $result = $responseContent | ConvertFrom-Json
        
        Write-ProgressSuccess "Upload successful!"
        Write-Host ""
        Write-Host "Sample ID: $($result.data.sample_id)" -ForegroundColor Cyan
        Write-Host "Filename: $($result.data.filename)" -ForegroundColor Gray
        Write-Host "Size: $([math]::Round($result.data.size / 1KB, 2)) KB" -ForegroundColor Gray
        Write-Host "Uploaded: $($result.data.uploaded_at)" -ForegroundColor Gray
        Write-Host ""
        
        # Output JSON for scripting
        Write-Host "MCP Call Example:" -ForegroundColor Yellow
        $result | ConvertTo-Json -Depth 5
    } else {
        $errorContent = $response.Content.ReadAsStringAsync().Result
        Write-ProgressError "Upload failed: $($response.StatusCode)"
        Write-Host "Details: $errorContent" -ForegroundColor Gray
        exit 1
    }
} catch [System.Net.Http.HttpRequestException] {
    Write-ProgressError "Connection failed: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check if MCP Server is running" -ForegroundColor Gray
    Write-Host "  2. Verify server URL: $Server" -ForegroundColor Gray
    Write-Host "  3. Check API key (if required)" -ForegroundColor Gray
    Write-Host "  4. Ensure port 18080 is not blocked" -ForegroundColor Gray
    exit 1
} catch {
    Write-ProgressError "Upload failed: $($_.Exception.Message)"
    exit 1
}
