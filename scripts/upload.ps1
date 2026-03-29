# Quick Upload Sample to Docker Container
# Usage: .\scripts\upload.ps1 "C:\path\to\sample.exe"

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path
)

& "$PSScriptRoot\upload-sample-direct.ps1" -Path $Path -OutputFormat mcp
