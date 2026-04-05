# Convert all scripts to UTF-8 without BOM
# Usage: .\scripts\convert-utf8-nobom.ps1

$ErrorActionPreference = "Continue"

$rootPath = "D:\Playground\rikune"
$excludeDirs = @('node_modules', 'dist', 'openspec', '.git', '.qwen')

# Get all script files
$files = @(
    Get-ChildItem -Path $rootPath -Recurse -Include '*.ps1','*.sh' | Where-Object {
        $exclude = $false
        foreach ($dir in $excludeDirs) {
            if ($_.FullName -like "*\$dir\*") {
                $exclude = $true
                break
            }
        }
        -not $exclude
    }
)

# Also convert Docker config if exists
$dockerConfigPath = "$env:USERPROFILE\.docker\config.json"
if (Test-Path $dockerConfigPath) {
    $files += Get-Item $dockerConfigPath
}

Write-Host "Converting $($files.Count) files to UTF-8 without BOM..." -ForegroundColor Cyan

foreach ($file in $files) {
    try {
        $content = Get-Content $file.FullName -Raw
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($file.FullName, $content, $utf8NoBom)
        Write-Host "閴?$($file.Name)" -ForegroundColor Green
    } catch {
        Write-Host "閴?$($file.Name) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nConversion complete!" -ForegroundColor Green
