# Docker Upload Server Connection Test
# 测试宿主机到容器的网络连接

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Docker Upload Server Connection Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check if container is running
Write-Host "[1] Checking container status..." -ForegroundColor Yellow
$container = docker ps --filter "name=windows-exe-decompiler-mcp" --format "{{.Names}}"
if ($container) {
    Write-Host "✓ Container is running: $container" -ForegroundColor Green
} else {
    Write-Host "✗ Container is NOT running!" -ForegroundColor Red
    Write-Host "  Run: docker-compose up -d" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# 2. Check port mapping
Write-Host "[2] Checking port mapping..." -ForegroundColor Yellow
$ports = docker port windows-exe-decompiler-mcp
if ($ports) {
    Write-Host "✓ Port mapping:" -ForegroundColor Green
    $ports | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "✗ No port mapping found!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# 3. Test health endpoint
Write-Host "[3] Testing upload server health..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:18081/health" -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "✓ Upload server is accessible at localhost:18081" -ForegroundColor Green
        $content = $response.Content | ConvertFrom-Json
        Write-Host "  Status: $($content.status)" -ForegroundColor Gray
        Write-Host "  Message: $($content.message)" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ Failed to connect to localhost:18081" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
    
    # Try host.docker.internal
    Write-Host ""
    Write-Host "Trying host.docker.internal..." -ForegroundColor Yellow
    try {
        $response = Invoke-WebRequest -Uri "http://host.docker.internal:18081/health" -TimeoutSec 5 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Upload server is accessible at host.docker.internal:18081" -ForegroundColor Green
            Write-Host "  Use this URL for uploads instead of localhost" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "✗ Also failed to connect to host.docker.internal:18081" -ForegroundColor Red
    }
}
Write-Host ""

# 4. Test API server
Write-Host "[4] Testing API server health..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:18080/api/v1/health" -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "✓ API server is accessible at localhost:18080" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Failed to connect to API server" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}
Write-Host ""

# 5. Network diagnostics
Write-Host "[5] Network diagnostics..." -ForegroundColor Yellow
Write-Host "Testing TCP connection to localhost:18081..." -ForegroundColor Gray
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connect = $tcpClient.BeginConnect("localhost", 18081, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne(2000, $false)
    if ($wait) {
        Write-Host "✓ TCP connection successful" -ForegroundColor Green
    } else {
        Write-Host "✗ TCP connection timeout" -ForegroundColor Red
    }
    $tcpClient.Close()
} catch {
    Write-Host "✗ TCP connection failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
