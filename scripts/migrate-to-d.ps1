# =============================================================================
# Docker 瀹屽叏杩佺Щ鍒?D 鐩樿剼鏈?# =============================================================================
# 鍔熻兘:
#   - 杩佺Щ Docker WSL2 鏁版嵁鍒?D 鐩?#   - 杩佺Щ搴旂敤鏁版嵁鍒?D 鐩?#   - 楠岃瘉杩佺Щ鎴愬姛
# =============================================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# 棰滆壊瀹氫箟
$ColorSuccess = "Green"
$ColorError = "Red"
$ColorInfo = "Cyan"
$ColorWarning = "Yellow"
$ColorWhite = "White"

function Write-Success {
    param([string]$Text)
    Write-Host "鉁?" -ForegroundColor $ColorSuccess -NoNewline
    Write-Host $Text -ForegroundColor $ColorSuccess
}

function Write-Error-Message {
    param([string]$Text)
    Write-Host "鉁?" -ForegroundColor $ColorError -NoNewline
    Write-Host $Text -ForegroundColor $ColorError
}

function Write-Warning-Message {
    param([string]$Text)
    Write-Host "鈿?" -ForegroundColor $ColorWarning -NoNewline
    Write-Host $Text -ForegroundColor $ColorWarning
}

function Write-Info {
    param([string]$Text)
    Write-Host "鈩?" -ForegroundColor $ColorInfo -NoNewline
    Write-Host $Text -ForegroundColor $ColorInfo
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲" -ForegroundColor $ColorInfo
    Write-Host "  $Text" -ForegroundColor $ColorInfo
    Write-Host "鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲" -ForegroundColor $ColorInfo
}

# =============================================================================
# 姝ラ 1: 娆㈣繋淇℃伅
# =============================================================================
Clear-Host
Write-Step "Docker 瀹屽叏杩佺Щ鍒?D 鐩?

Write-Host "`n鏈剼鏈皢甯姪鎮細" -ForegroundColor $ColorInfo
Write-Host "  1. 鍋滄 Docker Desktop 鍜?WSL2" -ForegroundColor $ColorInfo
Write-Host "  2. 杩佺Щ Docker WSL2 鏁版嵁鍒?D 鐩? -ForegroundColor $ColorInfo
Write-Host "  3. 杩佺Щ搴旂敤鏁版嵁鍒?D 鐩? -ForegroundColor $ColorInfo
Write-Host "  4. 楠岃瘉杩佺Щ鎴愬姛" -ForegroundColor $ColorInfo
Write-Host "`n棰勮鏃堕棿锛?0-30 鍒嗛挓锛堝彇鍐充簬 Docker 鏁版嵁澶у皬锛? -ForegroundColor $ColorInfo
Write-Host "`n鈿狅笍  閲嶈鎻愮ず锛氳縼绉昏繃绋嬩腑璇峰嬁鍏抽棴姝ょ獥鍙ｏ紒" -ForegroundColor $ColorWarning

$continue = Read-Host "`n鏄惁缁х画锛?Y/n)"
if ($continue -eq 'n' -or $continue -eq 'N') {
    Write-Warning-Message "杩佺Щ宸插彇娑?
    exit 0
}

# =============================================================================
# 姝ラ 2: 鍋滄 Docker 鍜?WSL2
# =============================================================================
Write-Step "鍋滄 Docker 鍜?WSL2"

Write-Host "`n姝ｅ湪鍋滄 Docker Desktop..." -ForegroundColor $ColorInfo
try {
    # 灏濊瘯浼橀泤鍏抽棴
    $dockerProcess = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
    if ($dockerProcess) {
        Stop-Process -Name "Docker Desktop" -Force
        Write-Success "Docker Desktop 宸插仠姝?
    } else {
        Write-Info "Docker Desktop 鏈繍琛?
    }

    # 绛夊緟杩涚▼瀹屽叏閫€鍑?    Start-Sleep -Seconds 5
} catch {
    Write-Warning-Message "鍋滄 Docker Desktop 澶辫触锛?($_.Exception.Message)"
}

Write-Host "`n姝ｅ湪鍋滄 WSL2..." -ForegroundColor $ColorInfo
try {
    wsl --shutdown
    Start-Sleep -Seconds 3
    Write-Success "WSL2 宸插仠姝?
} catch {
    Write-Warning-Message "鍋滄 WSL2 澶辫触锛?($_.Exception.Message)"
}

# =============================================================================
# 姝ラ 3: 杩佺Щ Docker WSL2 鏁版嵁
# =============================================================================
Write-Step "杩佺Щ Docker WSL2 鏁版嵁鍒?D 鐩?

# 鍒涘缓鐩爣鐩綍
$dockerWslDir = "D:\Docker\wsl\data"
if (-not (Test-Path $dockerWslDir)) {
    New-Item -ItemType Directory -Path $dockerWslDir -Force | Out-Null
    Write-Success "鍒涘缓鐩綍锛?dockerWslDir"
}

# 瀵煎嚭 Docker 鏁版嵁
Write-Host "`n姝ｅ湪瀵煎嚭 Docker 鏁版嵁锛堣繖鍙兘闇€瑕佸嚑鍒嗛挓锛?.." -ForegroundColor $ColorInfo
$exportPath = "D:\Docker\wsl\docker-desktop.tar"

try {
    # 妫€鏌ユ槸鍚﹀凡鏈夊鍑烘枃浠?    if (Test-Path $exportPath) {
        Write-Warning-Message "鍙戠幇宸插瓨鍦ㄧ殑瀵煎嚭鏂囦欢锛?exportPath"
        $overwrite = Read-Host "鏄惁瑕嗙洊锛?y/N)"
        if ($overwrite -eq 'y' -or $overwrite -eq 'Y') {
            Remove-Item $exportPath -Force
        } else {
            Write-Info "浣跨敤鐜版湁瀵煎嚭鏂囦欢"
        }
    }

    # 瀵煎嚭
    if (-not (Test-Path $exportPath)) {
        Write-Host "瀵煎嚭杩涘害锛? -NoNewline
        wsl --export docker-desktop $exportPath

        if (Test-Path $exportPath) {
            $size = (Get-Item $exportPath).Length / 1GB
            Write-Success "瀵煎嚭瀹屾垚锛?([math]::Round($size, 2)) GB"
        } else {
            throw "瀵煎嚭鏂囦欢鏈垱寤?
        }
    }
} catch {
    Write-Error-Message "瀵煎嚭 Docker 鏁版嵁澶辫触锛?($_.Exception.Message)"
    Write-Host "`n鍙兘鐨勫師鍥狅細" -ForegroundColor $ColorInfo
    Write-Host "  1. WSL2 鏈畬鍏ㄥ仠姝? -ForegroundColor $ColorInfo
    Write-Host "  2. C 鐩樼┖闂翠笉瓒? -ForegroundColor $ColorInfo
    Write-Host "  3. D 鐩樼┖闂翠笉瓒? -ForegroundColor $ColorInfo

    $continue = Read-Host "`n鏄惁缁х画灏濊瘯瀵煎叆锛?y/N)"
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        exit 1
    }
}

# 娉ㄩ攢褰撳墠 Docker 鏁版嵁
Write-Host "`n姝ｅ湪娉ㄩ攢 C 鐩?Docker 鏁版嵁..." -ForegroundColor $ColorInfo
try {
    wsl --unregister docker-desktop
    Write-Success "宸叉敞閿€ docker-desktop"
} catch {
    Write-Warning-Message "娉ㄩ攢澶辫触锛?($_.Exception.Message)"
}

# 浠?D 鐩樺鍏?Write-Host "`n姝ｅ湪浠?D 鐩樺鍏?Docker 鏁版嵁..." -ForegroundColor $ColorInfo
try {
    wsl --import docker-desktop $dockerWslDir $exportPath --version 2

    # 楠岃瘉瀵煎叆
    $wslList = wsl -l -v | Out-String
    if ($wslList -like "*docker-desktop*") {
        Write-Success "Docker 鏁版嵁宸叉垚鍔熷鍏ュ埌 D 鐩?
    } else {
        throw "瀵煎叆鍚庢湭鎵惧埌 docker-desktop"
    }
} catch {
    Write-Error-Message "瀵煎叆 Docker 鏁版嵁澶辫触锛?($_.Exception.Message)"
    exit 1
}

# 娓呯悊涓存椂鏂囦欢
Write-Host "`n姝ｅ湪娓呯悊涓存椂鏂囦欢..." -ForegroundColor $ColorInfo
try {
    if (Test-Path $exportPath) {
        Remove-Item $exportPath -Force
        Write-Success "宸插垹闄や复鏃跺鍑烘枃浠?
    }
} catch {
    Write-Warning-Message "娓呯悊涓存椂鏂囦欢澶辫触锛?($_.Exception.Message)"
}

# =============================================================================
# 姝ラ 4: 杩佺Щ搴旂敤鏁版嵁锛堝鏋滃瓨鍦級
# =============================================================================
Write-Step "杩佺Щ搴旂敤鏁版嵁鍒?D 鐩?

$appDataDir = "D:\Docker\decompile-mcp-server"
$oldAppDataDir = "$env:USERPROFILE\.windows-exe-decompiler-mcp-server"

if (Test-Path $oldAppDataDir) {
    Write-Host "`n鍙戠幇鏃х殑搴旂敤鏁版嵁锛?oldAppDataDir" -ForegroundColor $ColorInfo

    if (-not (Test-Path $appDataDir)) {
        New-Item -ItemType Directory -Path $appDataDir -Force | Out-Null
    }

    # 杩佺Щ瀛愮洰褰?    $subdirs = @("workspaces", "data", "cache", "ghidra-projects", "ghidra-logs", "logs")

    foreach ($subdir in $subdirs) {
        $source = Join-Path $oldAppDataDir $subdir
        $target = Join-Path $appDataDir $subdir

        if (Test-Path $source) {
            Write-Host "  杩佺Щ $subdir..." -NoNewline
            try {
                Move-Item -Path $source -Destination $target -Force
                Write-Success "宸茶縼绉?
            } catch {
                Write-Warning-Message "杩佺Щ澶辫触"
            }
        }
    }

    Write-Info "鏃ф暟鎹洰褰曞凡淇濈暀锛岀‘璁ゆ棤璇悗鍙墜鍔ㄥ垹闄?
} else {
    Write-Info "鏈彂鐜版棫鐨勫簲鐢ㄦ暟鎹?

    # 鍒涘缓鏂扮洰褰曠粨鏋?    if (-not (Test-Path $appDataDir)) {
        New-Item -ItemType Directory -Path $appDataDir -Force | Out-Null

        $subdirs = @("samples", "workspaces", "data", "cache", "ghidra-projects", "ghidra-logs", "logs")
        foreach ($subdir in $subdirs) {
            New-Item -ItemType Directory -Path (Join-Path $appDataDir $subdir) -Force | Out-Null
        }

        Write-Success "鍒涘缓鏂扮殑搴旂敤鏁版嵁鐩綍锛?appDataDir"
    }
}

# =============================================================================
# 姝ラ 5: 楠岃瘉杩佺Щ
# =============================================================================
Write-Step "楠岃瘉杩佺Щ"

Write-Host "`n妫€鏌?WSL2 鍙戣鐗?.." -ForegroundColor $ColorInfo
wsl -l -v

Write-Host "`n妫€鏌?Docker 鏈嶅姟..." -ForegroundColor $ColorInfo
try {
    $dockerVersion = docker --version
    Write-Success "Docker 鍙敤锛?dockerVersion"
} catch {
    Write-Warning-Message "Docker 涓嶅彲鐢紝璇锋墜鍔ㄥ惎鍔?Docker Desktop"
}

# =============================================================================
# 姝ラ 6: 瀹屾垚鎬荤粨
# =============================================================================
Write-Step "杩佺Щ瀹屾垚"

Write-Host "`n杩佺Щ鎽樿锛? -ForegroundColor $ColorSuccess
Write-Success "Docker WSL2 鏁版嵁宸茶縼绉诲埌锛欴:\Docker\wsl\data"
Write-Success "搴旂敤鏁版嵁宸茶縼绉诲埌锛欴:\Docker\decompile-mcp-server"

Write-Host "`n涓嬩竴姝ユ搷浣滐細" -ForegroundColor $ColorInfo
Write-Host "  1. 鍚姩 Docker Desktop" -ForegroundColor $ColorWhite
Write-Host "  2. 杩愯瀹夎鑴氭湰锛?\install-docker.ps1 -DataRoot 'D:\Docker\decompile-mcp-server'" -ForegroundColor $ColorWhite
Write-Host "  3. 纭鎵€鏈夋暟鎹兘鍦?D 鐩? -ForegroundColor $ColorWhite

Write-Host "`n鈿狅笍  閲嶈鎻愮ず锛? -ForegroundColor $ColorWarning
Write-Host "  - 璇风‘璁よ縼绉绘垚鍔熷悗鍐嶅垹闄?C 鐩樼殑鏃ф暟鎹? -ForegroundColor $ColorWhite
Write-Host "  - 鏃ф暟鎹綅缃細$env:USERPROFILE\.windows-exe-decompiler-mcp-server" -ForegroundColor $ColorWhite

Read-Host "`n鎸変换鎰忛敭閫€鍑?.."
