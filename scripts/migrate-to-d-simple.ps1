# =============================================================================
# Docker 閻庣懓鑻崣蹇旀交娴ｇ洅鈺呭礆?D 闁烩晜顭堥崜濂稿嫉椤掑﹦绀勭紒鐘亾闁告牗鐗滄晶妤呮晬?# =============================================================================
# 闁告梻鍠曢崗?
#   - 閺夆晙鑳朵簺 Docker WSL2 闁轰胶澧楀畵渚€宕?D 闁?#   - 閺夆晙鑳朵簺閹煎瓨姊婚弫銈夊极閻楀牆绁﹂柛?D 闁?#   - 濡ょ姴鐭侀惁澶嬫交娴ｇ洅鈺呭箣閹邦剙顫?# =============================================================================

#Requires -RunAsAdministrator

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "  Docker 閻庣懓鑻崣蹇旀交娴ｇ洅鈺呭礆?D 闁? -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "`n[1/6] 婵繐绲藉﹢顏堝磻濠婂嫷鍓?Docker Desktop..." -ForegroundColor Yellow
Get-Process "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 5

Write-Host "[2/6] 婵繐绲藉﹢顏堝磻濠婂嫷鍓?WSL2..." -ForegroundColor Yellow
wsl --shutdown
Start-Sleep -Seconds 3

Write-Host "`n[3/6] 婵繐绲藉﹢顏嗏偓鐢靛帶閸?Docker 闁轰胶澧楀畵渚€鏁嶉崼锝囩闁告瑯鍨甸崗姗€妫侀埀顒傛啺?5-10 闁告帒妫濋幐鎾绘晬?.." -ForegroundColor Yellow
Write-Host "      婵犙勫姧缁辩檲 闁?WSL2 闁告瑦鍨奸、鎴︽偋? -ForegroundColor Gray
Write-Host "      闁烩晩鍠楅悥锝夋晬濞?\Docker\wsl\docker-data.tar" -ForegroundColor Gray

if (Test-Path "D:\Docker\wsl\docker-data.tar") {
    Write-Host "      闁告瑦鍨归獮鍥ь啅閹绘帞鎽犻柛锔哄妿濞堟垹鈧數鍘ч崵顓㈠棘閸ワ附顐介柨娑樿嫰閸ㄥ綊姊介妶鍕幀..." -ForegroundColor Gray
    Remove-Item "D:\Docker\wsl\docker-data.tar" -Force
}

wsl --export docker-desktop-data "D:\Docker\wsl\docker-data.tar"

if (Test-Path "D:\Docker\wsl\docker-data.tar") {
    $size = (Get-Item "D:\Docker\wsl\docker-data.tar").Length / 1GB
    Write-Host "      闁?閻庣數鍘ч崵顓犫偓鐟版湰閸ㄦ岸鏁?([math]::Round($size, 2)) GB" -ForegroundColor Green
} else {
    Write-Error "閻庣數鍘ч崵顓熷緞鏉堫偉袝闁?
    Read-Host "闁圭顦幑銏ゅ箛韫囨稒鏆涢梺顐熷亾闁?
    exit 1
}

Write-Host "`n[4/6] 婵繐绲藉﹢顏勨枖閵娾晜鏁?C 闁?Docker 闁轰胶澧楀畵?.." -ForegroundColor Yellow
wsl --unregister docker-desktop-data
Write-Host "      闁?鐎圭寮堕弫鐐烘煥閳?docker-desktop-data" -ForegroundColor Green

Write-Host "`n[5/6] 婵繐绲藉﹢顏呯?D 闁烩晜锚椤曢亶宕?Docker 闁轰胶澧楀畵?.." -ForegroundColor Yellow
Write-Host "      闁烩晩鍠楅悥锝夋儎椤旇偐绉块柨娑欘儚:\Docker\wsl\data" -ForegroundColor Gray

if (-not (Test-Path "D:\Docker\wsl\data")) {
    New-Item -ItemType Directory -Path "D:\Docker\wsl\data" -Force | Out-Null
}

wsl --import docker-desktop-data "D:\Docker\wsl\data" "D:\Docker\wsl\docker-data.tar" --version 2

Write-Host "      闁?閻庣數鍘ч崣鍡欌偓鐟版湰閸? -ForegroundColor Green

Write-Host "`n[6/6] 婵繐绲藉﹢顏勩€掗崨顖涘€炲☉鎾崇摠濡炲倿寮崶锔筋偨..." -ForegroundColor Yellow
Remove-Item "D:\Docker\wsl\docker-data.tar" -Force
Write-Host "      闁?鐎圭寮剁粩濠氭偠? -ForegroundColor Green

Write-Host "`n==================================================" -ForegroundColor Green
Write-Host "  闁?Docker 鐎圭寮堕崹姘跺礉閻旇崵璁ｇ紒澶庮嚙閸?D 闁烩晜锕槐? -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

Write-Host "`n閺夆晙鑳朵簺濞达絽绉堕悿?" -ForegroundColor Cyan
Write-Host "  Docker WSL2 闁轰胶澧楀畵渚€鏁嶅▎?\Docker\wsl\data" -ForegroundColor White
Write-Host "  閹煎瓨姊婚弫銈夊极閻楀牆绁﹂柣鈺婂枛缂嶅秹鏁嶅▎?\Docker\decompile-mcp-server" -ForegroundColor White

Write-Host "`n濞戞挸顑勭粩鏉戭潰閵夛附鎯欏ù?" -ForegroundColor Cyan
Write-Host "  1. 闁告凹鍨版慨?Docker Desktop" -ForegroundColor White
Write-Host "  2. 閺夆晜鍔橀、鎴︽晬?\install-docker.ps1 -DataRoot 'D:\Docker\decompile-mcp-server'" -ForegroundColor White

Write-Host "`n闁圭顦幑銏ゅ箛韫囨稒鏆涢柛姘煎灠婵?Docker Desktop..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
