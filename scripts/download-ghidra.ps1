# =============================================================================
# 闁归潧顑呮慨鈺傜▔鐎ｎ厽绁?Ghidra 闁煎瓨纰嶅﹢?# 闁活潿鍔嬬花顒傛喆閿濆懎鏋€ Docker 闁哄瀚紓鎾诲籍閼稿灚锟ユ繛澶嬫磻缁?GitHub 濞戞挸顑堝ù鍥儍閸曨垱锛栧Λ?# =============================================================================

param(
    [string]$Version = "12.0.4",
    [string]$Date = "20240730",
    [string]$OutputDir = ".\downloads"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ghidra 闁归潧顑呮慨鈺傜▔鐎ｎ厽绁扮€规悶鍎遍崣? -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 闁告帗绋戠紓鎾存綇閹惧啿姣夐柣鈺婂枛缂?if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "闁?闁告帗绋戠紓鎾绘儎椤旇偐绉块柨?OutputDir" -ForegroundColor Green
}

# 闁哄瀚紓鎾寸▔鐎ｎ厽绁?URL
$filename = "ghidra_${Version}_PUBLIC_${Date}.zip"
$url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/ghidra_${Version}_BUILD/$filename"

Write-Host "`n濞戞挸顑堝ù鍥ㄧ┍閳╁啩绱?" -ForegroundColor Cyan
Write-Host "  闁绘鐗婂﹢浼存晬?Version" -ForegroundColor White
Write-Host "  闁告瑦鍨电粩鐑藉籍閵夛附鍩傞柨?Date" -ForegroundColor White
Write-Host "  URL: $url" -ForegroundColor White
Write-Host "  闁烩晩鍠楅悥锝夋晬?OutputDir\$filename" -ForegroundColor White

# 婵☆偀鍋撻柡灞诲劜閺嬪啯绂掗懜鍨﹂柛姘剧畱閸戯紕鈧稒锚濠€?if (Test-Path "$OutputDir\$filename") {
    $size = (Get-Item "$OutputDir\$filename").Length / 1MB
    Write-Host "`n闁?闁哄倸娲ｅ▎銏狀啅閹绘帞鎽犻柛锔荤厜缁?OutputDir\$filename (${size}MB)" -ForegroundColor Yellow
    
    $overwrite = Read-Host "闁哄嫷鍨伴幆渚€鏌屽鍡樼厐濞戞挸顑堝ù鍥晬?y/N)"
    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
        Write-Host "闁?濞达綀娉曢弫銈夋偝閻楀牊绠掗柡鍌氭矗濞? -ForegroundColor Green
        exit 0
    }
}

# 濞戞挸顑堝ù鍥棘閸ワ附顐?Write-Host "`n鐎殿喒鍋撳┑顔碱儎缁楀懏娼?.." -ForegroundColor Cyan

try {
    # 濞达綀娉曢弫?Invoke-WebRequest 濞戞挸顑堝ù鍥晬閸喐鏆滈柟闀愮劍閺屽洭鎮欓崷顓犳暰濞磋偐濯寸槐?    $ProgressPreference = 'SilentlyContinue'  # 缂佸倷鑳堕弫銈嗘交濞戞ê顔婇柡澶嗗墲濡绮?    
    Invoke-WebRequest -Uri $url -OutFile "$OutputDir\$filename" -UseBasicParsing
    
    $ProgressPreference = 'Continue'
    
    # 濡ょ姴鐭侀惁澶愬棘閸ワ附顐藉鍫嗗啰姣?    $size = (Get-Item "$OutputDir\$filename").Length
    $sizeMB = [math]::Round($size / 1MB, 2)
    
    Write-Host "`n闁?濞戞挸顑堝ù鍥箣閹邦剙顫?" -ForegroundColor Green
    Write-Host "  闁哄倸娲ｅ▎銏″緞瑜嶉惃顒勬晬?sizeMB MB" -ForegroundColor White
    
    # 缂佺姭鍋撻柛妤佹礋閻涙瑧鎷?ZIP 闁哄倸娲ｅ▎?    Write-Host "`n濡ょ姴鐭侀惁?ZIP 闁哄倸娲ｅ▎?.." -ForegroundColor Cyan
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead("$OutputDir\$filename")
        $entryCount = $zip.Entries.Count
        $zip.Dispose()
        
        Write-Host "闁?ZIP 闁哄倸娲ｅ▎銏ゅ嫉婢跺娅?(闁告牕鎳庨幆?$entryCount 濞戞搩浜濋弸鍐╃?" -ForegroundColor Green
    } catch {
        Write-Host "闁?ZIP 闁哄倸娲ｅ▎銏ゅ箲閻旈攱缍? -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "濞戞挸顑勭粩鏉戭潰閵夛附鎯欏ù?" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. 閻?ghidra.zip 濠㈣泛绉撮崺妤呭礆娴兼番鈧秹鎯勯鐣屽闁烩晩鍠栫紞? -ForegroundColor White
    Write-Host "2. 閺夆晜鍔橀、鎴︽晬濮濈€榗ker build --build-arg GHIDRA_ZIP_PATH=.\ghidra.zip -t windows-exe-decompiler:latest ." -ForegroundColor White
    Write-Host "`n闁瑰瓨鐗為埀顒€鎳愬ú鍧楀箳閵夈倕鈻忛柣顫妼閻ｃ劎鎲楅崨鏉垮闁哄牜鍓ㄧ槐娆愬濮樺啿娈伴柛鏂诲妽椤ュ懎霉鐎ｂ晝鐟撻弶鐐垫櫕濞堟垿寮崶锔筋偨闁? -ForegroundColor White
    
} catch {
    $ProgressPreference = 'Continue'
    
    Write-Host "`n闁?濞戞挸顑堝ù鍥ㄥ緞鏉堫偉袝" -ForegroundColor Red
    Write-Host "闂佹寧鐟ㄩ銈嗙┍閳╁啩绱栭柨?($_.Exception.Message)" -ForegroundColor Red
    
    Write-Host "`n闁告瑯鍨甸崗姗€鎯冮崟顐㈡枾闁?" -ForegroundColor Yellow
    Write-Host "  1. 缂傚啯鍨圭划鑸垫交閻愭潙澶嶉梻鍌ゅ櫍椤? -ForegroundColor White
    Write-Host "  2. GitHub 閻炴凹鍋勯惃婵嬫煥? -ForegroundColor White
    Write-Host "  3. URL 濞戞挸绉甸婊呮兜? -ForegroundColor White
    
    Write-Host "`n鐎点倝缂氶鍛喆閿濆懎鏋€闁哄倽顫夐、?" -ForegroundColor Cyan
    Write-Host "  1. 濞达綀娉曢弫銈吤硅箛姘兼綌闁革絻鍔嶆晶婊堝礉閵娿倗鐟撻弶鐐存灮缁?url" -ForegroundColor White
    Write-Host "  2. 濞达綀娉曢弫銈嗙閿濆洦鍊炵€规悶鍎遍崣鎸庣▔鐎ｎ厽绁? -ForegroundColor White
    Write-Host "  3. 濞达綀娉曢弫銈囩箔椤戣法鐟忛柡鍌炩偓娑氱憮閺夌偠妫勬导鎰板礂閸戙倗绀勫┑?IDM闁靛棔宸ia2c闁? -ForegroundColor White
    
    exit 1
}
