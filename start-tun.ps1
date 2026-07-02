param(
    [switch]$Elevated,
    [string]$Server = $env:SS_SERVER
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root "target\release\ss-client.exe"
$dll = Join-Path $root "target\release\wintun.dll"
$passwordFile = Join-Path $root ".ss-password.dat"
$logFile = Join-Path $root "ss-tun.log"

if ([string]::IsNullOrWhiteSpace($Server)) {
    throw "Missing server address. Set SS_SERVER or pass -Server host:port."
}

trap {
    $_ | Out-String | Add-Content -LiteralPath $logFile
    Write-Host "SS-RS failed. Details: $logFile" -ForegroundColor Red
    Write-Host $_ -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path),
        "-Elevated",
        "-Server", ('"{0}"' -f $Server)
    )
    exit
}

Start-Transcript -Path $logFile -Append | Out-Null

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Missing $exe. Run: cargo build --release"
}
if (-not (Test-Path -LiteralPath $dll)) {
    throw "Missing $dll. Copy the official x64 Wintun DLL beside ss-client.exe."
}

$running = Get-CimInstance Win32_Process -Filter "Name='ss-client.exe'" |
    Where-Object { $_.ExecutablePath -eq $exe }
$tunProcess = $running | Where-Object { $_.CommandLine -match '(?:^|\s)--tun(?:\s|$)' }
if ($tunProcess) {
    Write-Host "SS-RS TUN is already running (PID $($tunProcess.ProcessId))."
    exit
}
$running | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

if (Test-Path -LiteralPath $passwordFile) {
    $securePassword = Get-Content -Raw -LiteralPath $passwordFile | ConvertTo-SecureString
} else {
    $securePassword = Read-Host "SS-RS password" -AsSecureString
    $securePassword | ConvertFrom-SecureString | Set-Content -NoNewline -LiteralPath $passwordFile
}

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $env:SS_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $env:HTTP_PROXY = ""
    $env:HTTPS_PROXY = ""
    $env:ALL_PROXY = ""
    Write-Host "Starting SS-RS global tunnel. Press Ctrl+C to stop."
    & $exe --tun --listen 127.0.0.1:1080 --http-listen 127.0.0.1:1081 --server $Server
    if ($LASTEXITCODE -ne 0) {
        throw "ss-client exited with code $LASTEXITCODE"
    }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Item Env:SS_PASSWORD -ErrorAction SilentlyContinue
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
