$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$mihomo = if ($env:SS_RS_MIHOMO_PATH) { $env:SS_RS_MIHOMO_PATH } else { Join-Path $root "target\tools\mihomo-1.19.27\mihomo-windows-amd64.exe" }
$wintun = if ($env:SS_RS_WINTUN_PATH) { $env:SS_RS_WINTUN_PATH } else { Join-Path $root "target\release\wintun.dll" }
$output = Join-Path $root "dist\SS-RS-CDN.exe"

foreach ($name in "VLESS_SERVER", "VLESS_PORT", "VLESS_UUID", "VLESS_SNI", "VLESS_XHTTP_PATH") {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Missing build environment variable: $name"
    }
}
if (-not (Test-Path -LiteralPath $mihomo)) { throw "Missing Mihomo core: $mihomo" }
if (-not (Test-Path -LiteralPath $wintun)) { throw "Missing Wintun DLL: $wintun" }
if ((Get-AuthenticodeSignature -LiteralPath $wintun).Status -ne "Valid") { throw "Wintun signature is invalid" }

$env:SS_RS_MIHOMO_PATH = $mihomo
$env:SS_RS_WINTUN_PATH = $wintun
& cargo build --release -p ss-gui
if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed" }

New-Item -ItemType Directory -Force -Path (Split-Path $output) | Out-Null
Copy-Item -Force -LiteralPath (Join-Path $root "target\release\SS-RS.exe") -Destination $output
Write-Host "Created $output"
