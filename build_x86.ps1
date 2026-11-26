# Optional 32-bit payload/stager build for Windows 10 x86 (1507+).
# Run build.ps1 at least once first so loader\stage_key.h exists.
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$MSBuild = "D:\VisualStudio2022\MSBuild\Current\Bin\amd64\MSBuild.exe"
if (-not (Test-Path $MSBuild)) { throw "MSBuild not found at $MSBuild" }
if (-not (Test-Path (Join-Path $Root "loader\stage_key.h"))) {
    throw "run build.ps1 once first (it creates loader\stage_key.h)"
}

$payload = Join-Path $Root "$Configuration\Vexpayload.exe"
$loader = Join-Path $Root "loader\$Configuration\xloader.exe"
$stager = Join-Path $Root "$Configuration\stager.exe"
$dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

& $MSBuild (Join-Path $Root "Vexpayload.vcxproj") /p:Configuration=$Configuration /p:Platform=Win32 /m /v:m /nologo
if ($LASTEXITCODE -ne 0) { throw "x86 payload failed (exit $LASTEXITCODE)" }
& $MSBuild (Join-Path $Root "loader\xloader.vcxproj") /p:Configuration=$Configuration /p:Platform=Win32 /m /v:m /nologo
if ($LASTEXITCODE -ne 0) { throw "x86 loader failed (exit $LASTEXITCODE)" }

python (Join-Path $Root "tools\pack.py") $loader $payload $stager (Join-Path $dist "stage_x86.bin")
if ($LASTEXITCODE -ne 0) { throw "x86 pack failed (exit $LASTEXITCODE)" }

Copy-Item $stager (Join-Path $dist "stager_x86.exe") -Force
Copy-Item $payload (Join-Path $dist "Vexpayload_x86.exe") -Force
$line = "x86 payload: {0} bytes sha256 {1}`r`nx86 stager:  {2} bytes sha256 {3}" -f `
    (Get-Item $payload).Length, (Get-FileHash $payload -Algorithm SHA256).Hash, `
    (Get-Item $stager).Length, (Get-FileHash $stager -Algorithm SHA256).Hash
$line | Set-Content (Join-Path $dist "BUILD_X86.txt") -Encoding UTF8
Write-Host $line -ForegroundColor Green
