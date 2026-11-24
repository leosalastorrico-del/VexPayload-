# Verification: safe by default (never executes the payload).
# Payload-executing tests are lab-only: .\tools\ci.ps1 -Lab with
# VEX_ALLOW_PAYLOAD=1 set explicitly.
param([switch]$Lab)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step($name, [scriptblock]$body) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

Step "build + safe suites" { powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "build.ps1") -Test | Out-Null }
Step "opsec" { python (Join-Path $Root "tools\opsec_check.py") }
Step "fuzz container" { python (Join-Path $Root "tools\fuzz_container.py") --iterations 1000 }

if ($Lab) {
    if ($env:VEX_ALLOW_PAYLOAD -ne "1") {
        throw "refusing: set VEX_ALLOW_PAYLOAD=1 for lab/VM payload tests"
    }
    Step "stage" { python (Join-Path $Root "tools\stage_selftest.py") | Out-Null }
    Step "live e2e" { python (Join-Path $Root "tools\e2e_live.py") | Out-Null }
}

Write-Host "==> CI green (payload not executed)" -ForegroundColor Green
