# Lab matrix — dormancy & loader checks
#
# Manual-first. Run from the repository root in an elevated PowerShell.
# Each block is a checklist item; -Run executes the scripted subset.
param([switch]$Run)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$Exe = Join-Path $Root "x64\Release\Vexpayload.exe"
$Stager = Join-Path $Root "x64\Release\stager.exe"
$Scan = Join-Path $Root "tools\mem_scan.py"
$Marker = "VEX_MEM_MARKER_9f3a7c"
$Results = Join-Path $Root "docs\LAB_RESULTS.md"

function Say($t) { Write-Host "==> $t" -ForegroundColor Cyan }

Say "Preflight"
foreach ($p in @($Exe, $Stager, $Scan)) {
    if (-not (Test-Path $p)) { throw "missing $p" }
}
$env:VEX_ALLOW_PAYLOAD = "1"

if ($Run) {
    Say "1. Dormant memory proof (helper-process image encryption)"
    python (Join-Path $Root "tools\sleep_selftest.py")
    if ($LASTEXITCODE -ne 0) { throw "sleep selftest failed" }

    Say "2. Loader selftest (stager, no elevation)"
    & $Stager --selftest --no-elevate
    if ($LASTEXITCODE -ne 0) { throw "loader selftest failed" }

    Say "3. Stage fetch selftest"
    python (Join-Path $Root "tools\stage_selftest.py")
    if ($LASTEXITCODE -ne 0) { throw "stage selftest failed" }
}

Say "Manual VM checklist (record in docs/LAB_RESULTS.md)"
@"
[ ] Win10 22H2 + Defender on:
    - stager checkin, command, exfil
    - --sleep-crypt: mem_scan marker 0 while asleep, wake and ping
    - scoped detonation + decrypter roundtrip
[ ] Win11 23H2 + HVCI on:
    - same four checks; note Defender/HVCI verdicts
[ ] EDR VM:
    - sleep-crypt helper child visibility, process creation telemetry
    - whether parent image is flagged during 60 s sleep
[ ] Elevated scanner for stager runs: mem_scan must run elevated because the
    stager self-elevates; the unelevated harness test covers the payload image.
"@

Say "Append results to $Results (template exists)"
