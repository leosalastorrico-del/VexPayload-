param([int]$Port = 5000)

# Production launcher for Windows. Requires: pip install -r requirements.txt
$env:PORT = "$Port"
$env:VEX_HOST = if ($env:VEX_HOST) { $env:VEX_HOST } else { "127.0.0.1" }
$env:VEX_SECURE_COOKIE = if ($env:VEX_SECURE_COOKIE) { $env:VEX_SECURE_COOKIE } else { "1" }
$env:VEX_ROOT_USER = if ($env:VEX_ROOT_USER) { $env:VEX_ROOT_USER } else { "Leo" }
if (-not $env:VEX_MASTER -and -not (Test-Path "$PSScriptRoot\.master")) {
    Write-Host "set VEX_MASTER (or create VexC2\.master) before starting"
    exit 1
}
if (-not $env:VEX_PASS -and -not (Test-Path "$PSScriptRoot\vex_c2.db")) {
    Write-Host "set VEX_PASS before the first run (it seeds the admin operator)"
    exit 1
}

python "$PSScriptRoot\run_prod.py"
exit $LASTEXITCODE
