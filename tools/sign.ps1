# Code-signing prep. Without a certificate this is a no-op that prints the
# exact commands; with a .pfx it signs every deliverable.
param(
    [string]$Pfx = "",
    [string]$Password = "",
    [string]$Timestamp = "https://timestamp.digicert.com",
    [string]$ExpectedThumbprint = "",
    [string[]]$Targets = @()
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
# The packed stager must NOT be Authenticode-signed: the certificate table is
# appended after the VXPAY003 footer and breaks loading. Sign the payload and
# loader before packing instead, then rebuild the stager.
if ($Targets.Count -gt 0) {
    $targets = $Targets | Where-Object { Test-Path $_ }
} else {
    $targets = @(
        (Join-Path $Root "x64\Release\Vexpayload.exe"),
        (Join-Path $Root "loader\x64\Release\xloader.exe")
    ) | Where-Object { Test-Path $_ }
}

if (-not $targets) {
    Write-Host "[!] no signed targets found - build first"
    exit 1
}

$signtool = $null
$candidates = @(
    (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending)
)
if ($candidates) { $signtool = $candidates[0].FullName }
if (-not $signtool) { throw "signtool.exe not found under Windows Kits; install the SDK" }

if (-not $Pfx) {
    Write-Host "==> signing prepared (no certificate supplied)"
    Write-Host "  1. obtain an EV/OV code-signing certificate (PFX + password)"
    Write-Host "  2. run:"
    Write-Host "     .\tools\sign.ps1 -Pfx C:\path\cert.pfx -Password '***'"
    Write-Host "  targets (sign before packing):"
    $targets | ForEach-Object { Write-Host "    $_" }
    Write-Host "  signtool: $signtool"
    exit 1
}

if (-not (Test-Path $Pfx)) { throw "PFX not found: $Pfx" }
if (-not $Password) {
    $sec = Read-Host "PFX password" -AsSecureString
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if (-not $signtool) { throw "signtool.exe not found" }
& $signtool sign /f $Pfx /p $Password /fd SHA256 /tr $Timestamp /td SHA256 $targets
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
& $signtool verify /pa $targets
if ($LASTEXITCODE -ne 0) { throw "signature verification failed" }
if ($ExpectedThumbprint) {
    foreach ($t in $targets) {
        $sig = Get-AuthenticodeSignature $t
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) {
            throw "unexpected signer/status for $t"
        }
    }
}
Write-Host "==> signed and verified; now re-run build.ps1 to repack the stager" -ForegroundColor Green
