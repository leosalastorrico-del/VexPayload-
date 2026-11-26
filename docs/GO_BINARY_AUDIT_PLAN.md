# GO — Binary Revision and Audit Plan

Status: **planned, not started**
Candidate: `f7fd70a` (`Add Windows 10 1507+ compatibility and 32-bit loader support`)
Host baseline: Windows 10 Pro 22H2 x64, build 19045
Plan owner: lead / Ollie

## 0. GO contract

When the user says **GO**, execute this plan end-to-end:

- No further confirmation prompts for the steps listed here.
- Stop only on a **P0 safety issue**, a corrupted artifact, or a missing prerequisite.
- Do not release while any mandatory matrix cell is red.
- If a code fix is required, create a new candidate, rerun Phase 0, 1, 2 and every affected matrix cell.
- Produce the evidence pack and a PASS/FAIL report before touching production.

## 1. Candidate freeze and baseline

Capture before any test:

- `git status` clean; commit `f7fd70a`.
- Freeze these files:
  - `dist/Vexpayload.exe`
  - `dist/stager.exe`
  - `dist/Vexpayload_x86.exe`
  - `dist/stager_x86.exe`
  - `dist/BUILD_MANIFEST.json`
  - `dist/BUILD_X86.txt`
- Record SHA256:
  - x64 payload `FB4213970480EEC62DE1584A2E5AF4F38F2D120E9787D5C0130402145D0CD18F`
  - x64 stager `5F7E0DB1ABF3B12DE78A65B3693904B0223DD7A173EF29345920F7EA31598FB0`
  - x86 payload `22F73DB9DDB7B3030CA06C093F3A87E421057264FF8C5F56BDE74C7BC08CC9FF`
  - x86 stager `0C652FCB54F97076987A69EC5A219C4016EC2EF551D2752DAB1875D6F58C3126`
- Archive a read-only copy under `artifacts/audit/<timestamp>/candidate/`.
- Tag the pre-GO state locally: `pre-go-f7fd70a`.
- Back up `VexC2/vex_c2.db`, `-wal`, `-shm`, and the C2 `.master`/`.secret` material.
- Snapshot the C2 VM/host and every test VM.
- Confirm no production C2 traffic can reach the lab VMs.

## 2. Scope

### New binaries
- x64 payload and packed stager.
- x86 payload and packed stager.
- Server-generated decrypter: x86 and x64.

### Code range
- Payload: `f7fd70a` — Windows 10 1507 gate, default heap, UAC build-aware order, task fallback, TLS 1.2, x86 loader.
- C2: `11bcdd7`, `d99b39f`, `021899d`, `0ab91b9` — business state, phantom root, affiliate ownership, paid-only decrypter.

### Explicit non-goals
- No kernel-driver support on pre-19041 builds. BYOVD must report `unsupported-build` and fall back, not crash.
- No Windows 7/8.1 claim; those must exit cleanly.
- No production payload execution on the operator host.

## 3. Phase A — Source and build revision

1. Diff review of the candidate range from the previous release.
2. Review every changed line in:
   - `Vexpayload.cpp`
   - `Vexpayload.vcxproj`
   - `loader/xloader.cpp`
   - `build_x86.ps1`
   - `VexC2/app.py`, `VexC2/c2db.py`, templates
3. Check:
   - No accidental debug flags, test hosts, tokens, keys, or personal paths.
   - No `EnableSegmentHeap` manifest entry.
   - PE subsystem remains 6.00.
   - x86 loader has no x64 syscall stubs, no `.pdata` dependency, and correct HIGHLOW relocation.
   - x86 payload entry uses `__cdecl`.
   - UAC order is build-aware.
   - Task fallback quoting is valid for a path containing spaces.
   - TLS 1.2 pinning applies to both HTTP paths.
   - Version gate allows 10.0.10240 and rejects lower majors.
4. Clean rebuild:
   - `build.ps1 -Test`
   - `build_x86.ps1`
   - `--selftest` for x64 and x86.
5. Reproducibility:
   - Build twice from the same source.
   - Payload and loader hashes must match between clean builds.
   - Stager hashes may differ because `loader/stage_key.h` is per-build; document that.
6. Verify `BUILD_MANIFEST.json` and `BUILD_X86.txt` against the rebuilt artifacts.

**Gate A:** clean build, tests green, no diff drift, hashes recorded.

## 4. Phase B — Static binary audit

For both x64 and x86:

- `dumpbin /headers`: machine, subsystem 6.00, DLL characteristics.
- `dumpbin /imports`: no post-1507-only imports:
  - `SetThreadDescription`
  - `SetProcessDpiAwarenessContext`
  - `GetDpiForWindow`
  - `VirtualAlloc2`
  - `MapViewOfFile3`
  - `CreatePseudoConsole`
  - `GetSystemTimePreciseAsFileTime`
  - `GetTempPath2`
  - `WaitOnAddress` / `WakeByAddress` if not provided by the static CRT target
- Manifest extraction: no SegmentHeap, no unexpected requestedExecutionLevel.
- Pack footer:
  - `VXPAY003` present.
  - payload size, CRC32, salt, nonce, tag, HMAC present.
  - stage key not recoverable from the stager.
- Strings/opsec:
  - `tools/opsec_check.py`
  - no candidate host, token, secret, or local path leakage.
- Signatures:
  - Current manifest says `NotSigned`; either sign payload/loader with the release cert or record an explicit release exception.
- Check x86 stager does not contain the x64 `mov r10, rcx; syscall` stubs.

**Gate B:** no unexpected imports, no manifest regression, no secret leakage, signature decision recorded.

## 5. Phase C — Compatibility matrix

Every cell is a fresh VM snapshot. Run in an isolated lab network; C2 on a local panel.

### Mandatory release matrix

| OS | Build | Arch | Core | UAC | Persistence | BYOVD expectation |
|---|---:|---|---|---|---|---|
| Windows 10 1507 | 10240 | x64 | required | required | required | `unsupported-build`, fallback |
| Windows 10 1507 | 10240 | x86 | required | required | required | `unsupported-build`, fallback |
| Windows 10 1511 | 10586 | x64 | required | required | required | fallback |
| Windows 10 1607 | 14393 | x64 | required | required | required | fallback |
| Windows 10 1703 | 15063 | x64 | required | required | required | fallback |
| Windows 10 1709 | 16299 | x64 | required | required | required | fallback |
| Windows 10 1803 | 17134 | x64 | required | required | required | fallback |
| Windows 10 1809 | 17763 | x64 | required | required | required | fallback |
| Windows 10 1903 | 18362 | x64 | required | required | required | fallback |
| Windows 10 1909 | 18363 | x64 | required | required | required | fallback |
| Windows 10 2004 | 19041 | x64 | required | required | required | driver path |
| Windows 10 20H2 | 19042 | x64 | required | required | required | driver path |
| Windows 10 21H1 | 19043 | x64 | required | required | required | driver path |
| Windows 10 21H2 | 19044 | x64 | required | required | required | driver path |
| Windows 10 22H2 | 19045 | x64 | required | required | required | driver path |
| Windows 10 22H2 | 19045 | x86 | required | required | required | fallback |
| Windows 11 21H2 | 22000 | x64 | required | required | required | `unsupported-build` |
| Windows 11 22H2 | 22621 | x64 | required | required | required | `unsupported-build` |
| Windows 11 23H2 | 22631 | x64 | required | required | required | `unsupported-build` |
| Windows 11 24H2 | 26100 | x64 | required | required | required | `unsupported-build` |
| Server 2016 | 14393 | x64 | required | Desktop Experience only | required | fallback |
| Server 2019 | 17763 | x64 | required | Desktop Experience only | required | fallback |
| Server 2022 | 20348 | x64 | required | Desktop Experience only | required | fallback |

If a VM/ISO cannot be provisioned, the cell is **BLOCKED**, not PASS. Do not call the release complete without a recorded decision.

### Per-cell tests

1. `stager.exe --safe --no-elevate` → exit 2, clean explanation.
2. `stager.exe --selftest --no-elevate` → exit 0.
3. `stager.exe --persist-preview --ping-ms 120000` → exit 0, task XML present.
4. Actual install from a snapshot:
   - Run key written.
   - SYSTEM logon task created by XML; then repeat with XML blocked to force `schtasks /sc onlogon` fallback.
   - Reboot; process returns.
5. C2 checkin, ping, signed report.
6. Dry-run encryption of a sample tree; journal written.
7. Actual encryption on the snapshot; decrypter x86/x64 restores files and timestamps.
8. Uninstall/kill removes Run key, task, IFEO, state where expected.
9. UAC:
   - Default admin.
   - Standard user.
   - UAC "Always notify".
   - Record whether silent elevation worked or `runas` prompted.
10. BYOVD:
    - On 19041–19045: load/blocked/HVCI report.
    - On older/Windows 11: `unsupported-build`, fallback runs, no crash.
11. Check no uncaptured crash, hang, or reboot loop.

**Gate C:** every mandatory cell pass or explicit BLOCKED with rationale; no crash on any supported cell.

## 6. Phase D — Payload functional audit

- Engine:
  - `--dry-run`, actual `--encrypt`, `--check`.
  - Journal v3 and legacy v2.
  - Excluded paths (journal, key file, state).
  - Restore timestamps, `.restored` sidecar, `--force`.
- State:
  - DPAPI state, reboot resume, corrupted state refusal.
  - Single-instance mutex behavior.
- Persistence:
  - Run keys, task XML, fallback, IFEO.
  - `--no-persist`, `--no-usb`, `--no-spread`.
- Comms:
  - HTTP loopback and HTTPS/TLS 1.2.
  - No C2 reachable → backoff, no crash.
  - Signed ping/report/exfil.
- Commands:
  - shell, pull, push, lock, wipe, uninstall, reboot, recon, exfil, screenshot, lateral, USB.
  - Command timeout/retry/cancel.
- Safety:
  - Detonate on a paid victim does not execute.
  - Pardon cancels destructive commands.
  - Kill is idempotent.

## 7. Phase E — C2 and role audit

- C2 self-test: expect **250/250**.
- Phantom root:
  - Admin view: no root username, role, events, payment actor, 2FA path, or root console.
  - Root actions remain invisible to admins.
  - Root login and step-up still work.
- Affiliate:
  - Only owned campaigns appear.
  - Cross-campaign direct URL → 404.
  - Unpaid decrypter → 403.
  - Paid decrypter → 200.
  - Payout accounting and refunds still correct.
- Payments:
  - Paid transitions clear `detonate`.
  - Manual mark-paid books the quote and closes the invoice.
  - Full refund reverts status and commission.
- Campaign:
  - Token accepted and attributed.
  - Nuked campaign cannot compile.
- Decrypter:
  - x86 and x64 build.
  - Paid-only access.
  - Sample restore on every OS cell.
- Service:
  - Restart panel, migration, no stale process.
  - Login and step-up verified.

## 8. Phase F — Security and adversarial review

- Defender/EDR:
  - Real-time scan on the stager and payload.
  - Record detection names; do not disable Defender for the release test.
- HVCI/Credential Guard:
  - Confirm BYOVD refuses and fallback works.
- Strings/entropy:
  - No operator host, token, key, or campaign secret.
- Network:
  - No plaintext C2 outside loopback.
  - TLS certificate validation not bypassed.
- UAC:
  - Verify a non-elevated child cannot report success or recurse.
- Persistence:
  - Verify kill/pardon removes artifacts; no orphan SYSTEM task.
- Review:
  - Re-read all changed code for logic errors.
  - Check no unsigned release exception without explicit sign-off.

## 9. Phase G — Release gate

Release only when:

- Phase A/B: clean.
- Phase C: every mandatory cell PASS; BLOCKED cells explicitly accepted.
- Phase D/E: all P0/P1 tests PASS.
- No unresolved P0/P1 defects.
- P2/P3 documented with owner.
- Hashes match the frozen candidate.
- Signature decision recorded: signed, or signed exception approved.

Deliver:

- `artifacts/audit/<timestamp>/REPORT.md`
- `matrix.csv` with OS/build/arch/result/evidence path
- `hashes.txt`
- `BUILD_MANIFEST.json` verification
- `BUILD_X86.txt` verification
- test logs, screenshots, Defender detections
- defect list by severity
- final release decision

## 10. Rollback

- Restore `dist/` from the frozen `pre-go-f7fd70a` archive.
- Restore the C2 DB and WAL.
- Restore the C2 service and panel process.
- Revert to tag `pre-go-f7fd70a` if any code fix is rejected.
- Revert all VM snapshots.
- Do not leave a partially tested stager in `dist/`.

## 11. Known risks to watch

- UAC “Always notify” breaks silent elevation on every version; that is expected behavior, not a payload crash.
- Old Windows 10 task XML import may fail; the fallback must be proven, not assumed.
- x86 native testing is required; WOW64 passing is not proof for 32-bit Windows.
- BYOVD is unavailable before 19041 and on Windows 11; the fallback must be clean.
- The current binaries are unsigned; Defender may quarantine before execution.
- The C2 is running with `VEX_ALLOW_PLAINTEXT=1` on this host; production key custody must be reviewed separately.
- No test may run against real victim data or the production database.

## 12. GO execution order

1. Freeze and archive.
2. Phase A source/build.
3. Phase B static.
4. Phase C matrix.
5. Phase D payload functional.
6. Phase E C2/role.
7. Phase F security.
8. Phase G release report.
9. Rollback only if gate fails.

**Next GO = execute this plan, not just the happy-path build.**
