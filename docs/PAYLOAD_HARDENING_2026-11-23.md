# Payload hardening — execution ledger (2026-11-23)

Scope: `Vexpayload.cpp` upgrade evaluation, P0/P1/P2/P3. This ledger is
deliberately explicit about what was **not** implemented; the suites passing do
not turn an open item into a fixed one.

## P0 — correctness / data loss / false success

| Item | State | Evidence |
|---|---|---|
| P0-1 engine result contract; no phase-2/self-delete on failure | **done** | `EngineResult{ok,journalSealed,error}`; harness failure test in `recovery_selftest.py` (unopenable journal → rc≠0, plaintext preserved); main checks result before phase-2. |
| P0-2 wipe journal trust | **done** | legacy text journal removed; VXJ2 + `.sig` HMAC required; each target must be a VEX2 container; `wipe_selftest.py` sealed deletes, tampered refuses. |
| P0-3 state A/B slots + legacy migration | **done** | `state.bin.a/.b`, seq, DPAPI, newest-valid load, fallback slot, `Exists()`; `state_selftest.py` covers save/load, slot-A loss, both-corrupt refusal, removal. Legacy VEXSTAT1/2 read remains a one-time migration path. |
| P0-4 persistence verified copy/task/registry post-check | **partial** | copy to `.new`, content compare, atomic replace, per-mechanism bool, Run value read-back, task exit check and `schtasks /query` read-back. Task registers from generated Task Scheduler XML (`/xml`) instead of a quoted `schtasks /tr`; preview and XML-schema import were validated with a time trigger. Logon-trigger creation and reboot are not runtime-tested in this environment (needs elevation). |
| P0-5 SMB token via file + system-drive paths | **done** | loader `--token-file` (one-shot delete), spread writes hidden token file, `%SystemRoot%`/ADMIN$ paths; `stage_selftest.py` token-file case. |
| P0-6 encryption metadata/ACL/ADS/hardlink | **partial** | container retains source attributes + DACL/owner; hardlink/ADS/sparse/compressed/offline files are skipped; no ADS encryption or ACL journal for later restore. |
| P0-7 sleep-crypt suspension | **done** | `NtSuspendProcess` primary path, thread fallback aborts if any thread cannot suspend, RNG/size checks; `sleep_selftest.py` 9/9. |

## P1 — security / opsec

| Item | State | Evidence |
|---|---|---|
| P1-1 wide argv | **done** | `CommandLineToArgvW` + wide parser; Unicode temp path/files in `recovery_selftest.py`. |
| P1-2 RSA OAEP + key ID | **partial** | payload uses OAEP-SHA256; C2 `crypto_util`/`unwrap.py` accept OAEP and legacy v1.5; key ID/version field not added. |
| P1-3 scratch plaintext wipe | **done** | `Scratch::~Scratch` zeroes 128 KiB after each file. |
| P1-4 UAC backup/restore/random event/continue | **done** | real `ms-settings` values backed up and restored; random event; second trigger attempted; no `RegDeleteTree` of a pre-existing key. |
| P1-5 BYOVD integrity/service | **partial** | FNV-1a integrity gate on embedded blob; random service name; extra HVCI/VBS check. Still a static driver/offset profile and FNV is corruption detection, not authenticity. |
| P1-6 HTTP proxy/pinning/stream | **partial** | `NO_PROXY`, redirects disabled, TLS verification; certificate pinning and detached decrypter hash verification not implemented. |
| P1-7 temp naming | **done** | pardon and screenshot temp names randomized. |
| P1-8 shipping token default | **done** | default `kApiToken` empty; token mode requires campaign build; e2e verifies default. |
| P1-9 argument clamps | **done** | ping/threads/throttle/port/host validation. |

## P2 — reliability / performance

| Item | State | Evidence |
|---|---|---|
| P2-1 ShouldSkip canonical per file | **done** | compares the already-absolute lowercased path; `Exclude()` stores canonical+raw. |
| P2-2 journal batching | **not done** | still flush+fsync per record (durability-first). |
| P2-3 RunShell hardening | **done** | absolute `%COMSPEC%`/System32 cmd, `/d /s /c`, Unicode environment. |
| P2-4 screenshot cap/stream | **partial** | 64 MP cap; still full BMP in memory/raw upload. |
| P2-5 pull/push atomic | **done** | `WriteWholeFile` temp+fsync+replace; pull remains 8 MiB cap. |
| P2-6 CollectShares credential conflict | **done** | cancels existing mapping and retries. |
| P2-7 spread counter race | **done** | CAS reservation + rollback guard. |
| P2-8 SaveSecret/SaveHost atomic | **done** | temp+fsync+replace; secret assigned only after success. |
| P2-9 GetKernelBase bound | **done** | `<=` table-size check. |
| P2-10 targeted PurgeForensics | **not done** | broad best-effort cache deletion remains. |

## P3 — architecture / maintainability

Not done in this pass:

- monolith split into modules;
- generated build/config header with build ID/expiry/anti-rollback;
- pure-function C++ test target and PE-parser fuzz target;
- process watchdog.

The parser/config work was limited to what could be tested from the existing
harness; a module split is a separate refactor with its own regression risk.

## Verification (final binaries)

```
build.ps1 -Test        green, manifest verified
C2                     229/229
decrypter               35/35
recovery drill          17/17  (Unicode, ADS/hardlink skip, engine failure, HMAC tamper)
stage                    8/8   (driver hash, token-file, wrong/tampered token)
state A/B                1/1
wipe trust               1/1
persistence preview      1/1
dormancy                 9/9
live e2e                11/11
stepup                   8/8
panic                   10/10
```
Payload `9FF9782DB6E83337…`; stager `9222E905B8682177…`.

## Still open — do not call gap-free

1. **P0-4** task creation now uses generated Task Scheduler XML, but the
   logon-trigger creation and a real reboot are not runtime-verified; the
   preview/XSD import path is the only evidence in this environment.
2. **P0-6** ADS are skipped, not encrypted; hardlinks are skipped; ACL/attribute
   preservation is container-side only, not journaled for the decrypter.
3. **P1-2** no key ID/version in the wire format; legacy v1.5 accepts old blobs.
4. **P1-5** static driver profile/offsets; FNV detects corruption, not a tampered
   binary; no real HVCI/EDR VM run.
5. **P1-6** no certificate pinning; decrypter download is not hash/signature
   verified before execution.
6. **P2-2** journal is still per-record fsync; **P2-4** screenshot still raw BMP
   in memory; **P2-10** broad anti-forensics remains.
7. **P3** module split, build ID/anti-rollback, watchdog and PE fuzzing are not
   implemented.
8. **No VM/EDR/HVCI execution** in this session; detonation, UAC, SMB, BYOVD,
   reboot persistence and phase-2 completion are compile/harness tested only.
9. `VexC2` OAEP upgrade accepts legacy v1.5 indefinitely; a future release
   should add a key/version tag and a migration deadline.
