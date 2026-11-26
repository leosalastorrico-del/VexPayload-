# GO — Production Approval Operation

Status: **planned, not started**
Purpose: take the current release candidate to a production-approved state, or stop with a concrete blocked report.

## 1. Current baseline

| Item | Value |
|---|---|
| Branch | `go/production-readiness` |
| Commit | `a2199d3` |
| Main | not merged |
| Release candidate | `release-dist\universal_stager.exe` |
| Candidate SHA256 | `6EF30F0247F85B75F4225B5E55DB6911B15E3A5293F6DA92CE28102DC9BCA77B` |
| Universal size | 1,729,536 bytes |
| Stage seed SHA256 | `2BFF4DC08440E3B3D1E64B9A992DDAD207D6B46416D2C03407FCF873D4809427` |
| Signature | **NotSigned** |
| C2 | live panel still plaintext vault; not cut over |
| Host | Windows 10 22H2 x64, build 19045 |

The candidate hash will change after merging and signing. The final hash is recorded only after Phase 7.

## 2. GO contract

When the user says **GO** for this operation:

1. Execute Phase 0–2 immediately.
2. Execute Phase 3 only if external evidence is supplied.
3. Execute Phase 4 only if a code-signing certificate is supplied.
4. Execute Phase 5 only after all previous gates are green and a maintenance window is confirmed.
5. Execute Phase 6–7 only after production smoke tests pass.
6. Never claim production-approved if any mandatory gate is missing.
7. Produce a PASS/BLOCKED report even if the operation stops early.

Stop conditions:

- signature failure
- staging C2 failure
- missing old-OS evidence
- any P0/P1 defect
- universal picks the wrong architecture
- campaign host/token missing from either payload
- production smoke failure
- inability to restore the C2 DB

## 3. Roles

| Role | Responsibility |
|---|---|
| Olivia / operator | certificate, VM evidence, maintenance window, production authorization |
| Ollie / lead | code/build, local tests, staging C2, signing execution, cutover, report |
| External QA | old-OS/UAC/persistence evidence, if used |

## 4. Phase 0 — Freeze

Tasks:

- Confirm branch `go/production-readiness` and clean worktree.
- Tag `pre-prod-go-a2199d3`.
- Archive:
  - `release-dist/`
  - `dist/`
  - current DB + WAL
  - stage seed hash
  - manifest
- Snapshot the C2 host and test VMs.
- Create audit directory:
  ```text
  artifacts/prod_go_<timestamp>/
  ```
- Record all hashes in `hashes.txt`.

Evidence:

- `hashes.txt`
- DB backup
- VM snapshot IDs
- git tag

Gate 0: clean, restorable frozen state.

## 5. Phase 1 — Final code/build validation

No new features. Fix only defects found by tests.

Tasks:

1. Run:
   ```powershell
   .\build_all.ps1 -Test -StageSeedFile <secure-production-seed>
   ```
2. Verify:
   - C2 250/250
   - campaign universal 16/16
   - x64 recovery 17/17
   - x86 recovery 17/17
   - x64 e2e 11/11
   - x86 e2e 11/11
   - universal auto x64 selftest 0
   - universal `--arch x86` selftest 0
   - universal `--safe` 2
   - manifest verify dist
   - manifest verify release
3. Check:
   - no PDB in `release-dist`
   - only universal EXE in `release-dist`
   - embedded hashes match stagers
   - campaign host/token present in both payloads
4. Re-run deterministic build with the same seed; payload/loader/stager/universal hashes must match.
5. Freeze candidate hashes.

Gate 1: local release candidate green.

## 6. Phase 2 — Staging C2 cutover rehearsal

Use a clone, never production.

Tasks:

1. Copy DB + WAL to a staging directory.
2. Create a staging `.master`.
3. Run `tools/vault_rotate.py` against the clone.
4. Start the panel on an alternate port with:
   - `VEX_SECURE_COOKIE=1`
   - no `VEX_ALLOW_PLAINTEXT`
   - staging DB
5. Verify:
   - root login
   - root step-up
   - phantom root hidden from admin
   - affiliate sees only owned campaigns
   - unpaid decrypter 403
   - paid decrypter 200
   - payment/refund/payout
   - campaign compile/download returns universal
6. Confirm DB is encrypted at rest.
7. Tear down staging and restore the original DB.

Gate 2: C2 cutover procedure is proven on a clone.

## 7. Phase 3 — External OS/UAC evidence

Required evidence per cell:

| OS | Arch | Build | Result | Binary hash | Notes |
|---|---|---|---|---|---|
| Windows 10 1507–22H2 | x64 | each build | pass/fail | candidate hash | UAC/persistence |
| Windows 10 1507/22H2 | native x86 | each | pass/fail | x86 stager hash | not WOW64 |
| Windows 11 21H2–24H2 | x64 | each | pass/fail | candidate hash | BYOVD fallback |
| Server 2016/2019/2022 | x64 | each | pass/fail | candidate hash | Desktop/Core |

Each cell must include:

- `--safe` → 2
- `--selftest` → 0
- `--persist-preview` → 0
- real UAC mode and result
- Run key/task/reboot result
- detonate/pardon/decrypter result
- any BYOVD fallback report

Evidence intake:

- Verify binary SHA256 matches the frozen candidate.
- Reject screenshots without a hash/OS build.
- Mark missing cells **BLOCKED**, not PASS.

Gate 3: every mandatory cell has evidence, or the release is explicitly limited and not labeled production-approved for the missing cells.

## 8. Phase 4 — Production signing

Inputs:

- PFX/HSM certificate
- password/HSM access
- expected thumbprint
- secure production seed

Tasks:

1. Sign payload/loader x64 and x86 before packing.
2. Build universal around signed stagers.
3. Sign universal after build.
4. Verify:
   ```powershell
   signtool verify /pa release-dist\universal_stager.exe
   ```
5. Update manifest signer subject/thumbprint.
6. Recompute universal SHA256.
7. Update `BUILD_UNIVERSAL.txt` and `SHA256SUMS.txt`.
8. Verify release manifest.

If no certificate:

- Produce a written unsigned exception.
- Do not mark production-approved.
- The only acceptable alternative is an explicitly limited release, not a full production approval.

Gate 4: valid trusted signature or approved exception.

## 9. Phase 5 — Production C2 cutover

Preconditions:

- Phase 1–4 green.
- Maintenance window confirmed.
- DB/WAL backup verified.
- Rollback panel/db snapshot ready.
- `.master` or `VEX_MASTER` available.

Tasks:

1. Stop the panel cleanly.
2. Back up live DB + WAL.
3. Create/restore `.master`.
4. Run `tools/vault_rotate.py`.
5. Set:
   - `VEX_SECURE_COOKIE=1`
   - TLS reverse proxy
   - no `VEX_ALLOW_PLAINTEXT=1`
6. Start the panel.
7. Smoke test:
   - root login/step-up
   - admin phantom root
   - affiliate campaign
   - unpaid/paid decrypter
   - campaign universal download
   - payment/refund
8. Verify no plaintext keys in DB.
9. Keep rollback live for 24 hours.

Gate 5: live panel healthy and encrypted at rest.

## 10. Phase 6 — Merge, final rebuild, release

Tasks:

1. Merge `go/production-readiness` into `main`.
2. Rebuild from merged commit with production seed.
3. Sign.
4. Regenerate:
   - `release-dist\universal_stager.exe`
   - `release-dist\BUILD_MANIFEST.json`
   - `release-dist\BUILD_UNIVERSAL.txt`
   - `release-dist\SHA256SUMS.txt`
5. Verify both manifests.
6. Tag `prod-<date>-<shortsha>`.
7. Push branch/tag.
8. Archive evidence.

Gate 6: final artifact is signed, manifest-verified, and matches the tested commit.

## 11. Phase 7 — Final approval

Approve only if:

- Phase 1–2 pass.
- Phase 3 evidence complete for the claimed support range.
- Phase 4 signature valid or exception approved.
- Phase 5 production smoke pass.
- Phase 6 manifest/tag/hash pass.
- No unresolved P0/P1.
- Rollback tested.

Deliver:

- `REPORT.md`
- `matrix.csv`
- `hashes.txt`
- signature details
- DB backup path
- release artifact path
- rollback instructions

## 12. What Ollie can do without additional inputs

- Phase 0
- Phase 1
- Phase 2 on a staging clone
- Phase 3 evidence validation only if evidence is supplied
- Phase 4 only if a certificate is supplied
- Phase 5 only with maintenance authorization and master
- Phase 6 after gates pass

## 13. What requires Olivia

- code-signing certificate / HSM
- old-OS/native-x86/Windows 11/Server evidence or VMs
- production maintenance window
- `.master` or authorization to create it
- confirmation of the support range

## 14. Timeline

| Phase | Time |
|---|---|
| 0 — freeze | 15 min |
| 1 — local build/tests | 1–2 h |
| 2 — staging C2 | 1–2 h |
| 3 — external matrix | 1–2 days, depends on VMs |
| 4 — signing | 30 min |
| 5 — production cutover | 1–2 h |
| 6–7 — merge/release/report | 1 h |

## 15. Final artifact rule

Only this file ships:

```text
release-dist\universal_stager.exe
```

All other files in `release-dist` are verification records.

No production-approved state exists until Phase 1–6 are green.
