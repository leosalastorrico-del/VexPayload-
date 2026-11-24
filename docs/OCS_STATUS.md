# Operation Clean Sweep — execution status

Started 2026-11-23. This is the execution ledger for the plan in
`docs/REMEDIATION_2026-11-23.md`. "Done" means code + regression test; VM rows
are explicitly not claimed.

| Item | State | Evidence / note |
|---|---|---|
| A1 Authenticode ordering + manifest | **done (code)** | `build.ps1 -Sign -Pfx` signs payload/loader before `pack.py`; `dist/BUILD_MANIFEST.json` + optional `VEX_MANIFEST_KEY` HMAC; `tools/verify_manifest.py` runs every build. No certificate on this host: `-Sign`/signed-manifest path untested end-to-end (manifest shows `NotSigned`). |
| A2 Reproducible builds | **partial** | stage key injection and dependency pins exist; compiler/PE timestamp reproducibility not proven. |
| A3 Loader hardening | **partial** | PE bounds/System32/TLS-callback/RX done earlier; stage token still argv and anti-rollback not implemented. |
| A4 Stage transport | **partial** | TLS verification forced, redirects disabled, loopback-only cleartext; host pinning/MITM fixture not run. |
| A5 Signing runbook | **done** | `docs/BUILD.md` + `tools/sign.ps1` updated; no stager Authenticode. |
| B1 Audit chain v2 | **done (SQLite)** | HMAC all rows/backfill, external anchor + verify, prune anchor, serialized appends. PG advisory lock untested. |
| B2 Decrypter journal HMAC | **done (sidecar)** | payload seals journal with AES-key HMAC; decrypter rejects tampered sealed journal and keeps it; unsealed crash journal accepted for recovery. |
| B3 Recovery drills | **done (harness)** | `tools/recovery_selftest.py`: encrypt, journal HMAC, tampered-journal rejection, torn-tail trim, second-run; 13/13. VM power-loss/pardon matrix still manual. |
| B4 Vault KDF/rotation | **partial** | rotation verification/atomic `.master` from prior pass; per-install salt/AAD not done. |
| C1 Privileged UX/2FA | **done** | admin/root/shadow enrollment without lockout, policy prevents disable, keys export POST+step-up, viewer controls hidden, audit anchor test. |
| C2 Payment ledger | **partial** | unique addresses/shared skip; invoice `partial` status; no subaddress/payment-id derivation or auto-refund reversal. |
| C3 PostgreSQL | **blocked** | no Postgres host/driver in this environment; code paths audited only. |
| D1 VM matrix | **blocked** | no Win10/Win11/EDR VMs in this session; scripted subset only. |
| D2 Parser fuzzing | **partial** | container fuzzer + decrypter/journal tamper tests; PE fuzzer not added. |
| D3 Incident runbook | **done** | `docs/INCIDENT_RUNBOOK.md`. |

## Test state
- `build.ps1 -Test`: green, manifest verified (unsigned on this host).
- C2 selftest: 229/229.
- Decrypter selftest: 35/35.
- Recovery drill: 13/13.
- Stage/sleep/e2e/stepup/panic: 5/5, 9/9, 11/11, 8/8, 10/10.
- Final payload `9FF9782DB6E83337…`; stager `9222E905B8682177…` (rebuild after any edit; hashes move with the random stage key).

## Not to be inferred
- No VM/EDR/HVCI detonation was executed in this environment.
- No code-signing certificate was available; the `-Sign` path is untested
  end-to-end.
- The sidecar HMAC can be deleted to downgrade an old journal to CRC-only; a
  crash before sealing intentionally leaves no sidecar.
- Legacy audit rows are backfilled with HMAC but their original integrity is not
  retroactively proven.
