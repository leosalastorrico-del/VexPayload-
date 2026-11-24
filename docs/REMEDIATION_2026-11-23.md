# Remediation pass — 2026-11-23

This pass applied the P0/P1 fixes from `MASTER_EVALUATION.md` where a safe
change could be made and regression-tested. It is **not** a claim that every
finding is gone; the remaining items are listed at the bottom and must not be
mistaken for resolved.

## Fixed and tested

### C2 / authentication / custody
- `/api/checkin` delivers the HMAC secret **only on first registration**;
  re-registration of an existing VID requires `X-Vex-Ts/X-Vex-Sig` and is
  rejected otherwise. The payload signs re-checkins and refuses to run if it
  has no secret.
- `/api/pardon_exe` requires `pardon=1`.
- Portal proof is **one-time per victim** and consumes the attempt before
  decryption, so it is no longer an unlimited decryption oracle.
- Step-up replay stores the pending form **server-side** under a random token;
  only the token is in the session cookie.
- Root/shadow 2FA enrollment requires the current password; `require_2fa`
  (when enabled) still blocks admins without TOTP; root/shadow log in and are
  forced into TOTP by the destructive-action gate.
- `X-Forwarded-For` is only honored with `VEX_TRUST_PROXY=1`; nginx overwrites
  it and the service sets the flag.
- Victim AES keys are hidden from viewer/negotiator roles.
- `/admin/backup` requires root+step-up and redacts root/shadow/TOTP rows.
- Security headers (nosniff, DENY, CSP, HSTS when TLS) added.
- Panic pins cannot be replaced from the UI once configured.
- Root view-as cannot target shadow; deadman heartbeat continues while
  impersonating; step-up operator lookup no longer falls back to another root.
- Settings typing/validation; missing `require_2fa`, idle/rate-limit/negotiation/
  exfil keys added; wallet RPC password and API token are masked and blank means
  keep.
- Campaign build JSON no longer returns the API token; root console redacts the
  Postgres URL.

### State, audit, money, exfil
- Deadline locking skips pardoned/paid/dead victims; pardon and payment cancel
  queued `lock`/`wipe`; scheduled/deadman fleet actions skip paid/pardoned.
- `finish_command` is bound to `(id, vid, status='dispatched')`;
  `expire_commands` uses a compare-and-swap.
- Payment polling refuses shared addresses (no wrong-victim release), checks a
  finite rate, records the ledger, cancels destructive commands and syncs the
  invoice. Zero-price victims cannot be marked paid.
- Add-payment ledger/invoice handling fixed for zero price.
- Exfil v2 requires a known victim; assembly verifies per-chunk hashes, size and
  path confinement; delete is confined to uploads; unknown-victim v1 exfil is
  rejected.
- Audit events are serialized, the chain head and prune anchor are tracked,
  verification reads all rows, new events carry an HMAC keyed by
  `VEX_AUDIT_KEY`/`VEX_SECRET`/`.secret`, and pruned prefixes no longer break
  verification.
- Destructive `victims` migration now builds `victims_new`, verifies row counts,
  recovers an interrupted `victims_old`, and never drops the live table first.
- Vault rotation writes `.master` atomically, makes it durable before DB
  re-keying, refuses concurrent rotation, blocks new seals, verifies every
  sealed value, and keeps a pre-rotation DB backup. `.master` takes precedence
  over `VEX_MASTER`; `VEX_MASTER_FILE` relocates it for tests.

### Payload
- Ciphertext is `FlushFileBuffers`'d and replaced with
  `MOVEFILE_WRITE_THROUGH`.
- Torn journal tails are trimmed; foreign journals are quarantined; the header
  is validated; writes still flush before replace.
- RNG failure is checked for nonce/key generation; key generation aborts.
- A named mutex prevents concurrent payload instances/journal writers.
- `wipe` parses the binary VXJ2 journal; a corrupt journal keeps recovery
  material. `kill` keeps the journal/state when a journal exists.
- State saves use temp + fsync + hidden attributes + atomic replace; phase-0 and
  phase-1 save failures abort encryption.
- Harness `--key-out` refuses to overwrite an existing key and aborts on write
  failure; unknown arguments are rejected; loader-side flags are consumed.
- Elevation preserves the original argument tail (UAC bypass and runas).
- `--no-shares` no longer starts the SMB spray; `--no-usb` only stops USB;
  mapped network drives are skipped unless share encryption is explicitly on.
- Active C2 host is mutex-protected; host override path fixed; secret write uses
  hidden/system attributes; beacon metadata is URL-encoded; TLS verification is
  forced except loopback; command pipe final drain no longer blocks on a
  grandchild; IFEO never clobbers a foreign Debugger value; shell pipe timeout
  uses 64-bit tick count.
- Sleep-crypt helper validates the target image path and shared-memory magic,
  reducing the arbitrary-process primitive.
- `%ProgramData%\VEX` is re-ACLed to SYSTEM + Administrators before state/secret
  writes, so default ProgramData Users-read does not expose the key/secret.

### Loader / build / signing
- PE `SizeOfHeaders`, section table, section destinations, relocations and
  imports are bounds-checked; entry point validated.
- DLL loads use `LOAD_LIBRARY_SEARCH_SYSTEM32`; TLS certificate validation is
  always on (cleartext staging only for loopback); `--inspect` no longer
  elevates or patches; TLS callbacks run after section protections; syscall
  stubs are RX after writing.
- `build.ps1` generates a random 32-byte stage key into
  `loader/stage_key.h`, compiles it into the loader, and `pack.py`/
  `verify_spread.py`/`campaign_selftest.py` read the same file. The public
  constant key is gone.
- `sign.ps1` no longer signs the packed stager (which would corrupt the footer),
  pins signtool to the SDK, defaults the timestamp to HTTPS, validates the
  signer thumbprint, and fails when no certificate is supplied.
- `build.ps1` freshness includes tools/scripts and fails on a missing source
  baseline.

### Decrypter
- Legacy v1 rewinds before reading the chunk count; zero-chunk/non-container
  files are rejected; unverified legacy restores write `.restored` instead of
  replacing the source.
- Journal parse anomalies are fatal, keep the journal, and never publish a
  partial prefix; version/record bounds and the `el` OOB read are fixed.
- Journal targets must be drive-absolute, not UNC/device/GLOBALROOT, and
  `orig==enc`; `bcrypt.dll` loads from System32; GUI honors check/force;
  elevation preserves paths with spaces; output is flushed and write-through.

### Tests/tools
- `c2_selftest` uses temp DB/uploads/build cache, a generated RSA key and a
  test audit key; new regressions cover registration-secret non-reissue,
  unsigned recheckin, pardon gate, one-time proof, backup redaction, deadline
  pardon skip and step-up cookie secrecy.
- `stage_selftest`/`e2e_live` propagate `main()` failures; `e2e_live` no longer
  prints a generated admin password; `pg_integration` requires an explicit
  test-DB marker and signs its report; `RSA.py` refuses to overwrite `priv.pem`;
  `root_pin` rejects multiple/nonstandard roots; `campaign_selftest` skips with
  a non-zero code.

## Verification (this pass)
```
build.ps1 -Test                 green
c2 selftest                     223/223
decrypter selftest              35/35
stage selftest                  5/5
dormancy selftest               9/9
live e2e                        11/11
stepup live                     8/8
panic live                      10/10
payload encrypt/journal lab     round-trip OK; torn-tail repair OK
```
Final payload sha256 `9FF9782DB6E83337…`; stager sha256
`9222E905B8682177…`; stage key is generated per build and is **not** a
repository constant.

## Still open — do not treat as fixed

1. **Audit chain:** new events are HMACed, legacy rows are backfilled, the head
   is anchored outside the DB and verified on restart; PostgreSQL appends still
   rely on application serialization rather than a DB advisory lock, and an
   attacker with write access to both DB and anchor/`.secret` can still forge.
2. **Vault KDF:** fixed salt/120k PBKDF2/no AAD; rotation safer but not fully
   crash-atomic across DB + chunk files (backup is the recovery path).
3. **Payload key custody:** state/secret directory ACL is hardened, but the AES
   key is still machine-scope DPAPI (any local administrator can decrypt it);
   staged/reflective persistence still copies the host loader when no payload is
   embedded; SMB service launch expects a dispatcher; shell uses CreateProcess
   search order; anti-forensics results are not all checked; kernel EPROCESS
   walk remains best-effort.
4. **Decrypter:** sealed journals carry an AES-key HMAC sidecar (payload writes
   it at the end of a run; a crash before sealing leaves no sidecar by design so
   recovery still works); sidecar deletion downgrades to CRC-only. ACL
   restoration is incomplete; reports to `/api/report` are unsigned and rejected
   when a victim secret exists, so decrypter telemetry is lost.
5. **C2 UI:** admin-only controls are hidden for viewers, but server-side 403s
   remain the only enforcement for some actions; leak-page manifest still needs
   a validated-token review; admin can delete other admins.
6. **Payments:** shared addresses are skipped rather than resolved by
   subaddress/payment id; partial transfers are not credited automatically.
7. **Build/signing:** Authenticode is still not wired into `build.ps1`; the PFX
   password is necessarily passed to `signtool` (briefly on argv); toolchain
   paths are pinned but not signature-verified; `dist` publication before tests
   is unchanged.
8. **Test environment:** temp databases/dirs can still be left behind on hard
   failure; no VM/EDR/HVCI lab was executed in this pass; `e2e` uses the
   production `priv.pem` path unless overridden.

These residuals are security-relevant. The P0 key/payment/recovery paths are
materially better than the evaluated build, but a production operation still
requires the open items above to be closed and a fresh independent review.
