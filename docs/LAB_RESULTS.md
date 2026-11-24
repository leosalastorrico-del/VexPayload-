# Lab results — dormancy, recovery & loader

Environment: Windows host (this build agent), no VM/EDR/HVCI images available in
this session. Scripted suite only; VM rows remain **NOT RUN**.
Date: 2026-11-23
Payload: `x64/Release/Vexpayload.exe` — sha256 `9FF9782DB6E83337…`
Stager: `x64/Release/stager.exe` — sha256 `9222E905B8682177…`

## Scripted results

| Check | Result | Notes |
|---|---|---|
| `c2_selftest.py` | 236/236 PASS | panel/auth/payment/audit/UI/security fixes |
| `decrypter_selftest.py` | 35/35 PASS | real containers, partial/resume, journal kept |
| `recovery_selftest.py` | 17/17 PASS | Unicode, ADS/hardlink skip, journal HMAC, tamper, failure contract |
| `stage_selftest.py` | 8/8 PASS | per-build stage key, token-file, wrong token/tamper rejected |
| `state_selftest.py` | 1/1 PASS | A/B slots, fallback, both-corrupt refusal |
| `wipe_selftest.py` | 1/1 PASS | sealed wipe, tampered journal refused |
| `persist_selftest.py` | 1/1 PASS | preview; no registry/task mutation |
| `sleep_selftest.py` | 9/9 PASS | crypt/plain/stager dormant memory |
| `e2e_live.py` | 11/11 PASS | checkin, shell, exfil, signed ping, screenshot |
| `stepup_live.py` | 8/8 PASS | waitress, step-up, keys POST, panic |
| `panic_live.py` | 10/10 PASS | pins, burn, DB/WAL/key/uploads gone |
| `build.ps1 -Test` | PASS | manifest hashes verified |

## VM matrix

| Target | Checkin | Command | Exfil | Sleep-crypt marker | Detonate + decrypt | Defender/HVCI |
|---|---|---|---|---|---|---|
| Win10 22H2, Defender on | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Win11 23H2, HVCI on | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| EDR VM | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

## Observations

- Helper child process: not measured on a VM in this session.
- Parent image during sleep: `mem_scan` marker 0 in the scripted harness; no EDR
  telemetry collected.
- Wake reliability: scripted harness only, not N cycles on a VM.
- Journal HMAC: available for sealed runs; a crash before sealing leaves no
  sidecar by design so recovery still works. Deleting the sidecar downgrades to
  CRC-only (residual documented in `OCS_STATUS.md`).
- Payload `--selftest` no longer prints AES key material (was visible in the lab
  run before this fix).

## Follow-ups

- Execute the three VM rows and replace every NOT RUN with evidence.
- Measure helper-child visibility and parent-image marker behavior under EDR.
- Run power-loss/pardon/kill matrix with a VM snapshot.
