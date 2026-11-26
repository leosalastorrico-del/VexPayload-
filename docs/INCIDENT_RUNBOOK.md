# Incident runbook — Operation Clean Sweep

One page per playbook. Every action that burns, rotates, or deletes state has a
**stop** line: take a backup first unless the risk is active key compromise.

## 0. Universal first moves
1. Record UTC time, operator, host, and what changed.
2. Snapshot the DB and `.master` **before** destructive action:
   `python -c "import sys;sys.path.insert(0,'VexC2');import c2db;open('incident.db','wb').write(c2db.backup_bytes())"`
   (root step-up is required for the panel route; the file copy is the fallback).
3. Stop the panel (`Stop-Service vex-c2` or Ctrl-C) so nothing writes during triage.
4. Preserve logs, `%TEMP%\vex*`, `dist\BUILD_MANIFEST.json`, build hashes.
5. Do not reuse the incident host for the clean rebuild.

## 1. Suspected operator compromise
- Disable the operator: `/admin/operators` → delete (root) or set a new password
  from the panel. Sessions are invalidated only by logout/restart; **restart the
  panel** after removing an operator.
- Rotate `VEX_SECRET` (and `VEX_AUDIT_KEY` if used), then restart. Sessions and
  HMACs derived from the old secret die.
- Review `/admin/audit`, `events` for `login_failed`, `login_blocked`,
  `2fa_*`, `stepup_*`, `operator_*`, `panic_*`.
- If root was involved: rotate the vault master **after** exporting a backup;
  run `/admin/root/rotate-master` with a new master and verify all victims.

## 2. Vault master compromised / lost
**Compromised:** stop panel → backup DB → rotate master → verify every victim
key/chunk reveals → redeploy with new master → revoke old backups.
**Lost:** restore the last DB + matching `.master` backup. If neither exists,
victim keys are unrecoverable; do not destroy the DB (it may still be brute-forced
if the passphrase was weak). Update `docs/BUILD.md` custody notes.

## 3. Audit tamper / chain verification failure
- Do not delete events. Copy DB + `VexC2/.audit_anchor` first.
- Run `/admin/root/audit-verify`; if it reports an id, compare the anchor file to
  `audit_last_hash`. A mismatch means the DB or anchor was modified.
- Treat all events after the last trusted anchor as untrusted; reconstruct from
  backups and the operator's own timeline.
- Rotate `VEX_AUDIT_KEY` only with a documented epoch; old HMACs will not verify.

## 4. Stage/build key leak
- `loader/stage_key.h` leak: generate a new build (`build.ps1`) so a new random
  stage key is compiled and packed; old stagers keep working until rotated.
- `VEX_MANIFEST_KEY` leak: re-sign the manifest with a new key and redistribute
  the new public verification value out of band.
- Code-signing cert leak: revoke the certificate, rebuild signed artifacts,
  re-upload the stager, update the allowed thumbprint in the runbook.

## 5. C2 host compromise
- Snapshot DB/master, then rotate C2 host/domain and TLS cert.
- Change `api_token`; existing payloads need the new token in their state (or a
  new build). Check `last_ping` to identify which victims reconnected.
- Rotate vault master and operator passwords; invalidate root TOTP and re-enroll
  from a clean host.
- If the host is untrusted, use the panic/burn flow only after confirming the
  backup exists; burn is irreversible.

## 6. Panic/burn misfire
- Stop. Do not re-run burn. Restore DB/master/priv/uploads from the latest
  backup; restart panel; re-arm victims (paid/pardoned state is in the DB).
- If victim hosts already received `detonate=2`, they are dead; restore from
  victim backups/decrypter journals, not from the panel.
- Record the reason and add an approval gate/check to prevent recurrence.

## 7. Payment wrong credit / shared address
- Freeze payment polling (`payment_mode=manual`), export invoices/ledger.
- Do not delete ledger rows; add a correcting adjustment and a note.
- If an address was shared, a victim may have been marked paid incorrectly:
  check `add_payment`/`poll_once` logs, compare on-chain txid, and re-open the
  victim only after operator approval.
- Fix the address assignment before re-enabling auto mode.

## 8. Victim cannot decrypt / lost secret
- The check-in secret is registration-only and the decrypter uses the AES key,
  not the HMAC secret. A lost secret does not lose files; it stops signed pings.
- Recover the AES key from the panel (root/stepup) or the recovery journal; use
  the decrypter `--check` first, then restore.
- Never re-run detonation to "fix" it; encryption is idempotent but journal
  duplication/metadata can be lost.

## 9. Backup/restore drill (quarterly)
1. `GET /admin/backup` as root+step-up → save off-host.
2. Stop panel, restore to a scratch dir, point `VEX_DB`/`VEX_MASTER_FILE` at it.
3. Start panel on localhost, log in, open one victim, decrypt one proof sample.
4. Confirm audit chain verifies and root/shadow/TOTP rows are absent (redacted).
5. Record timings and gaps in `docs/LAB_RESULTS.md`.

## 10. Build/signing incident
- Unsigned/mismatched `dist/BUILD_MANIFEST.json`: stop distribution.
- `signtool verify /pa` must be `Valid` for payload and loader; the stager is
  intentionally unsigned (footer), verified by the manifest instead.
- Rebuild from a clean tree, compare hashes, and never reuse a stage key.

## Emergency contacts / custody
- Root operator: _fill in_
- Backup-holder: _fill in_
- Code-signing cert custodian: _fill in_
- Off-host backup location: _fill in_
