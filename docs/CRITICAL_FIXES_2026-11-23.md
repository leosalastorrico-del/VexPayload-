# Critical fixes — 2026-11-23

Follow-up to the five reported flaws. Each item has a regression test unless the
failure needs an OS-level fault injection.

| Reported flaw | Verdict | Fix |
|---|---|---|
| `_serve_cpp` injects `{{AES_KEY_B64}}` without escaping | **real (defense-in-depth)** | `_safe_aes_key()` requires canonical base64 of exactly 32 bytes; `_serve_cpp`/`_serve_exe`/`api_pardon_exe` fail closed (500) on anything else; canonical value is also `_cpp_literal`-escaped. Test: tampered sealed key `evil"key\ninject` → 500. |
| Pardon doesn't remove journal/`.l0cked`; decrypter should delete journal | **partly false / one real gap** | Decrypter already deletes journal, `.sig`, `.done` on full success. Server cannot touch victim files. Payload now checks `JournalGone()` (default + mirrors + `.sig`/`.done`) before reporting; server requires `journal=removed` and marks `pardon_incomplete` otherwise. `.l0cked` is a payload skip extension; legacy cleanup remains a migration item. |
| `/api/` CSRF bypass if session present | **misdiagnosed** | API routes never use session role; they use HMAC. The real issue was fail-open for unknown/empty-secret VIDs. `api_signature_guard` now aborts 400/403 for unknown or secretless victims; exfil v2 status is bound to its VID. |
| Chat attachment silently drops when `UPLOAD_DIR` missing | **real** | `UPLOAD_DIR` created at startup; `_save_chat_file` raises on failure; admin and portal routes log `chat_attachment_failed` and flash a visible error. |
| Burn paths may be relative / wrong CWD | **real hardening** | `PRIV_KEY_FILE`, `SECRET_FILE`, `UPLOAD_DIR`, `DB_FILE` and build cache are absolute at load; `_burn_targets` resolves/deduplicates; symlinks are unlinked rather than followed; `_burn_execute` handles symlinks before directories. |

## Tests

- `c2_selftest.py`: 236/236, including non-base64 key rejection, unknown VID
  fail-closed, absolute burn targets, startup uploads dir, pardon
  `journal=removed` requirement, and exfil v2 upload row.
- `e2e_live.py`: 11/11, including v2 exfil storage after the upload-row fix.
- stage 8/8, state 1/1, wipe 1/1, persistence preview 1/1, recovery 17/17,
  decrypter 35/35, stepup 8/8, panic 10/10, `build.ps1 -Test` green.

## Residuals

- Pardon evidence is a payload claim (`journal=removed`); the server cannot
  independently inspect the victim filesystem.
- `.l0cked` cleanup for pre-current journals is not implemented.
- Unknown/secretless VID reports are rejected, so a pre-registration
  `fatal_state` report may be lost by design.
- UPLOAD_DIR creation failure is logged at startup and surfaced per chat, but a
  permanently read-only uploads volume still prevents attachments.
