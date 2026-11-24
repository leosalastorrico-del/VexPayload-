#!/usr/bin/env python3
"""Reset the exclusive root operator's password (and optionally 2FA).

Run from the VexC2 directory, with the same VEX_DB / VEX_DB_URL the panel uses:

    python tools\\root_reset.py
    python tools\\root_reset.py --clear-totp

The root account is seeded only from VEX_ROOT_USER/VEX_ROOT_PASS at first
initialization. This tool changes an existing root; it never creates one.
"""

import argparse
import getpass
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))

import c2db  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--password", help="new password (omit to be prompted)")
    ap.add_argument("--clear-totp", action="store_true",
                    help="also remove TOTP/backup codes from root")
    args = ap.parse_args()

    with c2db.db() as conn:
        row = conn.execute("SELECT id FROM operators WHERE role='root' "
                           "LIMIT 1").fetchone()
    if not row:
        print("[-] no root operator in this database")
        print("    start the panel once with VEX_ROOT_PASS set, then retry")
        return 2

    pw = args.password
    if not pw:
        pw = getpass.getpass("new root password: ")
        again = getpass.getpass("repeat: ")
        if pw != again:
            print("[-] passwords do not match")
            return 2
    if len(pw) < 12:
        print("[-] use at least 12 characters")
        return 2

    sets = ["pw_hash=?"]
    params = [c2db.hash_password(pw)]
    if args.clear_totp:
        sets += ["totp_secret=''", "backup_codes=''"]
    params.append(row["id"])

    with c2db.db() as conn:
        conn.execute("UPDATE operators SET " + ", ".join(sets) + " WHERE id=?",
                     params)
        conn.commit()
    c2db.log_event("root-reset", "root_password_reset", "",
                   "totp cleared" if args.clear_totp else "password only")
    backend = "postgres" if c2db.IS_PG else c2db.DB_FILE
    print(f"[+] root password updated ({backend})")
    if args.clear_totp:
        print("[+] root 2FA cleared; enroll again on next login if desired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
