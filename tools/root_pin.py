#!/usr/bin/env python3
"""Pin the exclusive root operator to id 0 and set its password.

    python tools\\root_pin.py                 # prompts for the password
    python tools\\root_pin.py --password X    # non-interactive (lab only)

Root is the row every other id sorts above: id 0, role root, and no other
operator may occupy id 0. The password is hashed with c2db.hash_password.
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
    ap.add_argument("--password", help="root password (omit to be prompted)")
    ap.add_argument("--clear-totp", action="store_true",
                    help="also clear root TOTP/backup codes")
    args = ap.parse_args()

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

    pw_hash = c2db.hash_password(pw)

    root_user = os.environ.get("VEX_ROOT_USER", "root").strip() or "root"

    with c2db.db() as conn:
        roots = conn.execute("SELECT id, username FROM operators "
                             "WHERE role='root'").fetchall()
        if len(roots) > 1:
            print("[-] multiple root rows exist; resolve offline first")
            return 2
        other = conn.execute("SELECT id, username FROM operators "
                             "WHERE role!='root' AND id=0").fetchone()
        if other:
            print(f"[-] operator '{other['username']}' already holds id 0; "
                  "rename or delete it first")
            return 2

        row = conn.execute("SELECT id FROM operators WHERE role='root' "
                           "LIMIT 1").fetchone()
        if row:
            new_id = 0 if row["id"] == 0 else row["id"]
            if row["id"] != 0:
                # Move the row without tripping the primary key: park it on a
                # free negative id, then write it back as 0.
                conn.execute("UPDATE operators SET id=-1 WHERE id=?", (row["id"],))
                conn.execute("UPDATE operators SET id=0 WHERE id=-1")
                new_id = 0
            sets = ["pw_hash=?"]
            params = [pw_hash]
            if args.clear_totp:
                sets += ["totp_secret=''", "backup_codes=''"]
            params.append(0 if new_id == 0 else row["id"])
            conn.execute("UPDATE operators SET " + ", ".join(sets) + " WHERE id=?",
                         params)
        else:
            conn.execute("INSERT INTO operators (id, username, pw_hash, role, "
                         "created) VALUES (0, ?, ?, 'root', ?)",
                         (root_user, pw_hash, c2db.now()))
            print(f"[+] root operator '{root_user}' created at id 0")
        conn.commit()

        check = conn.execute("SELECT id, username, role FROM operators "
                             "WHERE role='root'").fetchall()
    for r in check:
        print(f"[+] root row: id={r['id']} username={r['username']} role={r['role']}")
    c2db.log_event("root-pin", "root_pinned", "", "id=0 password rotated")
    print("[+] password updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
