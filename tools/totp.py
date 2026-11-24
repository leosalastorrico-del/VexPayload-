#!/usr/bin/env python3
"""Local TOTP code generator for the VEX C2 panel.

No phone authenticator required. Reads the operator's base32 secret from the
same SQLite database the panel uses, or accepts --secret directly.

    python tools/totp.py --username Leo
    python tools/totp.py --secret O2O4XQWK47MO6R6CHUCTZBSRVTVYWRTU
    python tools/totp.py --username Leo --watch
"""

import argparse
import os
import sqlite3
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))

import c2db  # noqa: E402


def load_secret(username: str) -> str:
    db = c2db.DB_FILE
    if not os.path.exists(db):
        return ""
    with sqlite3.connect(db, timeout=10) as conn:
        row = conn.execute(
            "SELECT totp_secret FROM operators WHERE username=?",
            (username,)).fetchone()
    return (row[0] or "").strip() if row else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", default="Leo",
                    help="operator username (default: Leo)")
    ap.add_argument("--secret", default="",
                    help="base32 secret; overrides the database")
    ap.add_argument("--watch", action="store_true",
                    help="print a fresh code every 30 seconds")
    args = ap.parse_args()

    secret = (args.secret or load_secret(args.username)).strip()
    if not secret:
        print(f"[-] no TOTP secret for '{args.username}' in {c2db.DB_FILE}")
        print("    enroll first at /admin/root/2fa, or pass --secret")
        return 1

    try:
        while True:
            now = int(time.time())
            code = c2db.totp_code(secret, now)
            print(f"{args.username} TOTP: {code}   "
                  f"({30 - (now % 30)}s left)", flush=True)
            if not args.watch:
                return 0
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"[-] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
