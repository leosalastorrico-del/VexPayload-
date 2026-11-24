#!/usr/bin/env python3
"""Rotate the C2 master passphrase (re-seals DB columns + exfil chunks).

    python tools\\vault_rotate.py
    python tools\\vault_rotate.py --new-master "new passphrase"   # lab only

Requires the current master via VEX_MASTER or VexC2/.master. Writes a
VexC2/.master file only when VEX_MASTER is not set; if the panel uses the env
variable, update it there and restart.
"""

import argparse
import getpass
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))

import vault_rotate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-master", help="new master (omit to be prompted)")
    args = ap.parse_args()
    new = args.new_master
    if not new:
        new = getpass.getpass("new master passphrase: ")
        again = getpass.getpass("repeat: ")
        if new != again:
            print("[-] passphrases do not match")
            return 2
    try:
        res = vault_rotate.rotate(new)
    except (RuntimeError, ValueError) as exc:
        print("[-]", exc)
        return 2
    print(f"[+] victims re-sealed: {res['victims']}")
    print(f"[+] exfil chunks re-sealed: {res['files']}")
    if res["backup"]:
        print(f"[+] backup: {res['backup']}")
    print(f"[+] new master verified: {res['verified']}")
    if os.environ.get("VEX_MASTER"):
        print("[!] VEX_MASTER is set: update the environment and restart the panel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
