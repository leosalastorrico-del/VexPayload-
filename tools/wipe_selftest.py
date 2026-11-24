#!/usr/bin/env python3
"""Wipe journal trust harness: sealed deletes, tampered refuses."""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[skip] set VEX_ALLOW_PAYLOAD=1 to run the wipe harness")
        return 0
    if not os.path.exists(EXE):
        print(f"[!] missing {EXE}")
        return 2
    d = tempfile.mkdtemp(prefix="vex_wipe_")
    try:
        r = subprocess.run([EXE, "--wipe-selftest", d], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=60)
        print((r.stdout or "").rstrip())
        ok = r.returncode == 0 and "sealed=1 deleted=1 good=1 kept=1 bad=1" in (r.stdout or "")
        print("PASS wipe journal trust" if ok else "FAIL wipe journal trust")
        return 0 if ok else 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
