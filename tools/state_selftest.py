#!/usr/bin/env python3
"""State A/B + DPAPI round-trip harness (temp dir only)."""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[skip] set VEX_ALLOW_PAYLOAD=1 to run the state harness")
        return 0
    if not os.path.exists(EXE):
        print(f"[!] missing {EXE}; build first")
        return 2
    d = tempfile.mkdtemp(prefix="vex_state_")
    try:
        r = subprocess.run([EXE, "--state-selftest", d], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=60)
        print((r.stdout or "").rstrip())
        ok = r.returncode == 0 and "saved=1 same=1 fallback=1 allbad=1 gone=1" in (r.stdout or "")
        print("PASS state A/B round-trip" if ok else "FAIL state A/B round-trip")
        return 0 if ok else 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
