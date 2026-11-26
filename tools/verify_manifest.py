#!/usr/bin/env python3
"""Verify BUILD_MANIFEST.json hashes and optional detached HMAC.

Schema 2 records the x64/x86 payloads, loaders, stagers, and the single-file
universal launcher (including its embedded stager hashes). Schema 1 remains
supported for old releases.
"""
import hashlib
import hmac
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def verify_entry(name, entry, base=""):
    path = entry.get("path", "")
    if path and not os.path.isabs(path) and base:
        path = os.path.join(base, path)
    if not path or not os.path.isfile(path):
        print(f"[!] missing {name}: {path or '(no path)'}")
        return False
    actual = sha256(path)
    want = str(entry.get("sha256", ""))
    same = actual.lower() == want.lower()
    print(("PASS " if same else "FAIL ") + f"{name} sha256")
    if not same:
        print(f"     want {want}")
        print(f"     got  {actual}")
    size = entry.get("size")
    if size is not None and os.path.getsize(path) != int(size):
        print(f"[!] {name} size mismatch")
        return False
    return same


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIST, "BUILD_MANIFEST.json")
    try:
        raw = open(path, "rb").read()
        m = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"[!] cannot read manifest: {exc}")
        return 2

    ok = True
    base = os.path.dirname(os.path.abspath(path))
    schema = int(m.get("schema", 1))
    if schema >= 2:
        for name in ("payload_x64", "payload_x86", "loader_x64", "loader_x86",
                     "stager_x64", "stager_x86"):
            ok = verify_entry(name, m.get(name) or {}, base) and ok
        uni = m.get("universal") or {}
        ok = verify_entry("universal", uni, base) and ok

        stager_x64 = (m.get("stager_x64") or {}).get("sha256", "")
        stager_x86 = (m.get("stager_x86") or {}).get("sha256", "")
        if str(uni.get("embedded_x64_sha256", "")).lower() != stager_x64.lower():
            print("[!] universal embedded x64 hash does not match stager_x64")
            ok = False
        else:
            print("PASS universal embedded x64 hash")
        if str(uni.get("embedded_x86_sha256", "")).lower() != stager_x86.lower():
            print("[!] universal embedded x86 hash does not match stager_x86")
            ok = False
        else:
            print("PASS universal embedded x86 hash")
    else:
        # Legacy schema 1 paths.
        for name, rel in (
                ("payload", os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")),
                ("loader", os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe")),
                ("stager", os.path.join(ROOT, "x64", "Release", "stager.exe"))):
            if not os.path.exists(rel):
                print(f"[!] missing {name}: {rel}")
                ok = False
                continue
            same = sha256(rel).lower() == str((m.get(name) or {}).get("sha256", "")).lower()
            print(("PASS " if same else "FAIL ") + f"{name} sha256")
            ok = ok and same

    sig_path = path + ".sig"
    key = os.environ.get("VEX_MANIFEST_KEY", "").strip()
    if os.path.exists(sig_path):
        if not key:
            print("[!] manifest signature exists but VEX_MANIFEST_KEY is not set")
            ok = False
        else:
            want = hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
            got = open(sig_path, "r", encoding="utf-8").read().strip()
            same = hmac.compare_digest(want, got)
            print(("PASS " if same else "FAIL ") + "manifest HMAC")
            ok = ok and same
    elif key:
        print("[!] VEX_MANIFEST_KEY set but no .sig")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
