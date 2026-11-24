#!/usr/bin/env python3
"""Verify dist/BUILD_MANIFEST.json hashes and optional detached HMAC.

The stager itself is intentionally NOT Authenticode-signed: the certificate
table would be appended after the VXPAY003 footer. The signed payload/loader
hashes are recorded here instead, and an optional HMAC (VEX_MANIFEST_KEY) makes
the manifest tamper-evident on the release side.
"""
import hashlib
import hmac
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIST, "BUILD_MANIFEST.json")
    try:
        raw = open(path, "rb").read()
        m = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"[!] cannot read manifest: {exc}")
        return 2

    ok = True
    for name in ("payload", "loader", "stager"):
        rel = {"payload": os.path.join(ROOT, "x64", "Release", "Vexpayload.exe"),
               "loader": os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe"),
               "stager": os.path.join(ROOT, "x64", "Release", "stager.exe")}[name]
        if not os.path.exists(rel):
            print(f"[!] missing {name}: {rel}")
            ok = False
            continue
        data = open(rel, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        want = (m.get(name) or {}).get("sha256")
        same = digest.lower() == str(want or "").lower()
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
