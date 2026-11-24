#!/usr/bin/env python3
"""Verify the packed stager structure the SMB staged-delivery path depends on.

Checks, without executing anything:
- footer v3 magic/size/hmac are internally consistent (HMAC over ciphertext);
- the salt-derived key opens the AES-256-GCM blob and the plaintext CRC matches;
- the "loader prefix" (len - footer - payload) is byte-identical to the loader;
- the decoded payload starts with MZ.

Legacy v2 (XOR) stagers are decoded once the next build lands; this gate targets
the current footer version.
"""

import hashlib
import hmac
import os
import re
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGER = os.path.join(ROOT, "x64", "Release", "stager.exe")
LOADER = os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe")
FOOTER = struct.Struct("<8sQI16s12s16s32s")  # footer v3
MAGIC = b"VXPAY003"
KDF_LABEL = b"VEX-K3"


def _load_stage_key():
    p = os.path.join(ROOT, "loader", "stage_key.h")
    try:
        text = open(p, "r", encoding="utf-8").read()
    except OSError:
        return None
    vals = re.findall(r"0x([0-9a-fA-F]{2})", text)
    return bytes(int(v, 16) for v in vals)


HMAC_KEY = _load_stage_key()

CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def main() -> int:
    if not os.path.exists(STAGER) or not os.path.exists(LOADER):
        print("[-] build first")
        return 2

    data = open(STAGER, "rb").read()
    loader = open(LOADER, "rb").read()
    if not HMAC_KEY or len(HMAC_KEY) != 32:
        print("[-] loader/stage_key.h missing or invalid; run build.ps1 first")
        return 2
    if len(data) <= FOOTER.size:
        print("[-] stager shorter than footer")
        return 1
    ok("stager larger than footer", len(data) > FOOTER.size)

    magic, size, crc, salt, nonce, tag, mac = FOOTER.unpack(data[-FOOTER.size:])
    ok("footer magic", magic == MAGIC, magic)
    ok("payload size sane", 0 < size <= len(data) - FOOTER.size, size)

    off = len(data) - FOOTER.size - size
    ct = data[off:len(data) - FOOTER.size]
    prefix = data[:off]

    expect_mac = hmac.new(HMAC_KEY, ct, hashlib.sha256).digest()
    ok("hmac over ciphertext", hmac.compare_digest(expect_mac, mac))
    ok("loader prefix byte-identical", prefix == loader,
       f"{len(prefix)} vs {len(loader)}")

    key = hmac.new(HMAC_KEY, KDF_LABEL + salt, hashlib.sha256).digest()
    plain = None
    try:
        from Crypto.Cipher import AES

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        plain = cipher.decrypt_and_verify(ct, tag)
        ok("gcm tag verifies", True)
    except Exception as exc:  # ImportError or tag mismatch
        ok("gcm tag verifies", False, repr(exc))

    if plain is not None:
        ok("crc32 of plaintext", (zlib.crc32(plain) & 0xFFFFFFFF) == crc)
        ok("payload starts with MZ", plain[:2] == b"MZ")
    else:
        ok("crc32 of plaintext", False, "no plaintext")
        ok("payload starts with MZ", False, "no plaintext")

    ok("prefix is a PE", prefix[:2] == b"MZ")

    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
