"""Live HTTP smoke test for root step-up on the production entry point.

Starts VexC2/run_prod.py (waitress when installed), drives login + step-up +
keys.zip + panic through real HTTP with a cookie jar, and asserts the step-up
POST never returns 405.
"""

import http.cookiejar
import importlib.util
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = r"D:\Vexpayload"
BASE = tempfile.mkdtemp(prefix="vex_live_")
DB = os.path.join(BASE, "vex_c2.db")
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
    port = free_port()
    env = dict(os.environ)
    env.update({
        "VEX_DB": DB,
        "VEX_PASS": "live-admin-pass",
        "VEX_ROOT_PASS": "live-root-pass-123",
        "VEX_MASTER": "live-master",
        "VEX_SECRET": "y" * 64,
        "VEX_PRIV": os.path.join(ROOT, "VexC2", "priv.pem"),
        "VEX_ALLOW_PASSWORD_STEPUP": "1",
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
        return opener.open(req, timeout=20)

    def csrf(path):
        html = get(path).read().decode("utf-8", "replace")
        m = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
        return m.group(1) if m else ""

    try:
        ok("panel up", wait_port(port))
        ok("waitress installed",
           importlib.util.find_spec("waitress") is not None)

        t = csrf("/admin/login")
        r = post("/admin/login", {"csrf": t, "username": "root",
                                  "password": "live-root-pass-123"})
        html = r.read().decode("utf-8", "replace")
        ok("root login", r.status == 200 and "dashboard" in html.lower())

        r = get("/admin/root/stepup")
        html = r.read().decode("utf-8", "replace")
        ok("stepup page", r.status == 200 and 'name="password"' in html)
        tok = re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)
        nxt = re.search(r'name="next" value="([^"]*)"', html)
        ok("stepup page carries next", bool(nxt))

        r = post("/admin/root/stepup", {"csrf": tok,
                                        "next": "/admin/root",
                                        "password": "live-root-pass-123"})
        html = r.read().decode("utf-8", "replace")
        ok("stepup unlock (no 405)", r.status == 200 and "root console" in html.lower())

        html = get("/admin/root").read().decode("utf-8", "replace")
        tok = re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)
        r = post("/admin/root/keys.zip", {"csrf": tok})
        ok("keys zip over http", r.status == 200 and r.read(2) == b"PK")

        html = get("/admin/root").read().decode("utf-8", "replace")
        tok = re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)
        r = post("/admin/root/panic", {"csrf": tok, "confirm": "DESTROY"})
        body = r.read().decode("utf-8", "replace")
        ok("panic accepted", r.status == 200 and "panic queued" in body.lower())
        return 0
    finally:
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
    sys.exit(1 if bad else 0)
