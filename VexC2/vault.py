"""Key custody at rest.

Victim AES keys and RSA-wrapped keys are sealed with AES-256-GCM under a
master passphrase (VEX_MASTER or .master). A stolen database alone is useless;
the panel reveals keys only while the master is available.

Sealed values are self-describing:  enc:v1:<base64(nonce|ct|tag)>
Plain values pass through, so existing databases keep working.
"""

import base64
import hashlib
import os

from Crypto.Cipher import AES

PREFIX = "enc:v1:"
_HERE = os.path.dirname(os.path.abspath(__file__))
_MASTER_FILE = os.environ.get("VEX_MASTER_FILE") or os.path.join(_HERE, ".master")
_SALT = b"vex-vault-v1"
_CACHE = {"master": None, "loaded": False}
_ROTATING = False


def master_path() -> str:
    return _MASTER_FILE


def set_rotating(on: bool) -> None:
    global _ROTATING
    _ROTATING = bool(on)


def _master():
    if _CACHE["loaded"]:
        return _CACHE["master"]
    raw = ""
    try:
        with open(_MASTER_FILE, "rb") as f:
            raw = f.read().strip().decode("utf-8", "replace")
    except OSError:
        raw = ""
    if not raw:
        raw = os.environ.get("VEX_MASTER", "").strip()
    if raw:
        _CACHE["master"] = hashlib.pbkdf2_hmac("sha256", raw.encode(), _SALT, 120000)
    else:
        _CACHE["master"] = None
    _CACHE["loaded"] = True
    return _CACHE["master"]


def enabled() -> bool:
    return _master() is not None


def is_sealed(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value):
    if _ROTATING:
        raise RuntimeError("vault rotation in progress; retry shortly")
    if not value or not isinstance(value, str) or is_sealed(value):
        return value
    key = _master()
    if key is None:
        return value
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
    return PREFIX + base64.b64encode(nonce + ct + tag).decode()


def reveal(value):
    """Return plaintext, or '' if sealed and the master cannot open it."""
    if not value or not isinstance(value, str):
        return ""
    if not is_sealed(value):
        return value
    key = _master()
    if key is None:
        return ""
    try:
        blob = base64.b64decode(value[len(PREFIX):])
        nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode()
    except Exception:
        return ""


def status() -> str:
    return "sealed" if enabled() else "plaintext (set VEX_MASTER or .master)"
