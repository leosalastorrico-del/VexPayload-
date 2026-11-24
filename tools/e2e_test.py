#!/usr/bin/env python3
r"""End-to-end fixture for the encryption engine.

    python tools/e2e_test.py make   <root> <manifest.json>
    python tools/e2e_test.py count  <root> <manifest.json>   # expect VEX2 containers
    python tools/e2e_test.py verify <root> <manifest.json>   # expect plaintext back
    python tools/e2e_test.py clean  <root>

Long paths are built with the \\?\ prefix so the fixture itself proves the
engine's long-path handling.
"""
import hashlib
import json
import os
import shutil
import stat
import sys

BIG = 110 * 1024 * 1024          # crosses the 100 MiB intermittent threshold
LONG_SEG = "d" * 40
LONG_DEPTH = 6                   # ~246 chars below root, > MAX_PATH with root


def x(p: str) -> str:
    """Extended-length form for Python's Win32 calls."""
    if p.startswith("\\\\?\\"):
        return p
    return "\\\\?\\" + os.path.abspath(p)


def walk(root: str):
    base = x(root)
    stack = [base]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
            else:
                yield e.path


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(x(path), "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def make(root: str, manifest: str) -> int:
    if os.path.exists(x(root)):
        shutil.rmtree(x(root))
    os.makedirs(x(root))

    def write(rel: str, data: bytes) -> str:
        p = os.path.join(root, rel)
        os.makedirs(x(os.path.dirname(p)), exist_ok=True)
        with open(x(p), "wb") as f:
            f.write(data)
        return p

    files = []
    files.append(write("alpha.txt", os.urandom(10 * 1024)))
    files.append(write("beta.bin", os.urandom(2 * 1024 * 1024)))
    files.append(write("nested/deep/note.txt", b"hello nested\n"))
    files.append(write("empty.dat", b""))
    files.append(write("readonly.txt", os.urandom(4096)))
    os.chmod(x(files[-1]), stat.S_IREAD)

    long_rel = os.path.join(*([LONG_SEG] * LONG_DEPTH))
    files.append(write(os.path.join(long_rel, "deep.txt"), os.urandom(8192)))

    big = os.path.join(root, "big.bin")
    with open(x(big), "wb") as f:
        f.truncate(BIG)
        f.seek(0)
        f.write(b"HEAD" * 1024)
        f.seek(BIG - 4096)
        f.write(b"TAIL" * 1024)
    files.append(big)

    data = {os.path.abspath(p): {"sha256": sha256(p), "size": os.path.getsize(x(p))}
            for p in files}
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)

    longest = max(len(p) for p in data)
    print(f"[fixture] {len(data)} files, big={BIG >> 20} MiB, longest path={longest} chars")
    print(f"[fixture] manifest -> {manifest}")
    return 0


def is_container(path: str) -> bool:
    try:
        with open(x(path), "rb") as f:
            return f.read(4) == b"VEX2"
    except OSError:
        return False


def count(root: str, manifest: str) -> int:
    expected = len(json.load(open(manifest, encoding="utf-8")))
    files = list(walk(root))
    containers = sum(1 for p in files if is_container(p))
    other = len(files) - containers
    print(f"[count] containers={containers} other={other} expected={expected}")
    return 0 if containers == expected and other == 0 else 1


def verify(root: str, manifest: str) -> int:
    data = json.load(open(manifest, encoding="utf-8"))
    bad = 0
    for path, meta in data.items():
        if not os.path.exists(x(path)):
            print(f"[verify] MISSING {path}")
            bad += 1
            continue
        if sha256(path) != meta["sha256"]:
            print(f"[verify] MISMATCH {path}")
            bad += 1
    print(f"[verify] {len(data) - bad}/{len(data)} byte-identical")
    return 0 if bad == 0 else 1


def clean(root: str) -> int:
    if os.path.exists(x(root)):
        shutil.rmtree(x(root))
    print("[clean] done")
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    if mode == "make":
        return make(sys.argv[2], sys.argv[3])
    if mode == "count":
        return count(sys.argv[2], sys.argv[3])
    if mode == "verify":
        return verify(sys.argv[2], sys.argv[3])
    if mode == "clean":
        return clean(sys.argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
