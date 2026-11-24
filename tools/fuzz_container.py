#!/usr/bin/env python3
"""Mutation fuzzer for the container parser (crypto_util.decrypt_container).

Builds valid v1/v2 containers, mutates them (bit flips, truncation, header
garbage), and asserts the parser only ever returns bytes or raises ValueError.
No crash, no hang, no unexpected exception.
"""

import argparse
import os
import random
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "VexC2"))

from Crypto.Cipher import AES  # noqa: E402

import crypto_util  # noqa: E402


def v2_container(plain: bytes, key: bytes, chunk: int = 65536) -> bytes:
    chunks = [plain[i:i + chunk] for i in range(0, len(plain), chunk)]
    out = bytearray(struct.pack("<4sIQIIQ", b"VEX2", 0, len(plain), 1, chunk,
                                len(chunks)))
    for ch in chunks:
        nonce = os.urandom(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(ch)
        out += bytes([1]) + struct.pack("<I", len(ch)) + nonce + ct + tag
    return bytes(out)


def v1_container(plain: bytes, key: bytes, chunk: int = 65536) -> bytes:
    chunks = [plain[i:i + chunk] for i in range(0, len(plain), chunk)]
    out = bytearray(struct.pack("<Q", len(chunks)))
    for ch in chunks:
        nonce = os.urandom(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(ch)
        out += nonce + struct.pack("<I", len(ch)) + ct + tag
    return bytes(out)


def mutate(blob: bytes, rng: random.Random) -> bytes:
    b = bytearray(blob)
    kind = rng.randrange(6)
    if kind == 0 and b:                      # bit flip
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
    elif kind == 1 and len(b) > 8:           # truncate
        del b[rng.randrange(1, len(b)):
              rng.randrange(1, len(b)) + 1]
    elif kind == 2:                          # extend
        b += os.urandom(rng.randrange(1, 64))
    elif kind == 3 and len(b) >= 32:         # header garbage
        for i in range(32):
            if rng.random() < 0.3:
                b[i] = rng.randrange(256)
    elif kind == 4 and b:                    # zero a slice
        i = rng.randrange(len(b))
        j = min(len(b), i + rng.randrange(1, 32))
        b[i:j] = bytes(j - i)
    else:                                    # random blob
        return os.urandom(rng.randrange(0, 512))
    return bytes(b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=500)
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    key = bytes(range(32))
    plain = os.urandom(96 * 1024)
    seeds = [v2_container(plain, key), v1_container(plain, key),
             v2_container(b"", key), v2_container(b"x" * 100, key)]

    bad = 0
    started = time.time()
    for i in range(args.iterations):
        blob = mutate(rng.choice(seeds), rng)
        t0 = time.time()
        try:
            out = crypto_util.decrypt_container(blob, key, 4 * 1024 * 1024)
            if not isinstance(out, bytes):
                print(f"[!] iteration {i}: non-bytes return")
                bad += 1
        except ValueError:
            pass
        except Exception as exc:
            print(f"[!] iteration {i}: unexpected {type(exc).__name__}: {exc}")
            bad += 1
        if time.time() - t0 > 5:
            print(f"[!] iteration {i}: slow ({time.time() - t0:.1f}s)")
            bad += 1
    elapsed = time.time() - started
    if bad:
        print(f"[-] fuzz failed: {bad}/{args.iterations}")
        return 1
    print(f"[+] fuzz ok: {args.iterations} mutations in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
