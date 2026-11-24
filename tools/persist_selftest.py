#!/usr/bin/env python3
"""Persistence command preview: no registry/task writes, XML sanity."""
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "x64", "Release", "Vexpayload.exe")


def main() -> int:
    if os.environ.get("VEX_ALLOW_PAYLOAD") != "1":
        print("[skip] set VEX_ALLOW_PAYLOAD=1")
        return 0
    if not os.path.exists(EXE):
        print(f"[!] missing {EXE}")
        return 2
    r = subprocess.run([EXE, "--persist-preview", "--no-elevate"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    out = r.stdout or ""
    print(out.rstrip())
    xml_ok = False
    if "task_xml=" in out:
        raw = out.split("task_xml=", 1)[1]
        # The preview prints one XML document; stop at the next top-level key.
        raw = raw.split("\nrun=", 1)[0]
        try:
            root = ET.fromstring(raw)
            ns = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
            cmd = root.find(f".//{ns}Actions/{ns}Exec/{ns}Command")
            user = root.find(f".//{ns}Principals/{ns}Principal/{ns}UserId")
            xml_ok = (cmd is not None and cmd.text and
                      "WindowsSecurityHealthAgent.exe" in cmd.text and
                      user is not None and user.text == "S-1-5-18")
        except ET.ParseError:
            xml_ok = False
    ok = (r.returncode == 0 and "run=" in out and xml_ok
          and "--token" not in out and "--token-file" not in out)
    print("PASS persistence preview" if ok else "FAIL persistence preview")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
