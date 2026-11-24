#!/usr/bin/env python3
"""Production entry point. Uses waitress when installed, otherwise Flask."""

import os
import sys

# Key custody is mandatory in production: a stolen database without the master
# passphrase must stay useless. VEX_ALLOW_PLAINTEXT=1 is a development escape.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vault  # noqa: E402

if not vault.enabled() and os.environ.get("VEX_ALLOW_PLAINTEXT") != "1":
    print("[!] refusing to start: set VEX_MASTER (or VexC2/.master)")
    print("    development escape: VEX_ALLOW_PLAINTEXT=1")
    raise SystemExit(2)

import app as c2  # noqa: E402

try:
    from waitress import serve
except ImportError:  # pragma: no cover
    serve = None


if __name__ == "__main__":
    host = os.environ.get("VEX_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    threads = int(os.environ.get("VEX_THREADS", "8"))
    if serve:
        print(f"[*] VexC2 3.0 (waitress) on http://{host}:{port} threads={threads}")
        serve(c2.app, host=host, port=port, threads=threads, ident="VexC2")
    else:
        print("[!] waitress is not installed: using the Flask development server")
        print("[!] it is single-request-at-a-time, which can surface as")
        print("    '405 Method Not Allowed' on some form posts. Install it:")
        print("        python -m pip install waitress")
        print("    or run without the debug reloader: python run_prod.py")
        c2.app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)
