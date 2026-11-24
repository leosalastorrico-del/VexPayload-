"""Operator notifications: Telegram or a generic Discord-compatible webhook.

Env:
  VEX_TG_TOKEN / VEX_TG_CHAT   Telegram bot
  VEX_WEBHOOK                  any URL accepting {"content": "..."}
Fire-and-forget; failures never touch control flow.
"""

import json
import os
import threading
import urllib.request


def _post(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    for _ in range(2):
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                r.read(256)
            return
        except Exception:
            continue


def enabled() -> bool:
    return bool((os.environ.get("VEX_TG_TOKEN") and os.environ.get("VEX_TG_CHAT"))
                or os.environ.get("VEX_WEBHOOK"))


def send(text: str) -> None:
    if not enabled():
        return
    tg_token = os.environ.get("VEX_TG_TOKEN")
    tg_chat = os.environ.get("VEX_TG_CHAT")
    if tg_token and tg_chat:
        url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        payload = {"chat_id": tg_chat, "text": text, "disable_web_page_preview": True}
    else:
        url = os.environ["VEX_WEBHOOK"]
        payload = {"content": text, "text": text}
    threading.Thread(target=_post, args=(url, payload), daemon=True).start()
