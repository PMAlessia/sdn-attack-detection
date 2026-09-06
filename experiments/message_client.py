#!/usr/bin/env python3
"""
message_client.py - Emitatorul de mesaje pentru demo-ul ARP MITM (ruleaza pe h2).

Echivalentul reproductibil al lui `printf 'STATUS=OK\\n' | nc 10.0.0.1 9000`, dar
cu logare: se conecteaza la h1:9000 si trimite payload-ul configurat (STATUS=OK).
Daca h3 este MITM in modul atac, serverul va primi STATUS=NO (mesaj modificat).

Rulare (in namespace-ul h2):
    mininet> h2 python3 experiments/message_client.py --run-id demo01
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab


def main():
    lab = load_lab()
    ap = argparse.ArgumentParser(description="Emitator mesaje ARP MITM demo")
    ap.add_argument("--host", default=lab.arp.get("server_ip", "10.0.0.1"))
    ap.add_argument("--port", type=int, default=int(lab.arp.get("server_port", 9000)))
    ap.add_argument("--payload", default=lab.arp.get("original_payload", "STATUS=OK\n"))
    ap.add_argument("--run-id", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    ap.add_argument("--log-dir", default=None)
    args = ap.parse_args()

    log_dir = args.log_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "raw", args.run_id)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "message_client.jsonl")

    payload = args.payload.encode()
    result = "success"
    try:
        with socket.create_connection((args.host, args.port), timeout=3.0) as s:
            s.sendall(payload)
            time.sleep(0.2)
    except Exception as e:
        result = f"error:{type(e).__name__}"

    rec = {"event": "MESSAGE_SENT", "sent": args.payload, "result": result,
           "t_monotonic_ns": time.monotonic_ns(),
           "t_utc": datetime.now(timezone.utc).isoformat()}
    with open(log_path, "a", buffering=1) as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[msg-client] trimis {payload!r} -> {args.host}:{args.port} ({result})")


if __name__ == "__main__":
    main()