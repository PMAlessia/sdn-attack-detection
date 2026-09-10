#!/usr/bin/env python3
"""
message_server.py - Receptorul de mesaje pentru demo-ul ARP MITM (ruleaza pe h1).

Echivalentul reproductibil al lui `nc -l 9000`, dar cu logare: asculta pe
h1:9000, primeste o linie de text si o scrie in log cu timestamp. Comparand
mesajul receptionat cu cel asteptat se obtine metrica "mesaje modificate".

Pentru demonstratia VIZUALA se poate folosi direct netcat.
Acest script e pentru rulari reproductibile/grafice.

Rulare (in namespace-ul h1):
    mininet> h1 python3 experiments/message_server.py --run-id demo01 &
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
    ap = argparse.ArgumentParser(description="Receptor mesaje ARP MITM demo")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(lab.arp.get("server_port", 9000)))
    ap.add_argument("--expected", default=lab.arp.get("original_payload", "STATUS=OK\n"))
    ap.add_argument("--once", action="store_true",
                    help="accepta o singura conexiune si iese (one-shot per trial)")
    ap.add_argument("--run-id", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    ap.add_argument("--log-dir", default=None)
    args = ap.parse_args()

    log_dir = args.log_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "raw", args.run_id)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "message_server.jsonl")
    logf = open(log_path, "a", buffering=1)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(1)
    expected = args.expected.encode()
    print(f"[msg-server] ascult pe {args.host}:{args.port}; astept '{args.expected!r}'")

    try:
        while True:
            conn, addr = srv.accept()
            data = b""
            conn.settimeout(3.0)
            try:
                while b"\n" not in data:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            conn.close()
            modified = (data != expected)
            rec = {"event": "MESSAGE_RECEIVED",
                   "peer": f"{addr[0]}:{addr[1]}",
                   "received": data.decode(errors="replace"),
                   "expected": args.expected,
                   "modified": modified,
                   "t_monotonic_ns": time.monotonic_ns(),
                   "t_utc": datetime.now(timezone.utc).isoformat()}
            logf.write(json.dumps(rec) + "\n")
            logf.flush()
            flag = "MODIFICAT!" if modified else "intact"
            print(f"[msg-server] primit {data!r} ({flag})")
            if args.once:
                break
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        logf.close()


if __name__ == "__main__":
    main()