#!/usr/bin/env python3
"""
tcp_server.py - Serverul TCP tinta pentru experimentul SYN flood (ruleaza pe h1).

Asculta pe 0.0.0.0:8080, accepta rapid conexiunile legitime si scrie un log cu
timestamp pentru fiecare accept reusit. Un backlog mic face vizibila presiunea
asupra cozii de conexiuni in timpul atacului.

Comportamentul SYN-RECEIVED apartine kernelului Linux (nu acestui server);
epuizarea cozii SYN se observa separat cu `ss -tan state syn-recv` pe h1.

Rulare (in namespace-ul h1):
    mininet> h1 python3 experiments/tcp_server.py --run-id demo01 &
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab


def handle_client(conn, addr, logf, lock):
    try:
        conn.settimeout(2.0)
        conn.sendall(b"WELCOME\n")
        try:
            conn.recv(256)
        except Exception:
            pass
    finally:
        conn.close()
    rec = {"event": "ACCEPT", "peer": f"{addr[0]}:{addr[1]}",
           "t_monotonic_ns": time.monotonic_ns(),
           "t_utc": datetime.now(timezone.utc).isoformat()}
    with lock:
        logf.write(json.dumps(rec) + "\n")
        logf.flush()


def main():
    lab = load_lab()
    ap = argparse.ArgumentParser(description="Server TCP tinta (SYN flood)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(lab.syn.get("server_port", 8080)))
    ap.add_argument("--backlog", type=int, default=5,
                    help="dimensiunea cozii listen() (mic => epuizare vizibila)")
    ap.add_argument("--run-id", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    ap.add_argument("--log-dir", default=None)
    args = ap.parse_args()

    log_dir = args.log_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "raw", args.run_id)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "server_accepts.jsonl")
    logf = open(log_path, "a", buffering=1)
    lock = threading.Lock()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(args.backlog)
    print(f"[server] ascult pe {args.host}:{args.port} (backlog={args.backlog}), "
          f"log: {log_path}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client,
                             args=(conn, addr, logf, lock), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[server] oprit.")
    finally:
        srv.close()
        logf.close()


if __name__ == "__main__":
    main()