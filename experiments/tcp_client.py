#!/usr/bin/env python3
"""
tcp_client.py - Clientul legitim care masoara disponibilitatea serviciului.

Semnalul de SERVICIU pentru graficele SYN flood: la interval fix, clientul
incearca connect() catre h1:8080, masoara durata si marcheaza rezultatul
(success / timeout / error). Scrie un CSV cu o linie per incercare.

Ruleaza pe h2 pe durata intregului scenariu (baseline -> atac -> recuperare),
ca sa se vada degradarea si revenirea.

Rulare (in namespace-ul h2):
    mininet> h2 python3 experiments/tcp_client.py --run-id demo01 --duration 90 &
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab


def attempt(host, port, timeout):
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.recv(64)
            except Exception:
                pass
        return "success", (time.monotonic() - t0) * 1000.0
    except socket.timeout:
        return "timeout", (time.monotonic() - t0) * 1000.0
    except (ConnectionRefusedError, OSError) as e:
        return f"error:{type(e).__name__}", (time.monotonic() - t0) * 1000.0


def main():
    lab = load_lab()
    ap = argparse.ArgumentParser(description="Client TCP legitim (masoara serviciul)")
    ap.add_argument("--host", default=lab.syn.get("server_ip", "10.0.0.1"))
    ap.add_argument("--port", type=int, default=int(lab.syn.get("server_port", 8080)))
    ap.add_argument("--interval", type=float, default=0.5,
                    help="interval intre incercari (s)")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="timeout per connect() (s)")
    ap.add_argument("--duration", type=float, required=True,
                    help="durata totala a masuratorii (s)")
    ap.add_argument("--label", default="h2", help="eticheta clientului (h2/h4)")
    ap.add_argument("--run-id", default=datetime.now().strftime("run_%Y%m%d_%H%M%S"))
    ap.add_argument("--log-dir", default=None)
    args = ap.parse_args()

    log_dir = args.log_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "raw", args.run_id)
    os.makedirs(log_dir, exist_ok=True)
    csv_path = os.path.join(log_dir, f"client_{args.label}.csv")
    f = open(csv_path, "a", newline="")
    w = csv.writer(f)
    if os.stat(csv_path).st_size == 0:
        w.writerow(["t_utc", "t_monotonic_ns", "label", "result", "latency_ms"])

    print(f"[client {args.label}] {args.host}:{args.port} la fiecare "
          f"{args.interval}s, {args.duration}s total. Log: {csv_path}")

    t_end = time.monotonic() + args.duration
    n_ok = n_fail = 0
    try:
        while time.monotonic() < t_end:
            result, latency = attempt(args.host, args.port, args.timeout)
            w.writerow([datetime.now(timezone.utc).isoformat(),
                        time.monotonic_ns(), args.label, result, f"{latency:.2f}"])
            f.flush()
            if result == "success":
                n_ok += 1
            else:
                n_fail += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        f.close()
        print(f"[client {args.label}] gata: {n_ok} success, {n_fail} esec.")


if __name__ == "__main__":
    main()