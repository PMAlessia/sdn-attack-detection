"""
arp_guard.py - Validarea deterministica a pachetelor ARP (binding IP-MAC-port).

Principiu (validation-before-forward): intr-o topologie fixa, controllerul
cunoaste dinainte (din lab.yaml) ce IP, ce MAC si ce port ii corespund fiecarui
host. Un pachet ARP este LEGITIM doar daca:
    arp_spa este un IP cunoscut  SI
    arp_sha == eth_src == MAC-ul configurat pentru acel IP  SI
    in_port == portul configurat pentru acel IP.

Modulul este logica PURA (nu depinde de Ryu) -> testabil in tests/.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

# Coduri de verdict
VALID = "VALID"
UNKNOWN_SPA = "UNKNOWN_SPA"      # IP sursa care nu exista in lab.yaml
MAC_MISMATCH = "MAC_MISMATCH"    # MAC diferit de cel legitim pentru acel IP
PORT_MISMATCH = "PORT_MISMATCH"  # pachetul vine pe alt port decat cel legitim
ARP_PROBE = "ARP_PROBE"          # spa=0.0.0.0 (sonda ARP), tratata separat


@dataclass(frozen=True)
class Binding:
    ip: str
    mac: str
    switch_port: int


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str
    expected_mac: Optional[str] = None
    expected_port: Optional[int] = None

    @property
    def is_valid(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class ArpObservation:
    """Ce vede controllerul intr-un PacketIn ARP."""
    in_port: int
    eth_src: str
    arp_op: int          # 1 = request, 2 = reply
    arp_spa: str         # sender protocol address (IP pretins)
    arp_sha: str         # sender hardware address (MAC pretins)
    arp_tpa: str = ""    # target protocol address
    arp_tha: str = ""    # target hardware address


def normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower()


class ArpGuard:
    """Detine tabela de binding-uri legitime si valideaza observatiile ARP."""

    def __init__(self, bindings_by_ip: Dict[str, Binding]):
        # Normalizam MAC-urile la lowercase pentru comparatii sigure.
        self.bindings: Dict[str, Binding] = {
            ip: Binding(b.ip, normalize_mac(b.mac), b.switch_port)
            for ip, b in bindings_by_ip.items()
        }

    def validate(self, obs: ArpObservation) -> Verdict:
        eth_src = normalize_mac(obs.eth_src)
        arp_sha = normalize_mac(obs.arp_sha)

        # Sondele ARP (spa=0.0.0.0) sunt legitime la nivel de protocol; nu le
        # amestecam in aceeasi regula. Le marcam explicit.
        if obs.arp_spa in ("0.0.0.0", ""):
            return Verdict(ok=True, reason=ARP_PROBE)

        expected = self.bindings.get(obs.arp_spa)
        if expected is None:
            # In laboratorul fara DHCP, o sursa necunoscuta este invalida.
            return Verdict(ok=False, reason=UNKNOWN_SPA)

        if arp_sha != expected.mac or eth_src != expected.mac:
            return Verdict(ok=False, reason=MAC_MISMATCH,
                           expected_mac=expected.mac,
                           expected_port=expected.switch_port)

        if obs.in_port != expected.switch_port:
            return Verdict(ok=False, reason=PORT_MISMATCH,
                           expected_mac=expected.mac,
                           expected_port=expected.switch_port)

        return Verdict(ok=True, reason=VALID,
                       expected_mac=expected.mac,
                       expected_port=expected.switch_port)