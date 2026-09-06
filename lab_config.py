"""
lab_config.py - Incarcator comun pentru config/lab.yaml si config/scenarios.yaml

Folosit de controller, scripturile de atac, runner si analiza. Ofera o singura
sursa de adevar pentru binding-urile IP-MAC-port, porturi si parametri
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional

import yaml

# Radacina proiectului = directorul care contine acest fisier
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")


@dataclass(frozen=True)
class HostBinding:
    """Identitatea legitima a unui host (o intrare din tabela de incredere)."""
    name: str
    ip: str
    mac: str
    switch_port: int


class LabConfig:
    """Reprezentarea in memorie a fisierului config/lab.yaml."""

    def __init__(self, data: dict):
        self._data = data
        self.hosts: Dict[str, HostBinding] = {}
        for name, h in data["hosts"].items():
            self.hosts[name] = HostBinding(
                name=name,
                ip=str(h["ip"]),
                mac=str(h["mac"]).lower(),
                switch_port=int(h["switch_port"]),
            )
        self.roles = data.get("roles", {})
        self.syn = data.get("syn", {})
        self.arp = data.get("arp", {})
        self.syn_detection = data.get("syn_detection", {})
        self.mitigation = data.get("mitigation", {})

    # --- cautari utile 
    def host(self, name: str) -> HostBinding:
        return self.hosts[name]

    def role(self, role_name: str) -> HostBinding:
        """Ex.: role('attacker') -> HostBinding pentru h3."""
        return self.hosts[self.roles[role_name]]

    def binding_by_ip(self) -> Dict[str, HostBinding]:
        """Tabela IP -> HostBinding, folosita de arp_guard."""
        return {b.ip: b for b in self.hosts.values()}

    def binding_by_port(self) -> Dict[int, HostBinding]:
        return {b.switch_port: b for b in self.hosts.values()}

    def mac_of(self, ip: str) -> Optional[str]:
        for b in self.hosts.values():
            if b.ip == ip:
                return b.mac
        return None


def load_lab(path: Optional[str] = None) -> LabConfig:
    path = path or os.path.join(CONFIG_DIR, "lab.yaml")
    with open(path, "r") as f:
        return LabConfig(yaml.safe_load(f))


def load_scenarios(path: Optional[str] = None) -> dict:
    path = path or os.path.join(CONFIG_DIR, "scenarios.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    # Verificare rapida: `python lab_config.py`
    lab = load_lab()
    print("Hosturi incarcate din config/lab.yaml:")
    for name, b in lab.hosts.items():
        print(f"  {name}: ip={b.ip} mac={b.mac} port={b.switch_port}")
    print("Roluri:", lab.roles)
    print("Scenarii:", list(load_scenarios().keys()))