#!/usr/bin/env python3
"""
collectors.py - Colectarea dovezilor de stare (snapshot-uri) intr-o rulare.

Functii care ruleaza comenzi de sistem si salveaza iesirea in directorul rularii,
cu eticheta de faza (before / during / after). Folosite de scenario_runner

Snapshot-uri utile:
  * ip neigh          -> starea cache-ului ARP (dovada otravirii)
  * ss -tan syn-recv  -> conexiuni incomplete pe h1 (presiune SYN)
  * ovs-ofctl dump-flows -> flow-urile si counterele (dovada mitigarii)
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone


def _write(log_dir, name, phase, content):
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{name}_{phase}.txt")
    with open(path, "a") as f:
        f.write(f"# {datetime.now(timezone.utc).isoformat()}  phase={phase}\n")
        f.write(content)
        f.write("\n")
    return path


def snapshot_host_cmd(host, cmd, log_dir, name, phase):
    """Ruleaza o comanda pe un host Mininet (obiect cu .cmd) si salveaza iesirea."""
    out = host.cmd(cmd)
    return _write(log_dir, f"{name}_{host.name}", phase, out)


def snapshot_local_cmd(cmd_list, log_dir, name, phase):
    """Ruleaza o comanda locala (ex. ovs-ofctl) si salveaza iesirea."""
    try:
        out = subprocess.check_output(cmd_list, text=True, stderr=subprocess.STDOUT)
    except Exception as e:
        out = f"[eroare rulare {cmd_list}]: {e}"
    return _write(log_dir, name, phase, out)


def dump_ovs_flows(log_dir, phase, switch="s1"):
    return snapshot_local_cmd(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
        log_dir, "ovs_flows", phase)


def snapshot_arp_state(hosts, log_dir, phase):
    """hosts: dict/list de obiecte Mininet host. Salveaza `ip neigh` pentru fiecare."""
    paths = []
    for h in hosts:
        paths.append(snapshot_host_cmd(h, "ip neigh", log_dir, "ip_neigh", phase))
    return paths


def snapshot_syn_recv(host, log_dir, phase):
    """Conexiuni SYN-RECV pe host (presiunea SYN flood)."""
    return snapshot_host_cmd(
        host, "ss -tan state syn-recv | wc -l; echo '---'; ss -tan | head -20",
        log_dir, "syn_recv", phase)