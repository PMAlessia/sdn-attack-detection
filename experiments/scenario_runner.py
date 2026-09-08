#!/usr/bin/env python3
"""
scenario_runner.py - Rulare AUTOMATA a unui scenariu (pentru grafice reproductibile).

Scop: campania experimentala (figurile din lucrare), unde durata e FIXA si
identica intre repetari, iar oprirea e automata. Pentru demo-ul in fata comisiei
foloseste ghidul manual: docs/RUNBOOK_DEMO.md.

NECESITA root (Mininet). NU rula in acelasi timp cu o topologie pornita manual.

    sudo python3 experiments/scenario_runner.py --scenario syn_attack --run-id r01
    sudo python3 experiments/scenario_runner.py --scenario arp_mitigated --run-id r02
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import re
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab, load_scenarios, PROJECT_ROOT

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

from experiments import collectors


def wait_port(host, port, timeout=15.0):
    """Asteapta ca un port TCP local sa fie deschis (controllerul Ryu)."""
    import socket
    t_end = time.monotonic() + timeout
    while time.monotonic() < t_end:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_controller(mode, run_id, log_dir):
    env = dict(os.environ)
    env["SDN_MODE"] = mode
    env["SDN_RUN_ID"] = run_id
    env["SDN_LOG_DIR"] = log_dir
    cmd = ["venv/bin/ryu-manager", "--ofp-tcp-listen-port", "6653",
           os.path.join("controller", "sdn_ids.py")]
    ctrl_log = open(os.path.join(log_dir, "ryu.log"), "w")
    proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT, env=env,
                            stdout=ctrl_log, stderr=subprocess.STDOUT)
    return proc, ctrl_log


def build_net():
    lab = load_lab()
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=False, autoStaticArp=False)
    c0 = net.addController("c0", controller=RemoteController,
                           ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for name in sorted(lab.hosts, key=lambda n: lab.hosts[n].switch_port):
        b = lab.hosts[name]
        h = net.addHost(name, ip=f"{b.ip}/24", mac=b.mac)
        net.addLink(h, s1)
    net.build()
    c0.start()
    s1.start([c0])
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1")
    return net, lab


def run_syn(net, lab, scn, run_id, log_dir):
    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
    duration = float(scn["duration_s"])
    attack = scn["attack"] != "none"
    phase = duration / 3.0

    # profil vulnerabil pe victima (syncookies off + coada mica) => impact vizibil
    h1.cmd("sysctl -w net.ipv4.tcp_syncookies=0")
    h1.cmd("sysctl -w net.ipv4.tcp_max_syn_backlog=32")
    # servicii pe toata durata
    h1.cmd(f"python3 experiments/tcp_server.py --run-id {run_id} --backlog 8 "
           f"--log-dir {log_dir} > {log_dir}/h1_server.out 2>&1 &")
    time.sleep(1.0)
    h2.cmd(f"python3 experiments/tcp_client.py --run-id {run_id} --label h2 "
           f"--duration {duration:.0f} --log-dir {log_dir} > {log_dir}/h2_client.out 2>&1 &")
    h4.cmd(f"python3 experiments/tcp_client.py --run-id {run_id} --label h4 "
           f"--duration {duration:.0f} --log-dir {log_dir} > {log_dir}/h4_client.out 2>&1 &")

    collectors.snapshot_syn_recv(h1, log_dir, "baseline")
    collectors.dump_ovs_flows(log_dir, "baseline")
    time.sleep(phase)  # BASELINE

    if attack:
        h3.cmd(f"venv/bin/python3 attacks/syn_flood.py --rate {scn.get('attack_rate', 500):.0f} --duration {phase:.0f} "
               f"> {log_dir}/h3_attack.out 2>&1 &")
        time.sleep(phase / 2)
        collectors.snapshot_syn_recv(h1, log_dir, "attack")
        collectors.dump_ovs_flows(log_dir, "attack")
        time.sleep(phase / 2)
    else:
        time.sleep(phase)

    time.sleep(phase)  # RECUPERARE
    collectors.snapshot_syn_recv(h1, log_dir, "recovery")
    collectors.dump_ovs_flows(log_dir, "recovery")
    time.sleep(1.0)


def run_arp(net, lab, scn, run_id, log_dir):
    h1, h2, h3 = net.get("h1", "h2", "h3")
    duration = float(scn["duration_s"])
    attack = scn["attack"] != "none"

    h1.cmd(f"python3 experiments/message_server.py --run-id {run_id} "
           f"--log-dir {log_dir} > {log_dir}/h1_msgserver.out 2>&1 &")
    time.sleep(1.0)

    collectors.snapshot_arp_state([h1, h2], log_dir, "baseline")
    collectors.dump_ovs_flows(log_dir, "baseline")
    h2.cmd(f"python3 experiments/message_client.py --run-id {run_id} --log-dir {log_dir}")
    time.sleep(1.0)

    if attack:
        h3.cmd(f"venv/bin/python3 attacks/arp_mitm.py --duration {duration:.0f} "
               f"> {log_dir}/h3_arpmitm.out 2>&1 &")
        time.sleep(8.0)
        collectors.snapshot_arp_state([h1, h2], log_dir, "attack")
        collectors.dump_ovs_flows(log_dir, "attack")
        h2.cmd(f"python3 experiments/message_client.py --run-id {run_id} --log-dir {log_dir}")
        time.sleep(duration - 4.0)
    else:
        time.sleep(max(0.0, duration - 2.0))

    collectors.snapshot_arp_state([h1, h2], log_dir, "recovery")
    collectors.dump_ovs_flows(log_dir, "recovery")
    time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser(description="Runner automat de scenarii SDN")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rate", type=float, default=500.0)
    args = ap.parse_args()
    if args.run_id and not re.fullmatch(r"[A-Za-z0-9_.-]+", args.run_id):
        sys.exit("[EROARE] run_id invalid: doar litere, cifre, _ . -")

    scenarios = load_scenarios()
    if args.scenario not in scenarios:
        sys.exit(f"Scenariu necunoscut. Disponibile: {list(scenarios)}")
    scn = scenarios[args.scenario]
    scn = dict(scn)
    scn["attack_rate"] = args.rate
    run_id = args.run_id or f"{args.scenario}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    log_dir = os.path.join(PROJECT_ROOT, "logs", "raw", run_id)
    os.makedirs(log_dir, exist_ok=True)

    with open(os.path.join(log_dir, "run_config.json"), "w") as f:
        json.dump({"run_id": run_id, "scenario": args.scenario, "config": scn,
                   "t_utc": datetime.now(timezone.utc).isoformat()}, f, indent=2)

    setLogLevel("info")
    mode = scn["controller_mode"]
    print(f"== RUN {run_id} | scenariu={args.scenario} | mod={mode} ==")

    ctrl, ctrl_log = start_controller(mode, run_id, log_dir)
    net = None
    try:
        if not wait_port("127.0.0.1", 6653, timeout=15):
            raise RuntimeError("Controllerul Ryu nu asculta pe 6653 (vezi ryu.log)")
        net, lab = build_net()
        time.sleep(3.0)
        print("[runner] pingall de validare:")
        loss = net.pingAll()
        if loss > 0:
            raise RuntimeError(f"pingall a pierdut {loss}% - topologie invalida, opresc runul")

        if scn["family"] == "syn":
            run_syn(net, lab, scn, run_id, log_dir)
        else:
            run_arp(net, lab, scn, run_id, log_dir)

        print(f"[runner] scenariu terminat. Loguri in: {log_dir}")
    finally:
        if net is not None:
            net.stop()
        ctrl.send_signal(signal.SIGINT)
        try:
            ctrl.wait(timeout=5)
        except Exception:
            ctrl.kill()
        ctrl_log.close()
        subprocess.run(["mn", "-c"], stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()