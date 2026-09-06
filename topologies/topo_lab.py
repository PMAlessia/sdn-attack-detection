#!/usr/bin/env python3
"""
topo_lab.py - Topologia de laborator: 1 switch OVS (s1) + 4 hosturi (h1-h4).

Caracteristici cheie:
  * MAC-uri FIXE si porturi FIXE pe switch, identice cu config/lab.yaml.
  * OpenFlow 1.3 pe s1.
  * Controller REMOTE (Ryu) pe 127.0.0.1:6653.
  * Ordinea de adaugare a hosturilor => ordinea porturilor pe s1.

Pornire (dupa ce ruleaza controllerul intr-un alt terminal):
    sudo python3 topologies/topo_lab.py
"""
import os
import sys

# Permite `import lab_config` indiferent din ce director se ruleaza
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_config import load_lab  # noqa: E402

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def build(controller_ip: str = "127.0.0.1", controller_port: int = 6653):
    lab = load_lab()

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=False, autoStaticArp=False)

    info("*** Adaug controllerul remote Ryu\n")
    c0 = net.addController("c0", controller=RemoteController,
                           ip=controller_ip, port=controller_port)

    info("*** Adaug switch-ul s1 (OpenFlow 1.3)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adaug hosturile cu IP+MAC fixe (ordinea = ordinea porturilor)\n")
    for name in sorted(lab.hosts, key=lambda n: lab.hosts[n].switch_port):
        b = lab.hosts[name]
        host = net.addHost(name, ip=f"{b.ip}/24", mac=b.mac)
        net.addLink(host, s1)  # portul pe s1 = ordinea adaugarii linkului
        info(f"    {name}: ip={b.ip} mac={b.mac} -> s1 port {b.switch_port}\n")

    net.build()
    c0.start()
    s1.start([c0])

    # Dezactivam IPv6 pe hosturi ca sa nu polueze capturile cu trafic ND
    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1")

    info("\n*** Topologie pornita. Verifica maparea porturilor cu: sh ovs-ofctl -O OpenFlow13 show s1\n")
    info("*** Ruleaza `pingall` doar dupa ce controllerul e conectat.\n\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build()