"""
forwarding.py - Invatare MAC si forwarding L2 normal (independent de atac).

Este echivalentul unui simple_switch_13, dar izolat intr-un modul propriu:
NU stie nimic despre atacuri sau despre mitigare. Se ocupa doar de traficul
generic (non-ARP): invata maparea MAC->port si instaleaza reguli de forwarding
la prioritate joasa.

ARP-ul NU trece pe aici (e tratat de arp_gate/arp_guard). Traficul TCP catre
victima:8080 e tratat de flow-urile de numarare SYN (prioritate mai mare), asa
ca aici ajunge doar restul traficului.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict

from ryu.lib.packet import ethernet


class Forwarding:
    def __init__(self, flow_manager, forward_priority: int = 1):
        self.fm = flow_manager
        self.priority = forward_priority
        # dpid -> {mac: port}
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)

    def learn(self, dpid: int, src_mac: str, in_port: int) -> None:
        self.mac_to_port[dpid][src_mac] = in_port

    def handle(self, datapath, in_port, msg, eth: ethernet.ethernet) -> None:
        """Trateaza un PacketIn generic (non-ARP): invata si forwardeaza."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.learn(dpid, eth.src, in_port)

        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Daca stim portul destinatie, instalam o regula ca sa nu mai vina la
        # controller pachetele urmatoare (forwarding in planul de date).
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                    eth_src=eth.src)
            # cookie=0 => regula de forwarding, nu e atinsa de delete_by_cookie.
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.fm.add_flow(datapath, self.priority, match, actions,
                                 buffer_id=msg.buffer_id)
                return  # buffer-ul e consumat de FlowMod
            else:
                self.fm.add_flow(datapath, self.priority, match, actions)

        # Trimitem pachetul curent (PacketOut).
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)