"""
flow_manager.py - Instalarea si stergerea regulilor OpenFlow (FlowMod).

Responsabilitate unica: traduce deciziile controllerului in mesaje OpenFlow.
NU clasifica pachete (asta fac syn_guard/arp_guard).
"""
from __future__ import annotations

# Prefixe de cookie
ARP_GATE_COOKIE = 0xA2000001
ARP_DROP_PREFIX = 0xA2010000
SYN_COUNT_PREFIX = 0xA2020000
SYN_DROP_PREFIX = 0xA2030000
COOKIE_MASK_PREFIX = 0xFFFF0000  # masca pentru stergere pe prefix

ETH_TYPE_ARP = 0x0806
ETH_TYPE_IP = 0x0800
IP_PROTO_TCP = 6

TCP_SYN = 0x02
TCP_SYN_ACK = 0x12  # SYN+ACK, ca sa excludem raspunsurile serverului


class FlowManager:
    def __init__(self, logger=None):
        self.logger = logger

    # Primitive generice
    def add_flow(self, datapath, priority, match, actions, cookie=0, hard_timeout=0, idle_timeout=0, buffer_id=None):

        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(datapath=datapath, priority=priority, match=match, instructions=inst, cookie=cookie, hard_timeout=hard_timeout, idle_timeout=idle_timeout)

        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def delete_by_cookie(self, datapath, cookie, cookie_mask=COOKIE_MASK_PREFIX):
        """Sterge toate flow-urile care au cookie-ul in prefixul dat."""

        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=cookie, cookie_mask=cookie_mask,
            table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch())

        datapath.send_msg(mod)

    def request_barrier(self, datapath):
        """BarrierRequest: OVS confirma cu BarrierReply ca a procesat comenzile
        anterioare. Momentul BarrierReply = finalul timpului de mitigare."""

        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPBarrierRequest(datapath))

    # Reguli de baza instalate la conectarea switch-ului
    def install_table_miss(self, datapath):
        """table-miss: trimite catre controller ce nu se potriveste."""

        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def install_arp_gate(self, datapath, priority):
        """Orice ARP -> controller (validation-before-forward)."""

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        match = parser.OFPMatch(eth_type=ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=priority, match=match, actions=actions, cookie=ARP_GATE_COOKIE)

    def install_syn_count_flows(self, datapath, host_ports, victim_ip, victim_port_no, server_port, priority, use_tcp_flags=False):
        """Pentru fiecare port de host (mai putin victima): o regula care numara
        pachetele TCP catre victim_ip:server_port si LE SI FORWARDEAZA."""

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        for in_port in host_ports:
            fields = dict(in_port=in_port, eth_type=ETH_TYPE_IP, ip_proto=IP_PROTO_TCP, ipv4_dst=victim_ip, tcp_dst=server_port)

            if use_tcp_flags:
                fields["tcp_flags"] = (TCP_SYN, TCP_SYN | 0x10)  # SYN set, ACK clear

            match = parser.OFPMatch(**fields)
            actions = [parser.OFPActionOutput(victim_port_no)]
            cookie = SYN_COUNT_PREFIX | (in_port & 0xFFFF)

            self.add_flow(datapath, priority=priority, match=match, actions=actions, cookie=cookie)

    # Reguli de mitigare
    def install_arp_drop(self, datapath, in_port, arp_spa, alert_id, priority, hard_timeout):
        """Drop ARP fals: pachet ARP care intra pe in_port si pretinde arp_spa."""

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_ARP, arp_spa=arp_spa)

        cookie = ARP_DROP_PREFIX | (alert_id & 0xFFFF)
        self.add_flow(datapath, priority=priority, match=match, actions=[], cookie=cookie, hard_timeout=hard_timeout)

        if self.logger:
            self.logger.info("[flow_manager] ARP drop: in_port=%s arp_spa=%s "
                             "cookie=0x%X ht=%ss", in_port, arp_spa, cookie, hard_timeout)
        return cookie

    def install_syn_drop(self, datapath, in_port, victim_ip, server_port, priority, hard_timeout):
        """Drop SYN flood: tot TCP-ul de pe in_port-ul atacatorului catre
        victim_ip:server_port este aruncat."""

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP,
                                ip_proto=IP_PROTO_TCP, ipv4_dst=victim_ip,
                                tcp_dst=server_port)

        cookie = SYN_DROP_PREFIX | (in_port & 0xFFFF)
        self.add_flow(datapath, priority=priority, match=match, actions=[], cookie=cookie, hard_timeout=hard_timeout)

        if self.logger:
            self.logger.info("[flow_manager] SYN drop: in_port=%s dst=%s:%s "
                             "cookie=0x%X ht=%ss", in_port, victim_ip,
                             server_port, cookie, hard_timeout)
        return cookie