"""
sdn_ids.py - Punctul de intrare al aplicatiei Ryu (IDS/IPS SDN).

Coordoneaza modulele: forwarding, telemetry, syn_guard, arp_guard,
flow_manager, event_logger.

Moduri (variabila de mediu SDN_MODE):
    monitor_only  - detecteaza si alerteaza, dar NU blocheaza
    enforce       - dupa verdict/alerta, instaleaza regula de drop in OVS

Pornire:
    SDN_MODE=monitor_only SDN_RUN_ID=demo01 \
        ryu-manager --ofp-tcp-listen-port 6653 controller/sdn_ids.py
"""
from __future__ import annotations

import os
import sys
from collections import deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp

from lab_config import load_lab
from controller.event_logger import EventLogger
from controller.flow_manager import FlowManager
from controller.forwarding import Forwarding
from controller.telemetry import TelemetryPoller
from controller.syn_guard import SynGuard
from controller import arp_guard as ag


class SdnIds(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lab = load_lab()
        self.mode = os.environ.get("SDN_MODE", "monitor_only").strip()
        run_id = os.environ.get("SDN_RUN_ID") or datetime.now().strftime("run_%Y%m%d_%H%M%S")
        log_dir = os.environ.get("SDN_LOG_DIR") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "raw", run_id)
        self.run_id = run_id
        self.ev = EventLogger(log_dir, run_id)

        # --- module ---
        self.fm = FlowManager(logger=self.logger)
        self.forwarding = Forwarding(
            self.fm, forward_priority=self.lab.mitigation.get("forward_priority", 1))

        det = self.lab.syn_detection
        self.syn_guard = SynGuard(
            threshold=float(det.get("syn_rate_threshold", 200.0)),
            consecutive_windows=int(det.get("consecutive_windows", 3)),
            poll_interval_s=float(det.get("poll_interval_s", 1.0)))
        self.use_tcp_flags = bool(det.get("use_tcp_flags_match", False))

        self.arp_guard = ag.ArpGuard({
            ip: ag.Binding(b.ip, b.mac, b.switch_port)
            for ip, b in self.lab.binding_by_ip().items()})

        self.telemetry = TelemetryPoller(
            interval_s=float(det.get("poll_interval_s", 1.0)),
            on_counts=self._on_syn_counts, logger=self.logger)

        # --- stare ---
        self.datapath = None
        self.victim_ip = self.lab.syn.get("server_ip", "10.0.0.1")
        self.server_port = int(self.lab.syn.get("server_port", 8080))
        self.victim = self.lab.role("victim")
        self.port_to_host = {b.switch_port: name for name, b in self.lab.hosts.items()}
        self._pending_barriers = deque()
        self._alert_seq = 0

        self.logger.info("=" * 60)
        self.logger.info("SDN-IDS pornit | mod=%s | run_id=%s", self.mode, self.run_id)
        self.logger.info("Loguri in: %s", self.ev.path)
        self.logger.info("=" * 60)
        self.ev.log("CONTROLLER_START", mode=self.mode)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        mit = self.lab.mitigation

        self.fm.install_table_miss(datapath)
        self.fm.install_arp_gate(datapath, priority=mit.get("arp_gate_priority", 100))
        host_ports = [b.switch_port for b in self.lab.hosts.values()
                      if b.switch_port != self.victim.switch_port]
        self.fm.install_syn_count_flows(
            datapath, host_ports=host_ports, victim_ip=self.victim_ip,
            victim_port_no=self.victim.switch_port, server_port=self.server_port,
            priority=mit.get("count_priority", 50), use_tcp_flags=self.use_tcp_flags)

        self.telemetry.start(datapath)

        self.logger.info("Switch conectat (dpid=%s). Reguli de baza instalate. "
                         "Numarare SYN pe porturile %s.", datapath.id, host_ports)
        self.ev.log("SWITCH_CONNECTED", dpid=datapath.id, count_ports=host_ports,
                    use_tcp_flags=self.use_tcp_flags)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        t_packet_in = EventLogger.now_monotonic_ns()
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(datapath, in_port, msg, eth, pkt, t_packet_in)
            return

        self.forwarding.handle(datapath, in_port, msg, eth)

    def _handle_arp(self, datapath, in_port, msg, eth, pkt, t_packet_in):
        a = pkt.get_protocol(arp.arp)
        if a is None:
            return

        obs = ag.ArpObservation(
            in_port=in_port, eth_src=eth.src, arp_op=a.opcode,
            arp_spa=a.src_ip, arp_sha=a.src_mac,
            arp_tpa=a.dst_ip, arp_tha=a.dst_mac)
        verdict = self.arp_guard.validate(obs)
        t_detected = EventLogger.now_monotonic_ns()

        if verdict.is_valid:
            # Invatam maparea MAC->port DOAR pentru ARP complet validat
            # (spa se potriveste cu un binding de incredere, cu MAC si port corecte).
            # NU invatam din probe ARP (spa=0.0.0.0): sursa lor nu e verificata
            # fata de tabela de binding, deci o proba falsificata ar putea altfel
            # otravi tabela de forwarding L2.
            if verdict.reason == ag.VALID:
                self.forwarding.learn(datapath.id, eth.src, in_port)
            self.ev.log("ARP_VALID", in_port=in_port, arp_spa=a.src_ip,
                        arp_sha=eth.src, arp_op=a.opcode, reason=verdict.reason)
            self._arp_flood(datapath, in_port, msg)
            return

        self._alert_seq += 1
        alert_id = self._alert_seq
        self.ev.log("ARP_BINDING_VIOLATION", alert_id=alert_id, in_port=in_port,
                    arp_spa=a.src_ip, observed_mac=eth.src,
                    expected_mac=verdict.expected_mac,
                    expected_port=verdict.expected_port,
                    reason=verdict.reason, mode=self.mode,
                    t_packet_in=t_packet_in, t_detected=t_detected)
        self.logger.warning("[ARP] VIOLARE binding: port=%s pretinde spa=%s "
                            "(mac observat=%s, asteptat=%s) motiv=%s",
                            in_port, a.src_ip, eth.src, verdict.expected_mac,
                            verdict.reason)

        if self.mode == "enforce":
            cookie = self.fm.install_arp_drop(
                datapath, in_port=in_port, arp_spa=a.src_ip, alert_id=alert_id,
                priority=self.lab.mitigation.get("drop_priority", 200),
                hard_timeout=int(self.lab.mitigation.get("hard_timeout_s", 60)))
            t_flowmod_sent = EventLogger.now_monotonic_ns()
            self.ev.log("MITIGATION_FLOWMOD_SENT", alert_id=alert_id,
                        kind="arp_drop", in_port=in_port, arp_spa=a.src_ip,
                        cookie=hex(cookie), t_flowmod_sent=t_flowmod_sent)
            self._pending_barriers.append(dict(
                kind="arp_drop", alert_id=alert_id, in_port=in_port,
                arp_spa=a.src_ip, t_packet_in=t_packet_in,
                t_detected=t_detected, t_flowmod_sent=t_flowmod_sent))
            self.fm.request_barrier(datapath)
        else:
            self._arp_flood(datapath, in_port, msg)

    def _arp_flood(self, datapath, in_port, msg):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _on_syn_counts(self, counts):
        datapath = self.datapath
        if datapath is None:
            return
        for in_port, count in counts.items():
            alert = self.syn_guard.update(in_port, count)
            rate = self.syn_guard.last_rate(in_port)
            self.ev.log("SYN_RATE_SAMPLE", in_port=in_port,
                        host=self.port_to_host.get(in_port, "?"),
                        cumulative=count, rate=rate)
            if alert is None:
                continue

            self._alert_seq += 1
            alert_id = self._alert_seq
            t_detected = EventLogger.now_monotonic_ns()
            self.ev.log("SYN_FLOOD_ALERT", alert_id=alert_id, in_port=in_port,
                        host=self.port_to_host.get(in_port, "?"),
                        rate=alert.rate, threshold=alert.threshold,
                        windows=alert.windows, mode=self.mode,
                        t_detected=t_detected)
            self.logger.warning("[SYN] ALERTA flood pe port=%s (%s): %.1f SYN/s "
                                "(prag %.1f, %d ferestre)", in_port,
                                self.port_to_host.get(in_port, "?"),
                                alert.rate, alert.threshold, alert.windows)

            if self.mode == "enforce":
                cookie = self.fm.install_syn_drop(
                    datapath, in_port=in_port, victim_ip=self.victim_ip,
                    server_port=self.server_port,
                    priority=self.lab.mitigation.get("drop_priority", 200),
                    hard_timeout=int(self.lab.mitigation.get("hard_timeout_s", 60)))
                t_flowmod_sent = EventLogger.now_monotonic_ns()
                self.ev.log("MITIGATION_FLOWMOD_SENT", alert_id=alert_id,
                            kind="syn_drop", in_port=in_port,
                            cookie=hex(cookie), t_flowmod_sent=t_flowmod_sent)
                self._pending_barriers.append(dict(
                    kind="syn_drop", alert_id=alert_id, in_port=in_port,
                    t_packet_in=None, t_detected=t_detected,
                    t_flowmod_sent=t_flowmod_sent))
                self.fm.request_barrier(datapath)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.telemetry.handle_flow_stats_reply(ev.msg.body)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        t_barrier = EventLogger.now_monotonic_ns()
        if not self._pending_barriers:
            return
        p = self._pending_barriers.popleft()
        t_detect = p.get("t_flowmod_sent") or p.get("t_detected")
        t_mit_control_ms = (t_barrier - t_detect) / 1e6 if t_detect else None
        t_total_ms = None
        if p.get("t_packet_in"):
            t_total_ms = (t_barrier - p["t_packet_in"]) / 1e6
        self.ev.log("MITIGATION_CONFIRMED", alert_id=p.get("alert_id"),
                    kind=p.get("kind"), in_port=p.get("in_port"),
                    arp_spa=p.get("arp_spa"), t_barrier_reply=t_barrier,
                    t_mitigation_control_ms=t_mit_control_ms,
                    t_total_ms=t_total_ms)
        self.logger.info("[MITIGARE] confirmata (%s, port=%s): "
                         "timp control=%.2f ms", p.get("kind"), p.get("in_port"),
                         t_mit_control_ms if t_mit_control_ms else -1)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def _state_change_handler(self, ev):
        if ev.datapath and ev.datapath.id == getattr(self.datapath, "id", None):
            self.telemetry.stop()
            self.ev.log("SWITCH_DISCONNECTED")