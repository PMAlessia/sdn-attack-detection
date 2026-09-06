"""
telemetry.py - Polling periodic al statisticilor de flow (FlowStats).

Un fir verde (ryu.lib.hub) trimite periodic OFPFlowStatsRequest filtrat pe
cookie-ul flow-urilor de numarare SYN. La sosirea raspunsului, extrage per port
numarul cumulativ de pachete si il returneaza aplicatiei, care il paseaza lui
syn_guard pentru calculul ratei si al pragului.

Modelul urmeaza "Traffic Monitor" din Ryu Book. Volumul SYN ramane in planul de
date; controllerul citeste doar contoare, deci nu devine el insusi tinta.
"""
from __future__ import annotations

from typing import Callable, Dict, Optional

from ryu.lib import hub

from controller.flow_manager import SYN_COUNT_PREFIX, COOKIE_MASK_PREFIX


class TelemetryPoller:
    def __init__(self, interval_s: float, on_counts: Callable[[Dict[int, int]], None],
                 logger=None):
        self.interval_s = interval_s
        self.on_counts = on_counts        # callback(counts: {in_port: cumulative})
        self.logger = logger
        self._thread = None
        self._datapath = None
        self._stop = False

    def start(self, datapath):
        self._datapath = datapath
        self._stop = False
        if self._thread is None:
            self._thread = hub.spawn(self._loop)

    def stop(self):
        self._stop = True

    def _loop(self):
        while not self._stop:
            dp = self._datapath
            if dp is not None:
                self._request_flow_stats(dp)
            hub.sleep(self.interval_s)

    def _request_flow_stats(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        # Cerem doar flow-urile de numarare SYN (dupa prefixul de cookie).
        req = parser.OFPFlowStatsRequest(
            datapath, cookie=SYN_COUNT_PREFIX, cookie_mask=COOKIE_MASK_PREFIX)
        datapath.send_msg(req)

    def handle_flow_stats_reply(self, body):
        """
        Se apeleaza de aplicatie in handler-ul EventOFPFlowStatsReply.
        Extrage {in_port: packet_count} pentru flow-urile de numarare SYN si
        invoca callback-ul on_counts.
        """
        counts: Dict[int, int] = {}
        for stat in body:
            if (stat.cookie & COOKIE_MASK_PREFIX) != SYN_COUNT_PREFIX:
                continue
            in_port = stat.match.get("in_port")
            if in_port is None:
                # fallback: portul e codat in cookie
                in_port = stat.cookie & 0xFFFF
            counts[in_port] = stat.packet_count
        if counts:
            self.on_counts(counts)