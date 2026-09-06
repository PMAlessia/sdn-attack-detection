"""test_arp_guard.py - Oracolul determinist al validatorului ARP."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from controller.arp_guard import (ArpGuard, ArpObservation, Binding,
                                   VALID, MAC_MISMATCH, PORT_MISMATCH,
                                   UNKNOWN_SPA, ARP_PROBE)

BINDINGS = {
    "10.0.0.1": Binding("10.0.0.1", "00:00:00:00:00:01", 1),
    "10.0.0.2": Binding("10.0.0.2", "00:00:00:00:00:02", 2),
    "10.0.0.3": Binding("10.0.0.3", "00:00:00:00:00:03", 3),
    "10.0.0.4": Binding("10.0.0.4", "00:00:00:00:00:04", 4),
}


def guard():
    return ArpGuard(BINDINGS)


def test_binding_valid():
    v = guard().validate(ArpObservation(
        in_port=1, eth_src="00:00:00:00:00:01", arp_op=2,
        arp_spa="10.0.0.1", arp_sha="00:00:00:00:00:01"))
    assert v.is_valid and v.reason == VALID


def test_mac_fals():
    v = guard().validate(ArpObservation(
        in_port=3, eth_src="00:00:00:00:00:03", arp_op=2,
        arp_spa="10.0.0.1", arp_sha="00:00:00:00:00:03"))
    assert not v.is_valid and v.reason == MAC_MISMATCH


def test_mac_clonat_port_gresit():
    v = guard().validate(ArpObservation(
        in_port=3, eth_src="00:00:00:00:00:01", arp_op=2,
        arp_spa="10.0.0.1", arp_sha="00:00:00:00:00:01"))
    assert not v.is_valid and v.reason == PORT_MISMATCH


def test_ip_necunoscut():
    v = guard().validate(ArpObservation(
        in_port=3, eth_src="00:00:00:00:00:03", arp_op=2,
        arp_spa="10.0.0.99", arp_sha="00:00:00:00:00:03"))
    assert not v.is_valid and v.reason == UNKNOWN_SPA


def test_arp_probe():
    v = guard().validate(ArpObservation(
        in_port=3, eth_src="00:00:00:00:00:03", arp_op=1,
        arp_spa="0.0.0.0", arp_sha="00:00:00:00:00:03"))
    assert v.is_valid and v.reason == ARP_PROBE


def test_case_insensitive_mac():
    v = guard().validate(ArpObservation(
        in_port=2, eth_src="00:00:00:00:00:02", arp_op=2,
        arp_spa="10.0.0.2", arp_sha="00:00:00:00:00:02".upper()))
    assert v.is_valid


if __name__ == "__main__":
    fns = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for f in fns:
        f()
        print("OK", f.__name__)
    print(f"\n{len(fns)} teste trecute.")