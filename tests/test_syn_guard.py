"""test_syn_guard.py - Logica de detectie SYN (baseline + prag + ferestre)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from controller.syn_guard import SynGuard


def test_prima_citire_nu_alerteaza():
    g = SynGuard(threshold=100, consecutive_windows=3, poll_interval_s=1.0)
    assert g.update(3, 0) is None


def test_alerta_dupa_ferestre_consecutive():
    g = SynGuard(threshold=100, consecutive_windows=3, poll_interval_s=1.0)
    g.update(3, 0)
    assert g.update(3, 150) is None
    assert g.update(3, 300) is None
    alert = g.update(3, 450)
    assert alert is not None and alert.in_port == 3 and alert.rate == 150.0


def test_sub_prag_nu_alerteaza():
    g = SynGuard(threshold=100, consecutive_windows=2, poll_interval_s=1.0)
    g.update(2, 0)
    for c in (10, 20, 30, 40):
        assert g.update(2, c) is None


def test_burst_scurt_nu_declanseaza():
    g = SynGuard(threshold=100, consecutive_windows=3, poll_interval_s=1.0)
    g.update(2, 0)
    assert g.update(2, 200) is None
    assert g.update(2, 210) is None
    assert g.update(2, 220) is None


def test_o_singura_alerta_per_episod():
    g = SynGuard(threshold=100, consecutive_windows=2, poll_interval_s=1.0)
    g.update(3, 0)
    g.update(3, 200)
    a1 = g.update(3, 400)
    a2 = g.update(3, 600)
    assert a1 is not None and a2 is None


def test_atribuire_per_port():
    g = SynGuard(threshold=100, consecutive_windows=1, poll_interval_s=1.0)
    g.update(2, 0); g.update(3, 0)
    assert g.update(2, 10) is None
    a = g.update(3, 500)
    assert a is not None and a.in_port == 3


if __name__ == "__main__":
    fns = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for f in fns:
        f()
        print("OK", f.__name__)
    print(f"\n{len(fns)} teste trecute.")