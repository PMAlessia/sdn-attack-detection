"""test_metrics.py - Verifica parsarea logurilor si statisticile din metrics.py."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis import metrics as M
from tests._sample_logs import make_run


def test_syn_parsing():
    with tempfile.TemporaryDirectory() as tmp:
        rd = make_run(os.path.join(tmp, "syn_attack_01"), family="syn",
                      scenario="syn_attack", mode="monitor_only")
        ev = M.load_events(rd)
        ts = M.syn_rate_timeseries(ev)
        assert not ts.empty and set(ts["host"]) >= {"h2", "h3", "h4"}
        assert ts["rate"].max() > 200
        cl = M.load_clients(rd)
        assert not cl.empty and "ok" in cl
        sr = M.client_success_rate(cl, label="h2")
        assert 0 <= sr <= 100


def test_mitigation_times():
    with tempfile.TemporaryDirectory() as tmp:
        rd = make_run(os.path.join(tmp, "syn_mit_01"), family="syn",
                      scenario="syn_mitigated", mode="enforce")
        ev = M.load_events(rd)
        mt = M.mitigation_times(ev)
        assert not mt.empty and "t_mitigation_control_ms" in mt


def test_message_stats():
    with tempfile.TemporaryDirectory() as tmp:
        rd_att = make_run(os.path.join(tmp, "arp_attack_01"), family="arp",
                          scenario="arp_attack", mode="monitor_only")
        rd_mit = make_run(os.path.join(tmp, "arp_mit_01"), family="arp",
                          scenario="arp_mitigated", mode="enforce")
        assert M.message_stats(rd_att)["modified"] == 1
        assert M.message_stats(rd_mit)["modified"] == 0


def test_suggest_threshold():
    with tempfile.TemporaryDirectory() as tmp:
        dirs = [make_run(os.path.join(tmp, f"norm_{i}"), family="syn",
                         scenario="normal_syn", mode="monitor_only", seed=i)
                for i in range(3)]
        thr = M.suggest_threshold(dirs)
        assert thr["n_samples"] > 0 and thr["mean_plus_k_std"] > thr["mean"]


def test_aggregate_ci():
    a = M.aggregate([90.0, 92.0, 88.0, 91.0])
    assert a["n"] == 4 and a["ci95"] > 0 and abs(a["mean"] - 90.25) < 1e-6


if __name__ == "__main__":
    fns = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for f in fns:
        f()
        print("OK", f.__name__)
    print(f"\n{len(fns)} teste trecute.")