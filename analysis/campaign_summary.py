#!/usr/bin/env python3
"""
campaign_summary.py - Summary of the 3x3 campaign (SYN + ARP) for Chapter 5.

Computes, over the three repetitions of each scenario, the values reported in
Tables 5.3 and 5.4: client success rate, connect latency, attacker SYN rate,
alert timing, mitigation times, ARP violations and message integrity.
Values are mean +/- 95% CI (Student t, n-1 degrees of freedom).

Run from the project root:
    python3 analysis/campaign_summary.py            # uses logs/raw
    python3 analysis/campaign_summary.py --logs logs/raw
"""
from __future__ import annotations

import argparse
import json
import os
import statistics as st

import pandas as pd

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571}
THRESHOLD_DEFAULT = 20.0


def agg(xs):
    xs = [x for x in xs if x is not None]
    n = len(xs)
    if n == 0:
        return None
    m = sum(xs) / n
    if n == 1:
        return (m, 0.0, n)
    sd = st.stdev(xs)
    ci = T95.get(n - 1, 1.96) * sd / n ** 0.5
    return (m, ci, n)


def fmt(a, unit=""):
    if a is None:
        return "n/a"
    m, ci, n = a
    return f"{m:.2f} ± {ci:.2f}{unit} (n={n})"


def events(run):
    with open(os.path.join(run, "events.jsonl")) as f:
        return [json.loads(l) for l in f]


def client_stats(run):
    out = {}
    for lab in ("h2", "h4"):
        p = os.path.join(run, f"client_{lab}.csv")
        if not os.path.exists(p):
            continue
        df = pd.read_csv(p)
        ok = df["result"] == "success"
        out[lab] = (100.0 * ok.mean(),
                    df.loc[ok, "latency_ms"].mean() if ok.any() else None)
    return out


def attacker_rate(run, thr):
    r = [e["rate"] for e in events(run)
         if e["event"] == "SYN_RATE_SAMPLE" and e.get("host") == "h3"]
    active = [x for x in r if x >= thr]
    return (max(r) if r else 0.0, sum(active) / len(active) if active else 0.0)


def alert_info(run):
    ev = events(run)
    al = [e for e in ev if e["event"] == "SYN_FLOOD_ALERT"]
    if not al:
        return None
    a = al[0]
    thr = a.get("threshold", THRESHOLD_DEFAULT)
    first = next((e["t_monotonic_ns"] for e in ev
                  if e["event"] == "SYN_RATE_SAMPLE" and e.get("host") == "h3"
                  and e["rate"] >= thr), None)
    lat_s = (a["t_detected"] - first) / 1e9 if first else None
    return (a["rate"], a["windows"], lat_s, thr)


def mitigation(run):
    c = [e for e in events(run) if e["event"] == "MITIGATION_CONFIRMED"]
    ctrl = [e["t_mitigation_control_ms"] for e in c if e.get("t_mitigation_control_ms") is not None]
    tot = [e["t_total_ms"] for e in c if e.get("t_total_ms") is not None]
    return ctrl, tot


def arp_messages(run):
    p = os.path.join(run, "message_server.jsonl")
    if not os.path.exists(p):
        return (0, 0)
    tot = mod = 0
    with open(p) as f:
        for l in f:
            d = json.loads(l)
            tot += 1
            mod += 1 if d.get("modified") else 0
    return (tot, mod)


def arp_violations(run):
    v = [e for e in events(run) if e["event"] == "ARP_BINDING_VIOLATION"]
    reasons = {}
    for e in v:
        reasons[e.get("reason", "?")] = reasons.get(e.get("reason", "?"), 0) + 1
    return len(v), reasons


def reps(logs, prefix):
    return [os.path.join(logs, f"{prefix}_{i}") for i in (1, 2, 3)
            if os.path.isdir(os.path.join(logs, f"{prefix}_{i}"))]


def main():
    ap = argparse.ArgumentParser(description="3x3 campaign summary (Chapter 5)")
    ap.add_argument("--logs", default="logs/raw")
    args = ap.parse_args()
    L = args.logs

    print("=" * 66 + "\nSYN FAMILY  (Table 5.3)\n" + "=" * 66)
    for scn in ("norm_syn", "att_syn", "mit_syn"):
        runs = reps(L, scn)
        print(f"\n--- {scn}  ({len(runs)} runs) ---")
        s2, s4, lat, peak, sust, alat, ctrl = [], [], [], [], [], [], []
        for r in runs:
            cs = client_stats(r)
            if "h2" in cs: s2.append(cs["h2"][0]); lat.append(cs["h2"][1])
            if "h4" in cs: s4.append(cs["h4"][0]); lat.append(cs["h4"][1])
            ai = alert_info(r)
            thr = ai[3] if ai else THRESHOLD_DEFAULT
            pk, sm = attacker_rate(r, thr); peak.append(pk); sust.append(sm)
            if ai and ai[2] is not None: alat.append(ai[2])
            c, _ = mitigation(r); ctrl += c
            print(f"  {os.path.basename(r)}: h2={cs.get('h2', (float('nan'),))[0]:.1f}%  "
                  f"h4={cs.get('h4', (float('nan'),))[0]:.1f}%  peak={pk:.0f}/s  "
                  f"alert={'rate %.0f/s after %d windows, %.2fs after crossing' % (ai[0], ai[1], ai[2]) if ai else 'none'}")
        print(f"  h2 success rate : {fmt(agg(s2), '%')}")
        print(f"  h4 success rate : {fmt(agg(s4), '%')}")
        print(f"  connect latency : {fmt(agg(lat), ' ms')}")
        print(f"  attacker peak   : {fmt(agg(peak), ' pkt/s')}")
        print(f"  attacker sustained (>= threshold): {fmt(agg(sust), ' pkt/s')}")
        if alat: print(f"  alert after crossing: {fmt(agg(alat), ' s')}")
        if ctrl: print(f"  mitigation control time: {fmt(agg(ctrl), ' ms')}  values={['%.2f' % x for x in ctrl]}")

    print("\n" + "=" * 66 + "\nARP FAMILY  (Table 5.4)\n" + "=" * 66)
    for scn in ("norm_arp", "att_arp", "mit_arp"):
        runs = reps(L, scn)
        print(f"\n--- {scn}  ({len(runs)} runs) ---")
        tots, mods, viol, ctrl, tot = [], [], [], [], []
        for r in runs:
            t, m = arp_messages(r); tots.append(t); mods.append(m)
            nv, reasons = arp_violations(r); viol.append(nv)
            c, tt = mitigation(r); ctrl += c; tot += tt
            print(f"  {os.path.basename(r)}: messages={t} modified={m}  violations={nv} {reasons}")
        print(f"  messages received: {fmt(agg(tots))}   modified: {fmt(agg(mods))}")
        print(f"  violations       : {fmt(agg(viol))}")
        if ctrl: print(f"  mitigation control: {fmt(agg(ctrl), ' ms')}   total: {fmt(agg(tot), ' ms')}")


if __name__ == "__main__":
    main()