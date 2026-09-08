#!/usr/bin/env python3
"""
syn_figures.py - The SYN-flood figures for the thesis, in ONE script.

Generates the three figures we keep (all in English, all from REAL run logs):

  1) syn_rate_timeline_attack     - attack WITHOUT mitigation (monitor_only):
                                    the attacker's SYN rate crosses the alarm
                                    threshold and stays high.  => "detection".
  2) syn_rate_timeline_mitigated  - attack WITH mitigation (enforce): after the
                                    FlowMod, the attacker's rate collapses.
                                    => "mitigation".
  3) client_service_timeline      - legitimate clients h2/h4: latency + per-request
                                    success/fail over time, showing the outage
                                    during the attack.  => "impact on the client".

Data sources (produced by scenario_runner, never synthetic):
  events.jsonl                    -> SYN_RATE_SAMPLE, SYN_FLOOD_ALERT,
                                     MITIGATION_FLOWMOD_SENT
  client_h2.csv / client_h4.csv   -> result (success/fail), latency_ms, timestamp

Place in analysis/ next to metrics.py and style.py. Run from the project root
(venv active):

    python3 analysis/syn_figures.py \
        --attack-run    logs/raw/att_syn_1 \
        --mitigated-run logs/raw/mit_syn_1 \
        --out results/figures/final
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib.pyplot as plt
import numpy as np

from analysis import metrics as M
from analysis.style import new_fig, COLOR, apply_style


def _save(fig, out_dir, name):
    os.makedirs(out_dir, exist_ok=True)
    png = os.path.join(out_dir, name + ".png")
    pdf = os.path.join(out_dir, name + ".pdf")   # vector, for the thesis
    fig.savefig(png)
    fig.savefig(pdf)
    plt.close(fig)
    print(f"  [figure] {png}")
    print(f"  [figure] {pdf}")
    return png


# --------------------------------------------------------------------------- #
# 1) + 2)  SYN rate timeline (attack / mitigated)
# --------------------------------------------------------------------------- #
def fig_syn_timeline(run_dir, out_dir, out_name, title):
    # common time origin for the whole run, so this figure and the client
    # figure share the same "time = 0" (F09: aligned axes across figures)
    t0 = M.run_t0(run_dir)
    ev = M.load_events(run_dir, t0=t0)
    ts = M.syn_rate_timeseries(ev)
    if ts.empty:
        print(f"  [skip] no SYN_RATE_SAMPLE in {run_dir}")
        return None
    if t0 is None:
        t0 = int(ev["t_monotonic_ns"].min())
    fig, ax = new_fig()
    host_color = {"h2": COLOR["h2"], "h3": COLOR["h3"], "h4": COLOR["h4"]}
    host_label = {"h2": "h2 (legit client)", "h3": "h3 (attacker)", "h4": "h4 (legit client)"}
    for h in sorted(ts["host"].unique()):
        d = ts[ts["host"] == h].sort_values("t_rel_s")
        ax.plot(d["t_rel_s"], d["rate"], label=host_label.get(h, h),
                color=host_color.get(h, COLOR["syn_rate"]))

    alerts = M.syn_alerts(ev)
    if not alerts.empty:
        thr = float(alerts["threshold"].iloc[0])
        ax.axhline(thr, color=COLOR["threshold"], linestyle="--", linewidth=1.5,
                   label=f"alarm threshold = {thr:.0f} SYN/s")
        for _, a in alerts.iterrows():
            ax.axvline(a["t_detected"] / 1e9 - t0 / 1e9,
                       color=COLOR["alert"], linestyle=":", linewidth=1.5)
        ax.plot([], [], color=COLOR["alert"], linestyle=":", label="alert raised")

    fm = ev[ev["event"] == "MITIGATION_FLOWMOD_SENT"] if "event" in ev else None
    if fm is not None and not fm.empty:
        for _, r in fm.iterrows():
            ax.axvline(r["t_monotonic_ns"] / 1e9 - t0 / 1e9,
                       color=COLOR["flowmod"], linestyle="-.", linewidth=1.5)
        ax.plot([], [], color=COLOR["flowmod"], linestyle="-.", label="block rule installed")

    ax.set_xlabel("time [s]")
    ax.set_ylabel("SYN rate [packets/s]")
    ax.set_title(title)
    ax.legend(loc="upper right")
    return _save(fig, out_dir, out_name)


# --------------------------------------------------------------------------- #
# 3)  Client service timeline (latency + success/fail)
# --------------------------------------------------------------------------- #
def fig_client_service(run_dir, out_dir):
    # same common time origin as the SYN timeline of this run (F09)
    cl = M.load_clients(run_dir, t0=M.run_t0(run_dir))
    if cl.empty:
        print(f"  [skip] no client logs in {run_dir}")
        return None
    apply_style()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8.0, 6.0), sharex=True)
    lab_color = {"h2": COLOR["h2"], "h4": COLOR["h4"]}
    labels = sorted(cl["label"].unique())
    # robust y-limit computed up front; a few connections delayed to ~1 s are
    # extreme outliers that would flatten the normal band, so they are hidden
    succ_all = cl[cl["ok"]]
    top = max(float(succ_all["latency_ms"].quantile(0.97)) * 1.4, 5.0) if len(succ_all) else 5.0
    for lab in labels:
        d = cl[(cl["label"] == lab) & (cl["ok"])].sort_values("t_rel_s")
        t = d["t_rel_s"].to_numpy(dtype=float)
        y = d["latency_ms"].to_numpy(dtype=float)
        y[y > top] = np.nan   # hide extreme outliers (no line shooting off-chart)
        # break the line across gaps (e.g. the attack window has no successes)
        if len(t) > 1:
            cut = np.where(np.diff(t) > 3.0)[0] + 1
            if len(cut):
                t = np.insert(t, cut, np.nan)
                y = np.insert(y, cut, np.nan)
        ax1.plot(t, y, marker="o", markersize=4,
                 linewidth=1.5, color=lab_color.get(lab, COLOR["latency"]),
                 label=f"{lab} (successful)")
    ax1.set_ylim(0, top)
    ax1.set_ylabel("connect() latency [ms]")
    ax1.set_title("Impact on legitimate clients: connection failures during the attack")
    ax1.legend(loc="upper left")
    for lab in labels:
        d = cl[cl["label"] == lab].sort_values("t_rel_s")
        y = d["ok"].astype(int) + (0.03 if lab == "h4" else 0.0)
        ax2.plot(d["t_rel_s"], y, marker="|", linestyle="none", markersize=12,
                 color=lab_color.get(lab, COLOR["latency"]), label=lab)
    ax2.set_yticks([0, 1])
    ax2.set_yticklabels(["fail", "success"])
    ax2.set_ylim(-0.2, 1.2)
    ax2.set_xlabel("time [s]")
    ax2.set_ylabel("connect() result")
    ax2.legend(loc="lower left")
    return _save(fig, out_dir, "client_service_timeline")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="SYN-flood thesis figures (real logs only)")
    ap.add_argument("--attack-run", default="",
                    help="one run dir, attack WITHOUT mitigation -> detection timeline + client service")
    ap.add_argument("--mitigated-run", default="",
                    help="one run dir, attack WITH mitigation -> mitigation timeline")
    ap.add_argument("--out", default="results/figures/final")
    args = ap.parse_args()

    print(f"[out] {args.out}")
    if args.attack_run:
        fig_syn_timeline(args.attack_run, args.out, "syn_rate_timeline_attack",
                         "SYN flood detection: attacker traffic crosses the alarm threshold")
        fig_client_service(args.attack_run, args.out)
    if args.mitigated_run:
        fig_syn_timeline(args.mitigated_run, args.out, "syn_rate_timeline_mitigated",
                         "SYN flood mitigation: the controller blocks the attacker after detection")


if __name__ == "__main__":
    main()