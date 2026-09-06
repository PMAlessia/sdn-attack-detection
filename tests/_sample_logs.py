"""
_sample_logs.py - Genereaza un director de rulare FICTIV, doar pentru testarea
pipeline-ului de parsare/plotare (NU sunt date pentru lucrare).
"""
import json
import os
import random


def make_run(run_dir, family="syn", scenario="syn_attack", mode="enforce",
             seed=0):
    random.seed(seed)
    os.makedirs(run_dir, exist_ok=True)
    t0 = 1_000_000_000_000  # ns arbitrar

    with open(os.path.join(run_dir, "run_config.json"), "w") as f:
        json.dump({"run_id": os.path.basename(run_dir), "scenario": scenario,
                   "config": {"family": family, "controller_mode": mode}}, f)

    ev = []

    def log(event, dt_s, **kw):
        rec = {"event": event, "t_monotonic_ns": t0 + int(dt_s * 1e9)}
        rec.update(kw)
        ev.append(rec)

    log("CONTROLLER_START", 0, mode=mode)
    log("SWITCH_CONNECTED", 0.5, dpid=1)

    if family == "syn":
        for k in range(60):
            t = k * 1.0
            for host, port, base in (("h2", 2, 5), ("h4", 4, 3), ("h3", 3, 2)):
                rate = base + random.uniform(0, 3)
                if host == "h3" and 20 <= t < 40 and scenario != "normal_syn":
                    rate = 450 + random.uniform(-30, 30)
                    if mode == "enforce" and t >= 23:
                        rate = base  # dupa mitigare, revine
                log("SYN_RATE_SAMPLE", t, in_port=port, host=host,
                    rate=round(rate, 1), cumulative=int(rate * (k + 1)))
        if scenario != "normal_syn":
            log("SYN_FLOOD_ALERT", 22.8, alert_id=1, in_port=3, host="h3",
                rate=450.0, threshold=200.0, windows=3,
                t_detected=t0 + int(22.8e9))
            if mode == "enforce":
                log("MITIGATION_FLOWMOD_SENT", 22.82, alert_id=1, kind="syn_drop",
                    in_port=3)
                log("MITIGATION_CONFIRMED", 22.83, alert_id=1, kind="syn_drop",
                    in_port=3, t_mitigation_control_ms=round(random.uniform(3, 12), 2),
                    t_total_ms=None)
        for lab in ("h2", "h4"):
            path = os.path.join(run_dir, f"client_{lab}.csv")
            with open(path, "w") as f:
                f.write("t_utc,t_monotonic_ns,label,result,latency_ms\n")
                for k in range(120):
                    t = k * 0.5
                    ok = True
                    if 20 <= t < 40 and scenario == "syn_attack" and lab == "h2":
                        ok = random.random() > 0.7
                    if 20 <= t < 40 and scenario == "syn_mitigated" and lab == "h2":
                        ok = random.random() > 0.1
                    res = "success" if ok else "timeout"
                    lat = random.uniform(1, 8) if ok else random.uniform(1900, 2100)
                    f.write(f"2026-01-01T00:00:{k:02d}Z,{t0+int(t*1e9)},{lab},"
                            f"{res},{lat:.2f}\n")
    else:
        if scenario != "normal_arp":
            log("ARP_BINDING_VIOLATION", 5.0, alert_id=1, in_port=3,
                arp_spa="10.0.0.1", observed_mac="00:00:00:00:00:03",
                expected_mac="00:00:00:00:00:01", expected_port=1,
                reason="MAC_MISMATCH", mode=mode,
                t_packet_in=t0 + int(5.0e9), t_detected=t0 + int(5.0002e9))
            if mode == "enforce":
                log("MITIGATION_FLOWMOD_SENT", 5.001, alert_id=1, kind="arp_drop",
                    in_port=3, arp_spa="10.0.0.1")
                log("MITIGATION_CONFIRMED", 5.004, alert_id=1, kind="arp_drop",
                    in_port=3, arp_spa="10.0.0.1",
                    t_mitigation_control_ms=round(random.uniform(2, 9), 2),
                    t_total_ms=round(random.uniform(3, 11), 2))
        msgs = []
        msgs.append({"event": "MESSAGE_RECEIVED", "received": "STATUS=OK\n",
                     "expected": "STATUS=OK\n", "modified": False})
        if scenario == "arp_attack":
            msgs.append({"event": "MESSAGE_RECEIVED", "received": "STATUS=NO\n",
                         "expected": "STATUS=OK\n", "modified": True})
        elif scenario == "arp_mitigated":
            msgs.append({"event": "MESSAGE_RECEIVED", "received": "STATUS=OK\n",
                         "expected": "STATUS=OK\n", "modified": False})
        with open(os.path.join(run_dir, "message_server.jsonl"), "w") as f:
            for m in msgs:
                f.write(json.dumps(m) + "\n")

    with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
        for r in ev:
            f.write(json.dumps(r) + "\n")
    return run_dir