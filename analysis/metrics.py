"""
metrics.py - Citirea si prelucrarea logurilor experimentale in DataFrame-uri.

REGULA DE INTEGRITATE (din documentatie): figurile se genereaza NUMAI din
fisierele brute ale trialurilor. Nu se completeaza manual valori si nu se
folosesc date sintetice drept rezultate. Acest modul doar CITESTE si prelucreaza
ce a produs o rulare reala.

Structura unui director de rulare (logs/raw/<run_id>/):
    events.jsonl          - evenimentele controllerului (SYN_RATE_SAMPLE,
                            SYN_FLOOD_ALERT, ARP_BINDING_VIOLATION,
                            MITIGATION_FLOWMOD_SENT, MITIGATION_CONFIRMED, ...)
    client_h2.csv         - client legitim principal (result, latency_ms)
    client_h4.csv         - client de fundal
    server_accepts.jsonl  - accept-uri pe serverul TCP (h1:8080)
    message_server.jsonl  - mesaje receptionate (flag `modified`) pentru ARP
    run_config.json       - scenariul si parametrii rularii

Toate fisierele folosesc acelasi ceas monoton (time.monotonic_ns), comparabil
intre procese pe acelasi kernel. Pentru ca graficele diferite ale ACELEIASI
rulari sa aiba aceeasi origine de timp, foloseste run_t0() ca t0 comun.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

import pandas as pd


# --------------------------------------------------------------------------- #
# Incarcare fisiere brute
# --------------------------------------------------------------------------- #
def _read_jsonl(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return pd.DataFrame(rows)


def run_t0(run_dir: str) -> Optional[int]:
    """Momentul zero COMUN al unei rulari: cel mai mic t_monotonic_ns peste
    events.jsonl si CSV-urile clientilor. Foloseste-l ca t0 pentru toate
    graficele aceleiasi rulari, ca axa de timp sa fie aliniata intre ele."""
    mins = []
    ev = _read_jsonl(os.path.join(run_dir, "events.jsonl"))
    if not ev.empty and "t_monotonic_ns" in ev:
        mins.append(int(ev["t_monotonic_ns"].min()))
    for name in os.listdir(run_dir) if os.path.isdir(run_dir) else []:
        if name.startswith("client_") and name.endswith(".csv"):
            try:
                d = pd.read_csv(os.path.join(run_dir, name))
                if "t_monotonic_ns" in d and len(d):
                    mins.append(int(d["t_monotonic_ns"].min()))
            except Exception:
                pass
    return min(mins) if mins else None


def load_events(run_dir: str, t0: Optional[int] = None) -> pd.DataFrame:
    df = _read_jsonl(os.path.join(run_dir, "events.jsonl"))
    if not df.empty and "t_monotonic_ns" in df:
        base = t0 if t0 is not None else df["t_monotonic_ns"].min()
        df["t_rel_s"] = (df["t_monotonic_ns"] - base) / 1e9
    return df


def load_clients(run_dir: str, t0: Optional[int] = None) -> pd.DataFrame:
    frames = []
    for name in os.listdir(run_dir) if os.path.isdir(run_dir) else []:
        if name.startswith("client_") and name.endswith(".csv"):
            p = os.path.join(run_dir, name)
            try:
                frames.append(pd.read_csv(p))
            except Exception:
                pass
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    if "t_monotonic_ns" in df:
        base = t0 if t0 is not None else df["t_monotonic_ns"].min()
        df["t_rel_s"] = (df["t_monotonic_ns"] - base) / 1e9
    df["ok"] = df["result"] == "success"
    return df


def load_run_config(run_dir: str) -> dict:
    p = os.path.join(run_dir, "run_config.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}


# --------------------------------------------------------------------------- #
# SYN flood
# --------------------------------------------------------------------------- #
def syn_rate_timeseries(events: pd.DataFrame) -> pd.DataFrame:
    """Serie temporala a ratei SYN per port/host (din SYN_RATE_SAMPLE)."""
    if events.empty or "event" not in events:
        return pd.DataFrame()
    df = events[events["event"] == "SYN_RATE_SAMPLE"].copy()
    if df.empty:
        return df
    return df[["t_rel_s", "in_port", "host", "rate", "cumulative"]].reset_index(drop=True)


def syn_alerts(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty or "event" not in events:
        return pd.DataFrame()
    return events[events["event"] == "SYN_FLOOD_ALERT"].copy()


def client_success_rate(clients: pd.DataFrame, label: Optional[str] = None) -> float:
    if clients.empty:
        return float("nan")
    df = clients if label is None else clients[clients["label"] == label]
    if df.empty:
        return float("nan")
    return 100.0 * df["ok"].mean()


def client_latency_success(clients: pd.DataFrame, label: Optional[str] = None) -> pd.Series:
    if clients.empty:
        return pd.Series(dtype=float)
    df = clients if label is None else clients[clients["label"] == label]
    return df[df["ok"]]["latency_ms"]


# --------------------------------------------------------------------------- #
# Mitigare (SYN si ARP) - timpi din evenimente
# --------------------------------------------------------------------------- #
def mitigation_times(events: pd.DataFrame) -> pd.DataFrame:
    """
    Timpii de mitigare din MITIGATION_CONFIRMED:
      t_mitigation_control_ms = t_barrier_reply - t_flowmod_sent
      t_total_ms              = t_barrier_reply - t_packet_in (doar ARP)
    """
    if events.empty or "event" not in events:
        return pd.DataFrame()
    df = events[events["event"] == "MITIGATION_CONFIRMED"].copy()
    cols = [c for c in ["alert_id", "kind", "in_port",
                        "t_mitigation_control_ms", "t_total_ms"] if c in df]
    return df[cols].reset_index(drop=True) if not df.empty else df


def arp_violations(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty or "event" not in events:
        return pd.DataFrame()
    return events[events["event"] == "ARP_BINDING_VIOLATION"].copy()


# --------------------------------------------------------------------------- #
# ARP MITM - mesaje modificate
# --------------------------------------------------------------------------- #
def message_stats(run_dir: str) -> dict:
    """Numara mesajele receptionate si cate au fost modificate (integritate)."""
    df = _read_jsonl(os.path.join(run_dir, "message_server.jsonl"))
    if df.empty or "modified" not in df:
        return {"total": 0, "modified": 0}
    return {"total": int(len(df)), "modified": int(df["modified"].sum())}


# --------------------------------------------------------------------------- #
# Calibrarea pragului SYN din rulari NORMALE (nu se inventeaza)
# --------------------------------------------------------------------------- #
def suggest_threshold(normal_run_dirs: List[str], k: float = 4.0,
                      percentile: float = 99.0) -> dict:
    """
    Calculeaza un prag candidat pentru syn_rate_threshold din rulari NORMALE:
      * mean + k*std  (regula clasica)
      * percentila superioara (mai robusta la outlieri)
    Returneaza ambele; alegerea si justificarea se scriu in lucrare.
    """
    rates = []
    for d in normal_run_dirs:
        ev = load_events(d)
        ts = syn_rate_timeseries(ev)
        if not ts.empty:
            rates.extend(ts["rate"].tolist())
    if not rates:
        return {"n_samples": 0}
    s = pd.Series(rates)
    return {
        "n_samples": int(len(s)),
        "mean": float(s.mean()),
        "std": float(s.std(ddof=1)) if len(s) > 1 else 0.0,
        "mean_plus_k_std": float(s.mean() + k * (s.std(ddof=1) if len(s) > 1 else 0.0)),
        "k": k,
        f"p{percentile:g}": float(s.quantile(percentile / 100.0)),
        "max": float(s.max()),
    }


# --------------------------------------------------------------------------- #
# Agregare pe repetari (medie, mediana, dispersie, interval de incredere 95%)
# --------------------------------------------------------------------------- #
def aggregate(series: pd.Series) -> dict:
    """Statistici agregate cu interval de incredere 95% (t-Student aproximativ)."""
    s = pd.Series(series).dropna()
    n = len(s)
    if n == 0:
        return {"n": 0}
    mean = float(s.mean())
    std = float(s.std(ddof=1)) if n > 1 else 0.0
    sem = std / (n ** 0.5) if n > 0 else 0.0
    # aproximare 95% CI cu valori t-Student pentru n-1 grade de libertate.
    t_table = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45,
               7: 2.36, 8: 2.31, 9: 2.26, 10: 2.23, 11: 2.20, 12: 2.18,
               13: 2.16, 14: 2.14, 15: 2.13, 16: 2.12, 17: 2.11, 18: 2.10,
               19: 2.09, 20: 2.09, 21: 2.08, 22: 2.07, 23: 2.07, 24: 2.06,
               25: 2.06, 26: 2.06, 27: 2.05, 28: 2.05, 29: 2.05, 30: 2.04}
    t95 = t_table.get(n - 1, 1.96)
    return {
        "n": n, "mean": mean, "median": float(s.median()),
        "std": std, "sem": sem, "ci95": t95 * sem,
        "min": float(s.min()), "max": float(s.max()),
    }