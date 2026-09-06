"""
style.py - Stil comun pentru figurile lucrarii (matplotlib).

Principii (template facultate + bune practici de vizualizare):
  * fundal DESCHIS (template-ul interzice dark mode);
  * paleta categoriala colorblind-safe (Okabe-Ito), atribuita in ordine fixa
    entitatilor (nu ciclata dupa rang);
  * marcaje subtiri, grid discret, titlu + unitati + legenda pe fiecare figura;
  * fiecare figura de agregare indica numarul de repetari (n).
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")  # backend fara display (ruleaza si pe server/VM)
import matplotlib.pyplot as plt

# Paleta Okabe-Ito (ordine fixa)
OKABE_ITO = {
    "blue":      "#0072B2",
    "orange":    "#E69F00",
    "green":     "#009E73",
    "vermillion":"#D55E00",
    "purple":    "#CC79A7",
    "skyblue":   "#56B4E9",
    "yellow":    "#F0E442",
    "black":     "#000000",
}
PALETTE = list(OKABE_ITO.values())

# Roluri semantice stabile (aceeasi culoare pentru aceeasi entitate peste figuri)
COLOR = {
    "normal":     OKABE_ITO["blue"],
    "attack":     OKABE_ITO["vermillion"],
    "mitigated":  OKABE_ITO["green"],
    "h2":         OKABE_ITO["blue"],
    "h3":         OKABE_ITO["vermillion"],
    "h4":         OKABE_ITO["skyblue"],
    "threshold":  OKABE_ITO["orange"],
    "alert":      OKABE_ITO["vermillion"],
    "flowmod":    OKABE_ITO["purple"],
    "barrier":    OKABE_ITO["green"],
    "success":    OKABE_ITO["green"],
    "fail":       OKABE_ITO["vermillion"],
    "latency":    OKABE_ITO["blue"],
    "syn_rate":   OKABE_ITO["vermillion"],
    "syn_recv":   OKABE_ITO["purple"],
}


def apply_style():
    plt.rcParams.update({
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.labelsize": 11,
        "axes.edgecolor": "#666666",
        "axes.linewidth": 0.8,
        "axes.grid": True,
        "grid.color": "#DDDDDD",
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "legend.frameon": False,
        "legend.fontsize": 10,
        "lines.linewidth": 2.0,
        "figure.dpi": 130,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
    })


def new_fig(width=8.0, height=4.5):
    apply_style()
    return plt.subplots(figsize=(width, height))