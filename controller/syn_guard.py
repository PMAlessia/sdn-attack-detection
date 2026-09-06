"""
syn_guard.py - Detectia SYN flood pe baza de baseline + prag.

Model:
  Pentru fiecare port de intrare exista o regula in OVS care numara pachetele
  TCP catre h1:8080. telemetry.py citeste contoarele la interval fix Δt si
  calculeaza diferenta fata de citirea precedenta:
        R_SYN(k) = [C(k) - C(k-1)] / Δt   [pachete/s]

  Alerta se emite DOAR daca R_SYN depaseste pragul in mai multe ferestre
  CONSECUTIVE (reduce falsele alarme la burst-uri legitime scurte).

Logica PURA (fara Ryu) -> testabila in tests/.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class SynAlert:
    in_port: int
    rate: float
    threshold: float
    windows: int


@dataclass
class _PortState:
    prev_count: Optional[int] = None
    consecutive_over: int = 0
    alerted: bool = False


@dataclass
class SynGuard:
    threshold: float
    consecutive_windows: int = 3
    poll_interval_s: float = 1.0
    _ports: Dict[int, _PortState] = field(default_factory=dict)

    def reset(self) -> None:
        self._ports.clear()

    def last_rate(self, in_port: int) -> float:
        return getattr(self._ports.get(in_port, _PortState()), "_last_rate", 0.0)

    def update(self, in_port: int, cumulative_count: int) -> Optional[SynAlert]:
        """
        Se apeleaza o data pe fereastra, per port, cu contorul CUMULATIV curent.
        Returneaza un SynAlert la trecerea de la "sub" la "peste" prag pentru
        numarul cerut de ferestre consecutive; altfel None.
        """
        st = self._ports.setdefault(in_port, _PortState())

        if st.prev_count is None:
            # Prima citire: nu putem calcula o rata inca.
            st.prev_count = cumulative_count
            st._last_rate = 0.0  # type: ignore[attr-defined]
            return None

        delta = cumulative_count - st.prev_count
        st.prev_count = cumulative_count
        # Contoarele nu scad; daca scad (reset flow), tratam ca 0.
        if delta < 0:
            delta = 0
        rate = delta / self.poll_interval_s
        st._last_rate = rate  # type: ignore[attr-defined]

        if rate >= self.threshold:
            st.consecutive_over += 1
        else:
            st.consecutive_over = 0
            st.alerted = False  # revenit sub prag -> se poate re-alerta ulterior
            return None

        if st.consecutive_over >= self.consecutive_windows and not st.alerted:
            st.alerted = True
            return SynAlert(in_port=in_port, rate=rate, threshold=self.threshold, windows=st.consecutive_over)

        return None