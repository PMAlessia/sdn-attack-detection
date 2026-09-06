"""
event_logger.py - Evenimente structurate JSONL cu timestamp-uri.

Fiecare eveniment este o linie JSON (JSON Lines). Se folosesc:
  * un ceas MONOTON (time.monotonic_ns) pentru diferente temporale corecte;
  * un timestamp UTC ISO pentru corelarea intre fisiere/procese.

Acest modul NU depinde de Ryu, ca sa poata fi testat separat si refolosit.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class EventLogger:
    def __init__(self, log_dir: str, run_id: str, filename: str = "events.jsonl"):
        self.run_id = run_id
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, filename)
        # line buffering ca sa avem evenimentele pe disc aproape imediat.
        self._fh = open(self.path, "a", buffering=1)

    @staticmethod
    def now_monotonic_ns() -> int:
        return time.monotonic_ns()

    @staticmethod
    def now_utc_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def log(self, event: str, **fields: Any) -> Dict[str, Any]:
        """Scrie un eveniment. Returneaza dict-ul scris (util pentru teste)."""
        rec: Dict[str, Any] = {
            "run_id": self.run_id,
            "event": event,
            "t_monotonic_ns": self.now_monotonic_ns(),
            "t_utc": self.now_utc_iso(),
        }
        rec.update(fields)
        self._fh.write(json.dumps(rec) + "\n")
        return rec

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class NullLogger(EventLogger):
    """Logger fals pentru teste unitare (nu scrie pe disc)."""

    def __init__(self):  # noqa: D401 - intentionat nu apeleaza super().__init__
        self.run_id = "test"
        self.path = os.devnull
        self.records = []

    def log(self, event: str, **fields):
        rec = {"event": event, "t_monotonic_ns": self.now_monotonic_ns()}
        rec.update(fields)
        self.records.append(rec)
        return rec

    def close(self):
        pass