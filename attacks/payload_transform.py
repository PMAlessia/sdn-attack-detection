"""
payload_transform.py - Transformarea deterministica a payload-ului.

Separata de scapy_relay.py ca sa poata fi testata unitar fara Scapy.
Constrangere esentiala: lungimea in octeti trebuie sa ramana identica, altfel
numerele SEQ/ACK ale TCP devin incoerente.
"""
from __future__ import annotations

from typing import Tuple


def transform_payload(data: bytes, original: bytes, modified: bytes) -> Tuple[bytes, bool]:
    """
    Inlocuieste 'original' cu 'modified' in 'data' (o singura data).
    Returneaza (data_noua, s_a_modificat).
    
    """
    if len(original) != len(modified):
        raise ValueError("original si modified trebuie sa aiba aceeasi lungime "
                         f"({len(original)} != {len(modified)})")
    if original in data:
        return data.replace(original, modified, 1), True
    return data, False