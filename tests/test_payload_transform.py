"""test_payload_transform.py - Transformarea payload-ului cu lungime constanta."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.payload_transform import transform_payload

ORIG = b"STATUS=OK\n"
MOD = b"STATUS=NO\n"


def test_lungimi_egale():
    assert len(ORIG) == len(MOD)


def test_modificare():
    out, changed = transform_payload(ORIG, ORIG, MOD)
    assert changed and out == MOD and len(out) == len(ORIG)


def test_fara_potrivire():
    out, changed = transform_payload(b"ALTCEVA\n", ORIG, MOD)
    assert not changed and out == b"ALTCEVA\n"


def test_o_singura_inlocuire():
    data = ORIG + ORIG
    out, changed = transform_payload(data, ORIG, MOD)
    assert changed and out == MOD + ORIG


def test_lungime_diferita_ridica_eroare():
    try:
        transform_payload(b"x", b"AB", b"C")
        assert False, "trebuia ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    fns = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for f in fns:
        f()
        print("OK", f.__name__)
    print(f"\n{len(fns)} teste trecute.")