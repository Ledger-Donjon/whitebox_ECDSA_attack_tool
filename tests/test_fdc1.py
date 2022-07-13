from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from ecdsattack import Signature
from ecdsattack.attacks.fdc1 import FDC1


def _ecdsa_sign_with_fault(msg: int, x: int, k: int, e: int) -> Signature:
    n = NIST256p.order

    Q = k * NIST256p.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = (kinv * (msg + x * r + e)) % n
    return Signature(msg, r, s)


def test_fdc1():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)

    e = randrange(n)  # error in k

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign_with_fault(msg1, x, k1, e)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign_with_fault(msg2, x, k2, e)
    assert FDC1(sig1, sig2, sig3, sig4) == x
