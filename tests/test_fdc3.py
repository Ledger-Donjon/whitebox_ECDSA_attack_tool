from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from ecdsattack import Signature
from ecdsattack.attacks.fdc3 import FDC3


def _ecdsa_sign_with_fault(msg: int, x: int, k: int, e: int) -> Signature:
    n = NIST256p.order

    Q = k * NIST256p.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = ((kinv + e) * (msg + x * r)) % n
    return Signature(msg, r, s)


def test_fdc3():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)
    e = randrange(n)

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign_with_fault(msg1, x, k1, e)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign_with_fault(msg2, x, k2, e)
    assert FDC3(sig1, sig2, sig3, sig4) == x
