from ecdsa.curves import Curve, curves
from ecdsa.util import randrange

from .common import _ecdsa_sign
from ecdsattack import Signature
from ecdsattack.attacks.f import F


def _ecdsa_sign_with_fault(curve: Curve, msg: int, x: int, k: int):
    n = curve.order

    # Usually, Q = k * NIST256p.generator and r = Q.x() % n. Here, fault in r
    r = randrange(n)
    kinv = pow(k, n - 2, n)

    s = (kinv * (msg + x * r)) % n
    return Signature(msg, r, s)


def test_f():
    for curve in curves:
        n = curve.order

        msg = randrange(n)
        x = randrange(n)
        k = randrange(n)
        sig1 = _ecdsa_sign(curve, msg, x, k)
        sig2 = _ecdsa_sign_with_fault(curve, msg, x, k)

        assert F(curve, sig1, sig2) == x
