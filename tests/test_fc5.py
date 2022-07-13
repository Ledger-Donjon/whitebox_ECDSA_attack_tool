from ecdsa.curves import Curve, curves
from ecdsa.util import randrange

from ecdsattack import Signature
from ecdsattack.attacks.fc5 import FC5


def _ecdsa_sign_with_fault(curve: Curve, msg: int, x: int, k: int, e: int) -> Signature:
    n = curve.order

    Q = k * curve.generator
    r = Q.x() % n
    s = e * (msg + x * r) % n
    return Signature(msg, r, s)


def test_fc5():
    for curve in curves:
        n = curve.order

        msg1 = randrange(n)
        msg2 = randrange(n)
        k1 = randrange(n)
        k2 = randrange(n)
        x = randrange(n)
        e = randrange(n)

        sig1 = _ecdsa_sign_with_fault(curve, msg1, x, k1, e)
        sig2 = _ecdsa_sign_with_fault(curve, msg2, x, k2, e)
        assert FC5(curve, sig1, sig2) == x
