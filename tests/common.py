from ecdsa.curves import Curve

from ecdsattack import Signature


def _ecdsa_sign(curve: Curve, msg: int, x: int, k: int) -> Signature:
    n = curve.order

    Q = k * curve.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = (kinv * (msg + x * r)) % n
    return Signature(msg, r, s)
