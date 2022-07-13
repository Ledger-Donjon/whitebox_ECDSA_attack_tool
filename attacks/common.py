from ecdsa.curves import NIST256p

from signature import Signature


def _ecdsa_sign(msg: int, x: int, k: int) -> Signature:
    n = NIST256p.order

    Q = k * NIST256p.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = (kinv * (msg + x * r)) % n
    return Signature(msg, r, s)
