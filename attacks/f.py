"""Uncontrolled fault in r (faulty r returned)

We have two equations:
s_good * k = r_good * x + digest
s_bad  * k = r_bad  * x + digest

We can solve this:
k = (r_good * x + digest) / s_good
s_bad * (r_good * x + digest) / s_good = r_bad * x + digest

=> x = digest * (s_bad - s_good) / (s_good * r_bad - r_good * s_bad)
"""

from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from signature import Signature


def F(good: Signature, bad: Signature) -> int:
    assert good.h == bad.h

    digest = good.h
    denom = good.s * bad.r - good.r * bad.s
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (digest * (bad.s - good.s) * pow(denom, -1, n)) % n


def _ecdsa_sign_with_fault(msg: int, x: int, k: int):
    n = NIST256p.order

    # Usually, Q = k * NIST256p.generator and r = Q.x() % n. Here, fault in r
    r = randrange(n)
    kinv = pow(k, n - 2, n)

    s = (kinv * (msg + x * r)) % n
    return Signature(msg, r, s)


def test_f():
    n = NIST256p.order

    msg = randrange(n)
    x = randrange(n)
    k = randrange(n)
    sig1 = _ecdsa_sign(msg, x, k)
    sig2 = _ecdsa_sign_with_fault(msg, x, k)

    assert F(sig1, sig2) == x
