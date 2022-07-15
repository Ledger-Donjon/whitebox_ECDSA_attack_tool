"""Uncontrolled fault in r (faulty r returned)

We have two equations:
s_good * k = r_good * x + digest
s_bad  * k = r_bad  * x + digest

We can solve this:
k = (r_good * x + digest) / s_good
s_bad * (r_good * x + digest) / s_good = r_bad * x + digest

=> x = digest * (s_bad - s_good) / (s_good * r_bad - r_good * s_bad)
"""

from ecdsa.curves import Curve

from ..common import Signature


def F(curve: Curve, good: Signature, bad: Signature) -> int:
    assert good.h == bad.h

    digest = good.h
    denom = good.s * bad.r - good.r * bad.s
    n = curve.order
    if denom % n == 0:
        return 0
    return (digest * (bad.s - good.s) * pow(denom, -1, n)) % n
