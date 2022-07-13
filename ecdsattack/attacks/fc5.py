"""Value fault in k or k^-1

We have two equations
s1 * Z = r1 * x + digest1
s2 * Z = r2 * x + digest2,
with Z = e or e^-1, depending on whether the fault was injected on k or k^-1

(It is similar to F, but with two different values digest1 and digest2.)

We can solve this:
Z = (r1 * x + digest1) / s1
s2 * (r1 * x + digest1) / s1 = r2 * x + digest2

=> s2 * r1 * x + s2 * digest1 = s1 * r2 * x + s1 * digest2
<=> x = (digest2 * s1 - digest1 * s2) / (s2 * r1 - r2 * s1)
"""

from ecdsa.curves import NIST256p

from ..common import Signature


def FC5(bad1: Signature, bad2: Signature) -> int:
    assert bad1.h != bad2.h

    num = bad2.h * bad1.s - bad1.h * bad2.s
    denom = bad2.s * bad1.r - bad2.r * bad1.s
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n
