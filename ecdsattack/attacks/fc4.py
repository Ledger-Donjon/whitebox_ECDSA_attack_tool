"""Value fault in rd+h

We need two faulty equations, one of which is faulty such that digest_bad = digest_good but there is a collision on the error
We have four equations
s_good1 * k1 = r_good1 * x + digest1 (1)
s_bad1  * k1 = e                     (2)
s_good2 * k2 = r_good2 * x + digest2 (3)
s_bad2  * k2 = e                     (4)

We can solve this:
s_bad1*(1)-s_good1*(2) => s_good1 * e = s_bad1 * r_good1 * x + s_bad1 * digest1 (5)
s_bad2*(3)-s_good2*(4) => s_good2 * e = s_bad2 * r_good2 * x + s_bad2 * digest2 (6)

s_good2*(5)-s_good1*(6) => 0 = s_good2 * s_bad1 * r_good1 * x + s_good2 * s_bad1 * digest1
                              -s_good1 * s_bad2 * r_good2 * x - s_good1 * s_bad2 * digest2

<=>                        x = (s_good1 * s_bad2 * digest2 - s_good2 * s_bad1 * digest1)/
                               (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2)
"""

from ecdsa.curves import NIST256p

from ..common import Signature


def FC4(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad2.s * digest2 - good2.s * bad1.s * digest1
    denom = good2.s * bad1.s * good1.r - good1.s * bad2.s * good2.r
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n
