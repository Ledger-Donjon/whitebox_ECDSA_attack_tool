"""Value/differential fault in d

We need two faulty equations, one of which is faulty such that digest_bad = digest_good but there is a collision on the error
We have three equations
s_good1 * k1  = r_good1 * x + digest1 (1)
s_bad1  * k1  = r_bad1  * e + digest1 (2)
s_good2 * k2  = r_good1 * x + digest2 (3)
s_bad2  * k2  = r_bad2  * e + digest2 (4)

We can solve this:
s_bad1*(1)-s_good1*(2) => s_good1 * r_bad1 * e = s_bad1 * r_good1 * x + digest1 * (s_bad1 - s_good1) (4)
s_bad2*(3)-s_good2*(4) => s_good2 * r_bad2 * e = s_bad2 * r_good2 * x + digest2 * (s_bad2 - s_good2) (5)

s_good2*r_bad2(4)-s_good1*r_bad1(5) => 0 = s_good2 * r_bad2 * s_bad1 * r_good1 * x + s_good2 * r_bad2 * digest1 * (s_bad1 - s_good1)
                                          -s_good1 * r_bad1 * s_bad2 * r_good2 * x - s_good1 * r_bad1 * digest2 * (s_bad2 - s_good2)

<=>                                    x = s_good1 * r_bad1 * digest2 * (s_bad2 - s_good2) - s_good2 * r_bad2 * digest1 * (s_bad1 - s_good1) /
                                          (s_good2 * r_bad2 * s_bad1 * r_good1 - s_good1 * r_bad1 * s_bad2 * r_good2)
"""

from ecdsa.curves import NIST256p

from ..common import Signature


def FC2(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad1.r * digest2 * (
        bad2.s - good2.s
    ) - good2.s * bad2.r * digest1 * (bad1.s - good1.s)
    denom = good2.s * bad2.r * bad1.s * good1.r - good1.s * bad1.r * bad2.s * good2.r
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n
