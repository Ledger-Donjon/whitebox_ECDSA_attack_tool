"""Differential fault in k^-1 (faulty r returned)

We have two equations:
r_good1 * x + (s_good1 - s_bad1) / e = -digest1
r_good2 * x + (s_good2 - s_bad2) / e = -digest2

We can solve:
r_good1 * x + (s_good1 - s_bad1) = -digest1 * e (1)
r_good2 * x + (s_good2 - s_bad2) = -digest2 * e (2)

digest2*(1)-digest1*(2)=> (r_good1 * digest2 - r_good2 * digest1) * x + digest2 * (s_good1 - s_bad1) - digest1 * (s_good2 - s_bad2) = 0
<=> x = (digest1 * (s_good2 -s_bad2) - digest2 * (s_good1 - s_bad1)) / (r_good1 * digest2 - r_good2 * digest1)
"""

from ecdsa.curves import Curve

from ..common import Signature


def FDC3(
    curve: Curve,
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = digest2 * (good1.s - bad1.s) - digest1 * (good2.s - bad2.s)
    denom = good1.r * (good2.s - bad2.s) - good2.r * (good1.s - bad1.s)
    n = curve.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n
