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

from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from signature import Signature


def FDC3(
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
    n = NIST256p.order
    return (num * pow(denom, -1, n)) % n


def _ecdsa_sign_with_fault(msg: int, x: int, k: int, e: int) -> Signature:
    n = NIST256p.order

    Q = k * NIST256p.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = ((kinv + e) * (msg + x * r)) % n
    return Signature(msg, r, s)


def test_fdc3():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)
    e = randrange(n)

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign_with_fault(msg1, x, k1, e)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign_with_fault(msg2, x, k2, e)
    assert FDC3(sig1, sig2, sig3, sig4) == x
