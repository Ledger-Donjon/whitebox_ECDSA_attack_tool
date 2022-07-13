from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from ecdsattack.attacks.fc2 import FC2


def test_fc2():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)
    x2 = randrange(n)  # fault on x

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign(msg1, x2, k1)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign(msg2, x2, k2)
    assert FC2(sig1, sig2, sig3, sig4) == x
