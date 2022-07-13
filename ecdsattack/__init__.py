from typing import List, Optional

from ecdsa.ellipticcurve import Point

from .attacks.f import F
from .attacks.fc1 import FC1
from .attacks.fc2 import FC2
from .attacks.fc3 import FC3
from .attacks.fc4 import FC4
from .attacks.fc5 import FC5
from .attacks.fdc1 import FDC1
from .attacks.fdc2 import FDC2
from .attacks.fdc3 import FDC3
from .common import Signature


def recover_key(
    generator: Point,
    public_key: Point,
    correct_sigs: List[Signature], faulty_sigs: List[Signature]
) -> Optional[int]:
    res = []

    # first try using F, only needing a couple:
    for i in range(len(correct_sigs)):
        res.append(F(correct_sigs[i], faulty_sigs[i]))

    if len(correct_sigs) == 2 and len(faulty_sigs) == 2:
        c0, c1 = correct_sigs
        f0, f1 = faulty_sigs

        res.append(FC1(c0, f0, c1, f1))
        res.append(FC2(c0, f0, c1, f1))
        res.append(FC3(c0, f0, c1, f1))
        res.append(FC4(c0, f0, c1, f1))
        res.append(FC5(f0, f1))
        res.append(FDC1(c0, f0, c1, f1))
        res.append(FDC2(c0, f0, c1, f1))
        res.append(FDC3(c0, f0, c1, f1))

    for d in res:
        if d * generator == public_key:
            return d
    return None
