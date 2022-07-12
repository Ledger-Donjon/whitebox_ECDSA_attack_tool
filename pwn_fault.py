"""
This code tries to inject a random fault in the binary file of the ECDSA whitebox.

It implements attacks following the terminology of Attacks Against White-Box ECDSA and
Discussion of Countermeasures by Bauer et al. (https://eprint.iacr.org/2022/448.pdf)
"""
import argparse
import os
import random
import shutil
import string
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point

ORIGINAL_FILENAME_A = "main_a"
ORIGINAL_FILENAME_B = "main_b"
ECDSA_SIG_SIZE = 256 // 8 * 2

DIGEST_A = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
DIGEST_B = 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB


@dataclass
class Signature:
    h: int
    r: int
    s: int


def FDC1(
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    """Differential fault in r, rd, h, rd+h"""
    """
        We have four equations:
        s_good1 * k1 = r_good1 * x + digest1          (1)
        s_bad1  * k1 = r_bad1  * x + digest1 + e*Z,   (2)
        s_good2 * k2 = r_good2 * x + digest2          (3)
        s_bad2  * k2 = r_bad2  * x + digest2 + e*Z,   (4)
        with Z = d if the fault is on r and Z = 1 otherwise

        We can solve this:
        s_bad1*(1)-s_good1*(2)=> s_good1 * e*Z = s_bad1 * r_good1 * x + s_bad1 * digest1 - s_good1 * r_bad1  * x - s_good1 * digest1  (5)
        s_bad2*(3)-s_good2*(4)=> s_good2 * e*Z = s_bad2 * r_good2 * x + s_bad2 * digest2 - s_good2 * r_bad1  * x - s_good2 * digest2  (6)

        s_good2*(5)-s_good1*(6)=> 0 = s_good2 * s_bad1 * r_good1 * x + s_good2 * s_bad1 * digest1 - s_good2 * s_good1 * r_bad1  * x - s_good2 * s_good1 * digest1
                                    - s_good1 * s_bad2 * r_good2 * x - s_good1 * s_bad2 * digest2 + s_good1 * s_good2 * r_bad1  * x + s_good1 * s_good2 * digest2
        
        <=>  x = (s_good1 * s_bad2 * digest2 - s_good2 * s_bad1 * digest1) / (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2)
    """
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad2.s * digest2 - good2.s * bad1.s * digest1
    denom = good2.s * bad1.s * good1.r - good1.s * bad2.s * good2.r
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FDC2(
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    """Differential fault in k (faulty r returned)"""
    """
        We have four equations:
        s_good1 * k1     = r_good1 * x + digest1 (1)
        s_bad1  * (k1+e) = r_bad1  * x + digest1 (2)
        s_good2 * k2     = r_good2 * x + digest2 (3)
        s_bad2  * (k2+e) = r_bad2  * x + digest2 (4)
    
        We can solve this:
        s_good1*(2)-s_bad1*(1) => s_good1 * s_bad1 * e = x * (r_bad1 * s_good1 - r_good1 * s_bad1) + digest1 * (s_good1 - s_bad1) (5)
        s_good1*(3)-s_bad1*(4) => s_good2 * s_bad2 * e = x * (r_bad2 * s_good2 - r_good2 * s_bad2) + digest2 * (s_good2 - s_bad2) (6)

        s_good2*s_bad2*(5)-s_good1*s_bad1*(6) =>0 = x * s_good2 * s_bad2 * (r_bad1 * s_good1 - r_good1 * s_bad1) + digest1 * s_good2 * s_bad2 * (s_good1 - s_bad1) 
                                                   -x * s_good1 * s_bad1 * (r_bad2 * s_good2 - r_good2 * s_bad2) - digest2 * s_good1 * s_bad1 * (s_good2 - s_bad2) 
    
        <=> x = (digest2 * s_good1 * s_bad1 * (s_good2 - s_bad2) - digest1 * s_good2 * s_bad2 * (s_good1 - s_bad1)) /
                (s_good2 * s_bad2 * (r_bad1 * s_good1 - r_good1 * s_bad1) - s_good1 * s_bad1 * (r_bad2 * s_good2 - r_good2 * s_bad2))
    """
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = digest2 * good1.s * bad1.s * (
        good2.s - bad2.s
    ) - digest1 * good2.s * bad2.s * (good1.s - bad1.s)
    denom = good2.s * bad2.s * (
        bad1.r * good1.s - good1.r * bad1.s
    ) - good1.s * bad1.s * (bad2.r * good2.s - good2.r * bad2.s)
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FDC3(
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    """Differential fault in k^-1 (faulty r returned)"""
    """
        We have two equations:
        r_good1 * x + (s_good1 - s_bad1) / e = -digest1
        r_good2 * x + (s_good2 - s_bad2) / e = -digest2

        We can solve: 
        r_good1 * x + (s_good1 - s_bad1) = -digest1 * e (1)
        r_good2 * x + (s_good2 - s_bad2) = -digest2 * e (2)

        digest2*(1)-digest1*(2)=> (r_good1 * digest2 - r_good2 * digest1) * x + digest2 * (s_good1 - s_bad1) - digest1 * (s_good2 - s_bad2) = 0
        <=> x = (digest1 * (s_good2 -s_bad2) - digest2 * (s_good1 - s_bad1)) / (r_good1 * digest2 - r_good2 * digest1)
    """
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = digest1 * (good2.s - bad2.s) - digest2 * (good1.s - bad1.s)
    denom = good1.r * digest2 - good2.r * digest1
    n = NIST256p.order
    return (num * pow(denom, -1, n)) % n


def F(good: Signature, bad: Signature) -> int:
    """Uncontrolled fault in r (faulty r returned)"""
    """
        We have two equations:
        s_good * k = r_good * x + digest
        s_bad  * k = r_bad  * x + digest

        We can solve this:
        k = (r_good * x + digest) / s_good
        s_bad * (r_good * x + digest) / s_good = r_bad * x + digest

        => x = digest * (s_bad - s_good) / (s_good * r_bad - r_good * s_bad)
    """
    assert good.h == bad.h

    digest = good.h
    denom = good.s * bad.r - good.r * bad.s
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (digest * (bad.s - good.s) * pow(denom, -1, n)) % n


def FC1(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    """Value fault in r (correct r returned) or rd"""
    """
        We have the four equations:
        s_good1 * k1 = r_good1 * x + digest1 (1)
        s_bad1  * k1 =       e * Z + digest1 (2)
        s_good2 * k2 = r_good2 * x + digest2 (3)
        s_bad2  * k2 =       e * Z + digest2 (4),
        with Z = e*d or Z = d, depending on the localisation on the fault (on r or on r*d).

        We can solve this:
        s_bad1*(1)-s_good1*(2) => s_good1 * e * Z = s_bad1 * r_good1 * x + digest1 * (s_bad1 - s_good1) (4)
        s_bad2*(3)-s_good2*(4) => s_good2 * e * Z = s_bad2 * r_good2 * x + digest2 * (s_bad2 - s_good2) (5)

        s_good2*(4)-s_good1*(5) => 0 = s_good2 * s_bad1 * r_good1 * x + s_good2 * digest1 * (s_bad1 - s_good1) 
                                      -s_good1 * s_bad2 * r_good2 * x - s_good1 * digest2 * (s_bad2 - s_good2) 
        
        <=>                        x = (s_good1 * digest2 * (s_bad2 - s_good2) - s_good2 * digest1 * (s_bad1 - s_good1)) /
                                       (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2)
        
    """
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    denom = good2.s * bad1.s * good1.r - good1.s * bad2.s * good2.r
    num = good1.s * digest2 * (bad2.s - good2.s) - good2.s * digest1 * (
        bad1.s - good1.s
    )
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FC2(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    """Value/differential fault in d"""
    """
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
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad1.r * digest2 * (
        bad2.s - good2.s
    ) - good2.s * bad2.r * digest1 * (bad1.s - good1.s)
    denom = good2.s * bad2.r * bad1.s * good1.r - good1.s * bad1.r * bad2.s * good2.r
    """
    num = s_good1 * r_bad1 * digest2 * (
        s_bad2 - s_good2
    ) - s_good2 * r_bad2 * digest1 * (s_bad1 - s_good1)
    denom = s_good2 * r_bad2 * s_bad1 * r_good1 - s_good1 * r_bad1 * s_bad2 * r_good2
    """
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FC3(
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    """Value fault in h"""
    """
        We need two faulty equations, one of which is faulty such that digest_bad = digest_good but there is a collision on the error
        We have three equations
        s_good1 * k1 = r_good1 * x + digest1 (1)
        s_bad1  * k1 = r_bad1  * x + e       (2)
        s_good2 * k2 = r_good2 * x + digest2 (3)
        s_bad2  * k2 = r_bad2  * x + e       (4)

        We can solve this:
        s_bad1*(1)-s_good1*(2) => s_good1 * e = s_bad1 * r_good1 * x + s_bad1 * digest1 - s_good1 * r_bad1 * x
        s_bad2*(3)-s_good2*(4) => s_good2 * e = s_bad2 * r_good2 * x + s_bad2 * digest2 - s_good2 * r_bad2 * x 

        <=> s_good1 * e = (s_bad1 * r_good1 - s_good1 * r_bad1) * x + s_bad1 * digest1 (5)
            s_good2 * e = (s_bad2 * r_good2 - s_good2 * r_bad2) * x + s_bad2 * digest2 (6)

        =>  s_good2*(5)-s_good1*(6) => 0 = s_good2 * (s_bad1 * r_good1 - s_good1 * r_bad1) * x + s_good2 * s_bad1 * digest1
                                          -s_good1 * (s_bad2 * r_good2 - s_good2 * r_bad2) * x - s_good1 * s_bad2 * digest2
        
        <=>                            x = (s_good1 * s_bad2 * digest2 - s_good2 *s_bad1 *digest1) /
                                           (s_bad1 * r_good1 - s_good1 * r_bad1 - s_bad2 * r_good2 + s_good2 * r_bad2))
    """
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad2.s * digest2 - good2.s * bad1.s * digest1
    denom = bad1.s * good1.r - good1.s * bad1.r - bad2.s * good2.r + good2.s * bad2.r
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FC4(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    """Value fault in rd+h"""
    """
        We need two faulty equations, one of which is faulty such that digest_bad = digest_good but there is a collision on the error
        We have three equations
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
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = good1.s * bad2.s * digest2 - good2.s * bad1.s * digest1
    denom = good2.s * bad1.s * good1.r - good1.s * bad2.s * good2.r
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def FC5(bad1: Signature, bad2: Signature) -> int:
    """Value fault in k or k^-1"""
    """
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
    assert bad1.h != bad2.h

    num = bad2.h * bad1.s - bad1.h * bad2.s
    denom = bad2.s * bad1.r - bad2.r * bad1.s
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def recover_key(
    correct_sigs: List[Signature], faulty_sigs: List[Signature]
) -> List[int]:
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
    return res


def inject_and_run(origin_file_name: str, fault=None):
    copy_file_name = "faulted.out"
    shutil.copy(origin_file_name, copy_file_name)

    if fault:
        with open(copy_file_name, "r+b") as f:
            byte_index, byte_value = fault
            f.seek(byte_index)
            f.write(bytes([byte_value]))
    try:
        faulty_out = subprocess.check_output(
            os.path.join(".", copy_file_name), timeout=3
        ).decode()
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    return faulty_out


def get_signature(
    original_file_name: str, digest: int, fault=None
) -> Optional[Signature]:
    output = inject_and_run(original_file_name, fault)
    if not output:
        return None

    if len(output) == 129 and all(c in string.hexdigits for c in output[:128]):
        r = int(output[0 : ECDSA_SIG_SIZE], 16)
        s = int(output[ECDSA_SIG_SIZE : 2 * ECDSA_SIG_SIZE], 16)
        return Signature(digest, r, s)
    return None


def compile_challenge(name: str, challenge_id: int):
    subprocess.run(
        [
            "gcc-10",
            os.path.join("drivers", name + ".c"),
            os.path.join("drivers", "mocks.c"),
            os.path.join("challenges", str(challenge_id), "source.c"),
            "-o",
            name,
            "-lgmp",
        ],
        stdout=None,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def load_public_key(challenge_id: int) -> Point:
    with open(os.path.join("challenges", str(challenge_id), "pubkey")) as f:
        pubkey_data = f.read()
    public_key = Point(
        NIST256p.curve, int(pubkey_data[:64], 16), int(pubkey_data[64:], 16)
    )
    return public_key


def ecdsa_fault_attack(challenge_id: int, fast_mode=False):
    public_key = load_public_key(challenge_id)
    print("Target pubkey:", public_key)

    # get a couple valid signatures
    compile_challenge(ORIGINAL_FILENAME_A, challenge_id)
    correct_sigs = [get_signature(ORIGINAL_FILENAME_A, DIGEST_A)]
    file_size = os.path.getsize(ORIGINAL_FILENAME_A)
    if not fast_mode:
        compile_challenge(ORIGINAL_FILENAME_B, challenge_id)
        correct_sigs.append(get_signature(ORIGINAL_FILENAME_B, DIGEST_B))
        file_size = os.path.getsize(ORIGINAL_FILENAME_B)

    nb_no_effect = 0
    nb_crashes = 0
    max_tries_wo_effect = 1_000_000

    # main injection loop
    while nb_no_effect < max_tries_wo_effect:
        byte_index = random.randint(0, file_size)
        byte_value = random.randint(0, 255)
        fault = (byte_index, byte_value)

        faulty_sig_a = get_signature(ORIGINAL_FILENAME_A, DIGEST_A, fault)
        if faulty_sig_a:
            faulty_sigs = [faulty_sig_a]
        else:
            faulty_sigs = []

        faulty_sig_b = None
        if not fast_mode:
            faulty_sig_b = get_signature(ORIGINAL_FILENAME_B, DIGEST_B, fault)
            if faulty_sig_b:
                faulty_sigs.append(faulty_sig_b)

        if faulty_sig_a == correct_sigs[0] and (
            fast_mode or faulty_sig_b == correct_sigs[1]
        ):
            nb_no_effect += 1
        elif faulty_sig_a is None or (not fast_mode and faulty_sig_b is None):
            nb_crashes += 1
        else:
            print("Found fault:", faulty_sigs)
            print("Trying to recover the key...")
            dd = recover_key(correct_sigs, faulty_sigs)

            for d in dd:
                print("Trying", d)
                if d * NIST256p.generator == public_key:
                    print("Found correct public point:", public_key)
                    print("Found private key:", d)
                    print("In hex:", hex(d))
                    print(f"Fault: index={hex(byte_index)}, value={hex(byte_value)}")
                    print("# crashes = ", nb_crashes)
                    print("# faults without effect = ", nb_no_effect)
                    return

    print("No exploitable fault found")
    print("# crashes = ", nb_crashes)
    print("# faults without effect = ", nb_no_effect)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge_id", help="Challenge identifier to attack", type=int)

    # The attack "F" has the highest success rate. Moreover, it only requires one couple of (correct,faulty) signature
    # Consequently, we allow for the possibility to deactivate every other attack.
    parser.add_argument(
        "-f",
        "--fast",
        help="Perform only a single attack, with a high probability of success",
        action="store_true",
    )
    args = parser.parse_args()
    ecdsa_fault_attack(args.challenge_id, args.fast)


if __name__ == "__main__":
    main()
