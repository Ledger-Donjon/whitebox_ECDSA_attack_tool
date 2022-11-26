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
from typing import Optional

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point

from ecdsattack import recover_key, Signature

ORIGINAL_FILENAME_A = "main_a"
ORIGINAL_FILENAME_B = "main_b"
ECDSA_SIG_SIZE = 256 // 8 * 2

DIGEST_A = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
DIGEST_B = 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB


def inject_and_run(origin_file_name: str, fault=None):
    copy_file_name = origin_file_name + "_faulted"
    shutil.copy(origin_file_name, copy_file_name)

    if fault:
        with open(copy_file_name, "r+b") as f:
            byte_index, byte_value = fault
            f.seek(byte_index)
            f.write(bytes([byte_value]))
    try:
        faulty_out = subprocess.check_output(
            os.path.join(".", copy_file_name), stderr=subprocess.DEVNULL, timeout=3
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
        r = int(output[0:ECDSA_SIG_SIZE], 16)
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


def ecdsa_fault_attack(challenge_id: int, attack: str, fast_mode=False):
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
    print("Got original signatures")

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
            d = recover_key(
                NIST256p, NIST256p.generator, public_key,
                correct_sigs, faulty_sigs, attack
            )
            if d:
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
    group = parser.add_mutually_exclusive_group()
    # The attack "F" has the highest success rate. Moreover, it only requires one couple of (correct,faulty) signature
    # Consequently, we allow for the possibility to deactivate every other attack.
    group.add_argument(
        "-f",
        "--fast",
        help="Perform only a single attack, with a high probability of success",
        action="store_true",
    )
    group.add_argument(
        "-a",
        "--attack",
        choices=("f", "fc1", "fc2", "fc3", "fc4", "fdc1", "fdc2", "fdc3"),
        default=None,
        help="Select one attack from f, fc1, fc2, fc3, fc4, fdc1, fdc2, fdc3",
    )
    args = parser.parse_args()
    ecdsa_fault_attack(args.challenge_id, args.attack, args.fast)


if __name__ == "__main__":
    main()
