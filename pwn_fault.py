"""
This code tries to inject a random fault in the binary file of the ECDSA whitebox. 
It implements attacks following the terminology of Attacks Against White-Box ECDSA and Discussion of Countermeasures by Bauer et al. (https://eprint.iacr.org/2022/448.pdf)
"""

import os
import random
import shutil
import subprocess
import sys
import time

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import INFINITY

PATH = "./" 

def FDC1(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = s_good1 * s_bad2 * digest2 - s_good2 * s_bad1 * digest1
    denom = s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]
    
def FDC2(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = digest2 * s_good1 * s_bad1 * (s_good2 - s_bad2) - digest1 * s_good2 * s_bad2 * (s_good1 - s_bad1)
    denom = s_good2 * s_bad2 * (r_bad1 * s_good1 - r_good1 * s_bad1) - s_good1 * s_bad1 * (r_bad2 * s_good2 - r_good2 * s_bad2)
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]

def FDC3(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = digest1 * (s_good2 -s_bad2) - digest2 * (s_good1 - s_bad1)
    denom = r_good1 * digest2 - r_good2 * digest1
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]

def F(r_good, s_good, r_bad, s_bad, digest):
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
    denom = s_good * r_bad - r_good * s_bad
    n = NIST256p.order
    return [(digest * (s_bad - s_good) * pow(denom, -1, n)) % n]


def FC1(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    denom =  s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2
    num = s_good1 * digest2 * (s_bad2 - s_good2) - s_good2 * digest1 * (s_bad1 - s_good1)
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]
    
def FC2(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = s_good1 * r_bad1 * digest2 * (s_bad2 - s_good2) - s_good2 * r_bad2 * digest1 * (s_bad1 - s_good1)
    denom = s_good2 * r_bad2 * s_bad1 * r_good1 - s_good1 * r_bad1 * s_bad2 * r_good2
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]
    

def FC3(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = s_good1 * s_bad2 * digest2 - s_good2 *s_bad1 *digest1
    denom = s_bad1 * r_good1 - s_good1 * r_bad1 - s_bad2 * r_good2 + s_good2 * r_bad2
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]

def FC4(r_good1, s_good1, r_bad1, s_bad1, r_good2, s_good2, r_bad2, s_bad2, digest1, digest2):
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
    num = s_good1 * s_bad2 * digest2 - s_good2 * s_bad1 * digest1
    denom = s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]

def FC5(r1,s1,r2,s2,digest1,digest2):
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
    num = digest2 * s1 - digest1 * s2
    denom = s2 * r1 - r2 * s1
    n = NIST256p.order
    return [(num * pow(denom, -1,n)) % n]

def recover_key(correct_sigs, faulty_sigs, digests, test_only_F=True):
    # since F is the attack with the best success rate, we allow for the possibility to only try this approach
    res =[-1]
    try:
        correct_r = [] 
        faulty_r  = [] 
        correct_s = [] 
        faulty_s  = [] 
        for correct_out, faulty_out in zip(correct_sigs, faulty_sigs):
            # first, we retrieve values r,s
            correct_r += [int(correct_out[0:32*2], 16)]
            correct_s += [int(correct_out[32*2:64*2], 16)]

            faulty_r += [int(faulty_out[0:32*2], 16)]
            faulty_s += [int(faulty_out[32*2:64*2], 16)]
    except:
        return [-1]
    try:
        #first try using F, only needing a couple:
        for c_r,c_s,f_r,f_s,h in zip(correct_r,correct_s,faulty_r,faulty_s,digests):
            res += F(c_r,c_s,f_r,f_s,h)
    except:
        pass

    if not test_only_F:
        cr_0 = correct_r[0]
        cr_1 = correct_r[1]
        cs_0 = correct_s[0]
        cs_1 = correct_s[1]
        fr_0 = faulty_r[0]
        fr_1 = faulty_r[1]
        fs_0 = faulty_s[0]
        fs_1 = faulty_s[1] 
        h_0  = digests[0]
        h_1  = digests[1]

        try:
            res += FC5(fr_0, fs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FC1(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FC2(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FC3(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FC4(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FDC1(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FDC2(cr_0, cs_0, fr_0, fs_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
        try:
            res += FDC3(cr_0, cs_0, fr_0, fr_0, cr_1, cs_0, fr_1, fs_1, h_0, h_1)
        except:
            pass
    return res


def inject_fault(origin_file_name: str, faults):
    copy_file_name = "faulted_a.out"
    shutil.copy(origin_file_name, copy_file_name)

    f = open(copy_file_name, "r+b")
    for fault in faults:
        byte_index, byte_value = fault
        f.seek(byte_index)
        f.write(bytes([byte_value]))
    f.close()
    try:
        faulty_out = subprocess.check_output([PATH + copy_file_name], timeout=3).decode()
    except:
        return -1
    return faulty_out


def main():

    # The attack "F" has the highest success rate. Moreover, it only requires one couple of (correct,faulty) signature
    # Consequently, we allow for the possibility to deactivate every other attack.
    test_only_F = True

    pubkey_file = open("challenges/" + sys.argv[1] + "/pubkey")
    pubkey = pubkey_file.readlines()[0]
    print("Target pubkey:", pubkey)

    digests = [0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
    subprocess.run(
        ["gcc-10", "drivers/main_a.c", "drivers/mocks.c", os.path.join("challenges", sys.argv[1], "source.c"), "-o", "main_a",
         "-lgmp"],
        stdout=None, stderr=subprocess.DEVNULL, check=True)
    
    origin_file_name_a = "main_a"
    size_file = os.path.getsize(PATH + origin_file_name_a)

    print(origin_file_name_a)
    correct_out_a = subprocess.check_output([PATH + origin_file_name_a])
    correct_out_a = correct_out_a.decode()
    correct_sig1 = correct_out_a
    print("Correct sig1:",correct_sig1)

    if not test_only_F:
        digests += [0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb]
        subprocess.run(
            ["gcc-10", "drivers/main_b.c", "drivers/mocks.c", os.path.join("challenges", sys.argv[1], "source.c"), "-o", "main_b",
            "-lgmp"],
            stdout=None, stderr=subprocess.DEVNULL, check=True)
        
        origin_file_name_b = "main_b"
        size_file = os.path.getsize(PATH + origin_file_name_b)

        print(origin_file_name_b)
        correct_out_b = subprocess.check_output([PATH + origin_file_name_b])
        correct_out_b = correct_out_b.decode()
        correct_sig2 = correct_out_b
        print("Correct sig2:",correct_sig2)
        
    time.sleep(1)

    #check for deterministic ECDSA
    print(origin_file_name_a)
    new_out = subprocess.check_output([PATH + origin_file_name_a])
    new_out = new_out.decode()
    print("new_output:", new_out)

    if correct_out_a != new_out:
        print("ERROR: Non-deterministic ECDSA!")
        sys.exit(0)

    # restart with 0 fault, same file name
    correct_out_a = inject_fault(origin_file_name_a, [])
    correct_sigs = [correct_out_a]
    
    if not test_only_F:
        correct_out_b = inject_fault(origin_file_name_b, [])
        correct_sigs += [correct_out_b]
    
    nb_no_effect = 0
    nb_crashes = 0

    max_tries_wo_effect = 1_000_000

    # main injection loop
    while nb_no_effect < max_tries_wo_effect:
        byte_index = random.randint(0, size_file)
        byte_value = random.randint(0, 255)

        # inject faults: we can modify the next line if we want to inject several faults in the binary
        faults = [(byte_index, byte_value)]
      
        faulty_out_a = inject_fault(origin_file_name_a, faults)
        faulty_sigs = [faulty_out_a]
        
        if not test_only_F:
            faulty_out_b = inject_fault(origin_file_name_b, faults)
            faulty_sigs += [faulty_out_a]

        if correct_out_a == faulty_out_a and (test_only_F or correct_out_b == faulty_out_b):
            nb_no_effect += 1
        elif faulty_out_a == -1 or (not test_only_F and faulty_out_b == -1):
            nb_crashes += 1
        else:
            print("FOUND FAULT:", faulty_sigs)            
            print("trying to recover the key...")
            
            dd  = recover_key(correct_sigs, faulty_sigs, digests, test_only_F) 
            
            for d in dd:
                print("Trying", d)
                pt = d * NIST256p.generator

                if pt == INFINITY:
                    continue

                if int(pubkey[0:64], 16) == pt.x() and int(pubkey[64:], 16) == pt.y():
                    print("Found correct public point:", hex(pt.x()), hex(pt.y()))
                    print("Found private key:", d)
                    print("In hex:", hex(d))
                    print(f"Fault: index={hex(byte_index)}, value={hex(byte_value)}")
                    sys.exit(0)
                else:
                    print("Nope...")

    print("No exploitable fault found")
    print("Nb of crashes = ", nb_crashes)
    print("Nb of no effect faults = ", nb_no_effect)


if __name__ == "__main__":
    main()
