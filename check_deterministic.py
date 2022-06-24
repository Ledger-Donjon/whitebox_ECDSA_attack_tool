import os
import subprocess
import time

""" Check if the challenges are deterministic """

for dirname in sorted(os.listdir("challenges")):
    proc = subprocess.run(["gcc-10", "drivers/main.c", os.path.join("challenges", dirname, "source.c"), "-o", "challenge", "-lgmp"],
                    stdout=None, stderr=subprocess.DEVNULL)

    proc = subprocess.run(["./challenge"], capture_output=True)
    output = proc.stdout
    deterministic = True

    time.sleep(1.1)  # to detect k based on time()
    for i in range(5):
        proc2 = subprocess.run(["./challenge"], capture_output=True)
        if proc2.stdout != output:
            deterministic = False
    if not deterministic:
        print(dirname)
