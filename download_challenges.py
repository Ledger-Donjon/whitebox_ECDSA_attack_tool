import os
import shutil

import requests

""" Download all challenges from the website """

NUM_CHALLENGES = 346

WHIBOX_BASE_URL = "https://whibox.io/contests/2021/candidate/"
CHALLENGES_PATH = "challenges"

if os.path.exists(CHALLENGES_PATH):
    shutil.rmtree(CHALLENGES_PATH)
os.mkdir(CHALLENGES_PATH)


def main():
    session = requests.Session()
    for i in range(3, NUM_CHALLENGES + 1):
        print(i)
        challenge_base_url = f"{WHIBOX_BASE_URL}/{i:d}/"
        challenge_base_dir = os.path.join(CHALLENGES_PATH, str(i))

        for filename in ("source.c", "pubkey"):
            req = session.get(challenge_base_url + filename, allow_redirects=False)
            print(challenge_base_url + filename)
            print(i, req.status_code)
            if req.status_code != 200:
                continue

            if not os.path.exists(challenge_base_dir):
                os.mkdir(challenge_base_dir)

            with open(os.path.join(challenge_base_dir, filename), "wb") as f:
                f.write(req.content)


if __name__ == "__main__":
    main()
