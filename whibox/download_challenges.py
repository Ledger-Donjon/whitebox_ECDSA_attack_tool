import os
import shutil

import requests
from tqdm import tqdm

""" Download all challenges from the website """

MIN_CHALLENGE_ID = 3
MAX_CHALLENGE_ID = 346

WHIBOX_BASE_URL = "https://whibox.io/contests/2021/candidate/"
CHALLENGES_PATH = "challenges"


def main():
    if os.path.exists(CHALLENGES_PATH):
        shutil.rmtree(CHALLENGES_PATH)
    os.mkdir(CHALLENGES_PATH)

    session = requests.Session()
    for i in tqdm(range(MIN_CHALLENGE_ID, MAX_CHALLENGE_ID + 1)):
        challenge_base_url = f"{WHIBOX_BASE_URL}/{i:d}/"
        challenge_base_dir = os.path.join(CHALLENGES_PATH, str(i))

        for filename in ("source.c", "pubkey"):
            req = session.get(challenge_base_url + filename, allow_redirects=False)
            if req.status_code != 200:
                continue

            if not os.path.exists(challenge_base_dir):
                os.mkdir(challenge_base_dir)

            with open(os.path.join(challenge_base_dir, filename), "wb") as f:
                f.write(req.content)


if __name__ == "__main__":
    main()
