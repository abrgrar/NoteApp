"""Time a dictionary attack on the course's fictional unsalted MD5 dump."""

import argparse
import hashlib
from pathlib import Path
from time import perf_counter_ns


CRACK_DIR = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", action="store_true", help="Also try the course's username+pw bonus rule")
    args = parser.parse_args()
    accounts = {}
    for line in (CRACK_DIR / "leaked_users.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            username, digest = line.strip().split(":", 1)
            accounts[username] = digest

    wordlist = [
        word.strip()
        for word in (CRACK_DIR / "wordlist.txt").read_text(encoding="utf-8").splitlines()
        if word.strip()
    ]

    candidates = wordlist + [f"{username}pw" for username in accounts] if args.rules else wordlist

    # Time the full candidate scan as in the handout, excluding file I/O.
    cracked = {}
    start = perf_counter_ns()
    for candidate in candidates:
        candidate_digest = hashlib.md5(candidate.encode("utf-8")).hexdigest()
        for username, stored_digest in accounts.items():
            if username not in cracked and candidate_digest == stored_digest:
                cracked[username] = candidate
    elapsed_ms = (perf_counter_ns() - start) / 1_000_000

    print(f"Wordlist: {len(wordlist)} entries")
    if args.rules:
        print(f"Bonus: {len(accounts)} additional username+pw candidates")
    print(f"Cracked {len(cracked)} / {len(accounts)} in {elapsed_ms:.6f} ms")
    for username, password in cracked.items():
        print(f"  {username} : {password}")
    print("Held out: " + ", ".join(username for username in accounts if username not in cracked))
    print("Timing: dictionary scan only; file I/O excluded; one local CPU run.")


if __name__ == "__main__":
    main()
