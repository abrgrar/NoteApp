"""Generate the six fictional accounts supplied by the Lab 2 handout."""

import hashlib
from pathlib import Path


ACCOUNTS = {
    "liwei": "123456",
    "sofia": "iloveyou",
    "tomk": "qwerty123",
    "aisha": "password1",
    "marie": "mariepw",
    "raj": "Gv7#pLm2!xQ",
}
DUMP_PATH = Path(__file__).resolve().parent / "leaked_users.txt"


def main():
    with DUMP_PATH.open("w", encoding="utf-8") as dump:
        for username, password in ACCOUNTS.items():
            digest = hashlib.md5(password.encode("utf-8")).hexdigest()
            dump.write(f"{username}:{digest}\n")
    print(f"Wrote {len(ACCOUNTS)} fictional accounts to {DUMP_PATH.name}")


if __name__ == "__main__":
    main()
