import base64
import hashlib
import hmac
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def encode(data):
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWT_SECRET = b"s3cr3t"
header = {"alg": "hs256", "typ": "JWT"}
payload = {"user_id": 2, "username": "prof.turing", "role": "teacher"}

signing_input = encode(header) + "." + encode(payload)
digest = hmac.new(JWT_SECRET, signing_input.encode("ascii"), hashlib.sha256).digest()
signature = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
token = signing_input + "." + signature

url = "http://localhost:8080/api/notes/1"


def main():
    print("JWT signature:", signature)
    print("JWT:", token)

    cases = [
        ("signed JWT (HS256)", {"Authorization": "Bearer " + token}),
    ]

    for label, headers in cases:
        print("\n" + label)
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=5) as response:
                print("HTTP", response.status)
                print(response.read().decode())
        except HTTPError as error:
            print("HTTP", error.code)
            print(error.read().decode())


if __name__ == "__main__":
    main()
