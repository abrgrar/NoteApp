import base64
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def encode(data):
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 2, "username": "prof.turing", "role": "teacher"}

token = encode(header) + "." + encode(payload) + "."

url = "http://localhost:8080/api/notes/1"

cases = [
    ("fake JWT", {"Authorization": "Bearer " + token}),
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
