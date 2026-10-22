"""Verify the course's Alice migration through real HTTP and database reads.

Run inside the web container:
    docker compose exec -T web python - < class5/verify_migration.py
"""

from http.cookiejar import CookieJar
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, build_opener

from app import get_db, ph


def stored_password():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, password FROM users WHERE username = %s", ("alice",))
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("Course seed account alice is missing")
            return row["password"]
    finally:
        conn.close()


def login(opener, password):
    payload = urlencode({"username": "alice", "password": password}).encode("ascii")
    with opener.open("http://127.0.0.1:5000/login", payload, timeout=10) as response:
        body = response.read()
        return response.status, urlparse(response.url).path, body


before = stored_password()
print(f"Before login — alice password: {before}")

client = build_opener(HTTPCookieProcessor(CookieJar()))
status, path, body = login(client, "incorrect-lab-password")
assert status == 200 and path == "/login" and b"Invalid credentials." in body
assert stored_password() == before
print("Wrong password: rejected; stored password unchanged.")

status, path, _ = login(client, "alicepw")
assert status == 200 and path == "/dashboard"
after = stored_password()
assert after.startswith("$argon2id$") and ph.verify(after, "alicepw")
print(f"First correct login: HTTP {status}, final path {path}.")
print(f"After login — alice password: {after}")
print("Independent database connection confirms persisted Argon2id hash.")

with client.open("http://127.0.0.1:5000/logout", timeout=10) as response:
    response.read()
    assert urlparse(response.url).path == "/login"
status, path, _ = login(client, "alicepw")
assert status == 200 and path == "/dashboard"
assert stored_password() == after
print(f"Logout and second correct login: HTTP {status}, final path {path}; hash unchanged.")

fresh_client = build_opener(HTTPCookieProcessor(CookieJar()))
status, path, body = login(fresh_client, "incorrect-lab-password")
assert status == 200 and path == "/login" and b"Invalid credentials." in body
assert stored_password() == after
print("Wrong password after migration: rejected; stored hash unchanged.")
print("PASS: Alice's login migration and Argon2 authentication verified.")
