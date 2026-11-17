#!/usr/bin/env python3
"""Check the injection lab against a running local NotesApp using seed accounts."""

import argparse
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PreText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "pre":
            self.inside = False
            self.parts.append("\n")

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)


class Client:
    def __init__(self, base_url):
        self.base_url = base_url
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()), NoRedirect())

    def request(self, path, data=None):
        body = urlencode(data).encode() if data is not None else None
        request = Request(self.base_url + path, data=body)
        try:
            response = self.opener.open(request, timeout=20)
        except HTTPError as error:
            response = error
        with response:
            return response.code, response.headers, response.read().decode("utf-8")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def login(client, username, password):
    status, headers, _ = client.request(
        "/login", {"username": username, "password": password}
    )
    require(status == 302 and headers.get("Location") == "/",
            f"{username} login failed (HTTP {status}); check the seed credentials")


def ping(client, host):
    status, headers, body = client.request("/admin/ping", {"host": host})
    if status == 302 and headers.get("Location") == "/login":
        raise ValueError("ping requires a valid administrator session")
    require(status == 200, f"ping returned HTTP {status}")
    parser = PreText()
    parser.feed(body)
    result = "".join(parser.parts).strip()
    require(bool(result), "ping response has no result in its <pre> block")
    return result


def verify(base_url):
    student = Client(base_url)
    login(student, "alice", "alicepw")
    status, _, body = student.request("/dashboard")
    require(status == 200 and "My grades" in body,
            f"Alice's dashboard did not open (HTTP {status})")
    print("PASS: Alice login and dashboard")

    attempts = (
        ("admin' -- ", "anything"),
        ("admin' OR 1=1 -- ", "wrong-password"),
        ("missing' UNION SELECT 1, 'admin', 'admin', 'chosen-password' -- ",
         "chosen-password"),
    )
    for username, password in attempts:
        # Each attack starts without cookies from any earlier successful login.
        attacker = Client(base_url)
        status, _, body = attacker.request(
            "/login", {"username": username, "password": password}
        )
        require(status == 200 and "Invalid credentials." in body,
                "SQL injection was not rejected with an invalid-credentials response")
        status, headers, _ = attacker.request("/admin")
        require(status == 302 and headers.get("Location") == "/login",
                "SQL injection session can access the administrator page")
    print("PASS: SQL injection rejected (3 fresh sessions)")

    admin = Client(base_url)
    login(admin, "admin", "admin123")
    print("PASS: Administrator login")
    result = ping(admin, "127.0.0.1")
    success = r"\b1 packets transmitted,\s*1 (?:packets )?received\b"
    require(re.search(success, result) is not None,
            "normal 127.0.0.1 ping failed; inspect the administrator ping result")
    print("PASS: Normal 127.0.0.1 ping")

    result = ping(admin, "127.0.0.1; id")
    require(re.search(r"(?m)^\s*uid=\d+", result) is None,
            "command injection executed id")
    require(re.search(success, result) is None,
            "injected host unexpectedly produced a successful ping")
    print("PASS: Command injection rejected (no id output)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8080")
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if (url.scheme not in ("http", "https") or not url.netloc
            or url.username or url.password or url.query or url.fragment):
        parser.error("--base-url must be an HTTP(S) URL without credentials, query or fragment")
    try:
        verify(args.base_url.rstrip("/"))
    except (URLError, OSError) as error:
        print(f"FAIL: Cannot reach NotesApp: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
