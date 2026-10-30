"""JWT algorithm allowlist regressions; no PostgreSQL connection is needed.

Run from web/ with COMMENT_KEY and EXPORT_HMAC_KEY configured:
    python -m unittest discover -s tests -p test_jwt_algorithms.py -v
"""

import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

import app as notes_app


TEST_SECRET = "jwt-algorithm-test-secret"
PAYLOAD = {"user_id": 6, "username": "alice", "role": "student"}


def encode(data):
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signed_token(header):
    # Give unsupported headers a valid HMAC to exercise the algorithm allowlist.
    signing_input = f"{encode(header)}.{encode(PAYLOAD)}"
    digest = hmac.new(
        TEST_SECRET.encode("ascii"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    signature = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{signing_input}.{signature}"


class JWTAlgorithmTests(unittest.TestCase):
    def setUp(self):
        secret_patch = patch.object(notes_app, "JWT_SECRET", TEST_SECRET)
        secret_patch.start()
        self.addCleanup(secret_patch.stop)

    def test_issued_hs256_token_still_verifies(self):
        token = notes_app.make_jwt(PAYLOAD)
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(notes_app.verify_jwt(token), PAYLOAD)

    def test_other_algorithm_names_rejected_even_with_valid_hmac(self):
        for algorithm in ("hs256", "Hs256", "none", "HS384", "RS256", ""):
            with self.subTest(algorithm=algorithm):
                self.assertIsNone(
                    notes_app.verify_jwt(signed_token({"alg": algorithm}))
                )

    def test_missing_and_nonstring_algorithms_are_rejected(self):
        headers = [{}] + [{"alg": value} for value in (None, 256, True, [], {})]
        for header in headers:
            with self.subTest(header=header):
                self.assertIsNone(notes_app.verify_jwt(signed_token(header)))

    def test_nonobject_headers_are_rejected(self):
        for header in (None, [], "HS256", 256):
            with self.subTest(header=header):
                self.assertIsNone(notes_app.verify_jwt(signed_token(header)))

    def test_hs256_still_requires_a_valid_signature(self):
        header, payload, signature = notes_app.make_jwt(PAYLOAD).split(".")
        invalid_tokens = (
            f"{header}.{payload}.",
            f"{header}.{payload}.invalid-signature",
            f"{header}.{encode({**PAYLOAD, 'role': 'admin'})}.{signature}",
        )
        for token in invalid_tokens:
            with self.subTest(token=token):
                self.assertIsNone(notes_app.verify_jwt(token))

    def test_rejected_algorithm_returns_401_without_database_access(self):
        token = signed_token({"alg": "hs256"})
        with patch.dict(notes_app.app.config, {"TESTING": True}), patch.object(
            notes_app, "get_db"
        ) as get_db:
            response = notes_app.app.test_client().get(
                "/api/notes/1", headers={"Authorization": "Bearer " + token}
            )

        self.assertEqual(response.status_code, 401)
        get_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
