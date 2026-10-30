"""JWT key configuration and rotation regressions; no database is needed.

Run from web/ with JWT_SECRET, COMMENT_KEY and EXPORT_HMAC_KEY configured:
    python -m unittest discover -s tests -p test_jwt_secret.py -v
"""

import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import app as notes_app


NEW_SECRET = "new-jwt-secret-for-tests-" + "a" * 32
PAYLOAD = {"user_id": 6, "username": "alice", "role": "student"}


class JWTSecretTests(unittest.TestCase):
    def import_app(self, secret):
        environment = os.environ.copy()
        if secret is None:
            environment.pop("JWT_SECRET", None)
        else:
            environment["JWT_SECRET"] = secret
        return subprocess.run(
            [sys.executable, "-c", "import app"],
            cwd=Path(notes_app.__file__).resolve().parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_startup_rejects_missing_or_short_keys(self):
        for secret in (None, "", "s3cr3t", "x" * 31):
            with self.subTest(length=None if secret is None else len(secret)):
                result = self.import_app(secret)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("JWT_SECRET must contain at least 32 bytes", result.stderr)

    def test_startup_accepts_a_32_byte_key(self):
        result = self.import_app("x" * 32)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rotated_key_rejects_old_or_unrelated_hs256_signatures(self):
        for signing_secret in ("s3cr3t", "another-jwt-secret-for-tests-" + "b" * 32):
            with self.subTest(old_weak_key=signing_secret == "s3cr3t"):
                with patch.object(notes_app, "JWT_SECRET", signing_secret):
                    token = notes_app.make_jwt(PAYLOAD)
                with patch.object(notes_app, "JWT_SECRET", NEW_SECRET):
                    self.assertIsNone(notes_app.verify_jwt(token))

    def test_new_key_signs_tokens_that_verify(self):
        with patch.object(notes_app, "JWT_SECRET", NEW_SECRET):
            token = notes_app.make_jwt(PAYLOAD)
            self.assertEqual(notes_app.verify_jwt(token), PAYLOAD)


if __name__ == "__main__":
    unittest.main()
