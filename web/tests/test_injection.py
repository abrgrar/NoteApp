"""Command-injection regressions using a mocked process boundary.

Run from web/ with JWT_SECRET, COMMENT_KEY and EXPORT_HMAC_KEY configured:
    python -m unittest discover -s tests -p test_injection.py -v

SQL-injection integration tests share the PostgreSQL schema fixture in
test_comment_encryption.py. These tests never run commands from supplied hosts.
"""

import subprocess
import unittest
from unittest.mock import patch

import app as notes_app


class PingInjectionTests(unittest.TestCase):
    def setUp(self):
        for patcher in (
            patch.dict(notes_app.app.config, {"TESTING": True}),
            patch.object(notes_app, "_all_users", return_value=[]),
            patch.object(notes_app, "_all_classes", return_value=[]),
            patch.object(notes_app, "log"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        process_patch = patch.object(
            notes_app.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "one ping response", ""),
        )
        self.run_process = process_patch.start()
        self.addCleanup(process_patch.stop)

    def client(self, role="admin"):
        client = notes_app.app.test_client()
        if role is not None:
            with client.session_transaction() as session:
                session["user_id"] = 1
                session["username"] = role
                session["role"] = role
        return client

    def post_ping(self, host, role="admin"):
        client = self.client(role)
        with client.session_transaction() as session:
            token = session.setdefault("csrf", "test-csrf-token")
        return client.post("/admin/ping", data={"host": host, "csrf_token": token})

    def assert_host_argument(self, host):
        self.run_process.assert_called_once()
        args, kwargs = self.run_process.call_args
        command = args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "ping")
        self.assertEqual(command[-2:], ["--", host])
        self.assertFalse(kwargs.get("shell", False))
        self.assertTrue(kwargs["capture_output"])

    def test_localhost_ping_remains_available_to_admin(self):
        response = self.post_ping("localhost")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"one ping response", response.data)
        self.assert_host_argument("localhost")

    def test_shell_payloads_remain_a_single_host_argument(self):
        hosts = (
            "127.0.0.1; id; head -2 /etc/passwd",
            "127.0.0.1 && id",
            "127.0.0.1 | id",
            "$(id)",
            "`id`",
            "localhost\nid",
            "-V",
            "::1",
        )
        for host in hosts:
            with self.subTest(host=host):
                self.run_process.reset_mock()
                response = self.post_ping(host)
                self.assertEqual(response.status_code, 200)
                self.assert_host_argument(host)

    def test_ping_requires_an_admin_session(self):
        for role in (None, "student", "teacher"):
            with self.subTest(role=role):
                response = self.post_ping("127.0.0.1; id", role)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.endswith("/login"))
        self.run_process.assert_not_called()

    def test_ping_timeout_returns_the_admin_page(self):
        self.run_process.side_effect = subprocess.TimeoutExpired(["ping"], 10)
        response = self.post_ping("localhost")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"timed out", response.data)


if __name__ == "__main__":
    unittest.main()
