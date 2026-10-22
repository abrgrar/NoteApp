"""Password-storage route tests using real Argon2 and a mocked database.

Run from web/ with COMMENT_KEY and EXPORT_HMAC_KEY configured:
    python -m unittest discover -s tests -p test_password_storage.py -v

These tests exercise authentication decisions and SQL writes. They do not
claim to verify PostgreSQL persistence.
"""

import unittest
from unittest.mock import MagicMock, patch

from argon2 import PasswordHasher

import app as notes_app


class PasswordStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = PasswordHasher()
        cls.password = "a-correct-password"
        cls.encoded_password = cls.verifier.hash(cls.password)

    def setUp(self):
        config_patch = patch.dict(notes_app.app.config, {"TESTING": True})
        config_patch.start()
        self.addCleanup(config_patch.stop)
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value
        db_patch = patch.object(notes_app, "get_db", return_value=self.connection)
        self.get_db = db_patch.start()
        self.addCleanup(db_patch.stop)
        log_patch = patch.object(notes_app, "log")
        log_patch.start()
        self.addCleanup(log_patch.stop)

    def user(self, stored_password):
        return {
            "id": 6,
            "username": "alice",
            "role": "student",
            "password": stored_password,
        }

    def attempt_login(self, stored_password, submitted_password, exists=True):
        self.cursor.execute.reset_mock()
        self.connection.close.reset_mock()
        self.cursor.fetchone.return_value = self.user(stored_password) if exists else None
        client = notes_app.app.test_client()
        response = client.post(
            "/login", data={"username": "alice", "password": submitted_password}
        )
        return client, response

    def update_calls(self):
        return [
            call for call in self.cursor.execute.call_args_list
            if call.args[0].lstrip().upper().startswith("UPDATE ")
        ]

    def assert_authenticated(self, client, response):
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            self.assertEqual(session["user_id"], 6)
            self.assertEqual(session["username"], "alice")
            self.assertEqual(session["role"], "student")
            self.assertEqual(
                notes_app.verify_jwt(session["token"]),
                {"user_id": 6, "username": "alice", "role": "student"},
            )
        self.connection.close.assert_called_once()

    def assert_rejected(self, client, response):
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid credentials.", response.data)
        with client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("token", session)
        self.assertEqual(self.update_calls(), [])
        self.connection.close.assert_called_once()

    def assert_single_upgrade(self, password):
        updates = self.update_calls()
        self.assertEqual(len(updates), 1)
        query, params = updates[0].args
        self.assertIn("%s", query)
        encoded = params[0]
        self.assertTrue(encoded.startswith("$argon2id$"))
        self.assertNotEqual(encoded, password)
        self.assertNotIn(encoded, query)
        self.assertIn(6, params[1:])
        self.assertTrue(self.verifier.verify(encoded, password))

    def test_legacy_success_upgrades_with_argon2_and_preserves_identity(self):
        client, response = self.attempt_login(self.password, self.password)
        self.assert_authenticated(client, response)
        self.assert_single_upgrade(self.password)
        self.assertEqual(len(self.cursor.execute.call_args_list), 2)
        select = self.cursor.execute.call_args_list[0].args[0]
        self.assertTrue(select.lstrip().upper().startswith("SELECT "))
        self.assertIn("password", select.split("FROM", 1)[0])

    def test_legacy_wrong_password_does_not_upgrade_or_authenticate(self):
        client, response = self.attempt_login(self.password, "incorrect")
        self.assert_rejected(client, response)

    def test_unknown_account_does_not_write_or_authenticate(self):
        client, response = self.attempt_login(None, self.password, exists=False)
        self.assert_rejected(client, response)

    def test_existing_hash_accepts_correct_password_without_rehashing(self):
        client, response = self.attempt_login(self.encoded_password, self.password)
        self.assert_authenticated(client, response)
        self.assertEqual(self.update_calls(), [])
        self.assertEqual(len(self.cursor.execute.call_args_list), 1)

    def test_existing_hash_rejects_wrong_password_without_writing(self):
        client, response = self.attempt_login(self.encoded_password, "incorrect")
        self.assert_rejected(client, response)

    def test_hash_string_is_not_accepted_as_the_account_password(self):
        client, response = self.attempt_login(self.encoded_password, self.encoded_password)
        self.assert_rejected(client, response)

    def test_malformed_argon2_hash_is_rejected_without_plaintext_fallback(self):
        malformed = "$argon2id$not-a-valid-encoded-hash"
        for submitted in (self.password, malformed):
            with self.subTest(submitted=submitted):
                client, response = self.attempt_login(malformed, submitted)
                self.assert_rejected(client, response)

    def test_password_sql_payload_never_enters_the_select_query(self):
        payload = "' OR '1'='1"
        client, response = self.attempt_login(self.password, payload)
        self.assert_rejected(client, response)
        select = self.cursor.execute.call_args_list[0].args[0]
        self.assertNotIn(payload, select)
        where = select.upper().split("WHERE", 1)[1]
        self.assertNotIn("PASSWORD", where)
        # Username concatenation remains intentionally vulnerable for the
        # separate SQL injection lab.
        self.assertIn("'alice'", select)

    def test_unicode_legacy_password_can_log_in_and_upgrade(self):
        password = "密码-Café-🔐"
        client, response = self.attempt_login(password, password)
        self.assert_authenticated(client, response)
        self.assert_single_upgrade(password)

    def test_failed_legacy_upgrade_does_not_create_authenticated_session(self):
        self.cursor.execute.side_effect = [None, RuntimeError("upgrade write failed")]
        self.cursor.fetchone.return_value = self.user(self.password)
        client = notes_app.app.test_client()
        with self.assertRaisesRegex(RuntimeError, "upgrade write failed"):
            client.post(
                "/login", data={"username": "alice", "password": self.password}
            )
        with client.session_transaction() as session:
            self.assertNotIn("user_id", session)
            self.assertNotIn("token", session)
        self.connection.close.assert_called_once()

    def test_administrator_creates_users_with_argon2_passwords(self):
        client = notes_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1
            session["username"] = "admin"
            session["role"] = "admin"
        response = client.post(
            "/admin/users",
            data={
                "action": "create", "username": "new.student",
                "password": self.password, "role": "student",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.cursor.execute.assert_called_once()
        query, params = self.cursor.execute.call_args.args
        self.assertTrue(query.lstrip().upper().startswith("INSERT INTO USERS"))
        self.assertEqual(params[0], "new.student")
        self.assertEqual(params[2:], ("student", None))
        self.assertTrue(params[1].startswith("$argon2id$"))
        self.assertNotIn(params[1], query)
        self.assertTrue(self.verifier.verify(params[1], self.password))
        self.connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
