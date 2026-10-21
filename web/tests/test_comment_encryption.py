"""Run with: python -m unittest discover -s tests -v

Integration tests use a unique PostgreSQL schema; application data is untouched.
"""

import base64
import csv
import io
import unittest
import uuid
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg2 import sql

import app as notes_app
import comment_crypto
import migrate_comments
from comment_crypto import decrypt_comment, encrypt_comment
from export_integrity import TRAILER_PREFIX, verify_export


class CryptoTests(unittest.TestCase):
    def test_round_trip_and_fresh_nonces(self):
        for text in (None, "", "Good work!", "做得很好。 Café! 🐜", "Line 1\nLine 2", "x" * 4000):
            with self.subTest(text_length=len(text) if text is not None else None):
                encrypted = encrypt_comment(text)
                self.assertEqual(decrypt_comment(encrypted), text)
                if text is not None:
                    self.assertTrue(encrypted.startswith("gcm1:"))
                    self.assertNotEqual(encrypted, encrypt_comment(text))

    def test_modified_ciphertext_nonce_and_tag_are_rejected(self):
        original = base64.b64decode(encrypt_comment("Private comment")[5:])
        for index in (0, 12, len(original) - 1):
            with self.subTest(byte=index):
                changed = bytearray(original)
                changed[index] ^= 1
                value = "gcm1:" + base64.b64encode(changed).decode("ascii")
                with self.assertRaises(InvalidTag):
                    decrypt_comment(value)

    def test_wrong_key_and_associated_data_are_rejected(self):
        encrypted = encrypt_comment("Private comment")
        wrong_cipher = AESGCM(AESGCM.generate_key(bit_length=256))
        with patch.object(comment_crypto, "aes", wrong_cipher):
            with self.assertRaises(InvalidTag):
                decrypt_comment(encrypted)
        with patch.object(comment_crypto, "aad", b"another-field"):
            with self.assertRaises(InvalidTag):
                decrypt_comment(encrypted)

    def test_plaintext_and_malformed_values_are_rejected(self):
        for value in ("Legacy plaintext", "gcm1:AA==", "gcm1:!"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    decrypt_comment(value)


class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_get_db = staticmethod(notes_app.get_db)
        cls.schema = "comment_tests_" + uuid.uuid4().hex
        conn = cls.real_get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        finally:
            conn.close()
        cls.addClassCleanup(cls.drop_schema)
        conn = cls.connect()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL, role TEXT NOT NULL,
                        teacher_id INTEGER REFERENCES users(id)
                    );
                    CREATE TABLE classes (
                        id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                        teacher_id INTEGER REFERENCES users(id)
                    );
                    CREATE TABLE notes (
                        id SERIAL PRIMARY KEY,
                        student_id INTEGER REFERENCES users(id),
                        class_id INTEGER REFERENCES classes(id),
                        grade NUMERIC(4,1), comment TEXT
                    );
                """)
        finally:
            conn.close()

    @classmethod
    def connect(cls):
        conn = cls.real_get_db()
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(cls.schema)))
        return conn

    @classmethod
    def drop_schema(cls):
        conn = cls.real_get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema))
                )
        finally:
            conn.close()

    def setUp(self):
        self.db_patch = patch.object(notes_app, "get_db", side_effect=self.connect)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.migration_patch = patch.object(migrate_comments, "get_db", side_effect=self.connect)
        self.migration_patch.start()
        self.addCleanup(self.migration_patch.stop)
        previous_testing = notes_app.app.testing
        notes_app.app.testing = True
        self.addCleanup(setattr, notes_app.app, "testing", previous_testing)
        self.execute("TRUNCATE notes, classes, users RESTART IDENTITY CASCADE")
        self.execute("""
            INSERT INTO users (id, username, password, role) VALUES
                (1, 'admin', 'admin123', 'admin'),
                (2, 'prof.turing', 'teach123', 'teacher'),
                (6, 'alice', 'alicepw', 'student'),
                (7, 'bob', 'bobpw', 'student');
            INSERT INTO classes (id, name, teacher_id) VALUES
                (1, 'Mathematics', 2), (2, 'History', 2);
        """)
        self.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) VALUES (%s,%s,%s,%s)",
            (6, 1, 12.5, encrypt_comment("Original comment")),
        )
        self.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) VALUES (%s,%s,%s,%s)",
            (7, 2, 10, None),
        )

    def execute(self, query, params=None, fetch=False):
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall() if fetch else None
        finally:
            conn.close()

    def login(self, role):
        client = notes_app.app.test_client()
        username, password = {
            "teacher": ("prof.turing", "teach123"),
            "student": ("alice", "alicepw"),
            "admin": ("admin", "admin123"),
        }[role]
        response = client.post("/login", data={"username": username, "password": password})
        self.assertEqual(response.status_code, 302)
        return client

    def assert_read_paths(self, note_id, expected):
        student = self.login("student")
        teacher = self.login("teacher")
        for client, path in ((student, "/dashboard"), (teacher, "/teacher")):
            response = client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(expected, response.get_data(as_text=True))
            self.assertNotIn("gcm1:", response.get_data(as_text=True))
        response = student.get(f"/api/notes/{note_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["comment"], expected)
        with student.session_transaction() as session:
            token = session["token"]
        response = notes_app.app.test_client().get(
            f"/api/notes/{note_id}", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["comment"], expected)
        for path in ("/export.csv", "/export.csv?class_id=1"):
            response = teacher.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(verify_export(response.data, notes_app.EXPORT_HMAC_KEY))
            body = response.data[:response.data.rfind(TRAILER_PREFIX)].decode("utf-8")
            rows = list(csv.DictReader(io.StringIO(body, newline="")))
            self.assertIn(expected, [row["comment"] for row in rows])
            if "class_id" in path:
                self.assertTrue(all(row["class"] == "Mathematics" for row in rows))

    def test_create_update_and_all_read_paths(self):
        teacher = self.login("teacher")
        text = 'Good work, 做得很好。 "Keep going!"\nSecond line.'
        response = teacher.post(
            "/grades", data={"student_id": 6, "class_id": 1, "grade": "15.0", "comment": text}
        )
        self.assertEqual(response.status_code, 302)
        note = self.execute("SELECT * FROM notes ORDER BY id DESC LIMIT 1", fetch=True)[0]
        self.assertTrue(note["comment"].startswith("gcm1:"))
        self.assertNotIn(text, note["comment"])
        self.assertEqual(decrypt_comment(note["comment"]), text)
        self.assertEqual(float(note["grade"]), 15)
        self.assert_read_paths(note["id"], text)

        updated = "Updated feedback: excellent progress! 更新评语。"
        response = teacher.post(
            "/grades", data={"note_id": note["id"], "grade": "18.5", "comment": updated}
        )
        self.assertEqual(response.status_code, 302)
        saved = self.execute("SELECT * FROM notes WHERE id = %s", (note["id"],), True)[0]
        self.assertEqual(decrypt_comment(saved["comment"]), updated)
        self.assertNotEqual(saved["comment"], note["comment"])
        self.assertEqual((saved["student_id"], saved["class_id"]), (6, 1))
        self.assertEqual(float(saved["grade"]), 18.5)
        self.assert_read_paths(note["id"], updated)

    def test_empty_comment_is_encrypted_and_null_remains_null(self):
        teacher = self.login("teacher")
        self.assertEqual(
            teacher.post("/grades", data={"note_id": 1, "grade": "13", "comment": ""}).status_code,
            302,
        )
        rows = self.execute("SELECT id, comment FROM notes ORDER BY id", fetch=True)
        self.assertTrue(rows[0]["comment"].startswith("gcm1:"))
        self.assertEqual(decrypt_comment(rows[0]["comment"]), "")
        self.assertIsNone(rows[1]["comment"])
        student = self.login("student")
        self.assertEqual(student.get("/api/notes/1").json["comment"], "")
        with student.session_transaction() as session:
            session["user_id"] = 7
            session["username"] = "bob"
        self.assertIsNone(student.get("/api/notes/2").json["comment"])
        self.assertEqual(student.get("/dashboard").status_code, 200)
        self.assertEqual(teacher.get("/teacher").status_code, 200)

    def test_existing_authentication_and_other_routes(self):
        anonymous = notes_app.app.test_client()
        self.assertEqual(anonymous.get("/api/notes/1").status_code, 401)
        for path in ("/dashboard", "/teacher", "/export.csv", "/admin"):
            self.assertEqual(anonymous.get(path).status_code, 302)
        student = self.login("student")
        self.assertEqual(student.get("/teacher").status_code, 302)
        self.assertEqual(student.post("/grades", data={"note_id": 1}).status_code, 302)
        self.assertEqual(student.get("/api/notes/999999").status_code, 404)
        with student.get("/static/style.css") as response:
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.login("admin").get("/admin").status_code, 200)
        self.assertEqual(student.get("/healthz").status_code, 200)
        self.assertEqual(student.get("/logout").status_code, 302)
        self.assertEqual(student.get("/api/notes/1").status_code, 401)

    def test_corrupted_comments_are_rejected_by_all_read_paths(self):
        packed = bytearray(base64.b64decode(encrypt_comment("Secret comment")[5:]))
        packed[12] ^= 1
        corrupted = "gcm1:" + base64.b64encode(packed).decode("ascii")
        self.execute("UPDATE notes SET comment = %s WHERE id = 1", (corrupted,))
        for role, path in (
            ("student", "/dashboard"), ("student", "/api/notes/1"),
            ("teacher", "/teacher"), ("teacher", "/export.csv"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(InvalidTag):
                    self.login(role).get(path)

    def test_migration_preserves_data_and_can_be_repeated(self):
        self.execute("UPDATE notes SET comment = %s WHERE id = 1", ("Legacy 中文 feedback",))
        encrypted = encrypt_comment("Already encrypted")
        self.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) VALUES (6,1,11,%s), (6,1,12,%s)",
            (encrypted, ""),
        )
        before = self.execute("SELECT * FROM notes ORDER BY id", fetch=True)
        self.assertEqual(migrate_comments.migrate_comments(), {"migrated": 2, "verified": 1, "null": 1})
        after = self.execute("SELECT * FROM notes ORDER BY id", fetch=True)
        for old, new in zip(before, after):
            expected = decrypt_comment(old["comment"]) if old["id"] == 3 else old["comment"]
            self.assertEqual(decrypt_comment(new["comment"]), expected)
            self.assertEqual({k: v for k, v in old.items() if k != "comment"},
                             {k: v for k, v in new.items() if k != "comment"})
        self.assertEqual(after[2]["comment"], encrypted)
        self.assertEqual(migrate_comments.migrate_comments(), {"migrated": 0, "verified": 3, "null": 1})
        self.assertEqual(self.execute("SELECT * FROM notes ORDER BY id", fetch=True), after)

    def test_migration_rolls_back_on_invalid_ciphertext(self):
        self.execute("UPDATE notes SET comment = 'Must remain plaintext' WHERE id = 1")
        self.execute("UPDATE notes SET comment = 'gcm1:AA==' WHERE id = 2")
        before = self.execute("SELECT * FROM notes ORDER BY id", fetch=True)
        with self.assertRaises(RuntimeError):
            migrate_comments.migrate_comments()
        self.assertEqual(self.execute("SELECT * FROM notes ORDER BY id", fetch=True), before)

    def test_migration_rolls_back_with_wrong_key(self):
        self.execute("UPDATE notes SET comment = 'Must remain plaintext' WHERE id = 1")
        self.execute("UPDATE notes SET comment = %s WHERE id = 2", (encrypt_comment("Existing value"),))
        before = self.execute("SELECT * FROM notes ORDER BY id", fetch=True)
        with patch.object(comment_crypto, "aes", AESGCM(AESGCM.generate_key(bit_length=256))):
            with self.assertRaises(InvalidTag):
                migrate_comments.migrate_comments()
        self.assertEqual(self.execute("SELECT * FROM notes ORDER BY id", fetch=True), before)


if __name__ == "__main__":
    unittest.main()
