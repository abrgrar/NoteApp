"""CSRF regressions using Flask clients and a mocked database."""

import io
import unittest
from html.parser import HTMLParser
from unittest.mock import MagicMock, patch

import app as notes_app
from export_integrity import sign_export


class PostForms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {} if attrs.get("method", "get").lower() == "post" else None
            if self.current is not None:
                self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            if attrs.get("type") == "hidden" and "name" in attrs:
                self.current[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class CSRFTests(unittest.TestCase):
    def setUp(self):
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value
        self.cursor.fetchall.return_value = []
        self.cursor.fetchone.return_value = None
        for patcher in (
            patch.dict(notes_app.app.config, {"TESTING": True}),
            patch.object(notes_app, "log"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        db_patch = patch.object(notes_app, "get_db", return_value=self.connection)
        self.get_db = db_patch.start()
        self.addCleanup(db_patch.stop)

    def client_for(self, role="teacher"):
        client = notes_app.app.test_client()
        with client.session_transaction() as session:
            session.update(user_id=2, username=role, role=role)
        return client

    def form_token(self, client):
        response = client.get("/verify-export")
        self.assertEqual(response.status_code, 200)
        forms = PostForms(response.get_data(as_text=True)).forms
        self.assertEqual(len(forms), 1)
        token = forms[0].get("csrf_token")
        self.assertTrue(token)
        with client.session_transaction() as session:
            self.assertEqual(token, session["csrf"])
        return token

    def test_every_protected_post_form_renders_the_session_token(self):
        for path, role, count in (("/teacher", "teacher", 2),
                                  ("/admin", "admin", 3),
                                  ("/verify-export", "teacher", 1)):
            with self.subTest(path=path):
                client = self.client_for(role)
                self.cursor.fetchall.side_effect = (
                    [[{"id": 6, "username": "alice", "role": "student"}], []]
                    if role == "admin" else [[], [], []]
                )
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                forms = PostForms(response.get_data(as_text=True)).forms
                self.assertEqual(len(forms), count)
                with client.session_transaction() as session:
                    self.assertTrue(session["csrf"])
                    for form in forms:
                        self.assertEqual(form.get("csrf_token"), session["csrf"])

    def test_tokens_persist_per_session_and_differ_between_sessions(self):
        first, second = self.client_for(), self.client_for()
        token = self.form_token(first)
        self.assertEqual(self.form_token(first), token)
        self.assertNotEqual(self.form_token(second), token)
        self.assertIn("SameSite=Lax", second.get("/logout").headers["Set-Cookie"])
        self.get_db.assert_not_called()

    def test_missing_wrong_and_uninitialized_tokens_reject_before_database_access(self):
        for path in ("/grades", "/admin/users", "/admin/ping", "/verify-export"):
            for expected, submitted in (("expected-token", None),
                                        ("expected-token", "wrong-token"),
                                        ("expected-token", "错误的令牌"),
                                        (None, "submitted-token")):
                with self.subTest(path=path, expected=expected, submitted=submitted):
                    client = self.client_for("admin" if path.startswith("/admin") else "teacher")
                    if expected:
                        with client.session_transaction() as session:
                            session["csrf"] = expected
                    data = {} if submitted is None else {"csrf_token": submitted}
                    response = client.post(path, data=data)
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(b"CSRF token missing or wrong", response.data)
        self.get_db.assert_not_called()

    def test_valid_token_allows_a_signed_csv_upload(self):
        client = self.client_for()
        token = self.form_token(client)
        signed = sign_export(b"student,class,grade,comment\r\n", notes_app.EXPORT_HMAC_KEY)
        response = client.post("/verify-export", data={
            "csrf_token": token,
            "file": (io.BytesIO(signed), "grades.csv"),
        })
        self.addCleanup(response.request.input_stream.close)
        self.addCleanup(response.close)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CHECK PASSED", response.data)
        self.get_db.assert_not_called()

    def test_another_sessions_token_is_rejected(self):
        first, second = self.client_for(), self.client_for()
        token = self.form_token(first)
        self.form_token(second)
        response = second.post("/verify-export", data={"csrf_token": token})
        self.assertEqual(response.status_code, 400)
        self.get_db.assert_not_called()

    def test_login_remains_available_without_a_csrf_token(self):
        response = notes_app.app.test_client().post("/login", data={
            "username": "unknown-user", "password": "incorrect-password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid credentials", response.data)
        self.get_db.assert_called_once()


if __name__ == "__main__":
    unittest.main()
