"""Signed CSV unit and Flask tests; no PostgreSQL connection is needed.

Run from web/ with configured COMMENT_KEY and EXPORT_HMAC_KEY:
    python -m unittest discover -s tests -p test_export_integrity.py -v
"""

import base64
import csv
import hashlib
import hmac
import io
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

import app as notes_app
from comment_crypto import encrypt_comment
from export_integrity import decode_hmac_key, sign_export, verify_export


KEY = bytes(range(32))
TRAILER_PREFIX = b"# HMAC-SHA256: "
CSV_HEADER = b"student,class,grade,comment\r\n"
CSV_BODY = CSV_HEADER + b"alice,Mathematics,12.5,Good work\r\n"


class ExportIntegrityTests(unittest.TestCase):
    def test_key_requires_base64_encoded_32_bytes(self):
        self.assertEqual(decode_hmac_key(base64.b64encode(KEY).decode("ascii")), KEY)
        invalid = ["", "not base64!", base64.b64encode(KEY).decode("ascii") + "\n"]
        invalid.extend(base64.b64encode(b"x" * size).decode("ascii") for size in (0, 16, 31, 33, 64))
        for encoded in invalid:
            with self.subTest(encoded=encoded):
                with self.assertRaises(ValueError):
                    decode_hmac_key(encoded)

    def test_signature_is_standard_hmac_sha256_over_exact_csv_bytes(self):
        digest = hmac.new(KEY, CSV_BODY, hashlib.sha256).hexdigest().encode("ascii")
        signed = sign_export(CSV_BODY, KEY)
        self.assertEqual(signed, CSV_BODY + TRAILER_PREFIX + digest + b"\r\n")
        self.assertTrue(verify_export(signed, KEY))
        self.assertFalse(verify_export(signed, b"x" * 32))

    def test_multiline_unicode_and_signature_like_comment_round_trip(self):
        comment = '做得很好。 Café 🐜, "Keep going!"\n# HMAC-SHA256: fake\r\nSecond line.'
        buf = io.StringIO(newline="")
        writer = csv.writer(buf)
        writer.writerow(["student", "class", "grade", "comment"])
        writer.writerow(["alice", "Mathematics", "18.5", comment])
        body = buf.getvalue().encode("utf-8")
        signed = sign_export(body, KEY)
        self.assertTrue(verify_export(signed, KEY))
        self.assertEqual(signed[:len(body)], body)
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"), newline="")))
        self.assertEqual(rows[0]["comment"], comment)

    def test_export_with_no_grades_still_has_authenticated_header(self):
        self.assertTrue(verify_export(sign_export(CSV_HEADER, KEY), KEY))

    def test_any_grade_comment_header_or_newline_change_is_detected(self):
        signed = sign_export(CSV_BODY, KEY)
        changes = {
            "grade": signed.replace(b",12.5,", b",18.5,", 1),
            "comment": signed.replace(b"Good work", b"Great work", 1),
            "student": signed.replace(b"alice", b"carol", 1),
            "header": signed.replace(b"student,", b"Student,", 1),
            "line endings": signed.replace(b"\r\n", b"\n"),
            "BOM": b"\xef\xbb\xbf" + signed,
            "removed row": CSV_HEADER + signed[len(CSV_BODY):],
        }
        for name, changed in changes.items():
            with self.subTest(change=name):
                self.assertFalse(verify_export(changed, KEY))

    def test_unkeyed_sha256_cannot_replace_the_signature(self):
        forged = CSV_BODY + TRAILER_PREFIX + hashlib.sha256(CSV_BODY).hexdigest().encode("ascii") + b"\r\n"
        self.assertFalse(verify_export(forged, KEY))

    def test_unsigned_malformed_truncated_and_appended_files_are_rejected(self):
        signed = sign_export(CSV_BODY, KEY)
        digest = signed[len(CSV_BODY) + len(TRAILER_PREFIX):-2]
        invalid = {
            "empty": b"",
            "unsigned": CSV_BODY,
            "prefix only": CSV_BODY + TRAILER_PREFIX,
            "short digest": CSV_BODY + TRAILER_PREFIX + digest[:-1] + b"\r\n",
            "long digest": CSV_BODY + TRAILER_PREFIX + digest + b"0\r\n",
            "non hex digest": CSV_BODY + TRAILER_PREFIX + b"z" * 64 + b"\r\n",
            "uppercase digest": CSV_BODY + TRAILER_PREFIX + digest.upper() + b"\r\n",
            "changed algorithm": signed.replace(b"HMAC-SHA256", b"HMAC-SHA512"),
            "missing separator": signed.replace(TRAILER_PREFIX, b"# HMAC-SHA256:"),
            "missing final newline": signed[:-2],
            "LF trailer": signed[:-2] + b"\n",
            "extra blank line": signed + b"\r\n",
            "appended row": signed + b"bob,Mathematics,20,forged\r\n",
            "duplicate trailer": signed + signed[len(CSV_BODY):],
        }
        for name, value in invalid.items():
            with self.subTest(file=name):
                self.assertFalse(verify_export(value, KEY))


class SignedExportRouteTests(unittest.TestCase):
    def setUp(self):
        config_patch = patch.dict(notes_app.app.config, {"TESTING": True})
        config_patch.start()
        self.addCleanup(config_patch.stop)
        key_patch = patch.object(notes_app, "EXPORT_HMAC_KEY", KEY)
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value
        self.db_patch = patch.object(notes_app, "get_db", return_value=self.connection)
        self.get_db = self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.teacher = self.client_for("teacher")

    def client_for(self, role=None):
        client = notes_app.app.test_client()
        if role:
            with client.session_transaction() as session:
                session["user_id"] = 2 if role == "teacher" else 6
                session["username"] = "prof.turing" if role == "teacher" else role
                session["role"] = role
        return client

    def upload(self, payload, client=None, **kwargs):
        response = (client or self.teacher).post(
            "/verify-export",
            data={"file": (io.BytesIO(payload), "grades.csv")},
            content_type="multipart/form-data",
            **kwargs,
        )
        # Werkzeug may spool the multipart request itself to a temporary file.
        self.addCleanup(response.request.input_stream.close)
        self.addCleanup(response.close)
        return response

    def csv_rows(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("text/csv"))
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertTrue(verify_export(response.data, KEY))
        body = response.data[:response.data.rfind(TRAILER_PREFIX)]
        return list(csv.DictReader(io.StringIO(body.decode("utf-8"), newline="")))

    def test_export_signs_decrypted_comments_and_preserves_csv_fields(self):
        comment = '做得很好。 Café, "excellent"\n# HMAC-SHA256: not a trailer\r\nNext line.'
        self.cursor.fetchall.return_value = [
            {"student": "alice", "class": "Mathematics", "grade": Decimal("18.5"),
             "comment": encrypt_comment(comment)},
            {"student": "bob", "class": "History", "grade": None, "comment": None},
        ]
        response = self.teacher.get("/export.csv")
        self.assertEqual(self.csv_rows(response), [
            {"student": "alice", "class": "Mathematics", "grade": "18.5", "comment": comment},
            {"student": "bob", "class": "History", "grade": "", "comment": ""},
        ])
        self.assertNotIn(b"gcm1:", response.data)
        self.assertEqual(self.upload(response.data).status_code, 200)

    def test_filtered_and_empty_exports_are_signed(self):
        self.cursor.fetchall.return_value = [
            {"student": "alice", "class": "Mathematics", "grade": Decimal("12.5"),
             "comment": encrypt_comment("")},
        ]
        response = self.teacher.get("/export.csv?class_id=1")
        self.assertEqual(self.csv_rows(response)[0]["class"], "Mathematics")
        self.assertEqual(self.cursor.execute.call_args.args[1], ("1",))
        self.cursor.fetchall.return_value = []
        self.assertEqual(self.csv_rows(self.teacher.get("/export.csv?class_id=999")), [])

    def test_export_and_verification_require_a_teacher_session(self):
        for role in (None, "student", "admin"):
            client = self.client_for(role)
            for path in ("/export.csv", "/verify-export"):
                with self.subTest(role=role, path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 302)
                    self.assertTrue(response.headers["Location"].endswith("/login"))
            self.assertEqual(self.upload(sign_export(CSV_BODY, KEY), client).status_code, 302)
        jwt_only = self.client_for()
        token = notes_app.make_jwt({"user_id": 2, "username": "prof.turing", "role": "teacher"})
        self.assertEqual(jwt_only.get("/verify-export", headers={"Authorization": "Bearer " + token}).status_code, 302)
        self.get_db.assert_not_called()

    def test_verification_form_and_valid_upload_never_query_database(self):
        response = self.teacher.get("/verify-export")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'multipart/form-data', response.data)
        self.assertIn(b'name="file"', response.data)
        response = self.upload(sign_export(CSV_BODY, KEY))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CHECK PASSED", response.data)
        self.get_db.assert_not_called()

    def test_tampered_unsigned_and_wrong_key_uploads_fail_without_revealing_hmac(self):
        signed = sign_export(CSV_BODY, KEY)
        tampered_body = CSV_BODY.replace(b",12.5,", b",18.5,")
        cases = (
            (tampered_body + signed[len(CSV_BODY):], tampered_body),
            (CSV_BODY, CSV_BODY),
            (sign_export(CSV_BODY, b"x" * 32), CSV_BODY),
        )
        for payload, body in cases:
            with self.subTest(payload=payload[:40]):
                response = self.upload(payload)
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"CHECK FAILED", response.data)
                expected = hmac.new(KEY, body, hashlib.sha256).hexdigest().encode("ascii")
                self.assertNotIn(expected, response.data)
        self.get_db.assert_not_called()

    def test_missing_and_oversized_files_are_rejected(self):
        self.assertEqual(self.teacher.post("/verify-export", data={}).status_code, 400)
        self.assertEqual(self.upload(b"x" * (5 * 1024 * 1024 + 1)).status_code, 413)
        self.get_db.assert_not_called()

    def test_oversized_unknown_length_upload_is_bounded_during_multipart_parsing(self):
        streams = []
        stream_factory = notes_app.NotesRequest._get_file_stream

        def track_stream(*args, **kwargs):
            stream = stream_factory(*args, **kwargs)
            streams.append(stream)
            self.addCleanup(stream.close)
            return stream

        with patch.object(notes_app.NotesRequest, "_get_file_stream", autospec=True, side_effect=track_stream):
            response = self.upload(
                b"x" * (6 * 1024 * 1024),
                environ_overrides={"CONTENT_LENGTH": "", "wsgi.input_terminated": True},
            )
        self.assertEqual(response.request.environ["CONTENT_LENGTH"], "")
        self.assertEqual(response.status_code, 413)
        self.assertLessEqual(response.request.input_stream.tell(), 5 * 1024 * 1024 + 64 * 1024)
        self.assertTrue(streams)
        self.assertTrue(all(stream.closed for stream in streams))
        self.get_db.assert_not_called()

    def test_multipart_limit_is_scoped_to_verification_and_respects_lower_configuration(self):
        with patch.dict(notes_app.app.config, {"MAX_CONTENT_LENGTH": None}):
            with notes_app.app.test_request_context("/verify-export", method="POST"):
                self.assertEqual(notes_app.request.max_content_length, 5 * 1024 * 1024 + 64 * 1024)
            with notes_app.app.test_request_context("/grades", method="POST"):
                self.assertIsNone(notes_app.request.max_content_length)
        with patch.dict(notes_app.app.config, {"MAX_CONTENT_LENGTH": 1024}):
            with notes_app.app.test_request_context("/verify-export", method="POST"):
                self.assertEqual(notes_app.request.max_content_length, 1024)


if __name__ == "__main__":
    unittest.main()
