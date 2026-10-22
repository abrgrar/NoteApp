"""NotesApp - a small grades application.

Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""
import os
import csv
import io
import json
import hmac
import time
import base64
import hashlib
import subprocess

import psycopg2
import psycopg2.extras
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, Request, Response, jsonify, abort,
)

from comment_crypto import encrypt_comment, decrypt_comment
from export_integrity import decode_hmac_key, sign_export, verify_export

# --- Configuration ------------------------------------------------------------
# All configuration comes from the environment (set in docker-compose.yml).
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")
JWT_SECRET = os.environ.get("JWT_SECRET", "s3cr3t")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-session-key")
EXPORT_HMAC_KEY = decode_hmac_key(os.environ.get("EXPORT_HMAC_KEY", ""))
MAX_EXPORT_BYTES = 5 * 1024 * 1024


class NotesRequest(Request):
    @property
    def max_content_length(self):
        # Flask 3.0 has no per-request limit setter. Bound multipart parsing too,
        # including chunked requests without Content-Length, before file spooling.
        configured = super().max_content_length
        if self.endpoint == "verify_export_file":
            limit = MAX_EXPORT_BYTES + 64 * 1024
            return min(configured, limit) if configured is not None else limit
        return configured

    def _get_file_stream(self, *args, **kwargs):
        stream = super()._get_file_stream(*args, **kwargs)
        if self.endpoint == "verify_export_file":
            self.__dict__.setdefault("_export_upload_streams", []).append(stream)
        return stream

    def close(self):
        try:
            super().close()
        finally:
            # Aborted multipart parsing may never populate request.files.
            for stream in self.__dict__.get("_export_upload_streams", ()):
                stream.close()


app = Flask(__name__)
ph = PasswordHasher()
app.request_class = NotesRequest
app.secret_key = SECRET_KEY


def is_argon2_hash(value: str) -> bool:
    return value.startswith("$argon2")


LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")


def log(msg):
    """Very small access log. No rotation, no policy (see flaw #14)."""
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


# --- Database -----------------------------------------------------------------
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = True
    return conn


# --- Minimal JWT (deliberately weak) ------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(token: str):
    """Decode a JWT. Accepts alg:none (no signature) and HS256 with a short key.

    This is intentionally broken (flaw #4): an attacker can forge any identity
    by setting "alg":"none", and the HS256 key is trivially guessable.
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "").lower()
    if alg == "none":
        # No signature verification at all.
        return payload
    if alg == "hs256":
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig_b64):
            return payload
        return None
    return None


def current_identity():
    """Return the acting identity from a Bearer JWT if present, else the session."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_jwt(auth[7:].strip())
        if payload:
            return payload
    if "user_id" in session:
        return {"user_id": session["user_id"], "username": session.get("username"),
                "role": session.get("role")}
    return None


# --- Auth helpers -------------------------------------------------------------
def login_required(role=None):
    if "user_id" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session.get("role")
        if role == "student":
            return redirect(url_for("dashboard"))
        if role == "teacher":
            return redirect(url_for("teacher"))
        if role == "admin":
            return redirect(url_for("admin"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Flaw #8: SQL injection. Query built by string concatenation, no params.
        query = (
            "SELECT id, username, role, password FROM users "
            "WHERE username = '" + username + "'"
        )
        conn = get_db()
        cur = conn.cursor()
        authenticated = False
        try:
            try:
                cur.execute(query)
                row = cur.fetchone()
            except Exception as e:
                # Keep the raw error visible - helps the SQLi session.
                error = f"Query error: {e}"
                row = None
            if row:
                stored = row["password"]
                if is_argon2_hash(stored):
                    try:
                        ph.verify(stored, password)
                        authenticated = True
                    except (VerificationError, InvalidHash):
                        authenticated = False
                elif stored == password:
                    # Upgrade a legacy account only after a successful login.
                    new_hash = ph.hash(password)
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s",
                        (new_hash, row["id"]),
                    )
                    authenticated = True
                    log(f"upgraded {row['username']} to argon2")
        finally:
            conn.close()
        if authenticated:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            # Issue a weak JWT the dashboard uses to call the API.
            session["token"] = make_jwt({
                "user_id": row["id"], "username": row["username"], "role": row["role"],
            })
            log(f"login success user={row['username']} role={row['role']}")
            return redirect(url_for("index"))
        if not error:
            error = "Invalid credentials."
        log(f"login failure username={username!r}")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, c.name AS class_name "
        "FROM notes n JOIN classes c ON c.id = n.class_id "
        "WHERE n.student_id = %s ORDER BY c.name",
        (session["user_id"],),
    )
    notes = cur.fetchall()
    conn.close()
    for note in notes:
        note["comment"] = decrypt_comment(note["comment"])
    return render_template("dashboard.html", notes=notes, token=session.get("token"))


@app.route("/api/notes/<int:note_id>")
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    # Flaw #7 (IDOR): the owner of the note is never checked. Any authenticated
    # caller can read any note id. Flaw #4: `ident` may come from a forged token.
    cur.execute(
        "SELECT n.id, n.student_id, n.class_id, n.grade, n.comment, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id WHERE n.id = %s",
        (note_id,),
    )
    note = cur.fetchone()
    conn.close()
    if not note:
        return jsonify({"error": "not found"}), 404
    note["comment"] = decrypt_comment(note["comment"])
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    return jsonify(note)


@app.route("/teacher")
def teacher():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    # A teacher sees every class (no owner scoping - broken access control).
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY name")
    classes = cur.fetchall()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, n.student_id, n.class_id, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
    )
    notes = cur.fetchall()
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    for note in notes:
        note["comment"] = decrypt_comment(note["comment"])
    return render_template("teacher.html", classes=classes, notes=notes, students=students)


@app.route("/grades", methods=["POST"])
def grades():
    # Flaw #11: no CSRF token checked on this state-changing POST.
    if not login_required("teacher"):
        return redirect(url_for("login"))
    note_id = request.form.get("note_id", "").strip()
    student_id = request.form.get("student_id")
    class_id = request.form.get("class_id")
    grade = request.form.get("grade")
    comment = encrypt_comment(request.form.get("comment", ""))
    conn = get_db()
    cur = conn.cursor()
    if note_id:
        cur.execute(
            "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
            (grade, comment, note_id),
        )
    else:
        cur.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) "
            "VALUES (%s, %s, %s, %s)",
            (student_id, class_id, grade, comment),
        )
    conn.close()
    log(f"grade write by {session.get('username')} note_id={note_id or 'new'}")
    return redirect(url_for("teacher"))


@app.route("/export.csv")
def export_csv():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    class_id = request.args.get("class_id")
    conn = get_db()
    cur = conn.cursor()
    if class_id:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = cur.fetchall()
    conn.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        r["comment"] = decrypt_comment(r["comment"])
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
    return Response(
        sign_export(buf.getvalue().encode("utf-8"), EXPORT_HMAC_KEY), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=grades.csv"},
    )


@app.route("/verify-export", methods=["GET", "POST"])
def verify_export_file():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    result = None
    error = None
    status = 200
    if request.method == "POST":
        # Allow multipart overhead, but reject oversized requests before parsing.
        if request.content_length and request.content_length > MAX_EXPORT_BYTES + 64 * 1024:
            error = "File is too large. Upload a CSV of at most 5 MiB."
            status = 413
        else:
            upload = request.files.get("file")
            if upload is None or not upload.filename:
                error = "Choose a signed grades CSV file to verify."
                status = 400
            else:
                content = upload.stream.read(MAX_EXPORT_BYTES + 1)
                if len(content) > MAX_EXPORT_BYTES:
                    error = "File is too large. Upload a CSV of at most 5 MiB."
                    status = 413
                else:
                    result = verify_export(content, EXPORT_HMAC_KEY)
                    if not result:
                        status = 400
    return render_template("verify_export.html", result=result, error=error), status


@app.route("/admin")
def admin():
    if not login_required("admin"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    classes = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, classes=classes,
                           ping_result=request.args.get("ping_result"))


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    # Flaw #11: no CSRF token. Flaw #9: command injection via os/system shell.
    if not login_required("admin"):
        return redirect(url_for("login"))
    host = request.form.get("host", "")
    # Host is concatenated straight into a shell command.
    cmd = "ping -c 1 " + host
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    log(f"admin ping host={host!r}")
    return render_template("admin.html", users=_all_users(), classes=_all_classes(),
                           ping_result=output)


def _all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def _all_classes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route("/admin/users", methods=["POST"])
def admin_users():
    if not login_required("admin"):
        return redirect(url_for("login"))
    action = request.form.get("action")
    conn = get_db()
    cur = conn.cursor()
    if action == "create":
        cur.execute(
            "INSERT INTO users (username, password, role, teacher_id) "
            "VALUES (%s, %s, %s, %s)",
            (request.form.get("username"), ph.hash(request.form.get("password", "")),
             request.form.get("role", "student"), None),
        )
    elif action == "delete":
        cur.execute("DELETE FROM users WHERE id = %s", (request.form.get("user_id"),))
    conn.close()
    return redirect(url_for("admin"))


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return "ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == "__main__":
    # Plain HTTP on purpose (flaw #3). Nginx + TLS is added in a later lab.
    app.run(host="0.0.0.0", port=5000, debug=True)
