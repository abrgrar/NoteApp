# NotesApp

A small grades application used throughout the Computer Security course. Teachers
record grades and comments for their classes, students read their own grades, and an
admin manages users and classes.

## Run it

You need Docker with the Compose plugin.

```
git clone git@github.com:KristenPire/NoteApp.git notesapp
cd notesapp
docker compose up
```

The first start builds the image, launches PostgreSQL, and loads the seed data
automatically. When it is ready, open:

```
http://localhost:8080
```

## Test accounts

| Role    | Username      | Password   |
|---------|---------------|------------|
| Student | `alice`       | `alicepw`  |
| Teacher | `prof.turing` | `teach123` |
| Admin   | `admin`       | `admin123` |

(There are ~30 students in total; each student's password is their username + `pw`,
e.g. `bob` / `bobpw`.)

## Stack

- Python 3.11 + Flask (server-rendered Jinja2 pages and a small JSON API)
- PostgreSQL 15
- Docker Compose (`web` and `db` services)

## Encrypted grade comments (lab 3)

Create a project-root `.env` file containing `COMMENT_KEY=<Base64 AES-256 key>`.
After installing the lab 3 dependencies, generate the key once with:

```
python3 -m venv lab/lab3/.venv
lab/lab3/.venv/bin/python -m pip install -r lab/lab3/requirements.txt
lab/lab3/.venv/bin/python -c 'import base64; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print(base64.b64encode(AESGCM.generate_key(bit_length=256)).decode())'
```

Keep this key to read existing comments after a restart. `.env` is ignored by Git.
Build and start with `docker compose up -d --build`. Before serving requests, the
web container encrypts legacy comments in one transaction and verifies comments
that are already encrypted. Repeating migration does not re-encrypt them. An
invalid value or a wrong key rolls back migration and prevents startup.

The `notes.comment` TEXT column stores `gcm1:` followed by Base64-encoded nonce,
ciphertext, and authentication tag. Grade creation and updates encrypt comments;
student and teacher pages, the API, and CSV exports decrypt them in Flask.
Empty strings are encrypted and SQL NULL values remain NULL.

Manual migration and regression tests:

```
docker compose run --rm --no-deps web python migrate_comments.py
docker compose run --rm --no-deps web python -m unittest discover -s tests -v
```

Tests use a unique PostgreSQL schema that is removed afterwards and cover actual
SQL writes, page/API/CSV reads, migration rollback and repeatability, and GCM
authentication failures. Other teaching vulnerabilities remain part of the lab.

## Reset

```
docker compose down -v   # wipes the database volume
docker compose up        # reloads the seed data
```

## Updating your fork

The course repository is sometimes updated. Your fork does **not** update by itself.
To pull the latest changes into your fork:

**Easiest (GitHub website):** open your fork, and if it says *"This branch is behind
KristenPire/NoteApp"*, click **Sync fork → Update branch**. Then, in your local clone:

```
git pull
```

**Command line (keeps your own commits):**

```
git remote add upstream https://github.com/KristenPire/NoteApp.git   # once
git fetch upstream
git merge upstream/main
git push
```

Then **rebuild**, because the app code is baked into the Docker image:

```
docker compose up --build
```

A plain `docker compose up` would keep running the old image.
