"""Encrypt legacy comments in one transaction, and verify existing ciphertext."""

from app import get_db
from comment_crypto import decrypt_comment, encrypt_comment


def migrate_comments():
    counts = {"migrated": 0, "verified": 0, "null": 0}
    conn = get_db()
    try:
        conn.autocommit = False
        with conn:
            with conn.cursor() as cur:
                # Serialize migrations and prevent writes until conversion ends.
                cur.execute("LOCK TABLE notes IN SHARE ROW EXCLUSIVE MODE")
                cur.execute("SELECT id, comment FROM notes ORDER BY id")
                for row in cur.fetchall():
                    value = row["comment"]
                    if value is None:
                        counts["null"] += 1
                    elif value.startswith("gcm1:"):
                        # A wrong key or damaged value must abort the migration.
                        try:
                            decrypt_comment(value)
                        except ValueError as exc:
                            raise RuntimeError(
                                f"Invalid encrypted comment for note {row['id']}."
                            ) from exc
                        counts["verified"] += 1
                    else:
                        encrypted = encrypt_comment(value)
                        if decrypt_comment(encrypted) != value:
                            raise RuntimeError(
                                f"Comment verification failed for note {row['id']}."
                            )
                        cur.execute(
                            "UPDATE notes SET comment = %s WHERE id = %s",
                            (encrypted, row["id"]),
                        )
                        counts["migrated"] += 1
        return counts
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    try:
        counts = migrate_comments()
    except Exception as exc:
        print(
            f"Comment migration failed ({type(exc).__name__}); "
            "all changes rolled back. Check COMMENT_KEY and stored comments.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(
        f"Comment migration: {counts['migrated']} encrypted, "
        f"{counts['verified']} already encrypted and verified, "
        f"{counts['null']} NULL values preserved.",
        flush=True,
    )
