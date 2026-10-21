"""Byte-exact HMAC-SHA256 signatures for UTF-8 grades CSV downloads."""

import base64
import binascii
import hashlib
import hmac
import re


TRAILER_PREFIX = b"# HMAC-SHA256: "
TRAILER_PATTERN = re.compile(rb"# HMAC-SHA256: ([0-9a-f]{64})\r\n\Z")


def decode_hmac_key(encoded: str) -> bytes:
    """Require a persistent, independent 256-bit key; never use a dev default."""
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("EXPORT_HMAC_KEY must be a Base64-encoded 32-byte key") from exc
    if len(key) != 32:
        raise ValueError("EXPORT_HMAC_KEY must be a Base64-encoded 32-byte key")
    return key


def sign_export(csv_bytes: bytes, key: bytes) -> bytes:
    """Sign the header and all rows, including their original line endings."""
    if not csv_bytes.endswith(b"\r\n"):
        raise ValueError("CSV export must end with CRLF before signing")
    digest = hmac.new(key, csv_bytes, hashlib.sha256).hexdigest().encode("ascii")
    return csv_bytes + TRAILER_PREFIX + digest + b"\r\n"


def verify_export(signed_bytes: bytes, key: bytes) -> bool:
    """Check only the canonical final trailer without normalizing CSV content.

    Never expose the recomputed tag: that would let a caller sign edited files.
    A trailer-like line inside a quoted multiline comment stays part of the CSV.
    """
    trailer = TRAILER_PATTERN.search(signed_bytes)
    if trailer is None:
        return False
    csv_bytes = signed_bytes[:trailer.start()]
    if not csv_bytes.endswith(b"\r\n"):
        return False
    expected = hmac.new(key, csv_bytes, hashlib.sha256).hexdigest().encode("ascii")
    return hmac.compare_digest(expected, trailer.group(1))
