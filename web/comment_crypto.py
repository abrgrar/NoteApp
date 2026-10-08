import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = base64.b64decode(os.environ["COMMENT_KEY"], validate=True)
aes = AESGCM(key)
aad = b"notes.comment:v1"


def encrypt_comment(text):
    if text is None:
        return None

    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, text.encode("utf-8"), aad)
    return "gcm1:" + base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_comment(value):
    if value is None:
        return None
    if not value.startswith("gcm1:"):
        raise ValueError("Unencrypted comment: migration required")

    data = base64.b64decode(value[5:], validate=True)
    if len(data) < 28:
        raise ValueError("Invalid encrypted comment")

    return aes.decrypt(data[:12], data[12:], aad).decode("utf-8")
