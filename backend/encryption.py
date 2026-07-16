"""
Encryption helper for We Mental Health.

Sensitive text fields (message details, contact name, contact info) are
encrypted at rest using Fernet (AES128-CBC + HMAC) symmetric encryption.
The key is read from the ENCRYPTION_KEY environment variable — it must
NEVER be committed to git or hardcoded here.

Generate a key once with:
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Then set it on your server as an environment variable, e.g. in a .env file
that is in .gitignore.
"""
import os
from cryptography.fernet import Fernet, InvalidToken

_key = os.environ.get("ENCRYPTION_KEY")
_fernet = Fernet(_key.encode()) if _key else None


def is_configured() -> bool:
    return _fernet is not None


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    if not _fernet:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Refusing to store sensitive data unencrypted."
        )
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    if not _fernet:
        raise RuntimeError("ENCRYPTION_KEY is not set.")
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return "[unable to decrypt — wrong key or corrupted data]"

