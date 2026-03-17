"""
Jercept Dashboard — field-level encryption for sensitive data.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
Key is read from JERCEPT_ENCRYPTION_KEY env var (32-byte base64 string).

Generate a key:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Set in Railway:
    railway variables set JERCEPT_ENCRYPTION_KEY="<output from above>"
"""
from __future__ import annotations

import base64
import logging
import os

logger = logging.getLogger(__name__)

_ENCRYPTION_KEY: bytes | None = None


def _get_fernet():
    """Return a Fernet instance, lazily initialised from env var."""
    global _ENCRYPTION_KEY
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None  # cryptography not installed — run in plaintext mode

    if _ENCRYPTION_KEY is None:
        raw = os.getenv("JERCEPT_ENCRYPTION_KEY", "")
        if not raw:
            logger.warning(
                "JERCEPT_ENCRYPTION_KEY not set — webhook URLs stored in plaintext. "
                "Set this env var before deploying to production."
            )
            return None
        try:
            _ENCRYPTION_KEY = raw.encode()
            return Fernet(_ENCRYPTION_KEY)
        except Exception as e:
            logger.error("Invalid JERCEPT_ENCRYPTION_KEY: %s", e)
            return None

    return Fernet(_ENCRYPTION_KEY)


def encrypt_field(value: str) -> str:
    """
    Encrypt a string field for database storage.

    Falls back to plaintext if JERCEPT_ENCRYPTION_KEY is not set
    (with a logged warning). This allows the service to start without
    encryption configured while making the risk visible.

    Args:
        value: Plaintext string to encrypt.

    Returns:
        Fernet-encrypted base64 string, or original value if no key set.
    """
    f = _get_fernet()
    if f is None:
        return value
    return f.encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str:
    """
    Decrypt a previously encrypted field from the database.

    Returns the value as-is if it cannot be decrypted (handles
    pre-encryption plaintext values in existing databases).

    Args:
        value: Encrypted or plaintext string from the database.

    Returns:
        Decrypted plaintext string.
    """
    f = _get_fernet()
    if f is None:
        return value
    try:
        return f.decrypt(value.encode()).decode()
    except Exception:
        return value  # pre-existing plaintext value — return as-is
