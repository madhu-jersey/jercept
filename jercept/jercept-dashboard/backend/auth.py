"""
CSM Dashboard — API key generation, hashing, and FastAPI dependency.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import ApiKey

# Prefix makes keys instantly recognisable in logs / config files.
KEY_PREFIX: str = "jercept_live_"
KEY_BYTES: int = 24


def generate_api_key() -> str:
    """
    Generate a new plaintext API key.

    Format: ``jercept_live_`` + 32 URL-safe base64 characters.

    Returns:
        A unique, cryptographically random API key string.
    """
    return KEY_PREFIX + secrets.token_urlsafe(KEY_BYTES)


def hash_key(key: str) -> str:
    """
    Compute the SHA-256 hex digest of an API key.

    The plaintext key is NEVER retained beyond this call.

    Args:
        key: Plaintext API key.

    Returns:
        64-character hex string safe for database storage.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def verify_key(key: str, db: AsyncSession) -> Optional[ApiKey]:
    """
    Look up an API key by its hash.

    Args:
        key: The plaintext key from the ``Authorization`` header.
        db: An active async SQLAlchemy session.

    Returns:
        The :class:`ApiKey` record if found, else ``None``.
    """
    from sqlalchemy import select

    key_hash = hash_key(key)
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    return result.scalar_one_or_none()


async def get_current_key(
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
) -> ApiKey:
    """
    FastAPI dependency: extract + validate the Bearer token.

    Args:
        authorization: The raw ``Authorization`` header value.
        db: Injected async database session.

    Returns:
        The authenticated :class:`ApiKey` record.

    Raises:
        HTTPException 401: If the header is missing, malformed, or invalid.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must be 'Bearer <api_key>'",
        )

    raw_key = authorization.removeprefix("Bearer ").strip()
    api_key = await verify_key(raw_key, db)

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key. Obtain one at jercept.com",
        )

    return api_key
