"""
CSM Dashboard — POST /v1/keys route.

Generates new API keys and stores their hashes. Plaintext key is
returned exactly once — never again.
"""
from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from auth import generate_api_key, hash_key
from ratelimit import limiter
from database import get_db
from models import ApiKey

router = APIRouter()


class KeyRequest(BaseModel):
    name: str
    email: EmailStr


class KeyResponse(BaseModel):
    api_key: str
    name: str
    message: str


@router.post("/v1/keys", response_model=KeyResponse, status_code=201)
@limiter.limit("10/hour")
async def create_api_key(
    request: Request,
    body: KeyRequest,
    db: AsyncSession = Depends(get_db),
) -> KeyResponse:
    """
    Generate a new API key for the Jercept dashboard.

    The plaintext key is included in the response exactly once.
    **It is never stored on the server.** Save it immediately.

    Args:
        body: Name and email for the new API key record.
        db: Async database session.

    Returns:
        The plaintext API key (one-time only) and metadata.
    """
    plaintext_key = generate_api_key()
    key_hash = hash_key(plaintext_key)

    record = ApiKey(
        name=body.name,
        email=body.email,
        key_hash=key_hash,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        event_count=0,
    )
    db.add(record)

    return KeyResponse(
        api_key=plaintext_key,
        name=body.name,
        message=(
            "Save this key — it will never be shown again. "
            "Use it as the Authorization: Bearer <key> header, "
            "or pass it as telemetry_key= to protect_agent()."
        ),
    )
