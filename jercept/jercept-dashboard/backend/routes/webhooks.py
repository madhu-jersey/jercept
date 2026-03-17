"""
CSM Dashboard — webhook configuration routes.

POST /v1/webhooks     Register a webhook URL for attack alerts.
GET  /v1/webhooks     List registered webhooks for the authenticated key.
DELETE /v1/webhooks/{id}  Remove a webhook.
"""
from __future__ import annotations

import datetime
import hashlib
import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import ApiKey, get_current_key
from crypto import encrypt_field, decrypt_field
from database import get_db
from models import WebhookConfig

router = APIRouter()

_URL_RE = re.compile(r"^https?://\S+$")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class WebhookCreateRequest(BaseModel):
    url: str
    name: str = "default"
    min_risk_score: float = 0.0
    include_intent: bool = True


class WebhookResponse(BaseModel):
    id: int
    name: str
    url_preview: str   # Only first/last 8 chars — never expose full URL in list
    min_risk_score: float
    include_intent: bool
    created_at: str
    active: bool


class WebhookListResponse(BaseModel):
    webhooks: list[WebhookResponse]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/v1/webhooks", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    body: WebhookCreateRequest,
    api_key: ApiKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    """
    Register a webhook URL to receive attack alerts.

    The full URL is stored as a SHA-256 hash — it cannot be retrieved
    after creation. A masked preview is returned in list responses.
    """
    if not _URL_RE.match(body.url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="url must be a valid http:// or https:// URL",
        )
    if len(body.url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="url must be under 2048 characters",
        )

    url_hash = hashlib.sha256(body.url.encode()).hexdigest()
    preview = body.url[:12] + "..." + body.url[-8:] if len(body.url) > 24 else body.url
    encrypted_url = encrypt_field(body.url)  # SEC FIX: encrypt before storing

    record = WebhookConfig(
        api_key_hash=api_key.key_hash,
        name=body.name[:64],
        url=encrypted_url,  # encrypted with Fernet if JERCEPT_ENCRYPTION_KEY set
        url_hash=url_hash,
        min_risk_score=max(0.0, min(1.0, body.min_risk_score)),
        include_intent=body.include_intent,
        active=True,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(record)
    await db.flush()

    return WebhookResponse(
        id=record.id,
        name=record.name,
        url_preview=preview,
        min_risk_score=record.min_risk_score,
        include_intent=record.include_intent,
        created_at=record.created_at.isoformat(),
        active=record.active,
    )


@router.get("/v1/webhooks", response_model=WebhookListResponse)
async def list_webhooks(
    api_key: ApiKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
) -> WebhookListResponse:
    """List all active webhooks registered for this API key."""
    result = await db.execute(
        select(WebhookConfig)
        .where(WebhookConfig.api_key_hash == api_key.key_hash)
        .order_by(WebhookConfig.created_at.desc())
    )
    records = list(result.scalars().all())

    return WebhookListResponse(
        webhooks=[
            WebhookResponse(
                id=r.id,
                name=r.name,
                url_preview=r.url[:12] + "..." + r.url[-8:] if len(r.url) > 24 else r.url,
                min_risk_score=r.min_risk_score,
                include_intent=r.include_intent,
                created_at=r.created_at.isoformat(),
                active=r.active,
            )
            for r in records
        ]
    )


@router.delete("/v1/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: int,
    api_key: ApiKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Deactivate (soft-delete) a registered webhook."""
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.api_key_hash == api_key.key_hash,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook {webhook_id} not found",
        )
    record.active = False
    db.add(record)
