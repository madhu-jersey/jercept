"""
Jercept Dashboard — POST /v1/events route.

Receives telemetry payloads from the jercept SDK and stores individual
security events including full scope context for the scope visualizer.

Rate limit: 1000 requests per API key per hour.
"""
from __future__ import annotations

import datetime
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from auth import ApiKey, get_current_key
from database import get_db
from models import SecurityEvent
from ratelimit import limiter

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class EventItem(BaseModel):
    action: str = Field(max_length=64)
    resource: Optional[str] = Field(None, max_length=255)
    permitted: bool
    fn_name: Optional[str] = Field(None, max_length=128)
    ts: Optional[float] = None


class ScopePayload(BaseModel):
    allowed_actions: List[str] = Field(default_factory=list, max_length=50)
    allowed_resources: List[str] = Field(default_factory=list, max_length=50)
    denied_actions: List[str] = Field(default_factory=list, max_length=50)
    raw_intent: Optional[str] = Field(None, max_length=2000)
    confidence: Optional[float] = None
    ambiguous: Optional[bool] = None
    extraction_tier: Optional[str] = Field(None, max_length=16)


class SummaryPayload(BaseModel):
    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0


class SecurityEventPayload(BaseModel):
    session_id: str = Field(max_length=64)
    # BUG FIX: max_length=500 prevents batch-flooding DoS (was unlimited)
    events: List[EventItem] = Field(default_factory=list, max_length=500)
    summary: SummaryPayload = Field(default_factory=SummaryPayload)
    scope: ScopePayload = Field(default_factory=ScopePayload)
    ts: Optional[float] = None
    sdk_version: Optional[str] = Field(None, max_length=16)
    agent_type: Optional[str] = Field(None, max_length=64)


class EventsResponse(BaseModel):
    status: str
    stored: int


# ── Route ────────────────────────────────────────────────────────────────────

@router.post("/v1/events", response_model=EventsResponse)
@limiter.limit("1000/hour")
async def receive_events(
    request: Request,
    payload: SecurityEventPayload,
    api_key: ApiKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
) -> EventsResponse:
    """
    Ingest a batch of security events from the jercept SDK.

    Stores full scope context (allowed_actions, denied_actions,
    allowed_resources, extraction_tier) for the scope visualizer.

    Rate limited to 1000 requests per API key per hour.
    Event batch capped at 500 items to prevent DoS via batch flooding.

    Args:
        payload: Telemetry batch from the SDK.
        api_key: Authenticated API key record.
        db: Async database session.

    Returns:
        Status and count of stored events.
    """
    raw_intent   = payload.scope.raw_intent
    confidence   = payload.scope.confidence

    allowed_actions_json   = json.dumps(payload.scope.allowed_actions)
    denied_actions_json    = json.dumps(payload.scope.denied_actions)
    allowed_resources_json = json.dumps(payload.scope.allowed_resources)

    rows = []
    for event in payload.events:
        row = SecurityEvent(
            api_key_hash     = api_key.key_hash,
            session_id       = payload.session_id,
            action           = event.action,
            resource         = event.resource,
            permitted        = event.permitted,
            raw_intent       = raw_intent,
            confidence       = confidence,
            agent_type       = payload.agent_type,
            sdk_version      = payload.sdk_version,
            allowed_actions  = allowed_actions_json,
            denied_actions   = denied_actions_json,
            allowed_resources= allowed_resources_json,
            extraction_tier  = payload.scope.extraction_tier,
            created_at       = datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(row)
        rows.append(row)

    api_key.event_count  += len(rows)
    api_key.last_used_at  = datetime.datetime.now(datetime.timezone.utc)
    db.add(api_key)

    return EventsResponse(status="ok", stored=len(rows))
