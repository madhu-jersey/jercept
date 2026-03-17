"""
Jercept Dashboard — GET /v1/dashboard route.

Returns aggregated security statistics and scope visualizer data.
Rate limit: 60 requests per API key per minute.
"""
from __future__ import annotations

import datetime
import json
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import ApiKey, get_current_key
from database import get_db
from models import SecurityEvent
from ratelimit import limiter

router = APIRouter()


class ActionCount(BaseModel):
    action: str
    count: int


class TimelinePoint(BaseModel):
    hour: str
    blocked: int
    allowed: int


class RecentEvent(BaseModel):
    ts: Any
    session_id: str
    action: str
    resource: Optional[str]
    permitted: bool
    raw_intent: Optional[str]


class ScopeEvent(BaseModel):
    """Full scope context for the scope visualizer — one entry per session."""
    ts: Any
    session_id: str
    raw_intent: Optional[str]
    allowed_actions: List[str]
    denied_actions: List[str]
    allowed_resources: List[str]
    confidence: Optional[float]
    extraction_tier: Optional[str]
    total_calls: int
    blocked_calls: int


class DashboardResponse(BaseModel):
    total_requests: int
    blocked_attacks: int
    block_rate: float
    top_blocked_actions: List[ActionCount]
    attack_timeline: List[TimelinePoint]
    recent_events: List[RecentEvent]
    top_intents: List[Dict[str, Any]]
    scope_timeline: List[ScopeEvent]


@router.get("/v1/dashboard", response_model=DashboardResponse)
@limiter.limit("60/minute")
async def get_dashboard(
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=500, ge=1, le=5000),
    api_key: ApiKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
) -> DashboardResponse:
    """
    Return security dashboard statistics and scope visualizer data.

    scope_timeline is built in O(n) using a single defaultdict pass.
    All session grouping happens in one loop — no nested filtering.

    Rate limited to 60 requests per API key per minute.
    """
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)

    result = await db.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.api_key_hash == api_key.key_hash,
            SecurityEvent.created_at >= since,
        )
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    )
    events: list[SecurityEvent] = list(result.scalars().all())

    total   = len(events)
    blocked = sum(1 for e in events if not e.permitted)
    block_rate = round(blocked / total * 100, 2) if total else 0.0

    blocked_counter: Counter[str] = Counter(
        e.action for e in events if not e.permitted
    )
    top_blocked = [
        ActionCount(action=a, count=c)
        for a, c in blocked_counter.most_common(10)
    ]

    timeline_map: dict[str, dict] = defaultdict(lambda: {"blocked": 0, "allowed": 0})
    for e in events:
        hour_key = e.created_at.strftime("%Y-%m-%dT%H:00")
        if not e.permitted:
            timeline_map[hour_key]["blocked"] += 1
        else:
            timeline_map[hour_key]["allowed"] += 1
    timeline = [
        TimelinePoint(hour=h, blocked=v["blocked"], allowed=v["allowed"])
        for h, v in sorted(timeline_map.items())
    ]

    recent = [
        RecentEvent(
            ts=e.created_at.isoformat(),
            session_id=e.session_id,
            action=e.action,
            resource=e.resource,
            permitted=e.permitted,
            raw_intent=e.raw_intent,
        )
        for e in events[:50]
    ]

    intent_counter: Counter[str] = Counter(
        e.raw_intent for e in events if e.raw_intent
    )
    top_intents = [
        {"intent": intent[:100], "count": count}
        for intent, count in intent_counter.most_common(10)
    ]

    # O(n) single-pass session grouping — replaces O(n²) nested loop
    session_groups: dict[str, list] = defaultdict(list)
    for e in events:
        session_groups[e.session_id].append(e)

    scope_timeline: list[ScopeEvent] = []
    for session_id, session_events in list(session_groups.items())[:50]:
        first = session_events[0]
        session_blocked = sum(1 for x in session_events if not x.permitted)
        try:
            allowed_actions   = json.loads(first.allowed_actions or "[]")
            denied_actions    = json.loads(first.denied_actions or "[]")
            allowed_resources = json.loads(first.allowed_resources or "[]")
        except (json.JSONDecodeError, TypeError):
            allowed_actions = denied_actions = allowed_resources = []
        scope_timeline.append(ScopeEvent(
            ts=first.created_at.isoformat(),
            session_id=session_id,
            raw_intent=first.raw_intent,
            allowed_actions=allowed_actions,
            denied_actions=denied_actions,
            allowed_resources=allowed_resources,
            confidence=first.confidence,
            extraction_tier=first.extraction_tier,
            total_calls=len(session_events),
            blocked_calls=session_blocked,
        ))

    return DashboardResponse(
        total_requests=total,
        blocked_attacks=blocked,
        block_rate=block_rate,
        top_blocked_actions=top_blocked,
        attack_timeline=timeline,
        recent_events=recent,
        top_intents=top_intents,
        scope_timeline=scope_timeline,
    )
