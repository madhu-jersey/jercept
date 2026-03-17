"""
CSM Dashboard — SQLAlchemy ORM models.
"""
from __future__ import annotations

import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    """
    Stores hashed API keys for authentication.

    Plaintext keys are NEVER stored — only the SHA-256 hash.
    """
    __tablename__ = "api_keys"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    name       = Column(String(255), nullable=False)
    email      = Column(String(255), nullable=False)
    key_hash   = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    event_count  = Column(BigInteger, default=0, nullable=False)


class SecurityEvent(Base):
    """
    Individual tool-call event captured from a protected agent run.

    One row per tool call (both permitted and blocked).
    Includes full scope context for the scope visualizer.
    """
    __tablename__ = "security_events"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    api_key_hash = Column(String(64), nullable=False, index=True)
    session_id  = Column(String(36), nullable=False, index=True)
    action      = Column(String(64), nullable=False)
    resource    = Column(String(255), nullable=True)
    permitted   = Column(Boolean, nullable=False)
    raw_intent  = Column(Text, nullable=True)
    confidence  = Column(Float, nullable=True)
    agent_type  = Column(String(64), nullable=True)
    sdk_version = Column(String(16), nullable=True)
    # Scope visualizer fields — full scope context per event
    allowed_actions  = Column(Text, nullable=True)   # JSON array string
    denied_actions   = Column(Text, nullable=True)   # JSON array string
    allowed_resources = Column(Text, nullable=True)  # JSON array string
    extraction_tier  = Column(String(16), nullable=True)  # cache/regex/llm
    created_at  = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)


class DailyStats(Base):
    """
    Materialised daily aggregates per API key — enables fast dashboard queries.
    """
    __tablename__ = "daily_stats"
    __table_args__ = (UniqueConstraint("api_key_hash", "date", name="uq_daily_stats"),)

    id              = Column(Integer, primary_key=True, autoincrement=True)
    api_key_hash    = Column(String(64), nullable=False, index=True)
    date            = Column(String(10), nullable=False)   # YYYY-MM-DD
    total_requests  = Column(Integer, default=0, nullable=False)
    blocked_attacks = Column(Integer, default=0, nullable=False)


class WebhookConfig(Base):
    """
    Registered webhook URLs for attack alert notifications.

    When an agent session records a blocked action, the dashboard backend
    fires a POST to every active webhook registered for that API key.
    """
    __tablename__ = "webhook_configs"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    api_key_hash    = Column(String(64), nullable=False, index=True)
    name            = Column(String(64), nullable=False, default="default")
    url             = Column(String(2048), nullable=False)
    url_hash        = Column(String(64), nullable=False)
    min_risk_score  = Column(Float, default=0.0, nullable=False)
    include_intent  = Column(Boolean, default=True, nullable=False)
    active          = Column(Boolean, default=True, nullable=False, index=True)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
