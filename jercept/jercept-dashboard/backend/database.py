"""
Jercept Dashboard — async database connection via SQLAlchemy.

Supports PostgreSQL (production) and SQLite (development/testing).
Automatically runs column-add migrations on startup for existing deployments.
"""
from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import Base

logger = logging.getLogger(__name__)

_raw_url = os.getenv("DATABASE_URL", "")

# Default to SQLite for local development if no DATABASE_URL set
if not _raw_url:
    DATABASE_URL = "sqlite+aiosqlite:///./jercept.db"
    logger.info("No DATABASE_URL set — using local SQLite: jercept.db")
else:
    DATABASE_URL = _raw_url

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def _run_migrations() -> None:
    """
    Apply additive schema migrations for existing deployments.

    Uses ADD COLUMN IF NOT EXISTS (PostgreSQL) or catches OperationalError
    (SQLite) so migrations are idempotent — safe to run on every startup.
    """
    is_sqlite = "sqlite" in DATABASE_URL
    migrations = [
        # v1.0.0: scope visualizer columns
        "ALTER TABLE security_events ADD COLUMN allowed_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN denied_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN allowed_resources TEXT",
        "ALTER TABLE security_events ADD COLUMN extraction_tier VARCHAR(16)",
    ]
    async with engine.begin() as conn:
        for sql in migrations:
            try:
                if not is_sqlite:
                    await conn.execute(
                        __import__("sqlalchemy").text(sql + " IF NOT EXISTS")
                    )
                else:
                    await conn.execute(__import__("sqlalchemy").text(sql))
            except Exception as e:
                if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                    pass  # column exists — idempotent
                else:
                    logger.debug("Migration note: %s", e)


async def init_db() -> None:
    """
    Initialise database: create tables then run additive migrations.
    Safe to call on every startup.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _run_migrations()
    logger.info("Database initialised")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yield an async session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
