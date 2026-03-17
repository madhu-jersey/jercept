"""
Jercept Dashboard — versioned database migration runner.

Tracks applied migrations in a `_jercept_migrations` table.
Each migration is idempotent — safe to run multiple times.

Usage:
    python migrations/run.py              # apply all pending
    python migrations/run.py --status     # show applied/pending
    python migrations/run.py --dry-run    # show SQL without applying
"""
from __future__ import annotations
import argparse
import datetime
import os
import sys

# Migrations are ordered lists of (version, description, sql_statements)
MIGRATIONS: list[tuple[str, str, list[str]]] = [
    ("0001", "initial_schema", [
        """CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            key_hash VARCHAR(64) NOT NULL UNIQUE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME,
            event_count BIGINT NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hash VARCHAR(64) NOT NULL,
            session_id VARCHAR(36) NOT NULL,
            action VARCHAR(64) NOT NULL,
            resource VARCHAR(255),
            permitted BOOLEAN NOT NULL,
            raw_intent TEXT,
            confidence REAL,
            agent_type VARCHAR(64),
            sdk_version VARCHAR(16),
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        "CREATE INDEX IF NOT EXISTS idx_events_key_hash ON security_events(api_key_hash)",
        "CREATE INDEX IF NOT EXISTS idx_events_session ON security_events(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at)",
    ]),
    ("0002", "scope_visualizer_columns", [
        "ALTER TABLE security_events ADD COLUMN allowed_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN denied_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN allowed_resources TEXT",
        "ALTER TABLE security_events ADD COLUMN extraction_tier VARCHAR(16)",
    ]),
    ("0003", "webhook_configs", [
        """CREATE TABLE IF NOT EXISTS webhook_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hash VARCHAR(64) NOT NULL,
            name VARCHAR(64) NOT NULL DEFAULT 'default',
            url TEXT NOT NULL,
            url_hash VARCHAR(64) NOT NULL,
            min_risk_score REAL NOT NULL DEFAULT 0.0,
            include_intent BOOLEAN NOT NULL DEFAULT 1,
            active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        "CREATE INDEX IF NOT EXISTS idx_webhooks_key_hash ON webhook_configs(api_key_hash)",
    ]),
    ("0004", "daily_stats", [
        """CREATE TABLE IF NOT EXISTS daily_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hash VARCHAR(64) NOT NULL,
            date VARCHAR(10) NOT NULL,
            total_requests INTEGER NOT NULL DEFAULT 0,
            blocked_attacks INTEGER NOT NULL DEFAULT 0,
            UNIQUE(api_key_hash, date)
        )""",
    ]),
]

_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS _jercept_migrations (
    version VARCHAR(8) PRIMARY KEY,
    description VARCHAR(128) NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def _connect(db_url: str = ""):
    """Open a database connection based on DATABASE_URL."""
    url = db_url or os.getenv("DATABASE_URL", "")
    if url.startswith("postgresql"):
        # psycopg2 sync connection for migration runner
        import psycopg2
        dsn = url.replace("postgresql+asyncpg://", "postgresql://")
        return psycopg2.connect(dsn), "pg"
    else:
        import sqlite3
        path = url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "") or "jercept.db"
        conn = sqlite3.connect(path)
        return conn, "sqlite"


def _execute(conn, db_type: str, sql: str, silent_errors: tuple = ()) -> bool:
    """Execute one SQL statement, returning True on success."""
    try:
        conn.execute(sql)
        return True
    except Exception as e:
        msg = str(e).lower()
        if any(err in msg for err in ("duplicate column", "already exists", "table already")):
            return True  # idempotent — already applied
        if any(err in msg for err in silent_errors):
            return True
        print(f"    WARN: {e}")
        return False


def run(dry_run: bool = False, status_only: bool = False) -> int:
    """Apply all pending migrations. Returns exit code."""
    conn, db_type = _connect()
    conn.execute(_TRACKING_TABLE)
    conn.commit()

    applied = {
        row[0] for row in conn.execute(
            "SELECT version FROM _jercept_migrations"
        ).fetchall()
    }

    pending = [(v, d, stmts) for v, d, stmts in MIGRATIONS if v not in applied]

    if status_only:
        print(f"Applied: {len(applied)} | Pending: {len(pending)}")
        for v, d, _ in MIGRATIONS:
            mark = "✓" if v in applied else "○"
            print(f"  {mark}  {v}  {d}")
        conn.close()
        return 0

    if not pending:
        print("No pending migrations.")
        conn.close()
        return 0

    for version, description, statements in pending:
        print(f"  ── {version}: {description}")
        for sql in statements:
            preview = sql.strip()[:60].replace("\n", " ")
            print(f"      {preview}...")
            if not dry_run:
                _execute(conn, db_type, sql)
        if not dry_run:
            conn.execute(
                "INSERT INTO _jercept_migrations (version, description) VALUES (?, ?)",
                (version, description),
            )
            conn.commit()
            print(f"     Applied {version}")

    conn.close()
    if dry_run:
        print("Dry run — no changes made.")
    else:
        print(f"Done. Applied {len(pending)} migration(s).")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jercept DB migration runner")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    sys.exit(run(dry_run=args.dry_run, status_only=args.status))
