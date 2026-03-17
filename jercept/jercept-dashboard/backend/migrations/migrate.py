"""
Jercept Dashboard migration runner.

Usage:
    python migrations/migrate.py          # auto-detects DB from DATABASE_URL
    python migrations/migrate.py --dry-run # show SQL without running
"""
from __future__ import annotations
import os, sys

MIGRATIONS = [
    ("v1.0.0 scope columns", [
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS allowed_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS denied_actions TEXT",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS allowed_resources TEXT",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS extraction_tier VARCHAR(16)",
    ]),
]

def run(dry_run: bool = False) -> None:
    db_url = os.getenv("DATABASE_URL", "")
    print(f"Migration target: {db_url[:40] or 'SQLite (local)'}")
    for name, statements in MIGRATIONS:
        print(f"\n── {name} ──")
        for sql in statements:
            print(f"  {sql}")
            if not dry_run:
                _execute(db_url, sql)
    if dry_run:
        print("\nDry run complete — no changes made.")
    else:
        print("\nMigration complete.")

def _execute(db_url: str, sql: str) -> None:
    if db_url.startswith("postgresql"):
        import asyncio
        async def _pg() -> None:
            import asyncpg  # type: ignore
            conn = await asyncpg.connect(db_url.replace("postgresql+asyncpg://", "postgresql://"))
            try:
                await conn.execute(sql)
            except Exception as e:
                print(f"    WARN: {e}")
            finally:
                await conn.close()
        asyncio.run(_pg())
    else:
        import sqlite3, re
        path = re.sub(r"sqlite(\+aiosqlite)?:///", "", db_url) or "jercept.db"
        conn = sqlite3.connect(path)
        safe_sql = sql.replace(" IF NOT EXISTS", "")
        try:
            conn.execute(safe_sql)
            conn.commit()
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                print(f"    WARN: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    run(dry_run="--dry-run" in sys.argv)
