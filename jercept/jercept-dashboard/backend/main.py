"""
Jercept Dashboard — FastAPI application entry point.

sys.path is configured here so bare imports (from database import ...)
work whether uvicorn is run from the project root or from backend/.
"""
import sys as _sys
import os as _os

_BACKEND = _os.path.dirname(_os.path.abspath(__file__))
if _BACKEND not in _sys.path:
    _sys.path.insert(0, _BACKEND)

"""
Jercept Dashboard — FastAPI application entry point.

v1.0.0: Full scope visualizer, Railway deployment ready,
        static frontend serving, updated branding.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import init_db
from ratelimit import limiter
from routes.dashboard import router as dashboard_router
from routes.events import router as events_router
from routes.keys import router as keys_router
from routes.webhooks import router as webhooks_router

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Create database tables on startup if they don't exist."""
    await init_db()
    yield


app = FastAPI(
    title="Jercept Dashboard API",
    description="Real-time security monitoring for AI agents protected by Jercept IBAC.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# SEC FIX: CORS must never be wildcard in production.
# Set ALLOWED_ORIGINS env var: "https://app.jercept.com,https://jercept.com"
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# API routers
app.include_router(events_router)
app.include_router(dashboard_router)
app.include_router(keys_router)
app.include_router(webhooks_router)

# Serve frontend static files if directory exists
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index() -> FileResponse:
        """Serve the dashboard index page."""
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/dashboard")
    async def serve_dashboard() -> FileResponse:
        """Serve the main dashboard page."""
        return FileResponse(str(FRONTEND_DIR / "dashboard.html"))


@app.get("/health")
async def health() -> dict:
    """
    Service health check — used by Railway.app and load balancers.

    Also documents the API versioning strategy:
    - Current API version: v1 (all routes under /v1/)
    - Deprecation policy: 6-month notice via X-API-Deprecated header
    - Upgrade path: mount routes_v2/ at /v2/ in main.py when needed
    """
    return {
        "status":      "ok",
        "version":     "1.1.0",
        "api_version": "v1",
        "service":     "jercept-dashboard",
    }


@app.middleware("http")
async def add_api_version_header(request, call_next):
    """Attach X-API-Version header to every response for client awareness."""
    response = await call_next(request)
    response.headers["X-API-Version"] = "v1"
    response.headers["X-Jercept-Version"] = "1.1.0"
    return response
