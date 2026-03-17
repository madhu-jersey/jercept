"""
CSM Dashboard — shared rate limiter instance.

Imported by main.py (to attach to app) and by individual routes
(to apply @limiter.limit decorators). Centralising here avoids
circular imports between main.py and the route modules.
"""
from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _key_from_auth_header(request: Request) -> str:
    """
    Rate-limit key: first 16 chars of the Bearer token.

    This buckets requests per API key rather than per IP, preventing
    one compromised key from consuming another customer's quota.
    Falls back to remote IP for unauthenticated endpoints.
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()[:16]
    return get_remote_address(request)


# Single shared limiter — imported by main.py and all route files.
limiter = Limiter(key_func=_key_from_auth_header, default_limits=[])
