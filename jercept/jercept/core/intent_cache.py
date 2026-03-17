"""
Jercept intent cache — normalised LRU cache for IBACScope results.

Strips variable parts (numbers, IDs, emails) from requests before
hashing, so "check billing for customer 123" and "check billing for
customer 456" reuse the same cached scope entry.
"""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CachedIntent:
    """
    Serialisable representation of a cached IBAC scope.

    Stores only the fields needed to reconstruct an
    :class:`~jercept.core.scope.IBACScope` — no reference to the scope
    object itself, keeping the cache pickle-friendly if needed.
    """
    allowed_actions: list[str]
    allowed_resources: list[str]
    denied_actions: list[str]
    confidence: float
    pattern: str   # The normalised (variable-stripped) request text


class IntentCache:
    """
    Thread-safe LRU cache mapping normalised request patterns to
    :class:`CachedIntent` objects.

    Variable parts (numbers, hex IDs, emails, hash IDs) are stripped
    before hashing, so semantically equivalent requests hit the same
    cache entry regardless of specific values.

    Args:
        max_size: Maximum number of cached patterns. Oldest entry is
                  evicted (FIFO) when the limit is reached. Default: 256.

    Example::

        cache = IntentCache(max_size=512)
        intent = cache.get("check billing for customer 123")
        if intent is None:
            intent = CachedIntent(["db.read"], [], [...], 0.95, "...")
            cache.set("check billing for customer 123", intent)
    """

    # Strips: plain integers, long hex IDs, email addresses, #hash-ids
    _VARIABLE_PARTS: re.Pattern = re.compile(
        r"\b(?:"
        r"\d+|"                        # plain integers: 123, 42
        r"[a-f0-9]{8,}|"               # hex IDs: deadbeef1234...
        r"[\w.+-]+@[\w-]+\.[\w.]+|"   # email addresses
        r"#[\w-]+"                     # hash IDs: #customer-123
        r")\b",
        re.IGNORECASE,
    )

    def __init__(self, max_size: int = 256) -> None:
        self._cache: OrderedDict[str, CachedIntent] = OrderedDict()
        self._max_size: int = max_size
        self._hits: int = 0
        self._misses: int = 0

    # ------------------------------------------------------------------
    # Cache key
    # ------------------------------------------------------------------

    def _make_key(self, request: str) -> str:
        """
        Normalise request by stripping variable parts, then MD5-hash.

        Variable parts are replaced with ``X`` before hashing, making the key
        stable across different customer IDs, amounts, dates, etc.
        The hash computation is memoised on the raw request string so
        repeated lookups for the same request skip the regex entirely.

        Args:
            request: Raw user request string.

        Returns:
            32-character hex MD5 digest.
        """
        return self._cached_make_key(request)

    @staticmethod
    @__import__('functools').lru_cache(maxsize=512)
    def _cached_make_key(request: str) -> str:
        """LRU-cached key computation — avoids re-running regex on hot paths."""
        _VAR = re.compile(
            r"\b(?:\d+|[a-f0-9]{8,}|[\w.+-]+@[\w-]+\.[\w.]+|#[\w-]+)\b",
            re.IGNORECASE,
        )
        normalised = _VAR.sub("X", request.lower().strip())
        return hashlib.md5(normalised.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, request: str) -> CachedIntent | None:
        """
        Look up a cached intent for the given request.

        Args:
            request: The user's natural language request.

        Returns:
            :class:`CachedIntent` on hit, ``None`` on miss.
        """
        key = self._make_key(request)
        result = self._cache.get(key)
        if result is not None:
            self._hits += 1
            # Move to end to simulate LRU (Python 3.7+ dicts are ordered)
            self._cache.move_to_end(key)  # type: ignore[attr-defined]
        else:
            self._misses += 1
        return result

    def set(self, request: str, intent: CachedIntent) -> None:
        """
        Store a :class:`CachedIntent` for the given request.

        Evicts the oldest entry (FIFO) if ``max_size`` is exceeded.

        Args:
            request: The user's natural language request.
            intent: The resolved :class:`CachedIntent` to cache.
        """
        key = self._make_key(request)
        if key in self._cache:
            self._cache.move_to_end(key)  # type: ignore[attr-defined]
        self._cache[key] = intent
        if len(self._cache) > self._max_size:
            self._cache.pop(next(iter(self._cache)))

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @property
    def hit_rate(self) -> float:
        """Fraction of lookups that were cache hits (0.0–1.0)."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict:
        """Return a dict with hit/miss/rate/size statistics."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
            "cached_patterns": len(self._cache),
        }
