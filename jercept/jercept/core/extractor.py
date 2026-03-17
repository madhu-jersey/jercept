"""
Jercept IntentExtractor module.

Converts a user's natural language request into an IBACScope via a single
structured LLM call. This is the brain of the IBAC system — it determines
the minimal permission set needed to safely fulfil the user's intent.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import openai

from jercept.core.exceptions import IBACExtractionFailed
from jercept.core.scope import IBACScope, MIN_CONFIDENCE_THRESHOLD

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_MODEL: str = "gpt-4o-mini"
EXTRACTION_TEMPERATURE: float = 0.0
EXTRACTION_MAX_TOKENS: int = 400

SYSTEM_PROMPT: str = """You are a security policy engine for AI agents.
Given a user's natural language request, extract the minimal
permission scope needed to fulfill it safely.

SECURITY PRINCIPLE: Deny everything not explicitly required.
Default to the most restrictive scope possible.

Return ONLY valid JSON, no explanation, no markdown:
{
  "allowed_actions": ["db.read"],
  "allowed_resources": ["customer#123"],
  "denied_actions": ["db.export", "db.write", "db.delete", 
                     "file.write", "file.download", "code.execute",
                     "email.send", "web.browse"],
  "confidence": 0.95,
  "ambiguous": false,
  "reasoning": "One sentence: why this scope was chosen"
}

ACTION TAXONOMY:
db.read, db.write, db.export, db.delete
file.read, file.write, file.upload, file.download
email.read, email.send
api.call, web.browse, code.execute

RESOURCE FORMAT:
- Specific resource: customer#123, file#report.pdf, table#billing
- Type wildcard: customer.*, billing.*, email.*
- Full wildcard: * (only when truly any resource is acceptable)

AMBIGUITY RULE:
If the request does not clearly specify what data/resource is involved,
set ambiguous=true and allowed_actions=[] and confidence=0.0
Examples of ambiguous: "help me", "do the usual thing", "fix it",
"clean up the records", "send a message"

CONFIDENCE SCORING:
0.9-1.0: Clear specific request with identifiable resource
0.7-0.9: Clear action but resource inferred
0.5-0.7: Action clear but resource ambiguous  
below 0.5: Set ambiguous=true

EXAMPLES:
"check billing for customer 123"
→ allowed: [db.read], resources: [customer#123], denied: [db.export,db.write,db.delete,...], confidence: 0.97

"send the monthly report to the marketing team"
→ allowed: [email.send, file.read], resources: [email.marketing_team, report.*], confidence: 0.82

"help me with John's account"
→ ambiguous: true, allowed_actions: [], confidence: 0.0"""

# Required fields in the LLM JSON response
_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"allowed_actions", "allowed_resources", "denied_actions", "confidence", "ambiguous"}
)


class IntentExtractor:
    """
    Extracts a minimal IBAC permission scope from a user's natural language request.

    Uses a 3-tier pipeline for performance and reliability:
    1. Check LRU cache (0ms)
    2. Try fast regex extraction (1-5ms)
    3. Fall back to LLM call via configured provider (~200ms)

    Supports OpenAI, Anthropic Claude, Google Gemini, and local Ollama.

    Example::

        >>> extractor = IntentExtractor()                    # OpenAI default
        >>> extractor = IntentExtractor(llm_provider="anthropic")
        >>> extractor = IntentExtractor(llm_provider="ollama", model="llama3")
        >>> scope = extractor.extract("check billing for customer 123")
        >>> scope.allowed_actions
        ['db.read']
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: Optional[str] = None,
        use_cache: bool = True,
        use_fast_extract: bool = True,
        llm_provider: str = "openai",
        **provider_kwargs: Any,
    ) -> None:
        """
        Initialise the extractor with a provider and 3-tier pipeline.

        Args:
            model: LLM model name (provider-specific default if not given).
            api_key: API key for the provider.
            use_cache: Whether to use the LRU intent cache (default: True).
            use_fast_extract: Whether to try regex before LLM (default: True).
            llm_provider: One of "openai", "anthropic", "gemini", "ollama".
            **provider_kwargs: Extra kwargs forwarded to the provider
                (e.g., ollama_base_url="http://localhost:11434").
        """
        from jercept.core.providers import get_provider
        self.model = model
        self._provider = get_provider(
            llm_provider=llm_provider,
            model=model if model != DEFAULT_MODEL else None,
            api_key=api_key,
            **provider_kwargs,
        )
        self._use_fast = use_fast_extract

        if use_cache:
            from jercept.core.intent_cache import IntentCache
            self._cache: Optional[IntentCache] = IntentCache()
        else:
            self._cache = None

    def extract(self, user_request: str) -> IBACScope:
        """
        Extract an :class:`IBACScope` from a user's natural language request.

        Tries cache, then fast regex, then falls back to LLM.

        Args:
            user_request: The raw string the user sent to the agent.

        Returns:
            An :class:`IBACScope` representing the minimal safe permissions.
        """
        if not user_request or not user_request.strip():
            raise IBACExtractionFailed(
                reason="User request is empty — cannot derive a safe scope",
                original_request=user_request,
            )

        # ── Tier 1: Cache check ──────────────────────────────────────────────
        if self._cache is not None:
            assert self._cache is not None  # type narrowing
            from jercept.core.intent_cache import CachedIntent
            cached = self._cache.get(user_request)
            if cached:
                return IBACScope(
                    allowed_actions=cached.allowed_actions,
                    allowed_resources=cached.allowed_resources,
                    denied_actions=cached.denied_actions,
                    raw_intent=user_request,
                    confidence=cached.confidence,
                    ambiguous=False,
                )

        # ── Tier 2: Fast regex extraction ────────────────────────────────────
        if self._use_fast:
            from jercept.core.fast_extractor import try_fast_extract
            fast_scope = try_fast_extract(user_request)
            if fast_scope is not None:
                # Store in cache for next time
                if self._cache is not None:
                    assert self._cache is not None
                    from jercept.core.intent_cache import CachedIntent
                    self._cache.set(user_request, CachedIntent(
                        allowed_actions=fast_scope.allowed_actions,
                        allowed_resources=fast_scope.allowed_resources,
                        denied_actions=fast_scope.denied_actions,
                        confidence=fast_scope.confidence,
                        pattern=user_request,
                    ))
                # Add marker to raw_intent for auditing
                return IBACScope(
                    allowed_actions=fast_scope.allowed_actions,
                    allowed_resources=fast_scope.allowed_resources,
                    denied_actions=fast_scope.denied_actions,
                    raw_intent=user_request,
                    confidence=fast_scope.confidence,
                    ambiguous=fast_scope.ambiguous,
                )

        # ── Tier 3: LLM fallback ─────────────────────────────────────────────
        return self._llm_extract(user_request)

    def _llm_extract(self, user_request: str) -> IBACScope:
        """LLM-based extraction via configured provider. Retries on transient errors."""
        last_exc: Optional[Exception] = None
        max_retries = 3

        for attempt in range(max_retries):
            try:
                raw_content = self._provider.extract_scope_json(user_request)
                break
            except Exception as exc:
                last_exc = exc
                exc_type = type(exc).__name__
                # Don't retry auth errors — they won't resolve
                if "Auth" in exc_type or "authentication" in str(exc).lower():
                    raise IBACExtractionFailed(
                        reason="Authentication failed — check your API key",
                        original_request=user_request,
                        cause=exc,
                    ) from exc
                if attempt < max_retries - 1:
                    import time
                    wait = 0.5 * (2 ** attempt)  # 0.5s, 1s, 2s
                    logger.warning(
                        "LLM extraction attempt %d/%d failed (%s), retrying in %.1fs",
                        attempt + 1, max_retries, exc_type, wait,
                    )
                    time.sleep(wait)
        else:
            raise IBACExtractionFailed(
                reason=f"LLM call failed after {max_retries} attempts: {last_exc}",
                original_request=user_request,
                cause=last_exc,
            )

        raw_content = (raw_content or "").strip()

        # Strip markdown fences if provider wrapped JSON in them
        if raw_content.startswith("```"):
            raw_content = raw_content.split("```")[1]
            if raw_content.startswith("json"):
                raw_content = raw_content[4:]
            raw_content = raw_content.strip()

        try:
            data: Dict[str, Any] = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            raise IBACExtractionFailed(
                reason=f"LLM returned non-JSON response: {raw_content[:200]!r}",
                original_request=user_request,
                cause=exc,
            ) from exc

        missing = _REQUIRED_FIELDS - data.keys()
        if missing:
            raise IBACExtractionFailed(
                reason=f"LLM response missing required fields: {sorted(missing)}",
                original_request=user_request,
            )

        confidence: float = float(data.get("confidence", 0.0))
        ambiguous: bool = bool(data.get("ambiguous", False))

        if ambiguous or confidence < MIN_CONFIDENCE_THRESHOLD:
            reasoning = data.get("reasoning", "no reasoning provided")
            raise IBACExtractionFailed(
                reason=(
                    f"Request is too ambiguous to generate a safe scope "
                    f"(confidence={confidence:.2f}, ambiguous={ambiguous}). "
                    f"Reasoning: {reasoning}"
                ),
                original_request=user_request,
            )

        logger.debug(
            "Extracted scope for %r — confidence=%.2f actions=%s",
            user_request[:60],
            confidence,
            data.get("allowed_actions", []),
        )

        scope = IBACScope(
            allowed_actions=list(data.get("allowed_actions", [])),
            allowed_resources=list(data.get("allowed_resources", [])),
            denied_actions=list(data.get("denied_actions", [])),
            raw_intent=user_request,
            confidence=confidence,
            ambiguous=False,
        )

        # HIGH 1 FIX: Cross-validate LLM output against fast extractor.
        # If fast extractor matched this request but LLM returned dangerous
        # extras, strip them — defence against jailbroken/compromised LLM.
        try:
            from jercept.core.fast_extractor import (
                try_fast_extract, _FAST_EXTRACTOR_FORBIDDEN
            )
            fast_scope = try_fast_extract(user_request)
            if fast_scope is not None:
                llm_extras = [
                    a for a in scope.allowed_actions
                    if a in _FAST_EXTRACTOR_FORBIDDEN
                    and a not in fast_scope.allowed_actions
                ]
                if llm_extras:
                    logger.warning(
                        "LLM granted dangerous extras %s vs fast extractor %s "
                        "for %r — stripping (possible LLM jailbreak).",
                        llm_extras, list(fast_scope.allowed_actions), user_request[:60],
                    )
                    scope = IBACScope(
                        allowed_actions=[
                            a for a in scope.allowed_actions if a not in llm_extras
                        ],
                        allowed_resources=list(scope.allowed_resources),
                        denied_actions=list(scope.denied_actions) + llm_extras,
                        raw_intent=user_request,
                        confidence=confidence,
                        ambiguous=False,
                    )
        except Exception:
            pass  # cross-validation is best-effort — never breaks extraction

        if self._cache is not None:
            from jercept.core.intent_cache import CachedIntent
            self._cache.set(user_request, CachedIntent(
                allowed_actions=scope.allowed_actions,
                allowed_resources=scope.allowed_resources,
                denied_actions=scope.denied_actions,
                confidence=scope.confidence,
                pattern=user_request,
            ))

        return scope

    @property
    def cache_stats(self) -> dict:
        """Return cache hit/miss statistics."""
        if self._cache is not None:
            assert self._cache is not None
            return self._cache.stats
        return {}


# ---------------------------------------------------------------------------
# AsyncIntentExtractor — non-blocking extraction for production deployments
# ---------------------------------------------------------------------------

class AsyncIntentExtractor:
    """
    Async version of :class:`IntentExtractor` using ``openai.AsyncOpenAI``.

    Identical 3-tier pipeline (cache → fast regex → LLM) but the LLM call
    is a native ``await`` — it does NOT block the asyncio event loop.

    Use this in production async deployments (FastAPI, aiohttp, asyncio agents)
    to avoid the 200–400ms blocking window of the synchronous client.

    Example::

        extractor = AsyncIntentExtractor()
        scope = await extractor.extract("check billing for customer 123")
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: Optional[str] = None,
        use_cache: bool = True,
        use_fast_extract: bool = True,
    ) -> None:
        import openai as _openai
        self.model = model
        self._client = _openai.AsyncOpenAI(api_key=api_key) if api_key else _openai.AsyncOpenAI()
        self._use_fast = use_fast_extract

        if use_cache:
            from jercept.core.intent_cache import IntentCache
            self._cache: Optional[Any] = IntentCache()
        else:
            self._cache = None

    async def extract(self, user_request: str) -> IBACScope:
        """
        Async version of :meth:`IntentExtractor.extract`.

        Same 3-tier pipeline. The LLM fallback is a native coroutine —
        no event loop blocking.

        Args:
            user_request: The raw user request string.

        Returns:
            An :class:`IBACScope` with minimal safe permissions.

        Raises:
            IBACExtractionFailed: On API failure, invalid JSON, or ambiguity.
        """
        if not user_request or not user_request.strip():
            raise IBACExtractionFailed(
                reason="User request is empty — cannot derive a safe scope",
                original_request=user_request,
            )

        # Tier 1: Cache
        if self._cache is not None:
            from jercept.core.intent_cache import CachedIntent
            cached = self._cache.get(user_request)
            if cached:
                return IBACScope(
                    allowed_actions=cached.allowed_actions,
                    allowed_resources=cached.allowed_resources,
                    denied_actions=cached.denied_actions,
                    raw_intent=user_request,
                    confidence=cached.confidence,
                    ambiguous=False,
                )

        # Tier 2: Fast regex
        if self._use_fast:
            from jercept.core.fast_extractor import try_fast_extract
            from jercept.core.intent_cache import CachedIntent
            fast_scope = try_fast_extract(user_request)
            if fast_scope is not None:
                if self._cache is not None:
                    self._cache.set(user_request, CachedIntent(
                        allowed_actions=fast_scope.allowed_actions,
                        allowed_resources=fast_scope.allowed_resources,
                        denied_actions=fast_scope.denied_actions,
                        confidence=fast_scope.confidence,
                        pattern=user_request,
                    ))
                return IBACScope(
                    allowed_actions=fast_scope.allowed_actions,
                    allowed_resources=fast_scope.allowed_resources,
                    denied_actions=fast_scope.denied_actions,
                    raw_intent=user_request,
                    confidence=fast_scope.confidence,
                    ambiguous=fast_scope.ambiguous,
                )

        # Tier 3: Async LLM
        return await self._async_llm_extract(user_request)

    async def _async_llm_extract(self, user_request: str) -> IBACScope:
        """Non-blocking LLM extraction using AsyncOpenAI client."""
        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                temperature=EXTRACTION_TEMPERATURE,
                max_tokens=EXTRACTION_MAX_TOKENS,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_request},
                ],
            )
        except Exception as exc:
            reason = f"Async LLM call failed: {exc}"
            exc_type = type(exc).__name__
            if "Auth" in exc_type:
                reason = "OpenAI authentication failed — check your API key"
            elif "RateLimit" in exc_type:
                reason = "OpenAI rate limit exceeded — retry after a moment"
            raise IBACExtractionFailed(
                reason=reason,
                original_request=user_request,
                cause=exc,
            ) from exc

        raw_content: str = (response.choices[0].message.content or "").strip()

        try:
            data: Dict[str, Any] = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            raise IBACExtractionFailed(
                reason=f"LLM returned non-JSON response: {raw_content[:200]!r}",
                original_request=user_request,
                cause=exc,
            ) from exc

        missing = _REQUIRED_FIELDS - data.keys()
        if missing:
            raise IBACExtractionFailed(
                reason=f"LLM response missing required fields: {sorted(missing)}",
                original_request=user_request,
            )

        confidence: float = float(data.get("confidence", 0.0))
        ambiguous: bool = bool(data.get("ambiguous", False))

        if ambiguous or confidence < MIN_CONFIDENCE_THRESHOLD:
            raise IBACExtractionFailed(
                reason=(
                    f"Request too ambiguous (confidence={confidence:.2f}, "
                    f"ambiguous={ambiguous}). "
                    f"Reasoning: {data.get('reasoning', 'none')}"
                ),
                original_request=user_request,
            )

        scope = IBACScope(
            allowed_actions=list(data.get("allowed_actions", [])),
            allowed_resources=list(data.get("allowed_resources", [])),
            denied_actions=list(data.get("denied_actions", [])),
            raw_intent=user_request,
            confidence=confidence,
            ambiguous=False,
        )

        if self._cache is not None:
            from jercept.core.intent_cache import CachedIntent
            self._cache.set(user_request, CachedIntent(
                allowed_actions=scope.allowed_actions,
                allowed_resources=scope.allowed_resources,
                denied_actions=scope.denied_actions,
                confidence=scope.confidence,
                pattern=user_request,
            ))

        return scope

    @property
    def cache_stats(self) -> dict:
        """Return cache hit/miss statistics."""
        if self._cache is not None:
            return self._cache.stats
        return {}

