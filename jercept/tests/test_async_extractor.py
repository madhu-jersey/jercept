"""
Tests for jercept.core.extractor.AsyncIntentExtractor — v0.4.0.

Uses mocked OpenAI AsyncClient so no real API calls are made.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jercept.core.extractor import AsyncIntentExtractor
from jercept.core.scope import IBACScope
from jercept.core.exceptions import IBACExtractionFailed


def _make_async_client(response_json: dict):
    """Build a mock AsyncOpenAI client that returns the given JSON."""
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(response_json)

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    mock_completions = MagicMock()
    mock_completions.create = AsyncMock(return_value=mock_response)

    mock_chat = MagicMock()
    mock_chat.completions = mock_completions

    mock_client = MagicMock()
    mock_client.chat = mock_chat
    return mock_client


VALID_RESPONSE = {
    "allowed_actions": ["db.read"],
    "allowed_resources": ["customer#123"],
    "denied_actions": ["db.export", "db.write", "db.delete"],
    "confidence": 0.97,
    "ambiguous": False,
    "reasoning": "User wants to read one customer billing record",
}


class TestAsyncExtractorInit:
    def test_default_model(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
            assert extractor.model == "gpt-4o-mini"

    def test_cache_enabled_by_default(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
            assert extractor._cache is not None

    def test_cache_disabled(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor(use_cache=False)
            assert extractor._cache is None

    def test_fast_extract_enabled_by_default(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
            assert extractor._use_fast is True


class TestAsyncExtractCacheTier:
    """Cache tier returns immediately without LLM calls."""

    async def test_cache_hit_returns_scope(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()

        from jercept.core.intent_cache import CachedIntent
        extractor._cache.set(
            "check billing for customer 123",
            CachedIntent(
                allowed_actions=["db.read"],
                allowed_resources=["customer#123"],
                denied_actions=["db.export"],
                confidence=0.95,
                pattern="check billing for customer X",
            ),
        )
        scope = await extractor.extract("check billing for customer 123")
        assert isinstance(scope, IBACScope)
        assert "db.read" in scope.allowed_actions

    async def test_cache_hit_does_not_call_llm(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor()

        from jercept.core.intent_cache import CachedIntent
        extractor._cache.set(
            "check billing for customer 999",
            CachedIntent(
                allowed_actions=["db.read"],
                allowed_resources=[],
                denied_actions=[],
                confidence=0.9,
                pattern="check billing for customer X",
            ),
        )
        await extractor.extract("check billing for customer 999")
        mock_client.chat.completions.create.assert_not_called()


class TestAsyncExtractFastTier:
    """Fast regex tier bypasses LLM for known patterns."""

    async def test_billing_hits_fast_tier(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False)

        scope = await extractor.extract("check billing for customer 123")
        assert scope is not None
        assert "db.read" in scope.allowed_actions
        mock_client.chat.completions.create.assert_not_called()

    async def test_email_send_hits_fast_tier(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False)

        scope = await extractor.extract("send email to the team")
        assert "email.send" in scope.allowed_actions
        mock_client.chat.completions.create.assert_not_called()


class TestAsyncExtractLLMTier:
    """LLM tier: used when cache and fast regex both miss."""

    async def test_llm_called_for_unknown_request(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = _make_async_client(VALID_RESPONSE)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        scope = await extractor.extract("help me with something unclear")
        assert isinstance(scope, IBACScope)
        assert "db.read" in scope.allowed_actions

    async def test_returns_ibac_scope(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = _make_async_client(VALID_RESPONSE)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        scope = await extractor.extract("do something with customer 123")
        assert isinstance(scope, IBACScope)
        assert scope.confidence == 0.97

    async def test_raw_intent_preserved(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = _make_async_client(VALID_RESPONSE)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        req = "do something with customer 123"
        scope = await extractor.extract(req)
        assert scope.raw_intent == req


class TestAsyncExtractFailures:
    """Error cases must raise IBACExtractionFailed, never raw exceptions."""

    async def test_empty_request_raises(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
        with pytest.raises(IBACExtractionFailed, match="empty"):
            await extractor.extract("")

    async def test_whitespace_only_raises(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
        with pytest.raises(IBACExtractionFailed):
            await extractor.extract("   ")

    async def test_api_failure_raises_ibac_error(self):
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(
                side_effect=Exception("API connection failed")
            )
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        with pytest.raises(IBACExtractionFailed):
            await extractor.extract("do something")

    async def test_ambiguous_raises(self):
        ambiguous_response = {
            "allowed_actions": [],
            "allowed_resources": [],
            "denied_actions": [],
            "confidence": 0.0,
            "ambiguous": True,
            "reasoning": "Too vague",
        }
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = _make_async_client(ambiguous_response)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        with pytest.raises(IBACExtractionFailed, match="ambiguous"):
            await extractor.extract("do the thing")

    async def test_low_confidence_raises(self):
        low_conf = {**VALID_RESPONSE, "confidence": 0.2, "ambiguous": False}
        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = _make_async_client(low_conf)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        with pytest.raises(IBACExtractionFailed):
            await extractor.extract("something")

    async def test_invalid_json_raises(self):
        mock_choice = MagicMock()
        mock_choice.message.content = "not json at all"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        with patch("openai.AsyncOpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client
            extractor = AsyncIntentExtractor(use_cache=False, use_fast_extract=False)

        with pytest.raises(IBACExtractionFailed, match="non-JSON"):
            await extractor.extract("something unclear here")


class TestAsyncExtractorCacheStats:
    def test_cache_stats_returns_dict(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor()
        stats = extractor.cache_stats
        assert isinstance(stats, dict)
        assert "hits" in stats
        assert "misses" in stats

    def test_cache_stats_empty_when_disabled(self):
        with patch("openai.AsyncOpenAI"):
            extractor = AsyncIntentExtractor(use_cache=False)
        assert extractor.cache_stats == {}
