"""
Unit tests for IntentExtractor — all LLM calls are mocked.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from jercept.core.exceptions import IBACExtractionFailed
from jercept.core.extractor import IntentExtractor
from jercept.core.scope import IBACScope


def _make_openai_response(content: str) -> MagicMock:
    """Build a minimal mock that looks like an OpenAI ChatCompletion response."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def _good_payload(
    allowed_actions=None,
    allowed_resources=None,
    denied_actions=None,
    confidence=0.95,
    ambiguous=False,
    reasoning="Clear request.",
) -> str:
    return json.dumps(
        {
            "allowed_actions": allowed_actions or ["db.read"],
            "allowed_resources": allowed_resources or ["customer#123"],
            "denied_actions": denied_actions
            or ["db.export", "db.write", "db.delete", "code.execute"],
            "confidence": confidence,
            "ambiguous": ambiguous,
            "reasoning": reasoning,
        }
    )


@pytest.fixture()
def extractor():
    """An IntentExtractor with a mocked OpenAI client."""
    with patch("jercept.core.extractor.openai.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        inst = IntentExtractor(model="gpt-4o-mini", use_cache=False, use_fast_extract=False)
        inst._client = mock_client
        yield inst, mock_client


class TestSuccessfulExtraction:
    """Test 1: Clear request returns correct IBACScope."""

    def test_clear_request_returns_scope(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(
                allowed_actions=["db.read"],
                allowed_resources=["customer#123"],
                confidence=0.97,
            )
        )
        scope = inst.extract("check billing for customer 123")

        assert isinstance(scope, IBACScope)
        assert "db.read" in scope.allowed_actions
        assert "customer#123" in scope.allowed_resources
        assert scope.confidence == pytest.approx(0.97)
        assert scope.ambiguous is False
        assert scope.raw_intent == "check billing for customer 123"

    def test_scope_fields_populated(self, extractor):
        """Test 6: raw_intent, confidence, and ambiguous are all set correctly."""
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(confidence=0.88, ambiguous=False)
        )
        scope = inst.extract("send report to marketing")
        assert scope.raw_intent == "send report to marketing"
        assert scope.confidence == pytest.approx(0.88)
        assert scope.ambiguous is False


class TestAmbiguousRequest:
    """Test 2: Ambiguous request raises IBACExtractionFailed."""

    def test_ambiguous_flag_raises(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(ambiguous=True, confidence=0.0, allowed_actions=[])
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("help me")
        assert "ambiguous" in str(exc_info.value).lower()

    def test_ambiguous_message_includes_request(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(ambiguous=True, confidence=0.0, allowed_actions=[])
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("do the usual thing")
        # original_request attr is set
        assert exc_info.value.original_request == "do the usual thing"


class TestLowConfidence:
    """Test 3: Low confidence (< 0.5) raises IBACExtractionFailed."""

    def test_low_confidence_raises(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(confidence=0.3, ambiguous=False)
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("fix it")
        assert "confidence" in str(exc_info.value).lower()

    def test_exactly_at_threshold_passes(self, extractor):
        """confidence=0.5 is the boundary — should pass."""
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            _good_payload(confidence=0.5, ambiguous=False)
        )
        scope = inst.extract("read some customer data")
        assert scope.confidence == pytest.approx(0.5)


class TestAPIFailure:
    """Test 4: API failure raises IBACExtractionFailed."""

    def test_openai_api_error_raises(self, extractor):
        import openai

        inst, mock_client = extractor
        mock_client.chat.completions.create.side_effect = openai.APIError(
            message="server error", request=MagicMock(), body=None
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("check billing")
        assert exc_info.value.__cause__ is not None

    def test_auth_error_raises(self, extractor):
        import openai

        inst, mock_client = extractor
        mock_client.chat.completions.create.side_effect = openai.AuthenticationError(
            message="invalid key", response=MagicMock(), body=None
        )
        with pytest.raises(IBACExtractionFailed):
            inst.extract("check billing")

    def test_generic_exception_raises(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.side_effect = RuntimeError("network down")
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("check billing")
        assert "network down" in str(exc_info.value)


class TestInvalidJSON:
    """Test 5: Non-JSON LLM response raises IBACExtractionFailed."""

    def test_garbage_response_raises(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response(
            "Here is your answer: definitely not JSON!"
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("check billing")
        assert "JSON" in str(exc_info.value) or "json" in str(exc_info.value).lower()

    def test_missing_required_fields_raises(self, extractor):
        inst, mock_client = extractor
        # JSON but missing required fields
        mock_client.chat.completions.create.return_value = _make_openai_response(
            json.dumps({"allowed_actions": ["db.read"]})
        )
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("check billing")
        assert "missing" in str(exc_info.value).lower()

    def test_empty_string_response_raises(self, extractor):
        inst, mock_client = extractor
        mock_client.chat.completions.create.return_value = _make_openai_response("")
        with pytest.raises(IBACExtractionFailed):
            inst.extract("check billing")


class TestEmptyRequest:
    """Edge case: empty user request."""

    def test_empty_request_raises(self, extractor):
        inst, _ = extractor
        with pytest.raises(IBACExtractionFailed) as exc_info:
            inst.extract("")
        assert "empty" in str(exc_info.value).lower()
