"""Tests for jercept.core.providers - multi-LLM provider abstraction."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch


class TestGetProvider:
    def test_openai_default(self):
        from jercept.core.providers import get_provider, OpenAIProvider
        import types
        stub = types.ModuleType("openai")
        stub.OpenAI = lambda **k: MagicMock()
        stub.AsyncOpenAI = lambda **k: MagicMock()
        with patch.dict("sys.modules", {"openai": stub}):
            p = get_provider("openai")
            assert isinstance(p, OpenAIProvider)

    def test_openai_explicit_model(self):
        from jercept.core.providers import get_provider, OpenAIProvider
        import types
        stub = types.ModuleType("openai")
        stub.OpenAI = lambda **k: MagicMock()
        stub.AsyncOpenAI = lambda **k: MagicMock()
        with patch.dict("sys.modules", {"openai": stub}):
            p = get_provider("openai", model="gpt-4o")
            assert p.model == "gpt-4o"

    def test_unknown_provider_raises(self):
        from jercept.core.providers import get_provider
        with pytest.raises(ValueError, match="Unknown llm_provider"):
            get_provider("nonexistent")

    def test_case_insensitive(self):
        from jercept.core.providers import get_provider, OpenAIProvider
        import types
        stub = types.ModuleType("openai")
        stub.OpenAI = lambda **k: MagicMock()
        stub.AsyncOpenAI = lambda **k: MagicMock()
        with patch.dict("sys.modules", {"openai": stub}):
            p = get_provider("OpenAI")
            assert isinstance(p, OpenAIProvider)

    def test_anthropic_missing_package_raises(self):
        from jercept.core.providers import AnthropicProvider
        with patch.dict("sys.modules", {"anthropic": None}):
            with pytest.raises(ImportError, match="anthropic package"):
                AnthropicProvider()

    def test_gemini_missing_package_raises(self):
        from jercept.core.providers import GeminiProvider
        with pytest.raises(ImportError):
            GeminiProvider()

    def test_ollama_defaults(self):
        from jercept.core.providers import OllamaProvider
        p = OllamaProvider(model="llama3")
        assert p.base_url == "http://localhost:11434"
        assert p.model == "llama3"

    def test_ollama_custom_url(self):
        from jercept.core.providers import OllamaProvider
        p = OllamaProvider(base_url="http://10.0.0.1:11434/")
        assert not p.base_url.endswith("/")

    def test_ollama_via_get_provider(self):
        from jercept.core.providers import get_provider, OllamaProvider
        p = get_provider("ollama", model="phi3", ollama_base_url="http://0.0.0.0:11434")
        assert isinstance(p, OllamaProvider)
        assert p.model == "phi3"

    def test_ollama_extract_calls_httpx(self):
        from jercept.core.providers import OllamaProvider
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": '{"allowed_actions":["db.read"]}'}
        mock_response.raise_for_status = MagicMock()
        with patch("httpx.post", return_value=mock_response) as mock_post:
            p = OllamaProvider(model="llama3")
            result = p.extract_scope_json("check billing")
            assert "db.read" in result
            mock_post.assert_called_once()

    def test_openai_temperature_zero(self):
        import types
        stub = types.ModuleType("openai")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"allowed_actions":[]}'
        mock_client.chat.completions.create.return_value = mock_response
        stub.OpenAI = lambda **k: mock_client
        stub.AsyncOpenAI = lambda **k: MagicMock()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.core.providers import OpenAIProvider
            p = OpenAIProvider()
            p.extract_scope_json("test")
            call_kwargs = mock_client.chat.completions.create.call_args[1]
            assert call_kwargs.get("temperature") == 0.0

    def test_prompt_contains_all_actions(self):
        from jercept.core.providers import EXTRACTION_SYSTEM_PROMPT
        for action in ["db.read", "db.write", "db.export", "db.delete",
                       "file.read", "file.write", "email.read", "email.send",
                       "api.call", "web.browse", "code.execute"]:
            assert action in EXTRACTION_SYSTEM_PROMPT

    def test_prompt_security_principle(self):
        from jercept.core.providers import EXTRACTION_SYSTEM_PROMPT
        assert "SECURITY PRINCIPLE" in EXTRACTION_SYSTEM_PROMPT
