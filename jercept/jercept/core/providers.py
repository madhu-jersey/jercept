"""
Jercept LLM Provider abstraction.

Allows intent extraction to use any LLM backend — OpenAI, Anthropic Claude,
Google Gemini, or a local Ollama model. Enterprises with data residency
requirements can run Jercept entirely on-premise with Ollama.

Usage::

    from jercept import protect_agent

    # OpenAI (default)
    agent = protect_agent(my_agent)

    # Anthropic Claude
    agent = protect_agent(my_agent, llm_provider="anthropic",
                          model="claude-3-haiku-20240307")

    # Google Gemini
    agent = protect_agent(my_agent, llm_provider="gemini",
                          model="gemini-1.5-flash")

    # Local Ollama (no API key needed)
    agent = protect_agent(my_agent, llm_provider="ollama",
                          model="llama3")
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Shared extraction system prompt — used by all providers
EXTRACTION_SYSTEM_PROMPT: str = """You are a security policy engine for AI agents.
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
- Specific: customer#123, file#report.pdf
- Type wildcard: customer.*, billing.*
- Full wildcard: * (only when truly any resource needed)

AMBIGUITY RULE:
If the request does not clearly specify what data/resource is involved,
set ambiguous=true and allowed_actions=[] and confidence=0.0

CONFIDENCE SCORING:
0.9-1.0: Clear specific request with identifiable resource
0.7-0.9: Clear action but resource inferred
0.5-0.7: Action clear but resource ambiguous
below 0.5: Set ambiguous=true"""


class LLMProvider:
    """
    Abstract interface for LLM providers used in intent extraction.

    All providers accept a user request string and return a JSON string
    containing the extracted scope fields.
    """

    def extract_scope_json(self, user_request: str) -> str:
        """
        Call the LLM and return raw JSON string for scope extraction.

        Args:
            user_request: The user's natural language request.

        Returns:
            Raw JSON string (to be parsed by the caller).

        Raises:
            Exception: Any provider-specific API error.
        """
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    """
    OpenAI ChatCompletion provider (default).

    Supports all OpenAI models including gpt-4o-mini, gpt-4o, gpt-4-turbo.

    Args:
        model: OpenAI model name. Default: gpt-4o-mini.
        api_key: OpenAI API key. Falls back to OPENAI_API_KEY env var.
    """

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None) -> None:
        import openai as _openai
        self.model = model
        self._client = _openai.OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))

    def extract_scope_json(self, user_request: str) -> str:
        """Extract scope JSON using OpenAI Chat Completions (response_format=json_object)."""
        response = self._client.chat.completions.create(
            model=self.model,
            temperature=0.0,
            max_tokens=400,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
                {"role": "user", "content": user_request},
            ],
        )
        return response.choices[0].message.content or ""


class AsyncOpenAIProvider(LLMProvider):
    """Async OpenAI provider — non-blocking event loop."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None) -> None:
        import openai as _openai
        self.model = model
        self._client = _openai.AsyncOpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))

    async def extract_scope_json_async(self, user_request: str) -> str:
        """Async version — use this instead of extract_scope_json."""
        response = await self._client.chat.completions.create(
            model=self.model,
            temperature=0.0,
            max_tokens=400,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
                {"role": "user", "content": user_request},
            ],
        )
        return response.choices[0].message.content or ""

    def extract_scope_json(self, user_request: str) -> str:
        """Synchronous path — raises; use extract_scope_json_async() instead."""
        raise NotImplementedError("Use extract_scope_json_async() for async provider")


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude provider.

    Supports claude-3-haiku-20240307, claude-3-5-sonnet-20241022, and other
    Claude models. Requires the ``anthropic`` package:
    ``pip install jercept[anthropic]``

    Args:
        model: Anthropic model name. Default: claude-3-haiku-20240307.
        api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
    """

    def __init__(
        self,
        model: str = "claude-3-haiku-20240307",
        api_key: Optional[str] = None,
    ) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package required for AnthropicProvider. "
                "Install with: pip install jercept[anthropic]"
            ) from exc
        self.model = model
        self._client = _anthropic.Anthropic(
            api_key=api_key or os.getenv("ANTHROPIC_API_KEY")
        )

    def extract_scope_json(self, user_request: str) -> str:
        """Extract scope JSON via Anthropic Messages API (claude-3-haiku)."""
        message = self._client.messages.create(
            model=self.model,
            max_tokens=400,
            system=EXTRACTION_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_request}],
        )
        return message.content[0].text if message.content else ""


class GeminiProvider(LLMProvider):
    """
    Google Gemini provider.

    Supports gemini-1.5-flash, gemini-1.5-pro, and other Gemini models.
    Requires the ``google-generativeai`` package:
    ``pip install jercept[gemini]``

    Args:
        model: Gemini model name. Default: gemini-1.5-flash.
        api_key: Google API key. Falls back to GOOGLE_API_KEY env var.
    """

    def __init__(
        self,
        model: str = "gemini-1.5-flash",
        api_key: Optional[str] = None,
    ) -> None:
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ImportError(
                "google-generativeai package required for GeminiProvider. "
                "Install with: pip install jercept[gemini]"
            ) from exc
        key = api_key or os.getenv("GOOGLE_API_KEY")
        genai.configure(api_key=key)
        self.model = model
        self._genai = genai

    def extract_scope_json(self, user_request: str) -> str:
        """Extract scope JSON via Google Gemini generateContent API."""
        import google.generativeai as genai
        model = genai.GenerativeModel(
            self.model,
            system_instruction=EXTRACTION_SYSTEM_PROMPT,
        )
        response = model.generate_content(
            user_request,
            generation_config={"temperature": 0, "max_output_tokens": 400},
        )
        return response.text or ""


class OllamaProvider(LLMProvider):
    """
    Local Ollama provider — runs entirely on your machine, no API key needed.

    Perfect for air-gapped environments and enterprises with data residency
    requirements. Requires Ollama running locally (ollama.ai).

    Supports: llama3, mistral, phi3, gemma2, and any Ollama-compatible model.

    Args:
        model: Ollama model name. Default: llama3.
        base_url: Ollama server URL. Default: http://localhost:11434.
    """

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    def extract_scope_json(self, user_request: str) -> str:
        """Extract scope JSON via local Ollama (offline, no API key required)."""
        try:
            import httpx
        except ImportError as exc:
            raise ImportError("httpx required for OllamaProvider") from exc

        prompt = (
            f"{EXTRACTION_SYSTEM_PROMPT}\n\n"
            f"User request: {user_request}\n\n"
            "Return ONLY valid JSON:"
        )
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0, "num_predict": 400},
            },
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("response", "")


def get_provider(
    llm_provider: str = "openai",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> LLMProvider:
    """
    Factory function — return the correct LLMProvider for the given name.

    Args:
        llm_provider: One of "openai", "anthropic", "gemini", "ollama".
        model: Optional model override. Each provider has a sensible default.
        api_key: API key for the provider.
        **kwargs: Provider-specific kwargs (e.g., base_url for Ollama).

    Returns:
        An :class:`LLMProvider` instance ready for extraction.

    Raises:
        ValueError: If the provider name is not recognised.

    Example::

        provider = get_provider("anthropic", model="claude-3-haiku-20240307")
        provider = get_provider("ollama", model="llama3")
        provider = get_provider("openai")  # default
    """
    name = llm_provider.lower().strip()

    defaults = {
        "openai":    "gpt-4o-mini",
        "anthropic": "claude-3-haiku-20240307",
        "gemini":    "gemini-1.5-flash",
        "ollama":    "llama3",
    }

    if name not in defaults:
        raise ValueError(
            f"Unknown llm_provider {name!r}. "
            f"Valid options: {sorted(defaults.keys())}"
        )

    resolved_model = model or defaults[name]

    if name == "openai":
        return OpenAIProvider(model=resolved_model, api_key=api_key)
    if name == "anthropic":
        return AnthropicProvider(model=resolved_model, api_key=api_key)
    if name == "gemini":
        return GeminiProvider(model=resolved_model, api_key=api_key)
    if name == "ollama":
        base_url = kwargs.get("ollama_base_url", "http://localhost:11434")
        return OllamaProvider(model=resolved_model, base_url=base_url)

    raise ValueError(f"Unreachable: {name!r}")
