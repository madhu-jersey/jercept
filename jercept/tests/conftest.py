"""
Jercept test suite — shared pytest fixtures and configuration.

Run the full suite:
    pytest tests/ -v

Run a specific layer:
    pytest tests/test_scope.py -v
    pytest tests/test_security_fixes.py -v

Run with coverage:
    pytest tests/ --cov=jercept --cov-report=term-missing
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Global OpenAI stub — installed once for the entire test session.
# This prevents "No module named 'openai'" errors in any test file.
# ---------------------------------------------------------------------------

def _make_openai_stub() -> types.ModuleType:
    stub = types.ModuleType("openai")
    stub.OpenAI       = lambda **k: MagicMock()
    stub.AsyncOpenAI  = lambda **k: MagicMock()
    return stub


# Install the stub before any test module is imported
if "openai" not in sys.modules:
    sys.modules["openai"] = _make_openai_stub()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def openai_stub():
    """Return the installed OpenAI stub for tests that need to inspect it."""
    return sys.modules["openai"]


@pytest.fixture
def base_scope():
    """A minimal valid IBACScope for use in tests."""
    from jercept.core.scope import IBACScope
    return IBACScope(
        allowed_actions=("db.read",),
        denied_actions=("db.export", "db.delete", "code.execute", "file.download"),
        allowed_resources=("customer.*",),
        raw_intent="check billing for customer 123",
        confidence=0.95,
    )


@pytest.fixture
def enforcer(base_scope):
    """An IBACEnforcer initialised with base_scope."""
    from jercept.core.enforcer import IBACEnforcer
    return IBACEnforcer(base_scope)


@pytest.fixture
def billing_policy():
    """The standard billing agent policy for integration tests."""
    from jercept.policy import IBACPolicy
    return IBACPolicy(
        name="billing-readonly",
        allowed_actions=["db.read", "email.send"],
        denied_actions=["db.export", "db.delete", "code.execute", "file.download", "db.write"],
        allowed_resources=["customer.*", "billing.*"],
        description="Billing support agent — read-only access",
        version="1.0",
    )


@pytest.fixture
def confirm_session(billing_policy):
    """A ConversationScope in CONFIRM mode with billing policy."""
    from jercept.core.conversation import ConversationScope, ExpansionMode
    return ConversationScope(
        initial_request="check billing",
        policy=billing_policy,
        expansion_mode=ExpansionMode.CONFIRM,
        max_turns=10,
    )


@pytest.fixture
def mock_extractor():
    """An IntentExtractor with a mock provider that returns a safe db.read scope."""
    import json
    from jercept.core.extractor import IntentExtractor

    class _MockProvider:
        def extract_scope_json(self, request: str) -> str:
            return json.dumps({
                "allowed_actions": ["db.read"],
                "allowed_resources": ["customer.*"],
                "denied_actions": [
                    "db.export", "db.delete", "db.write",
                    "code.execute", "file.download", "email.send",
                ],
                "confidence": 0.95,
                "ambiguous": False,
                "reasoning": "Mock: read-only billing scope",
            })

    ext = IntentExtractor(use_cache=False, use_fast_extract=False)
    ext._provider = _MockProvider()
    return ext
