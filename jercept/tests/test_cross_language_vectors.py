"""
Jercept cross-language test vectors — Python SDK.

Identical vectors to jercept-js/tests/cross_language_vectors.test.js.
Ensures scope.permits() behaves identically in both implementations.
"""
from __future__ import annotations
import sys, types
from unittest.mock import MagicMock
import pytest

stub = types.ModuleType("openai")
stub.OpenAI = MagicMock; stub.AsyncOpenAI = MagicMock
sys.modules.setdefault("openai", stub)

from jercept.core.scope import IBACScope

# Shared vectors — must match cross_language_vectors.test.js exactly
# (action, resource, allowed_actions, denied_actions, allowed_resources, expected)
VECTORS = [
    ("db.read",            "customer#123", ["db.read"],   [],            ["customer.*"], True),
    ("db.export",          None,           ["db.*"],      ["db.export"], [],             False),
    ("db.write",           None,           ["db.*"],      [],            [],             True),
    ("db.read",            "admin#1",      ["db.read"],   [],            ["customer.*"], False),
    ("DB.READ",            None,           ["db.read"],   [],            [],             True),
    (None,                 None,           ["db.read"],   [],            [],             False),
    ("",                   None,           ["db.read"],   [],            [],             False),
    ("   ",                None,           ["db.read"],   [],            [],             False),
    ("db.read;db.export",  None,           ["db.read"],   [],            [],             False),
    ("code.execute",       None,           ["db.read"],   [],            [],             False),
    ("db.delete",          "customer#123", ["db.*"],      ["db.delete"], ["customer.*"], False),
    ("db.read",            None,           [],            [],            [],             False),
]


@pytest.mark.parametrize("action,resource,allowed,denied,resources,expected", VECTORS)
def test_cross_language_vector(action, resource, allowed, denied, resources, expected):
    """Each vector must match the JS SDK's scope.permits() output exactly."""
    scope = IBACScope(
        allowed_actions=allowed,
        denied_actions=denied,
        allowed_resources=resources,
    )
    assert scope.permits(action, resource) == expected, (
        f"permits({action!r}, {resource!r}) with allowed={allowed} "
        f"denied={denied} resources={resources} → expected {expected}"
    )
