"""Tests for IBACScope wildcard warnings and DANGEROUS_ACTIONS."""
from __future__ import annotations
import logging
import pytest
from jercept.core.scope import IBACScope, DANGEROUS_ACTIONS, MAX_INPUT_LENGTH


def test_dangerous_actions_defined():
    assert "db.export" in DANGEROUS_ACTIONS
    assert "db.delete" in DANGEROUS_ACTIONS
    assert "code.execute" in DANGEROUS_ACTIONS
    assert "file.download" in DANGEROUS_ACTIONS


def test_max_input_length_defined():
    assert MAX_INPUT_LENGTH == 10_000


def test_wildcard_scope_warns_on_dangerous(caplog):
    with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
        IBACScope(
            allowed_actions=["db.*"],
            denied_actions=[],
        )
    assert "WARNING" in caplog.text or len(caplog.records) > 0


def test_wildcard_scope_no_warn_when_dangerous_denied(caplog):
    with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
        IBACScope(
            allowed_actions=["db.*"],
            denied_actions=["db.export", "db.delete", "code.execute", "file.download"],
        )
    dangerous_warnings = [
        r for r in caplog.records
        if "implicitly permits dangerous" in r.message
    ]
    assert len(dangerous_warnings) == 0


def test_specific_actions_no_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
        IBACScope(
            allowed_actions=["db.read", "email.send"],
            denied_actions=[],
        )
    assert len(caplog.records) == 0


def test_star_star_wildcard_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
        IBACScope(
            allowed_actions=["*"],
            denied_actions=[],
        )
    assert len(caplog.records) > 0


def test_permits_still_works_after_warning():
    scope = IBACScope(
        allowed_actions=["db.*"],
        denied_actions=[],
    )
    # db.read should be permitted
    assert scope.permits("db.read")
    # db.export is technically permitted by wildcard (warning issued but not blocked)
    assert scope.permits("db.export")


def test_permits_respects_explicit_deny_over_wildcard():
    scope = IBACScope(
        allowed_actions=["db.*"],
        denied_actions=["db.export"],
    )
    assert scope.permits("db.read")
    assert not scope.permits("db.export")


def test_scope_frozen_immutable():
    scope = IBACScope(allowed_actions=["db.read"])
    with pytest.raises((AttributeError, TypeError)):
        scope.allowed_actions = ["db.write"]  # type: ignore


def test_from_dict_roundtrip():
    scope = IBACScope(
        allowed_actions=["db.read"],
        allowed_resources=["customer.*"],
        denied_actions=["db.export"],
        raw_intent="check billing",
        confidence=0.95,
    )
    restored = IBACScope.from_dict(scope.to_dict())
    assert restored.allowed_actions == scope.allowed_actions
    assert restored.confidence == scope.confidence
    assert restored.raw_intent == scope.raw_intent
