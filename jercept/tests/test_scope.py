"""
Unit tests for IBACScope.permits() — covering all edge cases.
"""
from __future__ import annotations

import pytest

from jercept.core.scope import IBACScope


def make_scope(
    allowed_actions=None,
    allowed_resources=None,
    denied_actions=None,
    raw_intent="test request",
    confidence=0.9,
    ambiguous=False,
) -> IBACScope:
    """Helper to build an IBACScope with sensible defaults."""
    return IBACScope(
        allowed_actions=allowed_actions or [],
        allowed_resources=allowed_resources or [],
        denied_actions=denied_actions or [],
        raw_intent=raw_intent,
        confidence=confidence,
        ambiguous=ambiguous,
    )


class TestExactMatch:
    """Test 1: Exact action match."""

    def test_exact_match_permitted(self):
        scope = make_scope(allowed_actions=["db.read"])
        assert scope.permits("db.read") is True

    def test_exact_match_not_in_allowed(self):
        scope = make_scope(allowed_actions=["db.read"])
        assert scope.permits("db.write") is False


class TestWildcardMatch:
    """Tests 2–3: Glob wildcard action matching."""

    def test_wildcard_matches_subaction(self):
        """Test 2: db.* should match db.read."""
        scope = make_scope(allowed_actions=["db.*"])
        assert scope.permits("db.read") is True
        assert scope.permits("db.write") is True
        assert scope.permits("db.export") is True

    def test_wildcard_no_cross_namespace_match(self):
        """Test 3: db.* should NOT match code.execute."""
        scope = make_scope(allowed_actions=["db.*"])
        assert scope.permits("code.execute") is False
        assert scope.permits("email.send") is False
        assert scope.permits("file.read") is False


class TestExplicitDeny:
    """Test 4: Explicit deny takes priority over wildcard allow."""

    def test_deny_overrides_wildcard_allow(self):
        """Test 4: allowed=[db.*] + denied=[db.read] → False for db.read."""
        scope = make_scope(
            allowed_actions=["db.*"],
            denied_actions=["db.read"],
        )
        assert scope.permits("db.read") is False

    def test_deny_does_not_affect_other_actions(self):
        scope = make_scope(
            allowed_actions=["db.*"],
            denied_actions=["db.read"],
        )
        assert scope.permits("db.write") is True

    def test_deny_exact_in_exact_allowed(self):
        scope = make_scope(
            allowed_actions=["db.read"],
            denied_actions=["db.read"],
        )
        assert scope.permits("db.read") is False


class TestResourceMatching:
    """Tests 5–7: Resource-scoped permission checks."""

    def test_resource_exact_match(self):
        """Test 5: Exact resource match."""
        scope = make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer#123"],
        )
        assert scope.permits("db.read", "customer#123") is True

    def test_resource_mismatch(self):
        """Test 6: Wrong resource ID → denied."""
        scope = make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer#123"],
        )
        assert scope.permits("db.read", "customer#999") is False

    def test_resource_wildcard(self):
        """Test 7: customer.* matches any customer resource."""
        scope = make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer.*"],
        )
        assert scope.permits("db.read", "customer#999") is True
        assert scope.permits("db.read", "customer#001") is True

    def test_resource_wildcard_does_not_match_different_type(self):
        scope = make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer.*"],
        )
        assert scope.permits("db.read", "billing#001") is False

    def test_no_resource_constraint_when_resources_empty(self):
        """When allowed_resources is empty, any resource is allowed."""
        scope = make_scope(allowed_actions=["db.read"], allowed_resources=[])
        assert scope.permits("db.read", "anything#123") is True
        assert scope.permits("db.read") is True


class TestEmptyAllowed:
    """Test 8: Empty allowed list denies everything."""

    def test_empty_allowed_denies_any_action(self):
        """Test 8: allowed=[] → False for any action."""
        scope = make_scope(allowed_actions=[])
        assert scope.permits("db.read") is False
        assert scope.permits("email.send") is False
        assert scope.permits("code.execute") is False


class TestCaseInsensitive:
    """Test 9: Action matching is case-insensitive."""

    def test_uppercase_action_matches_lowercase_allowed(self):
        """Test 9: DB.READ should match db.read."""
        scope = make_scope(allowed_actions=["db.read"])
        assert scope.permits("DB.READ") is True
        assert scope.permits("Db.Read") is True
        # When allowed_resources is empty, any resource is accepted
        assert scope.permits("DB.READ", "customer#123") is True


    def test_uppercase_action_with_resource_and_wildcard(self):
        scope = make_scope(
            allowed_actions=["db.*"],
            allowed_resources=["customer.*"],
        )
        assert scope.permits("DB.READ", "CUSTOMER#123") is True


class TestToDict:
    """Test serialisation round-trip."""

    def test_to_dict_contains_all_fields(self):
        scope = make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer#123"],
            denied_actions=["db.export"],
            raw_intent="check billing for customer 123",
            confidence=0.97,
            ambiguous=False,
        )
        d = scope.to_dict()
        assert d["allowed_actions"] == ["db.read"]
        assert d["allowed_resources"] == ["customer#123"]
        assert d["denied_actions"] == ["db.export"]
        assert d["raw_intent"] == "check billing for customer 123"
        assert d["confidence"] == pytest.approx(0.97)
        assert d["ambiguous"] is False
