"""Tests for IBACPolicy — enterprise action ceiling."""
from __future__ import annotations
import pytest
from jercept.policy import (IBACPolicy, READONLY_DB_POLICY,
    BILLING_AGENT_POLICY, SUPPORT_AGENT_POLICY, DEVOPS_AGENT_POLICY)
from jercept.core.scope import IBACScope

def make_scope(allowed, denied=None, resources=None):
    return IBACScope(allowed, resources or [], denied or [], 'test', 0.9, False)

class TestIBACPolicyCreation:
    def test_valid_policy_created(self):
        p = IBACPolicy(name="test", allowed_actions=["db.read"])
        assert p.name == "test"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="unknown action"):
            IBACPolicy(name="bad", allowed_actions=["invalid.action"])

    def test_glob_prefix_valid(self):
        p = IBACPolicy(name="t", allowed_actions=["db.*"])
        assert "db.*" in p.allowed_actions

    def test_unknown_glob_prefix_raises(self):
        with pytest.raises(ValueError):
            IBACPolicy(name="bad", allowed_actions=["xyz.*"])

    def test_wildcard_star_valid(self):
        p = IBACPolicy(name="t", allowed_actions=["*"])
        assert "*" in p.allowed_actions

    def test_to_dict_has_all_fields(self):
        p = IBACPolicy(name="t", allowed_actions=["db.read"],
                       denied_actions=["db.delete"], version="2.0")
        d = p.to_dict()
        assert d["name"] == "t"
        assert d["version"] == "2.0"
        assert "allowed_actions" in d

class TestIBACPolicyApply:
    def test_action_in_policy_kept(self):
        p = IBACPolicy(name="t", allowed_actions=["db.read"])
        scope = make_scope(["db.read", "email.send"])
        result = p.apply(scope)
        assert "db.read" in result.allowed_actions

    def test_action_not_in_policy_removed(self):
        p = IBACPolicy(name="t", allowed_actions=["db.read"])
        scope = make_scope(["db.read", "email.send"])
        result = p.apply(scope)
        assert "email.send" not in result.allowed_actions

    def test_policy_denied_added_to_scope(self):
        p = IBACPolicy(name="t", allowed_actions=["db.read"],
                       denied_actions=["db.delete"])
        scope = make_scope(["db.read"])
        result = p.apply(scope)
        assert "db.delete" in result.denied_actions

    def test_user_denied_preserved(self):
        p = IBACPolicy(name="t", allowed_actions=["db.*"])
        scope = make_scope(["db.read"], denied=["db.export"])
        result = p.apply(scope)
        assert "db.export" in result.denied_actions

    def test_glob_policy_allows_matching_actions(self):
        p = IBACPolicy(name="t", allowed_actions=["db.*"])
        scope = make_scope(["db.read", "db.write"])
        result = p.apply(scope)
        assert "db.read" in result.allowed_actions
        assert "db.write" in result.allowed_actions

    def test_policy_deny_overrides_glob_allow(self):
        p = IBACPolicy(name="t", allowed_actions=["db.*"],
                       denied_actions=["db.delete"])
        scope = make_scope(["db.read", "db.delete"])
        result = p.apply(scope)
        assert "db.read" in result.allowed_actions
        assert "db.delete" not in result.allowed_actions

    def test_raw_intent_preserved(self):
        p = IBACPolicy(name="t", allowed_actions=["db.read"])
        scope = IBACScope(["db.read"], [], [], "check billing", 0.9, False)
        result = p.apply(scope)
        assert result.raw_intent == "check billing"

class TestPrebuiltPolicies:
    def test_readonly_blocks_write(self):
        scope = make_scope(["db.read", "db.write"])
        result = READONLY_DB_POLICY.apply(scope)
        assert "db.write" not in result.allowed_actions

    def test_billing_blocks_code_execute(self):
        scope = make_scope(["db.read", "code.execute"])
        result = BILLING_AGENT_POLICY.apply(scope)
        assert "code.execute" not in result.allowed_actions

    def test_billing_allows_email_send(self):
        scope = make_scope(["db.read", "email.send"])
        result = BILLING_AGENT_POLICY.apply(scope)
        assert "email.send" in result.allowed_actions

    def test_devops_allows_code_execute(self):
        scope = make_scope(["file.read", "code.execute"])
        result = DEVOPS_AGENT_POLICY.apply(scope)
        assert "code.execute" in result.allowed_actions
