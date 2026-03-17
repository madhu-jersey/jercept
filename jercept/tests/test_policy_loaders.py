"""
Tests for IBACPolicy.from_dict() and IBACPolicy.from_yaml() — v0.4.0.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from jercept.policy import IBACPolicy, BILLING_AGENT_POLICY


class TestFromDict:
    """IBACPolicy.from_dict() — round-trips and error handling."""

    def test_round_trip_to_dict_and_back(self):
        original = BILLING_AGENT_POLICY
        d = original.to_dict()
        restored = IBACPolicy.from_dict(d)
        assert restored.name == original.name
        assert restored.allowed_actions == original.allowed_actions
        assert restored.denied_actions == original.denied_actions
        assert restored.allowed_resources == original.allowed_resources
        assert restored.description == original.description
        assert restored.version == original.version

    def test_minimal_dict_only_name(self):
        policy = IBACPolicy.from_dict({"name": "minimal"})
        assert policy.name == "minimal"
        assert policy.allowed_actions == []
        assert policy.denied_actions == []

    def test_full_dict(self):
        d = {
            "name": "test-policy",
            "allowed_actions": ["db.read", "email.send"],
            "denied_actions": ["db.delete", "code.execute"],
            "allowed_resources": ["customer.*"],
            "max_confidence_required": 0.75,
            "description": "Test policy",
            "version": "2.1",
        }
        policy = IBACPolicy.from_dict(d)
        assert policy.name == "test-policy"
        assert "db.read" in policy.allowed_actions
        assert "email.send" in policy.allowed_actions
        assert "db.delete" in policy.denied_actions
        assert policy.max_confidence_required == 0.75
        assert policy.version == "2.1"

    def test_unknown_keys_ignored(self):
        d = {"name": "x", "future_field": "ignored", "allowed_actions": ["db.read"]}
        policy = IBACPolicy.from_dict(d)
        assert policy.name == "x"

    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            IBACPolicy.from_dict({"allowed_actions": ["db.read"]})

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="dict"):
            IBACPolicy.from_dict(["db.read"])

    def test_invalid_action_raises_on_instantiation(self):
        with pytest.raises(ValueError, match="unknown action"):
            IBACPolicy.from_dict({
                "name": "bad",
                "allowed_actions": ["not.a.real.action"],
            })

    def test_defaults_applied(self):
        policy = IBACPolicy.from_dict({"name": "defaults-test"})
        assert policy.max_confidence_required == 0.6
        assert policy.version == "1.0"
        assert policy.description == ""

    def test_applies_correctly_after_from_dict(self):
        """Restored policy must behave identically to the original."""
        from jercept.core.scope import IBACScope
        original = BILLING_AGENT_POLICY
        restored = IBACPolicy.from_dict(original.to_dict())

        user_scope = IBACScope(
            allowed_actions=["db.read", "code.execute"],
            allowed_resources=["customer.*"],
            denied_actions=[],
            raw_intent="test",
            confidence=0.9,
            ambiguous=False,
        )
        orig_result = original.apply(user_scope)
        rest_result = restored.apply(user_scope)
        assert orig_result.allowed_actions == rest_result.allowed_actions
        assert set(orig_result.denied_actions) == set(rest_result.denied_actions)


class TestFromYaml:
    """IBACPolicy.from_yaml() — flat and nested formats, error handling."""

    def _write_yaml(self, content: str) -> str:
        """Write content to a temp YAML file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_flat_format(self):
        path = self._write_yaml("""
name: flat-test
allowed_actions:
  - db.read
  - email.send
denied_actions:
  - db.delete
  - code.execute
description: Flat format test
""")
        try:
            policy = IBACPolicy.from_yaml(path)
            assert policy.name == "flat-test"
            assert "db.read" in policy.allowed_actions
            assert "db.delete" in policy.denied_actions
        finally:
            os.unlink(path)

    def test_nested_policy_key_format(self):
        path = self._write_yaml("""
policy:
  name: nested-test
  allowed_actions:
    - file.read
    - file.write
  denied_actions:
    - db.export
""")
        try:
            policy = IBACPolicy.from_yaml(path)
            assert policy.name == "nested-test"
            assert "file.read" in policy.allowed_actions
        finally:
            os.unlink(path)

    def test_full_fields_in_yaml(self):
        path = self._write_yaml("""
name: full-yaml
allowed_actions: [db.read, email.send]
denied_actions: [db.delete, db.export, code.execute]
allowed_resources:
  - customer.*
  - billing.*
max_confidence_required: 0.8
description: Full YAML test policy
version: "3.0"
""")
        try:
            policy = IBACPolicy.from_yaml(path)
            assert policy.max_confidence_required == 0.8
            assert "customer.*" in policy.allowed_resources
            assert policy.version == "3.0"
        finally:
            os.unlink(path)

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            IBACPolicy.from_yaml("/tmp/nonexistent_csm_policy_xyz.yaml")

    def test_missing_name_in_yaml_raises(self):
        path = self._write_yaml("allowed_actions: [db.read]\n")
        try:
            with pytest.raises(ValueError, match="name"):
                IBACPolicy.from_yaml(path)
        finally:
            os.unlink(path)

    def test_invalid_action_in_yaml_raises(self):
        path = self._write_yaml("""
name: bad-yaml
allowed_actions:
  - not.a.valid.action
""")
        try:
            with pytest.raises(ValueError):
                IBACPolicy.from_yaml(path)
        finally:
            os.unlink(path)

    def test_round_trip_yaml(self):
        """Write a policy to YAML manually, load it back, verify equality."""
        import yaml
        original = BILLING_AGENT_POLICY
        d = original.to_dict()

        path = self._write_yaml(yaml.dump(d))
        try:
            restored = IBACPolicy.from_yaml(path)
            assert restored.name == original.name
            assert restored.allowed_actions == original.allowed_actions
        finally:
            os.unlink(path)
