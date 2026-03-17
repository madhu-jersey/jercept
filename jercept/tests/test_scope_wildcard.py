"""Tests for IBACScope wildcard warning and MAX_INPUT_LENGTH."""
from __future__ import annotations
import logging
import pytest
from jercept.core.scope import IBACScope, DANGEROUS_ACTIONS, MAX_INPUT_LENGTH


class TestWildcardWarning:
    def test_db_wildcard_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
            IBACScope(allowed_actions=["db.*"], allowed_resources=[], denied_actions=[])
        assert any("wildcard" in r.message.lower() or "dangerous" in r.message.lower()
                   for r in caplog.records)

    def test_db_wildcard_explicit_denies_no_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
            IBACScope(
                allowed_actions=["db.*"],
                allowed_resources=[],
                denied_actions=list(DANGEROUS_ACTIONS),
            )
        dangerous_warnings = [
            r for r in caplog.records
            if "wildcard" in r.message.lower() and r.levelno == logging.WARNING
        ]
        assert len(dangerous_warnings) == 0

    def test_specific_action_no_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
            IBACScope(allowed_actions=["db.read", "email.send"],
                      allowed_resources=[], denied_actions=[])
        wildcard_warnings = [r for r in caplog.records if "wildcard" in r.message.lower()]
        assert len(wildcard_warnings) == 0

    def test_full_wildcard_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
            IBACScope(allowed_actions=["*"], allowed_resources=[], denied_actions=[])
        assert len(caplog.records) > 0

    def test_file_wildcard_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="jercept.core.scope"):
            IBACScope(allowed_actions=["file.*"], allowed_resources=[], denied_actions=[])
        assert any("file.download" in r.message for r in caplog.records)


class TestDangerousActions:
    def test_dangerous_set_contains_expected(self):
        assert "db.export" in DANGEROUS_ACTIONS
        assert "db.delete" in DANGEROUS_ACTIONS
        assert "code.execute" in DANGEROUS_ACTIONS
        assert "file.download" in DANGEROUS_ACTIONS

    def test_db_read_not_dangerous(self):
        assert "db.read" not in DANGEROUS_ACTIONS

    def test_email_send_not_dangerous(self):
        assert "email.send" not in DANGEROUS_ACTIONS


class TestMaxInputLength:
    def test_constant_defined(self):
        assert MAX_INPUT_LENGTH == 10_000

    def test_constant_positive(self):
        assert MAX_INPUT_LENGTH > 0


class TestScopeLogic:
    def test_permits_allowed_action(self):
        s = IBACScope(allowed_actions=["db.read"], denied_actions=[])
        assert s.permits("db.read")

    def test_denies_not_allowed(self):
        s = IBACScope(allowed_actions=["db.read"], denied_actions=[])
        assert not s.permits("db.export")

    def test_explicit_deny_beats_allow(self):
        s = IBACScope(allowed_actions=["db.*"],
                      denied_actions=["db.export", "db.delete", "code.execute", "file.download"])
        assert not s.permits("db.export")
        assert s.permits("db.read")

    def test_resource_restriction(self):
        s = IBACScope(allowed_actions=["db.read"],
                      allowed_resources=["customer.*"],
                      denied_actions=[])
        assert s.permits("db.read", "customer#123")
        assert not s.permits("db.read", "admin_users")

    def test_empty_resources_allows_any(self):
        s = IBACScope(allowed_actions=["db.read"], allowed_resources=[], denied_actions=[])
        assert s.permits("db.read", "any_table")
        assert s.permits("db.read", "secret_admin_table")
