"""
Unit tests for jercept.core.fast_extractor — regex-based IBACScope extraction.
"""
from __future__ import annotations

import pytest
from jercept.core.fast_extractor import try_fast_extract, MIN_FAST_CONFIDENCE
from jercept.core.scope import IBACScope


class TestFastExtractPatterns:
    def test_billing_read(self):
        scope = try_fast_extract("check billing for customer 123")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_invoice_read(self):
        scope = try_fast_extract("view invoice for account 456")
        assert scope is not None
        assert "db.read" in scope.allowed_actions

    def test_send_email(self):
        scope = try_fast_extract("send email to the marketing team")
        assert scope is not None
        assert "email.send" in scope.allowed_actions

    def test_read_email(self):
        scope = try_fast_extract("read email from inbox")
        assert scope is not None
        assert "email.read" in scope.allowed_actions

    def test_read_file(self):
        scope = try_fast_extract("read the Q3 report file")
        assert scope is not None
        assert "file.read" in scope.allowed_actions

    def test_export_data(self):
        scope = try_fast_extract("export all customers to csv")
        assert scope is not None
        assert "db.export" in scope.allowed_actions

    def test_delete_account(self):
        scope = try_fast_extract("delete account for user 456")
        assert scope is not None
        assert "db.delete" in scope.allowed_actions

    def test_update_record(self):
        scope = try_fast_extract("update the profile settings for user")
        assert scope is not None
        assert "db.write" in scope.allowed_actions


class TestFastExtractFailSafe:
    def test_ambiguous_help_returns_none(self):
        assert try_fast_extract("help me") is None

    def test_ambiguous_usual_returns_none(self):
        assert try_fast_extract("do the usual") is None

    def test_ambiguous_fix_returns_none(self):
        assert try_fast_extract("fix it") is None

    def test_empty_string_returns_none(self):
        assert try_fast_extract("") is None

    def test_none_returns_none(self):
        assert try_fast_extract(None) is None

    def test_whitespace_only_returns_none(self):
        assert try_fast_extract("   ") is None


class TestFastExtractScopeProperties:
    def test_returns_ibac_scope_instance(self):
        scope = try_fast_extract("check billing for customer 123")
        assert isinstance(scope, IBACScope)

    def test_confidence_meets_minimum(self):
        scope = try_fast_extract("check billing for customer 123")
        assert scope.confidence >= MIN_FAST_CONFIDENCE

    def test_not_ambiguous(self):
        scope = try_fast_extract("check billing for customer 123")
        assert scope.ambiguous is False

    def test_raw_intent_preserved(self):
        req = "check billing for customer 123"
        scope = try_fast_extract(req)
        assert scope.raw_intent == req

    def test_denied_actions_populated(self):
        scope = try_fast_extract("check billing for customer 123")
        assert len(scope.denied_actions) > 0
        assert "db.export" in scope.denied_actions
