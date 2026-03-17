"""Tests for jercept.linter - policy lint rules."""
from __future__ import annotations
import pytest
from jercept.policy import IBACPolicy
from jercept.linter import lint_policy, LintSeverity


def make_clean_policy(**kwargs):
    defaults = dict(name="test-policy", allowed_actions=["db.read"],
                    denied_actions=["db.export", "db.delete", "code.execute"],
                    allowed_resources=["customer.*"], description="Test", version="2.0")
    defaults.update(kwargs)
    return IBACPolicy(**defaults)


class TestWildcard:
    def test_db_wildcard_error(self):
        p = IBACPolicy(name="p", allowed_actions=["db.*"], denied_actions=[])
        assert lint_policy(p).has_errors

    def test_db_wildcard_explicit_denies_ok(self):
        p = IBACPolicy(name="p", allowed_actions=["db.*"],
                       denied_actions=["db.export", "db.delete", "code.execute", "file.download"])
        r = lint_policy(p)
        assert not any(f.rule == "wildcard_dangerous_actions" for f in r.errors)

    def test_full_wildcard_error(self):
        p = IBACPolicy(name="p", allowed_actions=["*"], denied_actions=[])
        assert lint_policy(p).has_errors

    def test_specific_actions_no_wildcard_error(self):
        p = make_clean_policy()
        r = lint_policy(p)
        assert not any(f.rule == "wildcard_dangerous_actions" for f in r.errors)

    def test_file_wildcard_catches_download(self):
        p = IBACPolicy(name="p", allowed_actions=["file.*"], denied_actions=[])
        r = lint_policy(p)
        assert r.has_errors
        assert "file.download" in " ".join(f.message for f in r.errors)


class TestAllowDenyConflict:
    def test_conflict_is_error(self):
        p = IBACPolicy(name="p", allowed_actions=["db.read", "db.export"],
                       denied_actions=["db.export"])
        r = lint_policy(p)
        assert any(f.rule == "allow_deny_conflict" for f in r.errors)

    def test_no_conflict(self):
        p = make_clean_policy()
        assert not any(f.rule == "allow_deny_conflict" for f in lint_policy(p).findings)


class TestConfidenceThreshold:
    def test_very_low_is_error(self):
        p = IBACPolicy(name="p", allowed_actions=["db.read"],
                       denied_actions=["db.export"], max_confidence_required=0.3)
        r = lint_policy(p)
        assert any(f.rule == "low_confidence_threshold" and
                   f.severity == LintSeverity.ERROR for f in r.findings)

    def test_moderate_is_warning(self):
        p = IBACPolicy(name="p", allowed_actions=["db.read"],
                       denied_actions=["db.export"], max_confidence_required=0.55)
        r = lint_policy(p)
        assert any(f.rule == "low_confidence_threshold" and
                   f.severity == LintSeverity.WARNING for f in r.findings)

    def test_good_confidence_no_finding(self):
        p = make_clean_policy()
        assert not any(f.rule == "low_confidence_threshold" for f in lint_policy(p).findings)


class TestResourceWarning:
    def test_db_no_resources_warning(self):
        p = IBACPolicy(name="p", allowed_actions=["db.read"],
                       denied_actions=["db.export"], allowed_resources=[])
        r = lint_policy(p)
        assert any(f.rule == "empty_allowed_resources" for f in r.warnings)

    def test_email_no_resources_no_warning(self):
        p = IBACPolicy(name="p", allowed_actions=["email.send"],
                       denied_actions=[], allowed_resources=[])
        r = lint_policy(p)
        assert not any(f.rule == "empty_allowed_resources" for f in r.warnings)


class TestCodeExecute:
    def test_unrestricted_code_warning(self):
        p = IBACPolicy(name="p", allowed_actions=["code.execute"],
                       denied_actions=[], allowed_resources=[])
        assert any(f.rule == "unrestricted_code_execution" for f in lint_policy(p).warnings)


class TestLintResult:
    def test_clean_policy_passes(self):
        assert not lint_policy(make_clean_policy()).has_errors

    def test_str_contains_name(self):
        p = make_clean_policy(name="billing-v2")
        assert "billing-v2" in str(lint_policy(p))

    def test_errors_before_info(self):
        p = IBACPolicy(name="p", allowed_actions=["db.*"], denied_actions=[], description="")
        r = lint_policy(p)
        sev = [f.severity for f in r.findings]
        error_idx = [i for i, s in enumerate(sev) if s == LintSeverity.ERROR]
        info_idx = [i for i, s in enumerate(sev) if s == LintSeverity.INFO]
        if error_idx and info_idx:
            assert max(error_idx) < min(info_idx)
