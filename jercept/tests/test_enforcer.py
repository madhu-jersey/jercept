"""
Unit tests for IBACEnforcer — tool wrapping and audit logging.
"""
from __future__ import annotations

import time

import pytest

from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation
from jercept.core.scope import IBACScope


def make_scope(
    allowed_actions=None,
    allowed_resources=None,
    denied_actions=None,
    raw_intent="test",
    confidence=0.9,
) -> IBACScope:
    return IBACScope(
        allowed_actions=allowed_actions or ["db.read"],
        allowed_resources=allowed_resources or [],
        denied_actions=denied_actions or ["db.export", "code.execute"],
        raw_intent=raw_intent,
        confidence=confidence,
        ambiguous=False,
    )


class TestCheck:
    """Tests 1–2: check() returns True for permitted, raises for denied."""

    def test_permitted_action_returns_true(self):
        """Test 1: Permitted action → check() returns True."""
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))
        result = enforcer.check("db.read", fn_name="read_customer")
        assert result is True

    def test_denied_action_raises_violation(self):
        """Test 2: Denied action → check() raises IBACScopeViolation."""
        enforcer = IBACEnforcer(make_scope(denied_actions=["db.export"]))
        with pytest.raises(IBACScopeViolation) as exc_info:
            enforcer.check("db.export", fn_name="export_all")
        exc = exc_info.value
        assert exc.action == "db.export"
        assert exc.scope is enforcer.scope

    def test_violation_message_contains_action(self):
        enforcer = IBACEnforcer(make_scope(denied_actions=["db.export"]))
        with pytest.raises(IBACScopeViolation) as exc_info:
            enforcer.check("db.export")
        assert "db.export" in str(exc_info.value)

    def test_violation_message_contains_raw_intent(self):
        scope = make_scope(denied_actions=["code.execute"], raw_intent="read billing")
        enforcer = IBACEnforcer(scope)
        with pytest.raises(IBACScopeViolation) as exc_info:
            enforcer.check("code.execute")
        assert "read billing" in str(exc_info.value)


class TestAuditLog:
    """Tests 5–6: Audit log accumulates entries with required fields."""

    def test_permitted_action_logged(self):
        """Test 1 (audit): Permitted action is logged with permitted=True."""
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))
        enforcer.check("db.read", fn_name="read_fn")
        assert len(enforcer.audit_log) == 1
        entry = enforcer.audit_log[0]
        assert entry["permitted"] is True

    def test_denied_action_still_logged(self):
        """Test 2 (audit): Denied action is logged with permitted=False."""
        enforcer = IBACEnforcer(make_scope(denied_actions=["db.export"]))
        with pytest.raises(IBACScopeViolation):
            enforcer.check("db.export", fn_name="export_fn")
        assert len(enforcer.audit_log) == 1
        entry = enforcer.audit_log[0]
        assert entry["permitted"] is False

    def test_audit_log_accumulates_multiple_entries(self):
        """Test 5: Multiple calls accumulate in audit_log."""
        enforcer = IBACEnforcer(
            make_scope(allowed_actions=["db.read", "email.send"], denied_actions=["db.export"])
        )
        enforcer.check("db.read", fn_name="fn1")
        enforcer.check("email.send", fn_name="fn2")
        with pytest.raises(IBACScopeViolation):
            enforcer.check("db.export", fn_name="fn3")

        assert len(enforcer.audit_log) == 3
        assert enforcer.audit_log[0]["permitted"] is True
        assert enforcer.audit_log[1]["permitted"] is True
        assert enforcer.audit_log[2]["permitted"] is False

    def test_audit_entry_contains_required_fields(self):
        """Test 6: Each audit entry has ts, action, resource, permitted, fn_name."""
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))
        before = time.time()
        enforcer.check("db.read", "customer#1", fn_name="read_customer")
        after = time.time()

        entry = enforcer.audit_log[0]
        assert "ts" in entry
        assert "action" in entry
        assert "resource" in entry
        assert "permitted" in entry
        assert "fn_name" in entry

        assert entry["action"] == "db.read"
        assert entry["resource"] == "customer#1"
        assert entry["fn_name"] == "read_customer"
        assert before <= entry["ts"] <= after


class TestWrap:
    """Tests 3–4: wrap() creates an enforced proxy function."""

    def test_wrapped_fn_called_when_permitted(self):
        """Test 3: Permitted action → wrapped fn executes normally."""
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))
        call_log = []

        def original_fn(x):
            call_log.append(x)
            return x * 2

        wrapped = enforcer.wrap(original_fn, "db.read")
        result = wrapped(5)
        assert result == 10
        assert call_log == [5]

    def test_wrapped_fn_blocked_when_denied(self):
        """Test 4: Denied action → wrapped fn raises IBACScopeViolation."""
        enforcer = IBACEnforcer(make_scope(denied_actions=["db.export"]))

        def export_fn():
            return "all data"

        wrapped = enforcer.wrap(export_fn, "db.export")
        with pytest.raises(IBACScopeViolation):
            wrapped()

    def test_wrap_preserves_function_name(self):
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))

        def my_special_tool():
            pass

        wrapped = enforcer.wrap(my_special_tool, "db.read")
        assert wrapped.__name__ == "my_special_tool"

    def test_wrap_preserves_docstring(self):
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))

        def my_tool():
            """Read customer data from the database."""
            pass

        wrapped = enforcer.wrap(my_tool, "db.read")
        assert wrapped.__doc__ == "Read customer data from the database."

    def test_wrap_logs_to_audit(self):
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))

        def read_fn():
            return "data"

        wrapped = enforcer.wrap(read_fn, "db.read")
        wrapped()
        assert len(enforcer.audit_log) == 1
        assert enforcer.audit_log[0]["fn_name"] == "read_fn"


class TestWasAttacked:
    """Tests for was_attacked and blocked_actions properties."""

    def test_not_attacked_when_all_permitted(self):
        enforcer = IBACEnforcer(make_scope(allowed_actions=["db.read"]))
        enforcer.check("db.read")
        assert enforcer.was_attacked is False

    def test_attacked_when_blocked(self):
        enforcer = IBACEnforcer(make_scope(denied_actions=["db.export"]))
        with pytest.raises(IBACScopeViolation):
            enforcer.check("db.export")
        assert enforcer.was_attacked is True

    def test_blocked_actions_list(self):
        enforcer = IBACEnforcer(
            make_scope(allowed_actions=["db.read"], denied_actions=["db.export", "code.execute"])
        )
        enforcer.check("db.read")
        with pytest.raises(IBACScopeViolation):
            enforcer.check("db.export")
        with pytest.raises(IBACScopeViolation):
            enforcer.check("code.execute")
        assert set(enforcer.blocked_actions) == {"db.export", "code.execute"}
