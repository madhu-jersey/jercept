"""Tests for AutoGen adapter."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from jercept.adapters.autogen_adapter import wrap_autogen_agent
from jercept.core.scope import IBACScope
from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation
from jercept.decorators import ibac_tool

def make_enforcer(allowed, denied=None):
    scope = IBACScope(allowed, [], denied or [], 'test', 0.9, False)
    return IBACEnforcer(scope)

class MockAutoGenAgent:
    """Duck-typed AutoGen ConversableAgent for testing."""
    def __init__(self):
        self._function_map = {}
        self._tools = []

class TestAutoGenAdapter:
    def test_wrap_requires_autogen(self):
        agent = MockAutoGenAgent()
        enforcer = make_enforcer(["db.read"])
        with patch.dict("sys.modules", {"autogen": None, "pyautogen": None}):
            import sys
            sys.modules.pop("autogen", None)
            sys.modules.pop("pyautogen", None)
            with pytest.raises(ImportError, match="AutoGen is required"):
                import importlib
                import jercept.adapters.autogen_adapter as mod
                importlib.reload(mod)

    def test_function_map_wrapped(self):
        agent = MockAutoGenAgent()
        call_log = []
        def my_tool(x): call_log.append(x); return "result"
        agent._function_map["my_tool"] = my_tool
        enforcer = make_enforcer(["db.read"])
        with patch("builtins.__import__", side_effect=lambda n, *a, **kw: MagicMock() if n in ("autogen","pyautogen") else __import__(n, *a, **kw)):
            pass
        # Mock the import check
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            result = wrap_autogen_agent(agent, enforcer)
        assert result is agent
        assert "my_tool" in agent._function_map

    def test_permitted_call_executes(self):
        agent = MockAutoGenAgent()
        results = []
        def read_customer(id): results.append(id); return "billing data"
        agent._function_map["read_customer"] = read_customer
        enforcer = make_enforcer(["db.read"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            wrap_autogen_agent(agent, enforcer)
        agent._function_map["read_customer"]("123")
        assert "123" in results

    def test_denied_call_raises_violation(self):
        agent = MockAutoGenAgent()
        def export_all(): return "all data"
        agent._function_map["export_all"] = export_all
        enforcer = make_enforcer(["db.read"], denied=["db.export"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            wrap_autogen_agent(agent, enforcer)
        with pytest.raises(IBACScopeViolation):
            agent._function_map["export_all"]()

    def test_ibac_tool_overrides_inference(self):
        agent = MockAutoGenAgent()
        @ibac_tool("db.export")
        def crm_sync(): return "synced"
        agent._function_map["crm_sync"] = crm_sync
        enforcer = make_enforcer(["db.read"], denied=["db.export"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            wrap_autogen_agent(agent, enforcer)
        with pytest.raises(IBACScopeViolation) as exc_info:
            agent._function_map["crm_sync"]()
        assert exc_info.value.action == "db.export"

    def test_audit_log_records_calls(self):
        agent = MockAutoGenAgent()
        def read_fn(): return "data"
        agent._function_map["read_customer"] = read_fn
        enforcer = make_enforcer(["db.read"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            wrap_autogen_agent(agent, enforcer)
        agent._function_map["read_customer"]()
        assert len(enforcer.audit_log) == 1
        assert enforcer.audit_log[0]["permitted"] is True

    def test_returns_same_agent(self):
        agent = MockAutoGenAgent()
        enforcer = make_enforcer(["db.read"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            result = wrap_autogen_agent(agent, enforcer)
        assert result is agent

    def test_empty_function_map_safe(self):
        agent = MockAutoGenAgent()
        enforcer = make_enforcer(["db.read"])
        with patch.dict("sys.modules", {"autogen": MagicMock(), "pyautogen": MagicMock()}):
            result = wrap_autogen_agent(agent, enforcer)
        assert result is agent
