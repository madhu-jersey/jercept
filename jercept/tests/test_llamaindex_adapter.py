"""Tests for LlamaIndex adapter."""
from __future__ import annotations
import asyncio
import pytest
from unittest.mock import MagicMock, patch
from jercept.adapters.llamaindex_adapter import (
    wrap_llamaindex_agent, _extract_llamaindex_tools, _wrap_llamaindex_tool
)
from jercept.core.scope import IBACScope
from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation
from jercept.decorators import ibac_tool

def make_enforcer(allowed, denied=None):
    scope = IBACScope(allowed, [], denied or [], 'test', 0.9, False)
    return IBACEnforcer(scope)

class MockMetadata:
    def __init__(self, name): self.name = name

class MockLlamaTool:
    def __init__(self, name, action_hint=None):
        self.metadata = MockMetadata(name)
        self.name = name
        self._calls = []
        self._async_calls = []
    def call(self, *a, **kw):
        self._calls.append((a, kw)); return f"result_{self.name}"
    async def acall(self, *a, **kw):
        self._async_calls.append((a, kw)); return f"async_{self.name}"

class MockLlamaAgent:
    def __init__(self, tools):
        self.tools = tools

class TestLlamaIndexExtractTools:
    def test_extract_from_tools_attribute(self):
        t = MockLlamaTool("read_file")
        agent = MockLlamaAgent([t])
        tools = _extract_llamaindex_tools(agent)
        assert t in tools

    def test_extract_from_private_tools(self):
        t = MockLlamaTool("read_file")
        agent = MagicMock()
        del agent.tools
        agent._tools = [t]
        tools = _extract_llamaindex_tools(agent)
        assert t in tools

    def test_empty_when_no_tools(self):
        agent = MagicMock(spec=[])
        tools = _extract_llamaindex_tools(agent)
        assert tools == []

class TestLlamaIndexWrapTool:
    def test_call_wrapped(self):
        t = MockLlamaTool("read_file")
        enforcer = make_enforcer(["file.read"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        result = t.call("arg")
        assert result == "result_read_file"

    def test_acall_wrapped(self):
        t = MockLlamaTool("read_file")
        enforcer = make_enforcer(["file.read"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        result = asyncio.run(t.acall("arg"))
        assert result == "async_read_file"

    def test_denied_call_raises(self):
        t = MockLlamaTool("export_customers")
        enforcer = make_enforcer(["file.read"], denied=["db.export"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        with pytest.raises(IBACScopeViolation):
            t.call()

    def test_denied_acall_raises(self):
        t = MockLlamaTool("export_customers")
        enforcer = make_enforcer(["file.read"], denied=["db.export"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        with pytest.raises(IBACScopeViolation):
            asyncio.run(t.acall())

    def test_ibac_tool_decorator_used(self):
        t = MockLlamaTool("crm_sync")
        @ibac_tool("db.export")
        def fn(): return "ok"
        t.call = fn
        enforcer = make_enforcer(["file.read"], denied=["db.export"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        with pytest.raises(IBACScopeViolation) as exc_info:
            t.call()
        assert exc_info.value.action == "db.export"

    def test_audit_log_populated(self):
        t = MockLlamaTool("read_file")
        enforcer = make_enforcer(["file.read"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            _wrap_llamaindex_tool(t, enforcer)
        t.call()
        assert len(enforcer.audit_log) == 1

class TestWrapLlamaIndexAgent:
    def test_requires_llama_index(self):
        agent = MockLlamaAgent([])
        enforcer = make_enforcer(["file.read"])
        with patch.dict("sys.modules", {"llama_index": None}):
            import sys; sys.modules.pop("llama_index", None)
            with pytest.raises(ImportError, match="llama-index is required"):
                import importlib, csm.adapters.llamaindex_adapter as mod
                importlib.reload(mod)

    def test_returns_same_agent(self):
        t = MockLlamaTool("read_file")
        agent = MockLlamaAgent([t])
        enforcer = make_enforcer(["file.read"])
        with patch.dict("sys.modules", {"llama_index": MagicMock()}):
            result = wrap_llamaindex_agent(agent, enforcer)
        assert result is agent
