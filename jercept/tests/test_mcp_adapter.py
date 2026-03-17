"""Tests for MCP adapter — JSON-RPC IBAC middleware."""
from __future__ import annotations
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from jercept.adapters.mcp_adapter import MCPIBACMiddleware, wrap_mcp_server, _infer_mcp_action
from jercept.core.scope import IBACScope
from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation

def make_enforcer(allowed, denied=None):
    scope = IBACScope(allowed, [], denied or [], 'test', 0.9, False)
    return IBACEnforcer(scope)

def make_server(response=None):
    server = MagicMock()
    server.handle_request = AsyncMock(return_value=response or {"jsonrpc":"2.0","id":1,"result":"ok"})
    return server

class TestMCPMiddlewareCreation:
    def test_wrap_mcp_server_returns_middleware(self):
        server = make_server()
        enforcer = make_enforcer(["file.read"])
        result = wrap_mcp_server(server, enforcer)
        assert isinstance(result, MCPIBACMiddleware)

    def test_list_tools_delegates_to_server(self):
        server = MagicMock()
        server.list_tools.return_value = [{"name": "read_file"}]
        enforcer = make_enforcer(["file.read"])
        mw = MCPIBACMiddleware(server, enforcer)
        assert mw.list_tools() == [{"name": "read_file"}]

class TestMCPRequestHandling:
    def test_non_tools_call_passes_through(self):
        server = make_server({"jsonrpc":"2.0","id":1,"result":["read_file"]})
        enforcer = make_enforcer(["file.read"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/list","id":1}
        result = asyncio.run(mw.handle_request(req))
        assert result.get("result") == ["read_file"]

    def test_permitted_tools_call_forwarded(self):
        server = make_server({"jsonrpc":"2.0","id":1,"result":{"content":"data"}})
        enforcer = make_enforcer(["file.read"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/call","id":1,
               "params":{"name":"read_file","arguments":{"path":"/tmp/a.txt"}}}
        result = asyncio.run(mw.handle_request(req))
        assert "error" not in result

    def test_blocked_tools_call_returns_error(self):
        server = make_server()
        enforcer = make_enforcer(["file.read"], denied=["code.execute"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/call","id":2,
               "params":{"name":"bash","arguments":{"command":"rm -rf /"}}}
        result = asyncio.run(mw.handle_request(req))
        assert "error" in result
        assert result["error"]["code"] == -32603
        assert result["error"]["data"]["ibac_violation"] is True

    def test_blocked_error_has_tool_name(self):
        server = make_server()
        enforcer = make_enforcer(["file.read"], denied=["code.execute"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/call","id":3,
               "params":{"name":"execute_command","arguments":{}}}
        result = asyncio.run(mw.handle_request(req))
        assert result["error"]["data"]["tool_name"] == "execute_command"

    def test_audit_log_populated_for_allowed(self):
        server = make_server({"jsonrpc":"2.0","id":1,"result":"ok"})
        enforcer = make_enforcer(["file.read"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/call","id":1,
               "params":{"name":"read_file","arguments":{}}}
        asyncio.run(mw.handle_request(req))
        assert len(enforcer.audit_log) == 1
        assert enforcer.audit_log[0]["permitted"] is True

    def test_audit_log_populated_for_blocked(self):
        server = make_server()
        enforcer = make_enforcer(["file.read"], denied=["code.execute"])
        mw = MCPIBACMiddleware(server, enforcer)
        req = {"jsonrpc":"2.0","method":"tools/call","id":1,
               "params":{"name":"bash","arguments":{}}}
        asyncio.run(mw.handle_request(req))
        assert enforcer.audit_log[-1]["permitted"] is False

class TestMCPActionInference:
    def test_read_file_maps_to_file_read(self):
        assert _infer_mcp_action("read_file", {}) == "file.read"

    def test_write_file_maps_to_file_write(self):
        assert _infer_mcp_action("write_file", {}) == "file.write"

    def test_bash_maps_to_code_execute(self):
        assert _infer_mcp_action("bash", {}) == "code.execute"

    def test_execute_command_maps_to_code_execute(self):
        assert _infer_mcp_action("execute_command", {}) == "code.execute"

    def test_web_search_maps_to_web_browse(self):
        assert _infer_mcp_action("web_search", {}) == "web.browse"

    def test_database_query_maps_to_db_read(self):
        assert _infer_mcp_action("database_query", {}) == "db.read"
