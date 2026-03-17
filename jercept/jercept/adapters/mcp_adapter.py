"""
Jercept MCP (Model Context Protocol) adapter.

Intercepts JSON-RPC 2.0 tools/call requests and enforces IBAC
before forwarding to the underlying MCP server. Never raises —
always returns a valid JSON-RPC response.
"""
from __future__ import annotations

import inspect
import logging
from typing import Any, Optional

from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation

logger = logging.getLogger(__name__)


class MCPIBACMiddleware:
    """
    IBAC middleware for MCP (Model Context Protocol) servers.

    Wraps an MCP server's tool-call handler to enforce IBAC before
    any tool is invoked. Compatible with any MCP server that exposes
    handle_request(), process_request(), or is itself callable.

    Args:
        server: The underlying MCP server object.
        enforcer: IBACEnforcer for the current session.

    Example::

        from jercept.adapters.mcp_adapter import wrap_mcp_server

        protected = wrap_mcp_server(my_mcp_server, enforcer)
        result = await protected.handle_request(request)
    """

    def __init__(self, server: Any, enforcer: IBACEnforcer) -> None:
        self._server = server
        self._enforcer = enforcer

    async def handle_request(self, request: dict) -> dict:
        """
        Intercept a JSON-RPC request. If it is a tools/call, run IBAC
        check before forwarding. All other requests pass through unchanged.

        Args:
            request: Raw JSON-RPC 2.0 dict from MCP client.

        Returns:
            JSON-RPC response dict. If blocked, returns error code -32603.
        """
        method = request.get("method", "")
        req_id = request.get("id")

        if method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "unknown")
            action = _infer_mcp_action(tool_name, params)

            try:
                self._enforcer.check(action, fn_name=tool_name)
            except IBACScopeViolation as e:
                logger.warning(
                    "MCP IBAC BLOCKED: tool=%r action=%r", tool_name, action
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(e),
                        "data": {
                            "blocked_action": action,
                            "tool_name": tool_name,
                            "ibac_violation": True,
                        },
                    },
                }

        return await self._forward(request)

    async def _forward(self, request: dict) -> dict:
        """Forward request to the underlying MCP server."""
        handler = (
            getattr(self._server, "handle_request", None)
            or getattr(self._server, "process_request", None)
            or (self._server if callable(self._server) else None)
        )
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": "Server has no handler"},
            }
        try:
            if inspect.iscoroutinefunction(handler):
                return await handler(request)
            return handler(request)
        except Exception as exc:
            logger.error("MCP server error: %s", exc)
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32603, "message": f"Internal error: {exc}"},
            }

    def list_tools(self) -> list:
        """Return available tools from the wrapped server, if supported."""
        fn = getattr(self._server, "list_tools", None)
        return fn() if fn else []


def wrap_mcp_server(server: Any, enforcer: IBACEnforcer) -> MCPIBACMiddleware:
    """
    Wrap an MCP server with IBAC enforcement.

    Args:
        server: Any MCP-compatible server object.
        enforcer: IBACEnforcer for the current session.

    Returns:
        MCPIBACMiddleware wrapping the server.

    Example::

        protected = wrap_mcp_server(my_mcp_server, enforcer)
        result = await protected.handle_request(request)
    """
    return MCPIBACMiddleware(server, enforcer)


# MCP-specific tool name → IBAC action overrides
_MCP_TOOL_MAP: dict[str, str] = {
    "read_file": "file.read",
    "write_file": "file.write",
    "create_file": "file.write",
    "list_directory": "file.read",
    "create_directory": "file.write",
    "delete_file": "file.delete",
    "move_file": "file.write",
    "copy_file": "file.write",
    "search_files": "file.read",
    "get_file_info": "file.read",
    "execute_command": "code.execute",
    "run_terminal": "code.execute",
    "bash": "code.execute",
    "shell": "code.execute",
    "python": "code.execute",
    "run_script": "code.execute",
    "fetch": "web.browse",
    "web_search": "web.browse",
    "brave_search": "web.browse",
    "google_search": "web.browse",
    "http_request": "api.call",
    "slack_post": "email.send",
    "slack_send": "email.send",
    "send_message": "email.send",
    "send_email": "email.send",
    "read_email": "email.read",
    "github_create": "api.call",
    "github_push": "api.call",
    "database_query": "db.read",
    "sql_query": "db.read",
    "db_read": "db.read",
    "db_write": "db.write",
    "db_delete": "db.delete",
}


def _infer_mcp_action(tool_name: str, params: Optional[dict] = None) -> str:
    """
    Infer IBAC action from MCP tool name and optional params.

    Checks MCP-specific mappings first, then falls back to the
    general keyword inference from the OpenAI adapter.

    Args:
        tool_name: The MCP tool name from the tools/call request.
        params: The tool call arguments dict (unused currently).

    Returns:
        IBAC action string.
    """
    from jercept.adapters.openai_adapter import _infer_action

    lower = tool_name.lower().replace("-", "_")
    if lower in _MCP_TOOL_MAP:
        return _MCP_TOOL_MAP[lower]
    return _infer_action(tool_name)
