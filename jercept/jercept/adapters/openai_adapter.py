"""
Jercept OpenAI Agents SDK adapter.

Wraps an openai-agents Agent object so all tool invocations are checked
against the active IBACScope before execution.
"""
from __future__ import annotations

import logging
from typing import Any

from jercept.core.enforcer import IBACEnforcer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action inference keyword mappings (order matters — first match wins).
#
# PRIORITY RULES:
#   • Specific groups (file.*, email.*, web.*, code.*, api.*) appear FIRST.
#   • db.read is the LAST entry — it is the catch-all.
#   • Broad keywords like "read", "load", "save", "write" live ONLY in db.read.
#   • Never place broad keywords in a group above their specific group.
#
# VERIFIED mappings:
#   read_file     → file.read    (caught by file.read before db.read)
#   write_file    → file.write   (caught by file.write before db.read)
#   upload_doc    → file.upload
#   download_csv  → file.download
#   read_customer → db.read      (falls through all specific groups)
#   export_all    → db.export    (first group)
#   send_email    → email.send
#   read_email    → email.read   (before email.send)
#   run_shell     → code.execute
#   unknown_tool  → tool.unknown_tool (fallback)
# ---------------------------------------------------------------------------
_ACTION_KEYWORDS: list[tuple[list[str], str]] = [
    # 1. db.export — must be before db.read/write
    (["export", "dump", "backup"], "db.export"),

    # 2. db.delete
    (["delete", "remove", "drop", "purge", "truncate"], "db.delete"),

    # 3. db.write — specific write compound words only; NO bare "write"/"save"/"create"
    (["insert", "update", "upsert", "put", "post", "store", "save_db", "write_db"], "db.write"),

    # 4. file.upload — before file.write/file.read
    (["upload"], "file.upload"),

    # 5. file.download — before file.read
    (["download"], "file.download"),

    # 6. file.write — compound file-write keywords; before file.read
    (["write_file", "save_file", "create_file", "generate_file"], "file.write"),

    # 7. file.read — before db.read so read_file / load_file resolve here
    (["read_file", "open_file", "load_file", "read_doc", "parse_file", "file"], "file.read"),

    # 8. email.read — before email.send so read_email resolves here
    (["read_email", "inbox", "fetch_email", "get_email", "check_email"], "email.read"),

    # 9. email.send
    (["send_email", "email", "mail", "compose_email", "draft_email", "notify"], "email.send"),

    # 10. web.browse
    (["browse", "search_web", "web", "google", "fetch_url", "crawl", "scrape", "http"], "web.browse"),

    # 11. code.execute
    (["execute", "run", "eval", "python", "code", "shell", "bash", "script", "compile"], "code.execute"),

    # 12. api.call
    (["api", "call", "request", "invoke", "webhook", "rest"], "api.call"),

    # 13. db.read — LAST ENTRY: catch-all for any data-read or unknown DB operation.
    #     Contains broad keywords ("read", "load", "save", "write", "create") that
    #     would collide with specific groups if placed earlier.
    (["sql", "query", "database", "select", "fetch", "get", "lookup", "db", "read_db",
      "find", "read", "search", "customer", "billing", "user", "account", "record",
      "list_", "fetch_", "load", "retrieve", "save", "write", "create"], "db.read"),
]


def _infer_action(tool_name: str) -> str:
    """
    Map a tool function name to an IBAC action string via keyword matching.

    Iterates through keyword groups in priority order. The first keyword that
    appears as a substring of ``tool_name`` (case-insensitive) wins.

    Args:
        tool_name: The name of the tool function (e.g., ``"query_database"``).

    Returns:
        An IBAC action string such as ``"db.read"``, or a fallback string
        ``"tool.<tool_name>"`` if no keyword matches.

    Example:
        >>> _infer_action("query_database")
        'db.read'
        >>> _infer_action("send_email")
        'email.send'
        >>> _infer_action("custom_tool")
        'tool.custom_tool'
    """
    lower_name = tool_name.lower()
    for keywords, action in _ACTION_KEYWORDS:
        for kw in keywords:
            if kw in lower_name:
                logger.debug("Inferred action %r for tool %r (keyword=%r)", action, tool_name, kw)
                return action
    fallback = f"tool.{lower_name}"
    logger.debug("No action keyword matched for tool %r — using fallback %r", tool_name, fallback)
    return fallback


def wrap_openai_agent(agent: Any, enforcer: IBACEnforcer) -> Any:
    """
    Wrap an OpenAI Agents SDK Agent's tools with IBAC enforcement.

    Creates a new Agent instance with the same configuration as the original,
    but each tool's ``on_invoke_tool`` is wrapped by the enforcer. The original
    agent is never mutated.

    Args:
        agent: An ``openai_agents.Agent`` instance from the OpenAI Agents SDK.
        enforcer: The :class:`IBACEnforcer` for the current session.

    Returns:
        A new ``Agent`` with all tools IBAC-wrapped.

    Raises:
        ImportError: If the ``openai-agents`` package is not installed.
    """
    try:
        from agents import Agent, FunctionTool  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "openai-agents package is required for OpenAI adapter. "
            "Install it with: pip install jercept[openai-agents]"
        ) from exc

    from jercept.decorators import get_declared_actions

    wrapped_tools = []
    for tool in getattr(agent, "tools", []):
        tool_name: str = getattr(tool, "name", "") or getattr(tool, "__name__", "unknown")

        if isinstance(tool, FunctionTool):
            original_on_invoke = tool.on_invoke_tool

            # 1. Try explicit @ibac_tool first
            declared = get_declared_actions(original_on_invoke)
            if declared:
                action = declared[0]
                logger.debug("Tool %r uses explicitly declared action: %r", tool_name, action)
            else:
                # 2. Fall back to filename inference
                action = _infer_action(tool_name)

            async def _protected_invoke(
                ctx: Any,
                input: str,
                *,
                _action: str = action,
                _tool_name: str = tool_name,
                _original: Any = original_on_invoke,
            ) -> Any:
                enforcer.check(_action, fn_name=_tool_name)
                return await _original(ctx, input)

            wrapped_tool = FunctionTool(
                name=tool.name,
                description=tool.description,
                params_json_schema=tool.params_json_schema,
                on_invoke_tool=_protected_invoke,
                strict_json_schema=getattr(tool, "strict_json_schema", True),
            )
            wrapped_tools.append(wrapped_tool)
            logger.debug("Wrapped OpenAI tool %r → action=%r", tool_name, action)
        else:
            # Non-FunctionTool items passed through unchanged
            wrapped_tools.append(tool)

    protected_agent = Agent(
        name=getattr(agent, "name", "protected-agent"),
        instructions=getattr(agent, "instructions", ""),
        tools=wrapped_tools,
        model=getattr(agent, "model", "gpt-4o-mini"),
    )
    logger.info("Wrapped OpenAI agent %r with %d tools", protected_agent.name, len(wrapped_tools))
    return protected_agent
