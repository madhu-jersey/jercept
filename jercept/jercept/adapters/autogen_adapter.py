"""
Jercept AutoGen adapter.

Wraps Microsoft AutoGen ConversableAgent tools with IBAC enforcement
by replacing _function_map callables with IBAC-checked versions.
"""
from __future__ import annotations

import functools
import logging
from typing import Any

from jercept.core.enforcer import IBACEnforcer

logger = logging.getLogger(__name__)


def wrap_autogen_agent(agent: Any, enforcer: IBACEnforcer) -> Any:
    """
    Wrap a Microsoft AutoGen agent's tools with IBAC enforcement.

    AutoGen stores executable tools in agent._function_map as
    {tool_name: callable}. We replace each callable with an
    IBAC-checked version. The agent's LLM config and tool definitions
    are unchanged — only execution is intercepted.

    Args:
        agent: AutoGen ConversableAgent, AssistantAgent, or UserProxyAgent.
        enforcer: IBACEnforcer for the current session.

    Returns:
        The same agent with all tool callables wrapped (mutated in-place).

    Raises:
        ImportError: If neither autogen nor pyautogen is installed.

    Example::

        from jercept.adapters.autogen_adapter import wrap_autogen_agent

        protected = wrap_autogen_agent(my_autogen_agent, enforcer)
    """
    # Optional import check — adapter works via duck typing on _function_map
    # so we only raise if the agent clearly isn't an AutoGen agent
    _has_autogen = False
    try:
        import autogen  # noqa: F401
        _has_autogen = True
    except ImportError:
        try:
            import pyautogen  # noqa: F401
            _has_autogen = True
        except ImportError:
            pass

    if not _has_autogen:
        # Check if agent looks like AutoGen via duck typing
        has_function_map = hasattr(agent, "_function_map")
        if not has_function_map:
            raise ImportError(
                "AutoGen is required. Install: pip install pyautogen"
            )

    from jercept.adapters.openai_adapter import _infer_action
    from jercept.decorators import get_declared_actions

    wrapped_count = 0

    # Primary path: _function_map dict
    function_map = getattr(agent, "_function_map", {})
    for tool_name, tool_fn in list(function_map.items()):
        declared = get_declared_actions(tool_fn)
        action = declared[0] if declared else _infer_action(tool_name)

        @functools.wraps(tool_fn)
        def _safe(*args, _fn=tool_fn, _act=action, _name=tool_name, **kwargs):
            enforcer.check(_act, fn_name=_name)
            return _fn(*args, **kwargs)

        agent._function_map[tool_name] = _safe
        wrapped_count += 1
        logger.debug("Wrapped AutoGen tool %r → action=%r", tool_name, action)

    # Secondary path: _tools list (newer AutoGen 0.4+ API)
    tools_list = getattr(agent, "_tools", [])
    for tool in tools_list:
        original = (
            getattr(tool, "func", None)
            or getattr(tool, "callable", None)
            or getattr(tool, "function", None)
        )
        if original is None:
            continue

        tool_name = (
            getattr(tool, "name", None)
            or getattr(original, "__name__", "tool")
        )
        declared = get_declared_actions(original)
        action = declared[0] if declared else _infer_action(tool_name)

        @functools.wraps(original)
        def _safe_tool(*args, _fn=original, _act=action, _name=tool_name, **kwargs):
            enforcer.check(_act, fn_name=_name)
            return _fn(*args, **kwargs)

        if hasattr(tool, "func"):
            tool.func = _safe_tool
        elif hasattr(tool, "callable"):
            tool.callable = _safe_tool
        elif hasattr(tool, "function"):
            tool.function = _safe_tool

        wrapped_count += 1
        logger.debug("Wrapped AutoGen _tools entry %r → action=%r", tool_name, action)

    logger.info(
        "Wrapped AutoGen agent %r with %d tools",
        type(agent).__name__, wrapped_count,
    )
    return agent
