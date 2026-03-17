"""
Jercept LlamaIndex adapter.

Wraps LlamaIndex FunctionTool objects by replacing their call()
and acall() methods with IBAC-checked versions.
"""
from __future__ import annotations

import functools
import logging
from typing import Any

from jercept.core.enforcer import IBACEnforcer

logger = logging.getLogger(__name__)


def wrap_llamaindex_agent(agent: Any, enforcer: IBACEnforcer) -> Any:
    """
    Wrap a LlamaIndex agent's tools with IBAC enforcement.

    LlamaIndex agents use FunctionTool / BaseTool objects. Tools are
    stored in agent.tools, agent._tools, or accessible via tool_retriever.
    We wrap call() and acall() on each tool object.

    Args:
        agent: LlamaIndex AgentRunner, ReActAgent, or OpenAIAgent instance.
        enforcer: IBACEnforcer for the current session.

    Returns:
        The same agent with all tool call() / acall() methods wrapped.

    Raises:
        ImportError: If llama_index is not installed.

    Example::

        from jercept.adapters.llamaindex_adapter import wrap_llamaindex_agent

        protected = wrap_llamaindex_agent(my_llama_agent, enforcer)
    """
    # Optional import — works via duck typing on .tools attribute
    _has_llama = False
    try:
        import llama_index  # noqa: F401
        _has_llama = True
    except ImportError:
        try:
            import llama_index.core  # noqa: F401
            _has_llama = True
        except ImportError:
            pass

    if not _has_llama:
        has_tools = (
            hasattr(agent, "tools") or
            hasattr(agent, "_tools") or
            hasattr(agent, "tool_retriever")
        )
        if not has_tools:
            raise ImportError(
                "llama-index is required. Install: pip install llama-index"
            )

    tools = _extract_llamaindex_tools(agent)

    if not tools:
        logger.warning(
            "wrap_llamaindex_agent: no tools found on agent %r",
            type(agent).__name__,
        )
        return agent

    for tool in tools:
        _wrap_llamaindex_tool(tool, enforcer)

    logger.info(
        "Wrapped LlamaIndex agent %r with %d tools",
        type(agent).__name__, len(tools),
    )
    return agent


def _extract_llamaindex_tools(agent: Any) -> list:
    """
    Extract tool objects from various LlamaIndex agent types.

    Checks multiple attribute paths used by different LlamaIndex
    agent implementations.

    Args:
        agent: Any LlamaIndex agent object.

    Returns:
        List of tool objects (may be empty).
    """
    # Direct .tools attribute (most common)
    if hasattr(agent, "tools") and isinstance(agent.tools, (list, tuple)):
        return list(agent.tools)

    # Internal ._tools attribute
    if hasattr(agent, "_tools") and isinstance(agent._tools, (list, tuple)):
        return list(agent._tools)

    # AgentRunner with tool_retriever
    if hasattr(agent, "tool_retriever"):
        try:
            return list(agent.tool_retriever.retrieve(""))
        except Exception:
            pass

    # AgentWorker pattern
    worker = getattr(agent, "_agent_worker", None)
    if worker is not None:
        if hasattr(worker, "tools"):
            return list(worker.tools)
        if hasattr(worker, "_tools"):
            return list(worker._tools)

    return []


def _wrap_llamaindex_tool(tool: Any, enforcer: IBACEnforcer) -> None:
    """
    Wrap a single LlamaIndex BaseTool's call() and acall() methods.

    Args:
        tool: A LlamaIndex BaseTool or FunctionTool instance.
        enforcer: IBACEnforcer for the current session.
    """
    from jercept.adapters.openai_adapter import _infer_action
    from jercept.decorators import get_declared_actions

    # Resolve tool name from metadata or fallback
    metadata = getattr(tool, "metadata", None)
    tool_name = (
        getattr(metadata, "name", None)
        or getattr(tool, "name", None)
        or type(tool).__name__
    )

    # Infer IBAC action
    original_call = getattr(tool, "call", None)
    declared = get_declared_actions(original_call) if original_call else None
    action = declared[0] if declared else _infer_action(tool_name)

    # Wrap synchronous call()
    if original_call is not None:
        @functools.wraps(original_call)
        def _safe_call(*args, _fn=original_call, _act=action, _name=tool_name, **kwargs):
            enforcer.check(_act, fn_name=_name)
            return _fn(*args, **kwargs)
        tool.call = _safe_call

    # Wrap async acall()
    original_acall = getattr(tool, "acall", None)
    if original_acall is not None:
        @functools.wraps(original_acall)
        async def _safe_acall(*args, _fn=original_acall, _act=action, _name=tool_name, **kwargs):
            enforcer.check(_act, fn_name=_name)
            return await _fn(*args, **kwargs)
        tool.acall = _safe_acall

    logger.debug("Wrapped LlamaIndex tool %r → action=%r", tool_name, action)
