"""
Jercept LangChain adapter.

Wraps a LangChain agent's tools with IBAC enforcement so every tool call
is checked against the active IBACScope before execution.
"""
from __future__ import annotations

import logging
from typing import Any

from jercept.adapters.openai_adapter import _infer_action
from jercept.core.enforcer import IBACEnforcer

logger = logging.getLogger(__name__)


def wrap_langchain_agent(agent: Any, enforcer: IBACEnforcer) -> Any:
    """
    Wrap a LangChain agent's tools with IBAC enforcement.

    Supports both ``AgentExecutor`` (has a ``.tools`` list) and lower-level
    LangChain agent structures (``agent.agent.llm_chain``). Each tool's
    ``_run`` and ``_arun`` methods are wrapped in-place on the tool object.

    Args:
        agent: A LangChain ``AgentExecutor`` or raw agent object.
        enforcer: The :class:`IBACEnforcer` for the current session.

    Returns:
        The same agent object with tools wrapped (LangChain agents are
        mutable; mutation is the idiomatic approach here).

    Raises:
        ImportError: If the ``langchain`` package is not installed.

    Example:
        >>> from jercept.adapters.langchain_adapter import wrap_langchain_agent
        >>> protected = wrap_langchain_agent(executor, enforcer)
        >>> result = await protected.ainvoke({"input": "check billing"})
    """
    try:
        import langchain  # noqa: F401 — presence check only
    except ImportError as exc:
        raise ImportError(
            "langchain package is required for the LangChain adapter. "
            "Install it with: pip install jercept[langchain]"
        ) from exc

    tools = _extract_tools(agent)

    if not tools:
        logger.warning(
            "wrap_langchain_agent: no tools found on agent %r — nothing to wrap",
            type(agent).__name__,
        )
        return agent

    for tool in tools:
        _wrap_tool(tool, enforcer)
        logger.debug(
            "Wrapped LangChain tool %r → action=%r",
            getattr(tool, "name", repr(tool)),
            _infer_action(getattr(tool, "name", "")),
        )

    logger.info(
        "Wrapped LangChain agent %r with %d tools",
        type(agent).__name__,
        len(tools),
    )
    return agent


def _extract_tools(agent: Any) -> list[Any]:
    """
    Extract the list of tool objects from a LangChain agent structure.

    LangChain stores tools in different places depending on the agent class:
    - ``AgentExecutor.tools`` — standard attribute on the executor
    - ``agent.agent.tools`` — on the inner agent
    - ``agent.agent.llm_chain`` — for chain-based constructions

    Args:
        agent: Any LangChain agent object.

    Returns:
        A list of tool objects (may be empty).
    """
    # Direct tools attribute (AgentExecutor, newer LangGraph agents)
    if hasattr(agent, "tools") and isinstance(agent.tools, (list, tuple)):
        return list(agent.tools)

    # Nested agent.agent.tools
    inner = getattr(agent, "agent", None)
    if inner is not None:
        if hasattr(inner, "tools") and isinstance(inner.tools, (list, tuple)):
            return list(inner.tools)
        # Chain-based agent: tools stored on the chain
        chain = getattr(inner, "llm_chain", None)
        if chain is not None and hasattr(chain, "tools"):
            return list(chain.tools)

    return []


def _wrap_tool(tool: Any, enforcer: IBACEnforcer) -> None:
    """
    Mutate a single LangChain tool object to inject IBAC enforcement.

    Wraps the ``_run`` method (synchronous) and ``_arun`` method
    (asynchronous) if present. Uses :func:`~csm.adapters.openai_adapter._infer_action`
    to determine the IBAC action string.

    Args:
        tool: A LangChain ``BaseTool`` (or compatible duck-typed tool).
        enforcer: The :class:`IBACEnforcer` for the current session.
    """
    from jercept.decorators import get_declared_actions
    
    tool_name: str = getattr(tool, "name", "") or type(tool).__name__
    
    # ── Wrap synchronous _run ────────────────────────────────────────────────
    original_run = getattr(tool, "_run", None)
    if original_run is not None:
        declared = get_declared_actions(original_run)
        action: str = declared[0] if declared else _infer_action(tool_name)
        
        def _safe_run(*args: Any, _orig=original_run, _act=action, _name=tool_name, **kwargs: Any) -> Any:
            enforcer.check(_act, fn_name=_name)
            return _orig(*args, **kwargs)

        try:
            _safe_run.__name__ = getattr(original_run, "__name__", "_run")
            _safe_run.__doc__ = original_run.__doc__
        except AttributeError:
            pass
        tool._run = _safe_run  # type: ignore[method-assign]

    # ── Wrap asynchronous _arun ──────────────────────────────────────────────
    original_arun = getattr(tool, "_arun", None)
    if original_arun is not None:
        declared_async = get_declared_actions(original_arun)
        action_async: str = declared_async[0] if declared_async else _infer_action(tool_name)

        async def _safe_arun(*args: Any, _orig=original_arun, _act=action_async, _name=tool_name, **kwargs: Any) -> Any:
            enforcer.check(_act, fn_name=_name)
            return await _orig(*args, **kwargs)

        try:
            _safe_arun.__name__ = getattr(original_arun, "__name__", "_arun")
            _safe_arun.__doc__ = original_arun.__doc__
        except AttributeError:
            pass
        tool._arun = _safe_arun  # type: ignore[method-assign]

