"""
Jercept CrewAI adapter.

Wraps a CrewAI agent or Crew's tools with IBAC enforcement.
CrewAI tools use the same BaseTool interface as LangChain,
so we reuse the LangChain wrapping logic entirely.
"""
from __future__ import annotations

import logging
from typing import Any

from jercept.core.enforcer import IBACEnforcer

logger = logging.getLogger(__name__)


def wrap_crewai_agent(agent: Any, enforcer: IBACEnforcer) -> Any:
    """
    Wrap a CrewAI agent's tools with IBAC enforcement.

    CrewAI stores tools on agents as agent.tools (list of BaseTool),
    using the same interface as LangChain. We reuse the LangChain
    tool wrapping logic entirely.

    Args:
        agent: A CrewAI Agent or Crew instance.
        enforcer: The IBACEnforcer for the current session.

    Returns:
        The same agent object with tools wrapped (mutated in-place).

    Raises:
        ImportError: If the crewai package is not installed.
    """
    try:
        import crewai  # noqa: F401 — presence check only
    except ImportError as exc:
        raise ImportError(
            "crewai package is required for the CrewAI adapter. "
            "Install it with: pip install jercept[crewai]"
        ) from exc

    from jercept.adapters.langchain_adapter import _extract_tools, _wrap_tool
    from jercept.decorators import get_declared_actions
    from jercept.adapters.openai_adapter import _infer_action

    tools = _extract_tools(agent)

    if not tools:
        logger.warning(
            "wrap_crewai_agent: no tools found on agent %r",
            type(agent).__name__,
        )
        return agent

    for tool in tools:
        tool_name: str = getattr(tool, "name", "") or type(tool).__name__

        # Check for @ibac_tool declared actions first
        original_run = getattr(tool, "_run", None)
        declared = get_declared_actions(original_run) if original_run else None

        if declared:
            action = declared[0]
            logger.debug(
                "CrewAI tool %r: using declared action %r", tool_name, action
            )
            # Wrap manually using declared action
            from jercept.adapters.langchain_adapter import _wrap_tool as _base_wrap
            # Override the action by wrapping directly
            import functools

            if original_run is not None:
                @functools.wraps(original_run)
                def _safe_run(*args, _orig=original_run, _act=action, _name=tool_name, **kwargs):
                    enforcer.check(_act, fn_name=_name)
                    return _orig(*args, **kwargs)
                tool._run = _safe_run

            original_arun = getattr(tool, "_arun", None)
            if original_arun is not None:
                @functools.wraps(original_arun)
                async def _safe_arun(*args, _orig=original_arun, _act=action, _name=tool_name, **kwargs):
                    enforcer.check(_act, fn_name=_name)
                    return await _orig(*args, **kwargs)
                tool._arun = _safe_arun
        else:
            # Fall back to keyword inference
            _wrap_tool(tool, enforcer)

        logger.debug(
            "Wrapped CrewAI tool %r -> action=%r",
            tool_name,
            declared[0] if declared else _infer_action(tool_name),
        )

    logger.info(
        "Wrapped CrewAI agent %r with %d tools",
        type(agent).__name__,
        len(tools),
    )
    return agent
