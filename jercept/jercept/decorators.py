"""
Jercept decorators — explicit IBAC action metadata for tool functions.

Usage::

    from jercept import ibac_tool

    @ibac_tool("db.export")
    def crm_sync() -> str:
        ...

    @ibac_tool("db.write", "email.send")
    def process_invoice(invoice_id: str) -> str:
        ...
"""
from __future__ import annotations

from typing import Callable

# Attribute name stored on decorated functions.
IBAC_ACTION_ATTR: str = "_ibac_actions"

# Complete valid IBAC action taxonomy.
_VALID_ACTIONS: frozenset[str] = frozenset({
    "db.read", "db.write", "db.export", "db.delete",
    "file.read", "file.write", "file.upload", "file.download",
    "email.read", "email.send",
    "api.call", "web.browse", "code.execute",
})


def ibac_tool(*actions: str) -> Callable:
    """
    Decorator that explicitly declares the IBAC actions a tool performs.

    Overrides automatic keyword inference in all adapters (OpenAI, LangChain,
    CrewAI). Use this when your tool name is unconventional or ambiguous.

    The **first** action in the list is treated as the "primary" action —
    the one used for scope enforcement. Additional actions are stored for
    audit and documentation purposes.

    Args:
        *actions: One or more IBAC action strings this tool performs.
                  Use the most permissive action the tool can perform.

    Returns:
        The original function, unchanged, with ``_ibac_actions`` attribute set.

    Raises:
        ValueError: If any action string is not in the valid IBAC taxonomy.
                    Raised immediately at decoration time (import time), not
                    at runtime — so misconfigured tools fail fast.

    Example::

        @ibac_tool("db.export")
        def crm_sync() -> str:
            return export_all_crm_data()

        @ibac_tool("db.write", "email.send")
        def process_invoice(invoice_id: str) -> str:
            update_invoice(invoice_id)
            send_confirmation_email(invoice_id)
            return "done"
    """
    if not actions:
        raise ValueError(
            "ibac_tool() requires at least one action. "
            f"Valid actions: {sorted(_VALID_ACTIONS)}"
        )
    for action in actions:
        if action not in _VALID_ACTIONS:
            raise ValueError(
                f"Unknown IBAC action: {action!r}. "
                f"Valid actions: {sorted(_VALID_ACTIONS)}"
            )

    def decorator(fn: Callable) -> Callable:
        """Apply IBAC action declaration to a tool function."""
        setattr(fn, IBAC_ACTION_ATTR, list(actions))
        return fn

    return decorator


def get_declared_actions(fn: object) -> list[str] | None:
    """
    Return the explicitly declared IBAC actions from a decorated function.

    Used by adapters to skip keyword inference when ``@ibac_tool`` metadata
    is present on the underlying function.

    Args:
        fn: Any callable (or object with a callable attribute).

    Returns:
        List of declared action strings if ``@ibac_tool`` was applied,
        otherwise ``None``.

    Example::

        @ibac_tool("db.read")
        def get_customer(id: str): ...

        get_declared_actions(get_customer)  # ["db.read"]
        get_declared_actions(lambda x: x)  # None
    """
    return getattr(fn, IBAC_ACTION_ATTR, None)