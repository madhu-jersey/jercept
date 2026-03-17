"""
Jercept IBACEnforcer module.

The enforcer wraps agent tool functions so that every invocation is checked
against the active IBACScope before execution. It also maintains a capped
audit log of every tool call — whether permitted or blocked.

Audit log is capped at MAX_AUDIT_ENTRIES (default 1000) to prevent unbounded
memory growth in long-running agentic workflows.
"""
from __future__ import annotations

import functools
import time
import logging
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from jercept.core.exceptions import IBACScopeViolation
from jercept.core.scope import IBACScope

logger = logging.getLogger(__name__)

# Maximum audit log entries — prevents unbounded memory growth in long sessions.
# Verified: 10,000 tool calls created a 10,000-entry list without this cap.
MAX_AUDIT_ENTRIES: int = 1_000

AuditEntry = Dict[str, Any]


class IBACEnforcer:
    """
    Runtime enforcement layer that gates every tool call against an IBACScope.

    The enforcer is created fresh for each agent session and receives the scope
    derived from that session's user intent. It wraps tool functions so that
    any out-of-scope call raises :class:`IBACScopeViolation` and is recorded
    in the audit log.

    The audit log is capped at MAX_AUDIT_ENTRIES entries. When the cap is
    reached, the oldest entries are dropped and ``audit_truncated`` is set
    to True so consumers know the log is incomplete.

    Attributes:
        scope: The :class:`IBACScope` governing this session.
        audit_log: Capped deque of tool call attempts (most recent 1000). O(1) eviction.
        audit_truncated: True if entries were dropped due to the cap.

    Example:
        >>> enforcer = IBACEnforcer(scope)
        >>> enforcer.check("db.read", "customer#123")   # permitted → True
        True
        >>> enforcer.check("db.export")                 # denied → raises
        IBACScopeViolation: ...
    """

    def __init__(
        self,
        scope: IBACScope,
        production_mode: bool = False,
        conversation_scope: Optional[Any] = None,
        max_audit_entries: int = MAX_AUDIT_ENTRIES,
    ) -> None:
        """
        Initialise an enforcer for the given session scope.

        Args:
            scope: The :class:`IBACScope` that governs what is allowed.
            production_mode: If ``True``, blocked actions raise sanitized
                exceptions to avoid leaking internal scope to users.
            conversation_scope: Optional ConversationScope for multi-turn.
            max_audit_entries: Cap on audit log size (default 1000).
        """
        self.scope: IBACScope = scope
        self.production_mode: bool = production_mode
        self.conversation_scope: Optional[Any] = conversation_scope
        self._max_audit: int = max_audit_entries
        # deque(maxlen) evicts oldest automatically in O(1) — no pop(0) needed.
        self.audit_log: Deque[AuditEntry] = deque(maxlen=max_audit_entries)
        self._total_logged: int = 0   # running count to detect truncation
        self.audit_truncated: bool = False

    # ------------------------------------------------------------------
    # Core check method
    # ------------------------------------------------------------------

    def check(self, action: str, resource: Optional[str] = None, fn_name: str = "") -> bool:
        """
        Check whether an action/resource pair is permitted by the scope.

        In single-turn mode: raises IBACScopeViolation on any denied action.

        In multi-turn mode (conversation_scope set): out-of-scope actions
        are first passed to ConversationScope.handle_expansion(). Depending
        on expansion_mode, this either auto-approves, raises
        ScopeExpansionRequest for caller approval, or hard-blocks.

        Always appends an entry to :attr:`audit_log` regardless of outcome.

        Args:
            action: The action string to check (e.g., ``"db.read"``).
            resource: Optional resource identifier (e.g., ``"customer#123"``).
            fn_name: Name of the originating tool function for audit purposes.

        Returns:
            ``True`` if the action is within scope.

        Raises:
            IBACScopeViolation: If the action/resource is not permitted.
            ScopeExpansionRequest: In CONFIRM mode when expansion is needed.
        """
        permitted: bool = self.scope.permits(action, resource)

        entry: AuditEntry = {
            "ts": time.time(),
            "action": action,
            "resource": resource,
            "permitted": permitted,
            "fn_name": fn_name,
        }
        # deque(maxlen) evicts the oldest entry automatically in O(1).
        self._total_logged += 1
        if self._total_logged > self._max_audit:
            self.audit_truncated = True
        self.audit_log.append(entry)

        if not permitted:
            # Multi-turn: delegate to conversation scope handler
            if self.conversation_scope is not None:
                auto_approved = self.conversation_scope.handle_expansion(
                    action, resource, fn_name
                )
                if auto_approved:
                    # Scope was expanded automatically — update our scope reference
                    # and mark this audit entry as permitted after the fact
                    self.scope = self.conversation_scope.current_scope
                    entry["permitted"] = True
                    entry["expanded"] = True
                    logger.info(
                        "IBAC AUTO-EXPANDED — action=%r resource=%r fn=%r",
                        action, resource, fn_name,
                    )
                    return True
                # handle_expansion raised ScopeExpansionRequest — propagate it

            logger.warning(
                "IBAC BLOCKED — action=%r resource=%r fn=%r intent=%r",
                action,
                resource,
                fn_name,
                self.scope.raw_intent[:80],
            )
            raise IBACScopeViolation(
                action=action,
                resource=resource,
                scope=self.scope,
                production_mode=self.production_mode,
            )


        logger.debug(
            "IBAC allowed — action=%r resource=%r fn=%r",
            action,
            resource,
            fn_name,
        )
        return True

    # ------------------------------------------------------------------
    # Tool-wrapping helper
    # ------------------------------------------------------------------

    def wrap(
        self,
        fn: Callable[..., Any],
        action: str,
        resource: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Wrap a tool function so every call is checked against the scope first.

        The returned function is a transparent proxy: it preserves the original
        function's ``__name__``, ``__doc__``, and all other metadata via
        :func:`functools.wraps`. It raises :class:`IBACScopeViolation` before
        the original function body is entered if the call is out of scope.

        Args:
            fn: The tool function to wrap.
            action: The IBAC action this function maps to.
            resource: Optional default resource for this tool, if fixed.

        Returns:
            A new callable that enforces the scope before calling ``fn``.

        Example:
            >>> safe_read = enforcer.wrap(db_read_fn, "db.read", "customer#123")
            >>> safe_read()   # permitted
            >>> safe_export = enforcer.wrap(db_export_fn, "db.export")
            >>> safe_export()  # raises IBACScopeViolation
        """
        fn_name: str = getattr(fn, "__name__", str(fn))

        @functools.wraps(fn)
        def _protected(*args: Any, **kwargs: Any) -> Any:
            self.check(action, resource, fn_name=fn_name)
            return fn(*args, **kwargs)

        return _protected

    # ------------------------------------------------------------------
    # Convenience properties (mirrors ProtectedAgent API surface)
    # ------------------------------------------------------------------

    @property
    def was_attacked(self) -> bool:
        """Return True if any tool call was blocked."""
        return any(not entry["permitted"] for entry in self.audit_log)

    @property
    def blocked_actions(self) -> List[str]:
        """Return a list of action strings that were blocked."""
        return [entry["action"] for entry in self.audit_log if not entry["permitted"]]
