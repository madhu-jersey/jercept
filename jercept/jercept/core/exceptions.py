"""
Jercept exceptions module.

Defines the core exception hierarchy for IBAC (Intent-Based Access Control).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from jercept.core.scope import IBACScope


class IBACScopeViolation(PermissionError):
    """
    Raised when an agent tool call violates the active IBAC session scope.

    This exception is the primary enforcement mechanism — it is raised whenever
    the IBACEnforcer detects an action that was not explicitly permitted by the
    scope derived from the user's original request.

    Attributes:
        action: The action that was attempted (e.g., ``"db.export"``).
        resource: The resource that was targeted, if provided.
        scope: The IBACScope that denied the action.
        production_mode: Whether the sanitized message is used.

    Example::

        >>> try:
        ...     enforcer.check("db.export", "customers")
        ... except IBACScopeViolation as e:
        ...     print(f"Blocked: {e.action} on {e.resource}")
    """

    def __init__(
        self,
        action: str,
        resource: Optional[str],
        scope: "IBACScope",
        production_mode: bool = False,
    ) -> None:
        """
        Initialise the exception with full context for audit and debugging.

        Args:
            action: The action string attempted (e.g., ``"db.export"``).
            resource: The resource string targeted, or ``None``.
            scope: The :class:`IBACScope` that blocked this action.
            production_mode: When ``True``, ``str(exc)`` emits a generic message
                that does not reveal scope internals to potential attackers.
                Full details remain accessible via ``exc.action``, ``exc.resource``,
                and ``exc.scope`` for audit logging. Default: ``False``.
        """
        self.action = action
        self.resource = resource
        self.scope = scope
        self.production_mode = production_mode

        if production_mode:
            # Safe for external-facing logs — no scope details exposed.
            message = (
                "Request blocked by security policy. "
                "This incident has been logged."
            )
        else:
            # Detailed message for development and internal debugging.
            allowed_summary = (
                ", ".join(scope.allowed_actions) if scope.allowed_actions else "(none)"
            )
            resource_summary = f" on resource '{resource}'" if resource else ""
            message = (
                f"IBAC SCOPE VIOLATION: Action '{action}'{resource_summary} is NOT permitted. "
                f"Allowed actions for this session: [{allowed_summary}]. "
                f"Original intent: \"{scope.raw_intent}\". "
                f"If this action is legitimate, ensure the user's request explicitly includes it."
            )

        super().__init__(message)


class IBACExtractionFailed(ValueError):
    """
    Raised when the IntentExtractor cannot produce a valid IBACScope.

    This exception covers all failure modes of the intent extraction step:
    - LLM API call failure
    - Invalid or non-JSON response
    - Ambiguous user request (confidence too low)
    - Missing required fields in the extracted JSON

    Attributes:
        reason: A human-readable explanation of why extraction failed.
        original_request: The user request that could not be extracted.

    Example::

        >>> try:
        ...     scope = extractor.extract("help me")
        ... except IBACExtractionFailed as e:
        ...     print(f"Cannot determine safe scope: {e.reason}")
    """

    def __init__(
        self,
        reason: str,
        original_request: Optional[str] = None,
        cause: Optional[Exception] = None,
    ) -> None:
        """
        Initialise the exception with extraction failure context.

        Args:
            reason: Human-readable explanation of the failure.
            original_request: The user's original request string, if available.
            cause: The underlying exception that triggered this failure, if any.
        """
        self.reason = reason
        self.original_request = original_request

        request_context = (
            f" (request: \"{original_request}\")" if original_request else ""
        )
        message = (
            f"IBAC extraction failed{request_context}: {reason}. "
            f"Cannot determine a safe permission scope — agent execution halted. "
            f"Clarify the request or check your OpenAI API key."
        )
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause
