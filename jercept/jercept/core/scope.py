"""
Jercept IBACScope module.

Defines the per-session permission boundary for an AI agent run. A scope is
derived from the user's intent and limits what actions and resources the agent
may access during that session.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from functools import lru_cache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action taxonomy — the only valid action strings in the IBAC model.
# ---------------------------------------------------------------------------
VALID_ACTIONS: frozenset[str] = frozenset(
    {
        "db.read",
        "db.write",
        "db.export",
        "db.delete",
        "file.read",
        "file.write",
        "file.upload",
        "file.download",
        "email.read",
        "email.send",
        "api.call",
        "web.browse",
        "code.execute",
    }
)

# Actions that are dangerous and must never be silently included by a wildcard.
DANGEROUS_ACTIONS: frozenset[str] = frozenset(
    {"db.export", "db.delete", "code.execute", "file.download"}
)

# Confidence BELOW (strictly less than) this threshold escalates to
# IBACExtractionFailed. Exactly 0.5 passes (>=). 0.499 fails (<).
MIN_CONFIDENCE_THRESHOLD: float = 0.5

# Maximum input length for safety — longer inputs are truncated.
MAX_INPUT_LENGTH: int = 10_000



# Regex special characters to escape in glob patterns.
# Intentionally excludes '.' so that namespace separators like "customer.*"
# match any separator character (including '#' used in resource IDs).
_GLOB_ESCAPE_RE = re.compile(r"([\[\](){}^$+?|\\])")


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """
    Convert a simple glob pattern (supports ``*`` only) to a compiled regex.

    ``*`` is converted to ``.*`` (match anything).
    ``.`` is intentionally left un-escaped so that namespace wildcards like
    ``"customer.*"`` match any resource separator (including ``#``), e.g.
    ``"customer#123"``.  All other regex special characters are escaped.

    Args:
        pattern: A glob-style string such as ``"db.*"`` or ``"customer#123"``.

    Returns:
        Compiled case-insensitive regex pattern.

    Examples:
        >>> _glob_to_regex("customer.*").match("customer#999")   # True
        >>> _glob_to_regex("db.*").match("db.read")             # True
        >>> _glob_to_regex("customer#123").match("customer#123")  # True
    """
    # Escape only chars that have regex meaning (but NOT '.' or '*')
    escaped = _GLOB_ESCAPE_RE.sub(r"\\\1", pattern)
    # Replace glob '*' with regex '.*'
    regex_str = escaped.replace("*", ".*")
    return re.compile(f"^{regex_str}$", re.IGNORECASE)



@dataclass(frozen=True)
class IBACScope:
    """
    Immutable permission boundary for a single AI agent session.

    An IBACScope describes exactly what actions and resources an agent is
    allowed to access during one execution, derived from the user's natural
    language request. It is the central data structure of the IBAC model.

    Attributes:
        allowed_actions: Actions the agent MAY perform (supports ``*`` globs).
        allowed_resources: Resources the agent MAY access (supports ``*`` globs).
        denied_actions: Actions explicitly forbidden (takes priority over allows).
        raw_intent: The original user request string — stored for audit trails.
        confidence: Extraction confidence scored 0.0–1.0 by the LLM.
        ambiguous: True when the request was too vague to produce a safe scope.

    Example:
        >>> scope = IBACScope(
        ...     allowed_actions=["db.read"],
        ...     allowed_resources=["customer#123"],
        ...     denied_actions=["db.export", "db.delete"],
        ...     raw_intent="check billing for customer 123",
        ...     confidence=0.97,
        ...     ambiguous=False,
        ... )
        >>> scope.permits("db.read", "customer#123")
        True
        >>> scope.permits("db.export", "customer#123")
        False
    """

    allowed_actions: Tuple[str, ...] = field(default_factory=tuple)
    allowed_resources: Tuple[str, ...] = field(default_factory=tuple)
    denied_actions: Tuple[str, ...] = field(default_factory=tuple)
    raw_intent: str = ""
    confidence: float = 0.0
    ambiguous: bool = False

    def __post_init__(self) -> None:
        """
        Coerce lists to tuples, pre-compile regex patterns, and warn on wildcards.

        Pre-compiling patterns at creation time means permits() never calls
        re.compile() — only pre-compiled pattern.match(). For a 10-action scope
        with 1000 tool calls this eliminates ~10,000 re.compile() calls per session.
        """
        # 1. Coerce any list/set input to tuple — true immutability.
        object.__setattr__(self, "allowed_actions",  tuple(self.allowed_actions))
        object.__setattr__(self, "allowed_resources", tuple(self.allowed_resources))
        object.__setattr__(self, "denied_actions",   tuple(self.denied_actions))

        # 2. Pre-compile all glob patterns once at construction.
        object.__setattr__(self, "_compiled_denied",
            tuple(_glob_to_regex(p) for p in self.denied_actions))
        object.__setattr__(self, "_compiled_allowed",
            tuple(_glob_to_regex(p) for p in self.allowed_actions))
        object.__setattr__(self, "_compiled_resources",
            tuple(_glob_to_regex(p) for p in self.allowed_resources))

        # 3. Warn when dangerous actions are implicitly included via wildcard.
        for pattern in self.allowed_actions:
            if "*" in pattern:
                implicitly_permitted = [
                    a for a in DANGEROUS_ACTIONS
                    if _glob_to_regex(pattern).match(a)
                    and a not in self.denied_actions
                ]
                if implicitly_permitted:
                    logger.warning(
                        "IBACScope WARNING: allowed_actions pattern %r implicitly "
                        "permits dangerous actions %s. Add them to denied_actions "
                        "explicitly or list only the actions you need.",
                        pattern,
                        implicitly_permitted,
                    )

    def permits(self, action: str, resource: Optional[str] = None) -> bool:
        """
        Determine whether an action (and optional resource) is permitted.

        Evaluation order (first match wins):
        1. **Explicit deny** — if ``action`` matches any entry in
           ``denied_actions``, return ``False`` immediately.
        2. **Action allow check** — ``action`` must match at least one entry
           in ``allowed_actions`` (glob matching, case-insensitive).
        3. **Resource check** — if ``resource`` is provided and
           ``allowed_resources`` is non-empty, the resource must match at
           least one allowed resource pattern; otherwise deny.

        Args:
            action: The action string to check (e.g., ``"db.read"``).
            resource: Optional resource identifier (e.g., ``"customer#123"``).

        Returns:
            ``True`` if the action/resource pair is within scope, else
            ``False``.

        Examples:
            >>> scope.permits("db.read")                    # action only
            True
            >>> scope.permits("db.read", "customer#123")    # with resource
            True
            >>> scope.permits("db.export", "customer#123")  # denied
            False
        """
        # Normalise action — strip whitespace and control characters.
        # "db.read\n" must NOT match "db.read" — newlines could be injected
        # by an attacker controlling tool names.
        if action is None:
            return False
        # Strip whitespace and control characters (null bytes, etc.) before matching.
        # str.strip() does not remove null bytes — explicit replacement needed.
        action_lower = action.strip().lower()
        # Remove null bytes and other ASCII control characters (U+0000-U+001F)
        action_lower = "".join(c for c in action_lower if ord(c) >= 0x20 or c in " ")
        action_lower = action_lower.strip()
        if not action_lower:
            return False

        # ── Step 1: Explicit deny wins (pre-compiled, O(n) no re.compile) ───
        for pattern in self._compiled_denied:  # type: ignore[attr-defined]
            if pattern.match(action_lower):
                return False

        # ── Step 2: Must match an allowed action ────────────────────────────
        if not any(p.match(action_lower)
                   for p in self._compiled_allowed):  # type: ignore[attr-defined]
            return False

        # ── Step 3: Resource check (only if resources are scoped) ───────────
        if resource is not None and self.allowed_resources:
            resource_lower = resource.lower()
            if not any(p.match(resource_lower)
                       for p in self._compiled_resources):  # type: ignore[attr-defined]
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise the scope to a plain dictionary suitable for JSON export.

        Returns:
            A dictionary with all scope fields as JSON-serialisable values.

        Example:
            >>> scope.to_dict()
            {'allowed_actions': ['db.read'], 'allowed_resources': [...], ...}
        """
        return {
            "allowed_actions": list(self.allowed_actions),
            "allowed_resources": list(self.allowed_resources),
            "denied_actions": list(self.denied_actions),
            "raw_intent": self.raw_intent,
            "confidence": self.confidence,
            "ambiguous": self.ambiguous,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IBACScope":
        """
        Deserialise an IBACScope from a plain dictionary.

        Allows reconstruction from audit logs, dashboard API responses,
        stored policy records, or any JSON source. Unknown keys are silently
        ignored for forward compatibility.

        Args:
            data: Dictionary as produced by :meth:`to_dict`.

        Returns:
            A new :class:`IBACScope` instance.

        Raises:
            ValueError: If ``data`` is not a dict.

        Example:
            >>> d = scope.to_dict()
            >>> restored = IBACScope.from_dict(d)
            >>> restored.allowed_actions == scope.allowed_actions
            True
        """
        if not isinstance(data, dict):
            raise ValueError(
                f"IBACScope.from_dict() requires a dict, got {type(data).__name__}"
            )
        return cls(
            allowed_actions=list(data.get("allowed_actions", [])),
            allowed_resources=list(data.get("allowed_resources", [])),
            denied_actions=list(data.get("denied_actions", [])),
            raw_intent=str(data.get("raw_intent", "")),
            confidence=float(data.get("confidence", 0.0)),
            ambiguous=bool(data.get("ambiguous", False)),
        )
