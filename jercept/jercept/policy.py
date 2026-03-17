"""
Jercept IBACPolicy — enterprise policy composability.

Defines pre-approved action ceilings per agent role. The session scope
is the INTERSECTION of the user's extracted intent and the policy ceiling.
Result: zero-config for simple cases, enterprise control when needed.
"""
from __future__ import annotations
import functools

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from jercept.core.scope import IBACScope

logger = logging.getLogger(__name__)

# Single source of truth — import from core.scope to avoid DRY violation
from jercept.core.scope import VALID_ACTIONS  # noqa: E402

ALL_ACTIONS: List[str] = sorted(VALID_ACTIONS)  # stable ordered list


@dataclass
class IBACPolicy:
    """
    Pre-approved action ceiling for an agent role.

    Defines the maximum permissions an agent may ever receive,
    regardless of what the user requests. The session scope is
    the INTERSECTION of user intent and the policy ceiling.

    If a user requests an action the policy permits, IBAC grants it.
    If a user requests an action the policy does not permit, it is
    NEVER granted even if the LLM extraction would allow it.

    Args:
        name: Human-readable policy name.
        allowed_actions: Actions this agent role MAY ever perform.
                         Supports glob patterns: ["db.*"] or specific actions.
        denied_actions: Actions always denied regardless of user intent.
        allowed_resources: Resource patterns this agent may access.
        max_confidence_required: Minimum extraction confidence to proceed.
        description: Human-readable description for audit/compliance.
        version: Policy version string for change tracking.

    Example::

        from jercept.policy import IBACPolicy

        billing_policy = IBACPolicy(
            name="billing-agent-readonly",
            allowed_actions=["db.read", "email.send"],
            denied_actions=["db.delete", "db.export", "db.write",
                            "code.execute", "api.call"],
            allowed_resources=["customer.*", "billing.*"],
            description="Billing support agent — read-only",
        )

        agent = protect_agent(my_agent, policy=billing_policy)
    """

    name: str
    allowed_actions: List[str] = field(default_factory=list)
    denied_actions: List[str] = field(default_factory=list)
    allowed_resources: List[str] = field(default_factory=list)
    max_confidence_required: float = 0.6
    description: str = ""
    version: str = "1.0"

    def __post_init__(self) -> None:
        for action in list(self.allowed_actions) + list(self.denied_actions):
            if action == "*":
                continue
            if action.endswith(".*"):
                prefix = action[:-2]
                if not any(v.startswith(prefix + ".") for v in VALID_ACTIONS):
                    raise ValueError(
                        f"IBACPolicy {self.name!r}: unknown action prefix {action!r}"
                    )
            elif action not in VALID_ACTIONS:
                raise ValueError(
                    f"IBACPolicy {self.name!r}: unknown action {action!r}. "
                    f"Valid: {sorted(VALID_ACTIONS)}"
                )

    @functools.cached_property
    def _policy_ceiling_denied(self) -> list:
        """
        Pre-compute the list of ALL_ACTIONS that this policy denies.

        Cached as a property so apply() doesn't iterate ALL_ACTIONS on
        every single agent run — computed once per IBACPolicy instance.
        """
        return [a for a in ALL_ACTIONS if self._policy_denies(a)]

    def _matches(self, action: str, pattern: str) -> bool:
        """Check if action matches a policy pattern (supports glob)."""
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return action.startswith(prefix + ".")
        return action == pattern

    def _policy_allows(self, action: str) -> bool:
        return any(self._matches(action, p) for p in self.allowed_actions)

    def _policy_denies(self, action: str) -> bool:
        return any(self._matches(action, p) for p in self.denied_actions)

    def apply(self, scope: "IBACScope") -> "IBACScope":
        """
        Intersect a user-derived scope with this policy ceiling.

        Returns a new IBACScope containing only actions permitted by
        BOTH the user's intent AND this policy.

        Args:
            scope: IBACScope derived from user intent.

        Returns:
            New IBACScope constrained by this policy.
        """
        from jercept.core.scope import IBACScope

        # Intersection: keep only actions allowed by both user AND policy
        constrained_allowed = [
            a for a in scope.allowed_actions
            if self._policy_allows(a) and not self._policy_denies(a)
        ]

        # Union of denied: scope denied + policy denied.
        # _policy_ceiling_denied is computed once and cached per policy instance.
        extra_denied = [
            a for a in self._policy_ceiling_denied
            if a not in scope.denied_actions
        ]
        combined_denied = list(set(list(scope.denied_actions) + extra_denied))

        # Resource: use scope resources if both constrained, else most restrictive
        if self.allowed_resources and scope.allowed_resources:
            constrained_resources = scope.allowed_resources
        elif self.allowed_resources:
            constrained_resources = self.allowed_resources
        else:
            constrained_resources = scope.allowed_resources

        logger.debug(
            "Policy %r applied: %s → %s",
            self.name, scope.allowed_actions, constrained_allowed
        )

        return IBACScope(
            allowed_actions=constrained_allowed,
            allowed_resources=constrained_resources,
            denied_actions=combined_denied,
            raw_intent=scope.raw_intent,
            confidence=scope.confidence,
            ambiguous=scope.ambiguous,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the policy to a plain dictionary for JSON export."""
        return {
            "name": self.name,
            "version": self.version,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "allowed_resources": self.allowed_resources,
            "max_confidence_required": self.max_confidence_required,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IBACPolicy":
        """
        Construct an IBACPolicy from a plain dictionary.

        Useful for loading policies from a database, an API response,
        or any JSON/dict source. Unknown keys are silently ignored.

        Args:
            data: Dictionary with policy fields (as produced by
                  :meth:`to_dict`).

        Returns:
            A new :class:`IBACPolicy` instance.

        Raises:
            ValueError: If ``data`` is not a dict or ``name`` is missing.
            ValueError: If any action in the policy is invalid.

        Example::

            d = {
                "name": "my-policy",
                "allowed_actions": ["db.read", "email.send"],
                "denied_actions": ["db.delete", "code.execute"],
            }
            policy = IBACPolicy.from_dict(d)
        """
        if not isinstance(data, dict):
            raise ValueError(
                f"IBACPolicy.from_dict() requires a dict, got {type(data).__name__}"
            )
        if "name" not in data:
            raise ValueError("IBACPolicy.from_dict() requires a 'name' field")
        return cls(
            name=str(data["name"]),
            allowed_actions=list(data.get("allowed_actions", [])),
            denied_actions=list(data.get("denied_actions", [])),
            allowed_resources=list(data.get("allowed_resources", [])),
            max_confidence_required=float(data.get("max_confidence_required", 0.6)),
            description=str(data.get("description", "")),
            version=str(data.get("version", "1.0")),
        )

    @classmethod
    def from_yaml(cls, path: str) -> "IBACPolicy":
        """
        Load an IBACPolicy from a YAML file.

        Enables GitOps-style policy management — policies live in version-
        controlled YAML files alongside your agent code, not hard-coded in
        Python.

        The YAML file must contain a top-level ``policy`` key or be a flat
        mapping of policy fields. Both formats are accepted:

        Flat format::

            name: billing-agent
            allowed_actions:
              - db.read
              - email.send
            denied_actions:
              - db.delete
              - code.execute
            description: Billing support agent

        Nested format::

            policy:
              name: billing-agent
              allowed_actions: [db.read, email.send]

        Args:
            path: Absolute or relative path to the YAML file.

        Returns:
            A new :class:`IBACPolicy` instance.

        Raises:
            ImportError: If PyYAML (``pyyaml``) is not installed.
            FileNotFoundError: If the file does not exist.
            ValueError: If the YAML is malformed or ``name`` is missing.

        Example::

            from jercept.policy import IBACPolicy

            policy = IBACPolicy.from_yaml("policies/billing_agent.yaml")
            agent = protect_agent(my_agent, policy=policy)
        """
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required for IBACPolicy.from_yaml(). "
                "Install it with: pip install pyyaml"
            ) from exc

        import os
        if not os.path.exists(path):
            raise FileNotFoundError(f"Policy file not found: {path!r}")

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError(
                f"Policy YAML must be a mapping, got {type(raw).__name__}: {path!r}"
            )

        # Support both flat and nested {"policy": {...}} formats
        data = raw.get("policy", raw)
        return cls.from_dict(data)


# ── Pre-built policies ────────────────────────────────────────────────

READONLY_DB_POLICY = IBACPolicy(
    name="readonly-db",
    allowed_actions=["db.read", "file.read", "email.read"],
    denied_actions=["db.write", "db.export", "db.delete",
                    "code.execute", "api.call", "web.browse"],
    description="Read-only database access. No writes, exports, or code execution.",
)

BILLING_AGENT_POLICY = IBACPolicy(
    name="billing-agent",
    allowed_actions=["db.read", "email.send"],
    denied_actions=["db.write", "db.export", "db.delete",
                    "code.execute", "api.call", "web.browse"],
    allowed_resources=["customer.*", "billing.*", "invoice.*", "payment.*"],
    description="Billing support: read customer billing data, send emails only.",
)

SUPPORT_AGENT_POLICY = IBACPolicy(
    name="support-agent",
    allowed_actions=["db.read", "email.read", "email.send", "file.read"],
    denied_actions=["db.write", "db.export", "db.delete",
                    "code.execute", "api.call"],
    description="Customer support: read data and communicate, no mutations.",
)

DEVOPS_AGENT_POLICY = IBACPolicy(
    name="devops-agent",
    allowed_actions=["file.read", "file.write", "code.execute",
                     "api.call", "web.browse"],
    denied_actions=["db.export", "db.delete", "email.send"],
    description="DevOps: file ops and code execution, no database destruction.",
)