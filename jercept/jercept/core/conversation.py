"""
Jercept ConversationScope — multi-turn IBAC for stateful agent sessions.

Solves the core limitation of per-request scope: real agentic workflows
legitimately need more permissions as a task progresses across turns.

Example — travel booking agent:
    Turn 1: "book me a flight to Tokyo"
        → scope: api.call [flight-search.*], file.read [calendar.*]
    Turn 2: agent needs email.send to confirm booking
        → ScopeExpansionRequest raised → caller approves → granted
    Turn 3: agent needs api.call [payment.*]
        → policy ceiling checked → auto-approved if policy allows it

The key guarantee: scope can only GROW if explicitly approved.
It can never grow to exceed the policy ceiling.
Injected instructions cannot trigger automatic expansion.

Usage::

    from jercept.core.conversation import ConversationScope, ExpansionMode

    session = ConversationScope(
        initial_request="book me a flight to Tokyo",
        policy=TRAVEL_AGENT_POLICY,
        expansion_mode=ExpansionMode.CONFIRM,
    )

    # Wrap your agent with the session
    agent = protect_agent(my_agent, session=session)

    # Turn 1
    result1 = await agent.run("book me a flight to Tokyo next Friday")

    # Turn 2 — may raise ScopeExpansionRequest if new action needed
    try:
        result2 = await agent.run("confirm the booking and send me a summary")
    except ScopeExpansionRequest as req:
        print(f"Agent needs: {req.requested_action}")
        session.approve(req)   # or session.deny(req)
        result2 = await agent.run("confirm the booking and send me a summary")
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from jercept.core.scope import IBACScope, VALID_ACTIONS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Expansion modes
# ---------------------------------------------------------------------------

class ExpansionMode(str, Enum):
    """
    Controls how ConversationScope handles out-of-scope tool calls
    that are plausibly legitimate (not attacks).

    AUTO:
        If the policy ceiling permits the new action, grant it silently
        and continue. No interruption. Best for automated pipelines where
        a human is not available to approve.

    CONFIRM:
        Raise :class:`ScopeExpansionRequest` so the caller can decide.
        The agent is paused until the caller calls ``session.approve()``
        or ``session.deny()``. Best for interactive applications.

    DENY:
        Never expand scope mid-session. Out-of-scope actions always raise
        :class:`IBACScopeViolation`. Use when you want strict per-request
        scoping with no exceptions.
    """
    AUTO = "auto"
    CONFIRM = "confirm"
    DENY = "deny"


# ---------------------------------------------------------------------------
# ScopeExpansionRequest exception
# ---------------------------------------------------------------------------

class ScopeExpansionRequest(Exception):
    """
    Raised in CONFIRM mode when the agent needs an action outside the
    current session scope that the policy ceiling would permit.

    This is NOT an attack signal — it is a legitimate scope negotiation
    signal. The caller decides whether to approve or deny.

    Attributes:
        requested_action: The IBAC action string the agent needs.
        requested_resource: The resource the agent needs to access.
        fn_name: The tool function that triggered the request.
        turn: Which turn number this occurred on.
        reasoning: Why the agent needs this action (from audit context).
        session: The ConversationScope that raised this, for inline approval.

    Example::

        try:
            result = await agent.run("confirm booking and email me")
        except ScopeExpansionRequest as req:
            print(f"Agent wants to: {req.requested_action}")
            print(f"Triggered by tool: {req.fn_name}")
            req.session.approve(req)
            result = await agent.run("confirm booking and email me")
    """

    def __init__(
        self,
        requested_action: str,
        requested_resource: Optional[str],
        fn_name: str,
        turn: int,
        session: "ConversationScope",
        reasoning: str = "",
    ) -> None:
        self.requested_action = requested_action
        self.requested_resource = requested_resource
        self.fn_name = fn_name
        self.turn = turn
        self.session = session
        self.reasoning = reasoning

        super().__init__(
            f"Scope expansion needed: action={requested_action!r} "
            f"resource={requested_resource!r} tool={fn_name!r} "
            f"(turn {turn}). Call session.approve(request) to grant "
            f"or session.deny(request) to block."
        )


# ---------------------------------------------------------------------------
# ExpansionRecord — audit entry for each expansion decision
# ---------------------------------------------------------------------------

@dataclass
class ExpansionRecord:
    """Audit record for a single scope expansion event."""
    ts: float
    turn: int
    requested_action: str
    requested_resource: Optional[str]
    fn_name: str
    decision: str       # "approved", "denied", "auto_approved"
    decided_by: str     # "policy_auto", "caller", "deny_mode"


# ---------------------------------------------------------------------------
# ConversationScope
# ---------------------------------------------------------------------------

class ConversationScope:
    """
    Stateful IBAC scope that accumulates approved permissions across
    multiple turns of a multi-step agent conversation.

    The scope starts from the user's initial request and can grow
    during the conversation — but only if explicitly approved (CONFIRM mode)
    or permitted by the policy ceiling (AUTO mode).

    Key guarantees:
    - Scope can only GROW, never shrink during a session.
    - Scope can never exceed the policy ceiling.
    - Every expansion decision is recorded in the audit trail.
    - Injected instructions cannot trigger AUTO expansion because
      expansion is checked against the policy ceiling, not the LLM.

    Args:
        initial_request: The user's first natural language request.
            Used as the semantic anchor for the whole conversation.
        policy: Optional IBACPolicy ceiling. Expansions are only
            auto-approved if the policy permits the new action.
            If None, all AUTO expansions are permitted (less safe).
        expansion_mode: How to handle out-of-scope legitimate actions.
            Default: ExpansionMode.CONFIRM (safest for interactive apps).
        max_turns: Maximum number of turns allowed. Raises after this.
            Default: 20 (prevents runaway agent loops).
        max_expansions: Maximum number of scope expansions per session.
            Default: 10. Prevents infinite scope creep.

    Example::

        session = ConversationScope(
            initial_request="book a flight to Tokyo",
            policy=TRAVEL_AGENT_POLICY,
            expansion_mode=ExpansionMode.AUTO,
        )
        agent = protect_agent(my_agent, session=session)
        result = await agent.run("book me a flight to Tokyo next Friday")
        result = await agent.run("now add it to my calendar")
    """

    def __init__(
        self,
        initial_request: str,
        policy: Optional[Any] = None,
        expansion_mode: ExpansionMode = ExpansionMode.CONFIRM,
        max_turns: int = 20,
        max_expansions: int = 10,
    ) -> None:
        self.initial_request = initial_request
        self.expansion_mode = expansion_mode
        self.max_turns = max_turns
        self.max_expansions = max_expansions

        # CRITICAL 3 FIX: AUTO mode with no policy is dangerous.
        # Without a policy ceiling, AUTO will expand to ANY action including
        # db.export, db.delete, and code.execute with no restriction.
        # Apply a safe default ceiling when AUTO is used without an explicit policy.
        if policy is None and expansion_mode == ExpansionMode.AUTO:
            from jercept.policy import IBACPolicy
            policy = IBACPolicy(
                name="jercept-auto-default-ceiling",
                allowed_actions=[
                    "db.read", "db.write", "file.read", "file.write",
                    "email.read", "email.send", "api.call", "web.browse",
                ],
                denied_actions=[
                    "db.export", "db.delete", "code.execute", "file.download",
                ],
                description=(
                    "Default AUTO ceiling applied automatically. "
                    "Pass an explicit policy= to override. "
                    "Dangerous actions (db.export, db.delete, code.execute, "
                    "file.download) are blocked by this ceiling."
                ),
                version="auto",
            )
            logger.warning(
                "ConversationScope: AUTO mode used without an explicit policy. "
                "A safe default ceiling has been applied that blocks db.export, "
                "db.delete, code.execute, and file.download. "
                "Pass policy= explicitly to configure your own ceiling."
            )
        self.policy = policy

        # Current live scope — starts empty, filled after first extraction
        self._current_scope: Optional[IBACScope] = None

        # Accumulated approved actions across all turns
        self._approved_actions: Set[str] = set()
        self._approved_resources: Set[str] = set()

        # Explicitly denied actions for this session (never re-request)
        self._denied_actions: Set[str] = set()

        # Turn counter
        self._turn: int = 0

        # Expansion audit trail
        self._expansion_log: List[ExpansionRecord] = []

        # Full turn-by-turn audit
        self._turn_log: List[Dict[str, Any]] = []

        # Pending expansion request (set when CONFIRM mode raises)
        self._pending_expansion: Optional[ScopeExpansionRequest] = None

    # ── Turn management ────────────────────────────────────────────────

    def begin_turn(self, scope: IBACScope, _policy_already_applied: bool = False) -> IBACScope:
        """
        Start a new turn with a freshly extracted scope.

        Merges the new scope with previously approved actions, applies
        the policy ceiling, and returns the effective scope for this turn.

        Args:
            scope: Scope extracted from the current turn's user input.

        Returns:
            Merged IBACScope combining new intent + approved history.

        Raises:
            RuntimeError: If max_turns is exceeded.
        """
        self._turn += 1
        if self._turn > self.max_turns:
            raise RuntimeError(
                f"ConversationScope: max_turns ({self.max_turns}) exceeded. "
                f"Start a new session for a new task."
            )

        # Merge: new scope actions + all previously approved actions
        merged_allowed = list(
            set(scope.allowed_actions) | self._approved_actions
        )
        merged_resources = list(
            set(scope.allowed_resources) | self._approved_resources
        )
        # Denied: new scope denied + session-level denials
        merged_denied = list(
            set(scope.denied_actions) | self._denied_actions
        )

        merged = IBACScope(
            allowed_actions=merged_allowed,
            allowed_resources=merged_resources,
            denied_actions=merged_denied,
            raw_intent=scope.raw_intent,
            confidence=scope.confidence,
            ambiguous=scope.ambiguous,
        )

        # Apply policy ceiling — only if policy not already applied upstream.
        # Prevents double-application when callers pre-constrain the scope.
        if self.policy is not None and not _policy_already_applied:
            merged = self.policy.apply(merged)

        self._current_scope = merged

        # Record turn
        self._turn_log.append({
            "turn": self._turn,
            "ts": time.time(),
            "request": scope.raw_intent,
            "new_actions": list(set(scope.allowed_actions) - self._approved_actions),
            "effective_scope": merged.to_dict(),
        })

        logger.debug(
            "ConversationScope turn=%d effective_allowed=%s",
            self._turn, merged_allowed,
        )

        return merged

    # ── Expansion handling ─────────────────────────────────────────────

    def handle_expansion(
        self,
        action: str,
        resource: Optional[str],
        fn_name: str,
    ) -> bool:
        """
        Handle a request for an action outside the current session scope.

        Called by the enforcer when a tool call fails the scope check.
        Applies the expansion_mode policy to decide outcome.

        Returns:
            True if the action was auto-approved and execution should continue.

        Raises:
            ScopeExpansionRequest: In CONFIRM mode — caller must decide.
            IBACScopeViolation: In DENY mode, or if policy ceiling blocks it.
        """
        from jercept.core.exceptions import IBACScopeViolation

        # If explicitly denied this session, always block
        if action in self._denied_actions:
            logger.warning(
                "ConversationScope: action %r is session-denied", action
            )
            raise IBACScopeViolation(
                action=action,
                resource=resource,
                scope=self._current_scope,
            )

        # Check if we've hit the expansion limit
        approved_so_far = len([r for r in self._expansion_log if "approved" in r.decision])
        if approved_so_far >= self.max_expansions:
            logger.warning(
                "ConversationScope: max_expansions (%d) reached, blocking %r",
                self.max_expansions, action,
            )
            raise IBACScopeViolation(
                action=action,
                resource=resource,
                scope=self._current_scope,
            )

        if self.expansion_mode == ExpansionMode.DENY:
            # Strict mode — never expand
            self._record_expansion(action, resource, fn_name, "denied", "deny_mode")
            raise IBACScopeViolation(
                action=action,
                resource=resource,
                scope=self._current_scope,
            )

        # Check policy ceiling before any approval
        if self.policy is not None and not self._policy_permits(action):
            logger.warning(
                "ConversationScope: policy ceiling blocks expansion of %r", action
            )
            self._record_expansion(action, resource, fn_name, "denied", "policy_ceiling")
            raise IBACScopeViolation(
                action=action,
                resource=resource,
                scope=self._current_scope,
            )

        if self.expansion_mode == ExpansionMode.AUTO:
            # Policy permits it — grant silently
            self._grant(action, resource)
            self._record_expansion(action, resource, fn_name, "auto_approved", "policy_auto")
            logger.info(
                "ConversationScope: AUTO expanded scope with %r (turn %d)",
                action, self._turn,
            )
            return True  # caller should retry the tool call

        # CONFIRM mode — raise for caller decision
        req = ScopeExpansionRequest(
            requested_action=action,
            requested_resource=resource,
            fn_name=fn_name,
            turn=self._turn,
            session=self,
        )
        self._pending_expansion = req
        self._record_expansion(action, resource, fn_name, "pending", "awaiting_caller")
        raise req

    def approve(self, request: ScopeExpansionRequest) -> None:
        """
        Approve a pending ScopeExpansionRequest.

        Grants the requested action for the remainder of this session.
        The next call to the same tool will succeed.

        Args:
            request: The ScopeExpansionRequest to approve.
        """
        self._grant(request.requested_action, request.requested_resource)

        # Update the pending log entry to approved
        for record in reversed(self._expansion_log):
            if (record.requested_action == request.requested_action
                    and record.decision == "pending"):
                record.decision = "approved"
                record.decided_by = "caller"
                break

        self._pending_expansion = None
        logger.info(
            "ConversationScope: caller APPROVED expansion of %r",
            request.requested_action,
        )

    def deny(self, request: ScopeExpansionRequest) -> None:
        """
        Deny a pending ScopeExpansionRequest for the rest of this session.

        The denied action is added to the session-level deny list —
        any future attempt by the agent to call it will raise
        IBACScopeViolation immediately without another expansion request.

        Args:
            request: The ScopeExpansionRequest to deny.
        """
        self._denied_actions.add(request.requested_action)

        for record in reversed(self._expansion_log):
            if (record.requested_action == request.requested_action
                    and record.decision == "pending"):
                record.decision = "denied"
                record.decided_by = "caller"
                break

        self._pending_expansion = None
        logger.info(
            "ConversationScope: caller DENIED expansion of %r (session-blocked)",
            request.requested_action,
        )

    # ── Private helpers ────────────────────────────────────────────────

    def _grant(self, action: str, resource: Optional[str]) -> None:
        """Add action/resource to the approved set and rebuild current scope."""
        self._approved_actions.add(action)
        if resource:
            self._approved_resources.add(resource)

        # Rebuild current scope to include the new action
        if self._current_scope is not None:
            new_allowed = list(set(self._current_scope.allowed_actions) | {action})
            new_resources = list(set(self._current_scope.allowed_resources)
                                 | ({resource} if resource else set()))
            self._current_scope = IBACScope(
                allowed_actions=new_allowed,
                allowed_resources=new_resources,
                denied_actions=list(self._current_scope.denied_actions),
                raw_intent=self._current_scope.raw_intent,
                confidence=self._current_scope.confidence,
                ambiguous=self._current_scope.ambiguous,
            )

    def _policy_permits(self, action: str) -> bool:
        """Check if the policy ceiling would allow this action."""
        if self.policy is None:
            return True
        return self.policy._policy_allows(action) and not self.policy._policy_denies(action)

    def _record_expansion(
        self,
        action: str,
        resource: Optional[str],
        fn_name: str,
        decision: str,
        decided_by: str,
    ) -> None:
        self._expansion_log.append(ExpansionRecord(
            ts=time.time(),
            turn=self._turn,
            requested_action=action,
            requested_resource=resource,
            fn_name=fn_name,
            decision=decision,
            decided_by=decided_by,
        ))

    # ── Public inspection ──────────────────────────────────────────────

    @property
    def current_scope(self) -> Optional[IBACScope]:
        """The live scope for the current turn."""
        return self._current_scope

    @property
    def turn(self) -> int:
        """Current turn number (1-indexed)."""
        return self._turn

    @property
    def approved_actions(self) -> List[str]:
        """All actions approved so far across all turns."""
        return sorted(self._approved_actions)

    @property
    def denied_actions(self) -> List[str]:
        """Actions explicitly denied for this session."""
        return sorted(self._denied_actions)

    @property
    def expansion_log(self) -> List[Dict[str, Any]]:
        """Full audit trail of every expansion event."""
        return [
            {
                "ts": r.ts,
                "turn": r.turn,
                "action": r.requested_action,
                "resource": r.requested_resource,
                "fn_name": r.fn_name,
                "decision": r.decision,
                "decided_by": r.decided_by,
            }
            for r in self._expansion_log
        ]

    @property
    def turn_log(self) -> List[Dict[str, Any]]:
        """Full turn-by-turn audit trail."""
        return list(self._turn_log)

    @property
    def pending_expansion(self) -> Optional[ScopeExpansionRequest]:
        """The pending expansion request, if any (CONFIRM mode)."""
        return self._pending_expansion

    def summary(self) -> Dict[str, Any]:
        """Return a complete session summary for audit/dashboard."""
        return {
            "initial_request": self.initial_request,
            "turns_completed": self._turn,
            "approved_actions": self.approved_actions,
            "denied_actions": self.denied_actions,
            "expansions": len(self._expansion_log),
            "auto_approved": sum(1 for r in self._expansion_log if r.decision == "auto_approved"),
            "caller_approved": sum(1 for r in self._expansion_log if r.decision == "approved"),
            "denied": sum(1 for r in self._expansion_log if r.decision == "denied"),
            "current_scope": self._current_scope.to_dict() if self._current_scope else {},
            "expansion_log": self.expansion_log,
        }

    def reset(self) -> None:
        """
        Reset the session for a completely new user task.

        Clears all accumulated scope, turn history, and expansion log.
        The policy and expansion_mode settings are preserved.
        """
        self._current_scope = None
        self._approved_actions.clear()
        self._approved_resources.clear()
        self._denied_actions.clear()
        self._turn = 0
        self._expansion_log.clear()
        self._turn_log.clear()
        self._pending_expansion = None
        logger.debug("ConversationScope reset for new session")

    # ------------------------------------------------------------------
    # Persistence — serialise / deserialise for Redis or database storage
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Serialise the session state to a JSON-safe dictionary.

        Enables ConversationScope persistence across process restarts,
        pod restarts, or horizontal scale-out. Store in Redis or a DB
        and restore with :meth:`from_dict`.

        Returns:
            JSON-serialisable dict with all session state.

        Example::

            state = session.to_dict()
            redis.set(f"session:{user_id}", json.dumps(state), ex=3600)
        """
        return {
            "initial_request":    self.initial_request,
            "expansion_mode":     self.expansion_mode.value,
            "max_turns":          self.max_turns,
            "max_expansions":     self.max_expansions,
            "turn":               self._turn,
            "approved_actions":   list(self._approved_actions),
            "approved_resources": list(self._approved_resources),
            "denied_actions":     list(self._denied_actions),
            "current_scope":      self._current_scope.to_dict() if self._current_scope else None,
        }

    @classmethod
    def from_dict(cls, data: dict, policy: "Any" = None) -> "ConversationScope":
        """
        Restore a ConversationScope from a serialised dictionary.

        Args:
            data: Dict previously produced by :meth:`to_dict`.
            policy: Optional IBACPolicy ceiling — pass the same policy
                    that was used when the session was originally created.

        Returns:
            Restored :class:`ConversationScope` with all session state.

        Example::

            raw = redis.get(f"session:{user_id}")
            session = ConversationScope.from_dict(json.loads(raw), policy=policy)
        """
        from jercept.core.scope import IBACScope

        session = cls(
            initial_request = data["initial_request"],
            policy          = policy,
            expansion_mode  = ExpansionMode(data.get("expansion_mode", "confirm")),
            max_turns       = data.get("max_turns", 20),
            max_expansions  = data.get("max_expansions", 10),
        )
        session._turn               = data.get("turn", 0)
        session._approved_actions   = set(data.get("approved_actions", []))
        session._approved_resources = set(data.get("approved_resources", []))
        session._denied_actions     = set(data.get("denied_actions", []))

        scope_data = data.get("current_scope")
        if scope_data:
            session._current_scope = IBACScope.from_dict(scope_data)

        return session
