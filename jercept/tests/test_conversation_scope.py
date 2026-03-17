"""
Tests for jercept.core.conversation — ConversationScope, ExpansionMode,
ScopeExpansionRequest — v0.5.0 multi-turn IBAC.

All tests run without a real OpenAI API key.
"""
from __future__ import annotations

import pytest
from jercept.core.conversation import (
    ConversationScope,
    ExpansionMode,
    ScopeExpansionRequest,
)
from jercept.core.scope import IBACScope
from jercept.core.enforcer import IBACEnforcer
from jercept.core.exceptions import IBACScopeViolation
from jercept.policy import BILLING_AGENT_POLICY, DEVOPS_AGENT_POLICY, IBACPolicy


# ── Helpers ────────────────────────────────────────────────────────────────

def _scope(allowed, resources=None, denied=None, intent="test"):
    return IBACScope(
        allowed_actions=allowed,
        allowed_resources=resources or [],
        denied_actions=denied or [],
        raw_intent=intent,
        confidence=0.92,
        ambiguous=False,
    )


def _session(mode=ExpansionMode.CONFIRM, policy=None, **kw):
    return ConversationScope(
        initial_request="test session",
        expansion_mode=mode,
        policy=policy,
        **kw,
    )


# ── Init and basic state ───────────────────────────────────────────────────

class TestConversationScopeInit:
    def test_defaults(self):
        s = ConversationScope(initial_request="book a flight")
        assert s.initial_request == "book a flight"
        assert s.expansion_mode == ExpansionMode.CONFIRM
        assert s.turn == 0
        assert s.current_scope is None
        assert s.approved_actions == []
        assert s.denied_actions == []

    def test_expansion_mode_auto(self):
        s = ConversationScope("x", expansion_mode=ExpansionMode.AUTO)
        assert s.expansion_mode == ExpansionMode.AUTO

    def test_expansion_mode_deny(self):
        s = ConversationScope("x", expansion_mode=ExpansionMode.DENY)
        assert s.expansion_mode == ExpansionMode.DENY

    def test_max_turns_default(self):
        s = ConversationScope("x")
        assert s.max_turns == 20

    def test_max_expansions_default(self):
        s = ConversationScope("x")
        assert s.max_expansions == 10


# ── begin_turn ─────────────────────────────────────────────────────────────

class TestBeginTurn:
    def test_first_turn_sets_scope(self):
        s = _session()
        scope = _scope(["db.read"])
        effective = s.begin_turn(scope)
        assert "db.read" in effective.allowed_actions
        assert s.turn == 1

    def test_turn_counter_increments(self):
        s = _session()
        s.begin_turn(_scope(["db.read"]))
        s.begin_turn(_scope(["email.send"]))
        assert s.turn == 2

    def test_second_turn_merges_approved_actions(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        # Turn 1
        s.begin_turn(_scope(["db.read"]))
        # Approve email.send during turn 1
        try:
            s.handle_expansion("email.send", None, "fn")
        except ScopeExpansionRequest as req:
            s.approve(req)
        # Turn 2: api.call — email.send must carry over from approval
        effective = s.begin_turn(_scope(["api.call"]))
        assert "email.send" in effective.allowed_actions   # carried from approval
        assert "api.call" in effective.allowed_actions     # from new scope

    def test_max_turns_raises(self):
        s = ConversationScope("x", max_turns=2)
        s.begin_turn(_scope(["db.read"]))
        s.begin_turn(_scope(["db.read"]))
        with pytest.raises(RuntimeError, match="max_turns"):
            s.begin_turn(_scope(["db.read"]))

    def test_policy_ceiling_applied(self):
        # BILLING_AGENT_POLICY only allows db.read and email.send
        s = ConversationScope("x", policy=BILLING_AGENT_POLICY)
        # User somehow got code.execute in their scope
        scope = _scope(["db.read", "code.execute"])
        effective = s.begin_turn(scope)
        assert "code.execute" not in effective.allowed_actions
        assert "db.read" in effective.allowed_actions

    def test_turn_log_populated(self):
        s = _session()
        s.begin_turn(_scope(["db.read"], intent="check billing"))
        assert len(s.turn_log) == 1
        assert s.turn_log[0]["turn"] == 1
        assert "db.read" in s.turn_log[0]["effective_scope"]["allowed_actions"]


# ── DENY mode ──────────────────────────────────────────────────────────────

class TestDenyMode:
    def test_out_of_scope_raises_violation(self):
        s = _session(mode=ExpansionMode.DENY)
        s.begin_turn(_scope(["db.read"]))
        enforcer = IBACEnforcer(_scope(["db.read"]), conversation_scope=s)
        with pytest.raises(IBACScopeViolation):
            enforcer.check("email.send", fn_name="send_email")

    def test_deny_mode_records_in_expansion_log(self):
        s = _session(mode=ExpansionMode.DENY)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except IBACScopeViolation:
            pass
        assert len(s.expansion_log) == 1
        assert s.expansion_log[0]["decision"] == "denied"
        assert s.expansion_log[0]["decided_by"] == "deny_mode"


# ── AUTO mode ──────────────────────────────────────────────────────────────

class TestAutoMode:
    def test_policy_allowed_action_auto_approved(self):
        # DEVOPS_AGENT_POLICY allows code.execute
        s = ConversationScope(
            "run deployment",
            expansion_mode=ExpansionMode.AUTO,
            policy=DEVOPS_AGENT_POLICY,
        )
        s.begin_turn(_scope(["file.read"]))
        # code.execute is in policy — should auto-approve
        result = s.handle_expansion("code.execute", None, "run_script")
        assert result is True

    def test_auto_approved_action_in_approved_set(self):
        s = ConversationScope(
            "run deployment",
            expansion_mode=ExpansionMode.AUTO,
            policy=DEVOPS_AGENT_POLICY,
        )
        s.begin_turn(_scope(["file.read"]))
        s.handle_expansion("code.execute", None, "run_script")
        assert "code.execute" in s.approved_actions

    def test_auto_approved_updates_current_scope(self):
        s = ConversationScope(
            "run deployment",
            expansion_mode=ExpansionMode.AUTO,
            policy=DEVOPS_AGENT_POLICY,
        )
        s.begin_turn(_scope(["file.read"]))
        s.handle_expansion("code.execute", None, "run_script")
        assert "code.execute" in s.current_scope.allowed_actions

    def test_policy_ceiling_blocks_auto(self):
        # BILLING_AGENT_POLICY does NOT allow code.execute
        s = ConversationScope(
            "check billing",
            expansion_mode=ExpansionMode.AUTO,
            policy=BILLING_AGENT_POLICY,
        )
        s.begin_turn(_scope(["db.read"]))
        with pytest.raises(IBACScopeViolation):
            s.handle_expansion("code.execute", None, "run_script")

    def test_auto_expansion_logged(self):
        s = ConversationScope(
            "deploy",
            expansion_mode=ExpansionMode.AUTO,
            policy=DEVOPS_AGENT_POLICY,
        )
        s.begin_turn(_scope(["file.read"]))
        s.handle_expansion("code.execute", None, "run_script")
        log = s.expansion_log
        assert len(log) == 1
        assert log[0]["decision"] == "auto_approved"
        assert log[0]["decided_by"] == "policy_auto"

    def test_no_policy_auto_approves_any_action(self):
        # No policy = no ceiling = auto approves anything
        s = ConversationScope("x", expansion_mode=ExpansionMode.AUTO)
        s.begin_turn(_scope(["db.read"]))
        result = s.handle_expansion("email.send", None, "send_email")
        assert result is True


# ── CONFIRM mode ───────────────────────────────────────────────────────────

class TestConfirmMode:
    def test_raises_scope_expansion_request(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        with pytest.raises(ScopeExpansionRequest) as exc_info:
            s.handle_expansion("email.send", None, "send_email")
        req = exc_info.value
        assert req.requested_action == "email.send"
        assert req.fn_name == "send_email"
        assert req.turn == 1
        assert req.session is s

    def test_pending_expansion_set(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest:
            pass
        assert s.pending_expansion is not None
        assert s.pending_expansion.requested_action == "email.send"

    def test_approve_grants_action(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            s.approve(req)
        assert "email.send" in s.approved_actions
        assert s.pending_expansion is None

    def test_approve_updates_scope(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            s.approve(req)
        assert "email.send" in s.current_scope.allowed_actions

    def test_approve_logs_caller_decision(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            s.approve(req)
        assert s.expansion_log[0]["decision"] == "approved"
        assert s.expansion_log[0]["decided_by"] == "caller"

    def test_deny_blocks_action_for_session(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            s.deny(req)
        assert "email.send" in s.denied_actions
        assert s.pending_expansion is None

    def test_denied_action_always_blocks_after_deny(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            s.deny(req)
        # Second attempt — should raise IBACScopeViolation, not ScopeExpansionRequest
        with pytest.raises(IBACScopeViolation):
            s.handle_expansion("email.send", None, "send_email")

    def test_expansion_request_has_session_ref(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        s.begin_turn(_scope(["db.read"]))
        try:
            s.handle_expansion("email.send", None, "send_email")
        except ScopeExpansionRequest as req:
            assert req.session is s


# ── max_expansions limit ───────────────────────────────────────────────────

class TestMaxExpansions:
    def test_max_expansions_blocks_after_limit(self):
        s = ConversationScope(
            "x",
            expansion_mode=ExpansionMode.AUTO,
            max_expansions=2,
        )
        s.begin_turn(_scope(["db.read"]))
        s.handle_expansion("email.send", None, "t1")
        s.handle_expansion("file.read", None, "t2")
        # Third expansion should be blocked
        with pytest.raises(IBACScopeViolation):
            s.handle_expansion("api.call", None, "t3")


# ── Enforcer integration ───────────────────────────────────────────────────

class TestEnforcerIntegration:
    def test_in_scope_action_passes(self):
        s = _session(mode=ExpansionMode.AUTO)
        scope = _scope(["db.read"])
        s.begin_turn(scope)
        enforcer = IBACEnforcer(scope, conversation_scope=s)
        assert enforcer.check("db.read") is True

    def test_out_of_scope_auto_expands_via_enforcer(self):
        s = ConversationScope(
            "x",
            expansion_mode=ExpansionMode.AUTO,
            policy=DEVOPS_AGENT_POLICY,
        )
        scope = _scope(["file.read"])
        s.begin_turn(scope)
        enforcer = IBACEnforcer(scope, conversation_scope=s)
        # code.execute not in scope but policy allows it → auto-expand
        result = enforcer.check("code.execute", fn_name="run_script")
        assert result is True

    def test_out_of_scope_confirm_raises_expansion_request(self):
        s = _session(mode=ExpansionMode.CONFIRM)
        scope = _scope(["db.read"])
        s.begin_turn(scope)
        enforcer = IBACEnforcer(scope, conversation_scope=s)
        with pytest.raises(ScopeExpansionRequest):
            enforcer.check("email.send", fn_name="send_email")

    def test_no_conversation_scope_raises_violation(self):
        scope = _scope(["db.read"])
        enforcer = IBACEnforcer(scope)   # no conversation_scope
        with pytest.raises(IBACScopeViolation):
            enforcer.check("email.send")


# ── Summary and reset ──────────────────────────────────────────────────────

class TestSummaryAndReset:
    def test_summary_has_all_fields(self):
        s = _session(mode=ExpansionMode.AUTO)
        s.begin_turn(_scope(["db.read"]))
        summ = s.summary()
        assert "initial_request" in summ
        assert "turns_completed" in summ
        assert "approved_actions" in summ
        assert "denied_actions" in summ
        assert "expansions" in summ
        assert "current_scope" in summ
        assert "expansion_log" in summ

    def test_reset_clears_state(self):
        s = _session(mode=ExpansionMode.AUTO)
        s.begin_turn(_scope(["db.read"]))
        s._approved_actions.add("email.send")
        s.reset()
        assert s.turn == 0
        assert s.approved_actions == []
        assert s.current_scope is None
        assert s.expansion_log == []

    def test_reset_preserves_policy_and_mode(self):
        s = ConversationScope(
            "x",
            expansion_mode=ExpansionMode.AUTO,
            policy=BILLING_AGENT_POLICY,
        )
        s.reset()
        assert s.expansion_mode == ExpansionMode.AUTO
        assert s.policy is BILLING_AGENT_POLICY


# ── Full booking scenario ──────────────────────────────────────────────────

class TestBookingScenario:
    """
    Simulates the travel booking scenario described in the architecture doc:
    Turn 1: api.call [flight-search.*]
    Turn 2: needs email.send → expansion approved
    Turn 3: needs api.call [payment.*] → already in approved set
    """

    def test_booking_auto_scenario(self):
        TRAVEL_POLICY = IBACPolicy(
            name="travel-agent",
            allowed_actions=["api.call", "file.read", "email.send", "db.read"],
            denied_actions=["db.delete", "db.export", "code.execute"],
            description="Travel booking agent",
        )
        s = ConversationScope(
            initial_request="book me a flight to Tokyo",
            policy=TRAVEL_POLICY,
            expansion_mode=ExpansionMode.AUTO,
        )

        # Turn 1: flight search
        t1_scope = _scope(["api.call", "file.read"], intent="find flights to Tokyo")
        effective1 = s.begin_turn(t1_scope)
        assert "api.call" in effective1.allowed_actions

        # Simulate enforcer allowing api.call
        enforcer1 = IBACEnforcer(effective1, conversation_scope=s)
        assert enforcer1.check("api.call") is True

        # Turn 2: confirm booking, needs email.send
        t2_scope = _scope(["api.call"], intent="book cheapest flight")
        effective2 = s.begin_turn(t2_scope)
        enforcer2 = IBACEnforcer(effective2, conversation_scope=s)

        # email.send not yet in scope → auto-expand because policy allows it
        result = enforcer2.check("email.send", fn_name="send_confirmation")
        assert result is True
        assert "email.send" in s.approved_actions

        # Turn 3: email.send now in approved set — no expansion needed
        t3_scope = _scope(["db.read"], intent="check booking confirmation")
        effective3 = s.begin_turn(t3_scope)
        assert "email.send" in effective3.allowed_actions  # carried from approval

        assert s.turn == 3
        summ = s.summary()
        assert summ["auto_approved"] == 1
        assert summ["turns_completed"] == 3
