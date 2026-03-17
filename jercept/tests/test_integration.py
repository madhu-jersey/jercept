"""
Integration tests for ProtectedAgent — end-to-end scenarios.

Uses a lightweight mock agent that executes tools synchronously so these
tests run without a real OpenAI API key.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from jercept.core.exceptions import IBACExtractionFailed, IBACScopeViolation
from jercept.core.scope import IBACScope
from jercept.protect import ProtectedAgent
from jercept.core.extractor import IntentExtractor
from jercept.core.enforcer import IBACEnforcer


# ---------------------------------------------------------------------------
# Minimal mock agent that calls its tools deterministically
# ---------------------------------------------------------------------------

class MockTool:
    """A duck-typed LangChain-compatible tool."""

    def __init__(self, name: str, return_value: Any = "tool_result"):
        self.name = name
        self.description = f"Mock tool: {name}"
        self._return_value = return_value
        self.call_count = 0

    def _run(self, *args, **kwargs):
        self.call_count += 1
        return self._return_value

    async def _arun(self, *args, **kwargs):
        self.call_count += 1
        return self._return_value


class MockAgent:
    """
    Minimal agent that invokes a predetermined list of tools via ainvoke().
    Simulates a LangChain AgentExecutor structure.
    """

    def __init__(self, tools: list[MockTool], tools_to_call: list[str] = None):
        """
        Args:
            tools: All available tool objects.
            tools_to_call: Names of tools the agent will attempt, in order.
                           Defaults to all tools.
        """
        self.tools = tools
        self._tools_map = {t.name: t for t in tools}
        self._tools_to_call = tools_to_call or [t.name for t in tools]

    async def ainvoke(self, inputs: dict, **kwargs) -> dict:
        results = []
        for tool_name in self._tools_to_call:
            tool = self._tools_map[tool_name]
            result = await tool._arun()
            results.append(result)
        return {"output": " | ".join(str(r) for r in results)}


def _make_scope(allowed_actions, allowed_resources=None, denied_actions=None) -> IBACScope:
    return IBACScope(
        allowed_actions=allowed_actions,
        allowed_resources=allowed_resources or [],
        denied_actions=denied_actions or [],
        raw_intent="integration test request",
        confidence=0.95,
        ambiguous=False,
    )


def _make_extractor_with_scope(scope: IBACScope) -> IntentExtractor:
    """Return a patched IntentExtractor that always yields a fixed scope."""
    extractor = MagicMock(spec=IntentExtractor)
    extractor.extract.return_value = scope
    return extractor


@pytest.mark.asyncio
class TestLegitimateRequest:
    """Test 1: Legitimate request — all tool calls succeed."""

    async def test_legitimate_agent_run_succeeds(self):
        billing_tool = MockTool("read_customer", return_value="billing_data")
        agent = MockAgent(tools=[billing_tool], tools_to_call=["read_customer"])

        scope = _make_scope(allowed_actions=["db.read"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        result = await protected.run("check billing for customer 123")

        assert "billing_data" in result
        assert billing_tool.call_count == 1

    async def test_session_scope_populated_after_run(self):
        tool = MockTool("read_customer")
        agent = MockAgent(tools=[tool])

        scope = _make_scope(allowed_actions=["db.read"], allowed_resources=["customer#123"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        await protected.run("check billing for customer 123")

        session = protected.session_scope
        assert "db.read" in session["allowed_actions"]
        assert "customer#123" in session["allowed_resources"]


@pytest.mark.asyncio
class TestInjectionAttack:
    """Test 2: Injected tool call outside scope → IBACScopeViolation raised."""

    async def test_out_of_scope_tool_raises_violation(self):
        read_tool = MockTool("read_customer")
        export_tool = MockTool("export_all_customers")

        # Agent tries BOTH tools — export is out of scope
        agent = MockAgent(
            tools=[read_tool, export_tool],
            tools_to_call=["read_customer", "export_all_customers"],
        )

        scope = _make_scope(
            allowed_actions=["db.read"],
            denied_actions=["db.export"],
        )
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        with pytest.raises(IBACScopeViolation) as exc_info:
            await protected.run("check billing for customer 123")

        exc = exc_info.value
        assert exc.action == "db.export"


@pytest.mark.asyncio
class TestWasAttacked:
    """Test 3: was_attacked → True after a blocked call."""

    async def test_was_attacked_true_after_block(self):
        read_tool = MockTool("read_customer")
        export_tool = MockTool("export_all_customers")

        agent = MockAgent(
            tools=[read_tool, export_tool],
            tools_to_call=["read_customer", "export_all_customers"],
        )
        scope = _make_scope(allowed_actions=["db.read"], denied_actions=["db.export"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        with pytest.raises(IBACScopeViolation):
            await protected.run("check billing")

        # was_attacked should be True because db.export was blocked
        assert protected.was_attacked is True

    async def test_was_attacked_false_when_no_blocks(self):
        tool = MockTool("read_customer")
        agent = MockAgent(tools=[tool])
        scope = _make_scope(allowed_actions=["db.read"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        await protected.run("check billing")

        assert protected.was_attacked is False


@pytest.mark.asyncio
class TestAuditTrail:
    """Test 4: audit_trail contains the full log after a run."""

    async def test_audit_trail_populated(self):
        read_tool = MockTool("read_customer")
        agent = MockAgent(tools=[read_tool])
        scope = _make_scope(allowed_actions=["db.read"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        await protected.run("check billing")

        trail = protected.audit_trail
        assert len(trail) >= 1
        assert all("ts" in e for e in trail)
        assert all("action" in e for e in trail)
        assert all("permitted" in e for e in trail)

    async def test_audit_trail_has_blocked_entries(self):
        read_tool = MockTool("read_customer")
        export_tool = MockTool("export_all_customers")
        agent = MockAgent(
            tools=[read_tool, export_tool],
            tools_to_call=["read_customer", "export_all_customers"],
        )
        scope = _make_scope(allowed_actions=["db.read"], denied_actions=["db.export"])
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        with pytest.raises(IBACScopeViolation):
            await protected.run("check billing")

        # The enforcer recorded the blocked call even though it raised
        trail = protected.audit_trail
        blocked = [e for e in trail if not e["permitted"]]
        assert len(blocked) >= 1
        assert blocked[0]["action"] == "db.export"


@pytest.mark.asyncio
class TestSessionScope:
    """Test 5: session_scope → returns correct scope after run."""

    async def test_session_scope_after_run(self):
        tool = MockTool("read_customer")
        agent = MockAgent(tools=[tool])
        scope = _make_scope(
            allowed_actions=["db.read"],
            allowed_resources=["customer#123"],
            denied_actions=["db.export"],
        )
        extractor = _make_extractor_with_scope(scope)

        protected = ProtectedAgent(agent=agent, extractor=extractor)
        await protected.run("check billing")

        s = protected.session_scope
        assert s["allowed_actions"] == ["db.read"]
        assert s["allowed_resources"] == ["customer#123"]
        assert "db.export" in s["denied_actions"]
        assert s["confidence"] == pytest.approx(0.95)

    async def test_session_scope_empty_before_run(self):
        tool = MockTool("read_customer")
        agent = MockAgent(tools=[tool])
        extractor = _make_extractor_with_scope(_make_scope(["db.read"]))
        protected = ProtectedAgent(agent=agent, extractor=extractor)
        # No run yet
        assert protected.session_scope == {}


@pytest.mark.asyncio
class TestExtractionFailed:
    """IBACExtractionFailed propagates correctly."""

    async def test_extraction_failure_propagates(self):
        tool = MockTool("read_customer")
        agent = MockAgent(tools=[tool])

        extractor = MagicMock(spec=IntentExtractor)
        extractor.extract.side_effect = IBACExtractionFailed(
            reason="too ambiguous", original_request="help me"
        )
        protected = ProtectedAgent(agent=agent, extractor=extractor)

        with pytest.raises(IBACExtractionFailed):
            await protected.run("help me")

        # Agent should not have been called at all
        assert tool.call_count == 0
