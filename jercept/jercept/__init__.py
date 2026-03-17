"""
Jercept v1.2.0 — The authorization layer for AI agents.

Intent-Based Access Control (IBAC): your agent can only do what the
user actually asked for — even under prompt injection attack.

The same paradigm shift OAuth brought to web APIs, IBAC brings to AI agents.

Quick start::

    from jercept import protect_agent

    agent = protect_agent(my_agent)
    result = await agent.run("check billing for customer 123")

    # With Anthropic / Gemini / local Ollama
    agent = protect_agent(my_agent, llm_provider="anthropic")
    agent = protect_agent(my_agent, llm_provider="ollama", model="llama3")

    # With real-time dashboard
    agent = protect_agent(my_agent, telemetry_key="jercept_live_xxxx")

Enterprise policy::

    from jercept import IBACPolicy, protect_agent
    from jercept.linter import lint_policy

    policy = IBACPolicy(
        name="billing-readonly",
        allowed_actions=["db.read", "email.send"],
        denied_actions=["db.export", "db.delete", "code.execute"],
        allowed_resources=["customer.*", "billing.*"],
        description="Billing support — read only",
    )
    result = lint_policy(policy)
    if result.has_errors:
        raise SystemExit(str(result))
    agent = protect_agent(my_agent, policy=policy)

Multi-turn agent with session persistence::

    from jercept import ConversationScope, ExpansionMode, protect_agent
    import json, redis

    # Create or restore session
    raw = redis.get(f"session:{user_id}")
    session = (ConversationScope.from_dict(json.loads(raw), policy=policy)
               if raw else
               ConversationScope("book a flight", policy=policy,
                                 expansion_mode=ExpansionMode.CONFIRM))

    agent = protect_agent(my_agent, session=session)
    result = await agent.run(user_message)

    # Persist after each turn
    redis.set(f"session:{user_id}", json.dumps(session.to_dict()), ex=3600)

Structured logging for Datadog / CloudWatch::

    from jercept import configure_structured_logging
    import logging

    configure_structured_logging(level=logging.WARNING)
    # All jercept events now emit JSON: {"event":"ibac_blocked","action":"db.export",...}

CLI::

    jercept preview "check billing for customer 123"
    jercept lint policies/billing.yaml
    jercept version
"""
from __future__ import annotations

from jercept.adapters.mcp_adapter import MCPIBACMiddleware, wrap_mcp_server
from jercept.core.conversation import ConversationScope, ExpansionMode, ScopeExpansionRequest
from jercept.core.enforcer import IBACEnforcer, AuditEntry
from jercept.core.exceptions import IBACExtractionFailed, IBACScopeViolation
from jercept.core.extractor import AsyncIntentExtractor, IntentExtractor
from jercept.core.injection_scanner import ScanResult, scan_input, scan_context
from jercept.core.scope import IBACScope, VALID_ACTIONS, DANGEROUS_ACTIONS
from jercept.core.semantic_scanner import SemanticScanResult, SemanticScanner
from jercept.decorators import ibac_tool
from jercept.linter import lint_policy, LintResult
from jercept.logging import JerceptJsonFormatter, configure_structured_logging
from jercept.policy import (
    BILLING_AGENT_POLICY,
    DEVOPS_AGENT_POLICY,
    IBACPolicy,
    READONLY_DB_POLICY,
    SUPPORT_AGENT_POLICY,
)
from jercept.protect import ProtectedAgent, protect_agent
from jercept.telemetry.client import TelemetryClient
from jercept.telemetry.notifier import WebhookNotifier

__version__: str = "1.2.0"
__author__:  str = "Jercept Security"

__all__ = [
    # ── Entry points ──────────────────────────────────────────────────
    "protect_agent",
    "ProtectedAgent",
    # ── Core types ────────────────────────────────────────────────────
    "IBACScope",
    "IBACEnforcer",
    "AuditEntry",
    "VALID_ACTIONS",
    "DANGEROUS_ACTIONS",
    # ── Exceptions ────────────────────────────────────────────────────
    "IBACScopeViolation",
    "IBACExtractionFailed",
    # ── Multi-turn ────────────────────────────────────────────────────
    "ConversationScope",
    "ExpansionMode",
    "ScopeExpansionRequest",
    # ── Policy ────────────────────────────────────────────────────────
    "IBACPolicy",
    "lint_policy",
    "LintResult",
    "READONLY_DB_POLICY",
    "BILLING_AGENT_POLICY",
    "SUPPORT_AGENT_POLICY",
    "DEVOPS_AGENT_POLICY",
    # ── Extraction ────────────────────────────────────────────────────
    "IntentExtractor",
    "AsyncIntentExtractor",
    # ── Scanning ──────────────────────────────────────────────────────
    "scan_input",
    "scan_context",
    "ScanResult",
    "SemanticScanner",
    "SemanticScanResult",
    # ── Telemetry ─────────────────────────────────────────────────────
    "TelemetryClient",
    "WebhookNotifier",
    # ── Logging ───────────────────────────────────────────────────────
    "configure_structured_logging",
    "JerceptJsonFormatter",
    # ── Decorators ────────────────────────────────────────────────────
    "ibac_tool",
    # ── MCP ───────────────────────────────────────────────────────────
    "MCPIBACMiddleware",
    "wrap_mcp_server",
]
