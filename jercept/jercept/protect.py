"""
Jercept ProtectedAgent — the public entry point for IBAC protection.

v1.1.0: Multi-LLM providers, policy linter, CLI, scope visualizer,
        ConversationScope, structured logging, full security hardening.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from jercept.adapters.langchain_adapter import wrap_langchain_agent
from jercept.adapters.openai_adapter import wrap_openai_agent
from jercept.core.enforcer import IBACEnforcer, AuditEntry
from jercept.core.exceptions import IBACExtractionFailed
from jercept.core.extractor import IntentExtractor
from jercept.core.injection_scanner import ScanResult, scan_input
from jercept.core.scope import IBACScope
from jercept.telemetry.client import TelemetryClient

logger = logging.getLogger(__name__)


class ProtectedAgent:
    """
    Drop-in replacement for any AI agent with full IBAC protection.

    Supports: LangChain, OpenAI Agents SDK, CrewAI, AutoGen,
              LlamaIndex, MCP servers.

    Example::

        from jercept import protect_agent
        agent = protect_agent(my_agent)
        result = await agent.run("check billing for customer 123")
        result = agent.run_sync("check billing for customer 123")
    """

    def __init__(
        self,
        agent: Any,
        extractor: IntentExtractor,
        telemetry: Optional[TelemetryClient] = None,
        production_mode: bool = False,
        policy: Optional[Any] = None,
        semantic_scanner: Optional[Any] = None,
        session: Optional[Any] = None,
    ) -> None:
        self.agent = agent
        self.extractor = extractor
        self.telemetry = telemetry
        self._production_mode = production_mode
        self._policy = policy
        self._semantic_scanner = semantic_scanner
        self._session = session   # ConversationScope for multi-turn

        self._scope: Optional[IBACScope] = None
        self._enforcer: Optional[IBACEnforcer] = None
        self._scan_result: Optional[ScanResult] = None
        self._semantic_result: Optional[Any] = None

    async def run(self, user_input: str, **kwargs: Any) -> Any:
        """Run the agent with full IBAC protection."""
        # Step 1: Regex injection scan (never blocks)
        scan_result = scan_input(user_input)
        self._scan_result = scan_result
        if scan_result.is_suspicious:
            logger.warning(
                "INJECTION SCAN: risk=%.2f patterns=%s",
                scan_result.risk_score, scan_result.matched_patterns,
            )

        # Step 2: Optional semantic scan (never blocks)
        if self._semantic_scanner:
            sem = self._semantic_scanner.scan(user_input)
            self._semantic_result = sem

        # Step 3: Extract intent → scope
        try:
            scope = self.extractor.extract(user_input)
        except IBACExtractionFailed:
            raise

        # Step 4: Apply policy ceiling if configured (single-turn only)
        if self._policy is not None and self._session is None:
            scope = self._policy.apply(scope)
            logger.info(
                "Policy %r applied → allowed=%s",
                self._policy.name, scope.allowed_actions,
            )

        # Step 5: Multi-turn — merge with ConversationScope
        if self._session is not None:
            scope = self._session.begin_turn(scope)
            logger.info(
                "ConversationScope turn=%d effective_allowed=%s",
                self._session.turn, scope.allowed_actions,
            )

        # Step 6: Create enforcer — stored BEFORE agent runs
        enforcer = IBACEnforcer(
            scope,
            production_mode=self._production_mode,
            conversation_scope=self._session,
        )
        self._scope = scope
        self._enforcer = enforcer

        # Step 7: Wrap tools
        wrapped_agent = self._wrap_agent(enforcer)

        # Step 8: Execute
        result = await self._run_agent(wrapped_agent, user_input, **kwargs)

        # Step 8: Telemetry (fire-and-forget)
        if self.telemetry and self.telemetry.enabled:
            event = self.telemetry.build_event(enforcer, scope)
            self.telemetry.send(event)

        return result

    def run_sync(self, user_input: str, **kwargs: Any) -> Any:
        """Synchronous wrapper for run(). Use in Flask, scripts, etc."""
        try:
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run, self.run(user_input, **kwargs)
                ).result()
        except RuntimeError:
            return asyncio.run(self.run(user_input, **kwargs))

    # ── Properties ────────────────────────────────────────────────────

    @property
    def session_scope(self) -> Dict[str, Any]:
        """Scope generated for the last run as a plain dictionary."""
        return self._scope.to_dict() if self._scope else {}

    @property
    def audit_trail(self) -> List[AuditEntry]:
        """Every tool call attempt with action, resource, permitted flag, and timestamp."""
        return list(self._enforcer.audit_log) if self._enforcer else []

    @property
    def was_attacked(self) -> bool:
        """True if any tool call was blocked this run — strongly indicates injection."""
        if not self._enforcer:
            return False
        return any(not e["permitted"] for e in self._enforcer.audit_log)

    @property
    def blocked_actions(self) -> List[str]:
        """List of action strings that were denied this run (e.g. ['db.export'])."""
        if not self._enforcer:
            return []
        return [e["action"] for e in self._enforcer.audit_log if not e["permitted"]]

    @property
    def scan_result(self) -> Optional[ScanResult]:
        """Regex injection scan result for the last run's user input."""
        return self._scan_result

    @property
    def semantic_scan_result(self) -> Optional[Any]:
        """LLM-based semantic scan result (only when semantic_scan=True)."""
        return self._semantic_result

    @property
    def active_policy(self) -> Optional[Dict[str, Any]]:
        """Active IBACPolicy as a dictionary, or None if no policy is set."""
        return self._policy.to_dict() if self._policy else None

    @property
    def session_summary(self) -> Optional[Dict[str, Any]]:
        """Full multi-turn session audit (only when session= is set)."""
        return self._session.summary() if self._session else None

    # ── Framework detection ───────────────────────────────────────────

    def _is_openai_agent(self, agent: Any) -> bool:
        return (
            hasattr(agent, "tools")
            and hasattr(agent, "instructions")
            and hasattr(agent, "name")
        )

    def _is_crewai_agent(self, agent: Any) -> bool:
        module = type(agent).__module__
        return "crewai" in module.lower() or type(agent).__name__ in (
            "Agent", "Crew", "Task"
        )

    def _is_autogen_agent(self, agent: Any) -> bool:
        module = type(agent).__module__
        return "autogen" in module.lower() or type(agent).__name__ in (
            "ConversableAgent", "AssistantAgent",
            "UserProxyAgent", "GroupChat", "GroupChatManager",
        )

    def _is_llamaindex_agent(self, agent: Any) -> bool:
        module = type(agent).__module__
        return "llama_index" in module.lower() or "llama-index" in module.lower()

    def _is_mcp_server(self, agent: Any) -> bool:
        module = type(agent).__module__
        name = type(agent).__name__
        return (
            "mcp" in module.lower()
            or "mcp" in name.lower()
            or hasattr(agent, "handle_request")
            or hasattr(agent, "process_request")
        )

    def _is_langchain_agent(self, agent: Any) -> bool:
        return hasattr(agent, "agent") or (
            hasattr(agent, "run") and hasattr(agent, "tools")
        )

    # ── Tool wrapping ─────────────────────────────────────────────────

    def _wrap_agent(self, enforcer: IBACEnforcer) -> Any:
        if self._is_mcp_server(self.agent):
            from jercept.adapters.mcp_adapter import wrap_mcp_server
            return wrap_mcp_server(self.agent, enforcer)
        if self._is_autogen_agent(self.agent):
            from jercept.adapters.autogen_adapter import wrap_autogen_agent
            return wrap_autogen_agent(self.agent, enforcer)
        if self._is_llamaindex_agent(self.agent):
            from jercept.adapters.llamaindex_adapter import wrap_llamaindex_agent
            return wrap_llamaindex_agent(self.agent, enforcer)
        if self._is_openai_agent(self.agent):
            return wrap_openai_agent(self.agent, enforcer)
        if self._is_crewai_agent(self.agent):
            from jercept.adapters.crewai_adapter import wrap_crewai_agent
            return wrap_crewai_agent(self.agent, enforcer)
        if self._is_langchain_agent(self.agent):
            return wrap_langchain_agent(self.agent, enforcer)
        # Unknown agent type — attempt generic tool wrapping
        tools = getattr(self.agent, "tools", None)
        if not tools:
            # MEDIUM 4 FIX: No tools found on unknown agent — raise clearly.
            # Previously this silently returned the unwrapped agent, giving
            # developers a false sense of security with zero IBAC enforcement.
            raise ValueError(
                f"Jercept could not detect tools on agent of type "
                f"{type(self.agent).__name__!r}. "
                f"The agent has no .tools attribute and does not match any "
                f"supported framework (LangChain, OpenAI Agents, CrewAI, "
                f"AutoGen, LlamaIndex, MCP). "
                f"Either add a .tools list to your agent, use a supported "
                f"framework, or use enforcer.wrap() / enforcer.check() directly "
                f"inside your agent function."
            )
        logger.warning(
            "Unknown agent type %r — wrapping .tools list directly. "
            "For best results use a supported framework adapter.",
            type(self.agent).__name__,
        )
        return self._wrap_tools_directly(enforcer)

    def _wrap_tools_directly(self, enforcer: IBACEnforcer) -> Any:
        from jercept.adapters.openai_adapter import _infer_action
        tools = getattr(self.agent, "tools", [])
        for tool in tools:
            tool_name = getattr(tool, "name", "") or type(tool).__name__
            action = _infer_action(tool_name)
            original_run = getattr(tool, "_run", None)
            if original_run is not None:
                def _safe_run(*a, _o=original_run, _act=action, _n=tool_name, **kw):
                    enforcer.check(_act, fn_name=_n)
                    return _o(*a, **kw)
                tool._run = _safe_run
            original_arun = getattr(tool, "_arun", None)
            if original_arun is not None:
                async def _safe_arun(*a, _o=original_arun, _act=action, _n=tool_name, **kw):
                    enforcer.check(_act, fn_name=_n)
                    return await _o(*a, **kw)
                tool._arun = _safe_arun
        return self.agent

    # ── Agent execution ───────────────────────────────────────────────

    async def _run_agent(self, wrapped_agent: Any, user_input: str, **kwargs: Any) -> Any:
        # MCP server — return wrapped middleware for caller to use
        if self._is_mcp_server(self.agent):
            return wrapped_agent

        # OpenAI Agents SDK
        if self._is_openai_agent(self.agent):
            try:
                from agents import Runner  # type: ignore
                result = await Runner.run(wrapped_agent, user_input, **kwargs)
                return result.final_output
            except ImportError as exc:
                raise ImportError(
                    "openai-agents required. Install: pip install jercept[openai-agents]"
                ) from exc

        # AutoGen
        if self._is_autogen_agent(self.agent):
            generate_reply = getattr(wrapped_agent, "generate_reply", None)
            if generate_reply:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: generate_reply(
                        messages=[{"role": "user", "content": user_input}]
                    ),
                )
                return result if isinstance(result, str) else str(result)

        # LlamaIndex
        if self._is_llamaindex_agent(self.agent):
            achat = getattr(wrapped_agent, "achat", None)
            if achat:
                result = await achat(user_input)
                return result.response if hasattr(result, "response") else str(result)
            chat = getattr(wrapped_agent, "chat", None)
            if chat:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: chat(user_input))
                return result.response if hasattr(result, "response") else str(result)

        # LangChain / generic async
        ainvoke = getattr(wrapped_agent, "ainvoke", None)
        if ainvoke is not None:
            result = await ainvoke({"input": user_input}, **kwargs)
            return result.get("output", result) if isinstance(result, dict) else result

        invoke = getattr(wrapped_agent, "invoke", None)
        if invoke is not None:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: invoke({"input": user_input}, **kwargs)
            )
            return result.get("output", result) if isinstance(result, dict) else result

        run_fn = getattr(wrapped_agent, "run", None)
        if run_fn is not None:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: run_fn(user_input))

        raise NotImplementedError(
            f"Agent {type(self.agent).__name__!r} has no recognised runner."
        )


# ── Public factory ────────────────────────────────────────────────────


def protect_agent(
    agent: Any,
    model: str = "gpt-4o-mini",
    api_key: Optional[str] = None,
    telemetry_key: Optional[str] = None,
    production_mode: bool = False,
    use_cache: bool = True,
    use_fast_extract: bool = True,
    policy: Optional[Any] = None,
    semantic_scan: bool = False,
    semantic_scan_model: str = "gpt-4o-mini",
    session: Optional[Any] = None,
    llm_provider: str = "openai",
    **provider_kwargs: Any,
) -> ProtectedAgent:
    """
    Wrap any AI agent with IBAC protection.

    Args:
        agent: LangChain, OpenAI Agents SDK, CrewAI, AutoGen,
               LlamaIndex, or MCP server.
        model: LLM model for intent extraction (default: gpt-4o-mini).
        api_key: API key for the chosen provider.
        telemetry_key: Jercept dashboard API key.
        production_mode: Sanitize error messages for external logs.
        use_cache: Enable LRU intent cache (default: True).
        use_fast_extract: Enable regex fast extraction (default: True).
        policy: IBACPolicy ceiling for enterprise action limits.
        semantic_scan: Enable LLM-based semantic injection detection.
        semantic_scan_model: Model for semantic scanner.
        session: ConversationScope for multi-turn stateful sessions.
        llm_provider: LLM backend - "openai" (default), "anthropic",
                      "gemini", or "ollama".
        **provider_kwargs: Extra kwargs for the provider
                           (e.g. ollama_base_url="http://localhost:11434").

    Returns:
        ProtectedAgent - drop-in replacement for agent.

    Examples::

        # OpenAI (default)
        agent = protect_agent(my_agent)

        # Anthropic Claude
        agent = protect_agent(my_agent, llm_provider="anthropic",
                              model="claude-3-haiku-20240307")

        # Local Ollama - no API key needed
        agent = protect_agent(my_agent, llm_provider="ollama",
                              model="llama3")

        # Multi-turn with auto scope expansion
        from jercept import ConversationScope, ExpansionMode
        session = ConversationScope(
            initial_request="book a flight to Tokyo",
            expansion_mode=ExpansionMode.AUTO,
        )
        agent = protect_agent(my_agent, session=session)
        r1 = await agent.run("find flights to Tokyo next Friday")
        r2 = await agent.run("book the cheapest and email confirmation")
    """
    extractor = IntentExtractor(
        model=model,
        api_key=api_key,
        use_cache=use_cache,
        use_fast_extract=use_fast_extract,
        llm_provider=llm_provider,
        **provider_kwargs,
    )
    telemetry = TelemetryClient(api_key=telemetry_key)

    semantic_scanner = None
    if semantic_scan:
        from jercept.core.semantic_scanner import SemanticScanner
        semantic_scanner = SemanticScanner(
            model=semantic_scan_model, api_key=api_key
        )

    return ProtectedAgent(
        agent=agent,
        extractor=extractor,
        telemetry=telemetry,
        production_mode=production_mode,
        policy=policy,
        semantic_scanner=semantic_scanner,
        session=session,
    )
