# Jercept

> **Intercept every tool call. Block every injection. Zero config.**
>
> *The authorization layer for AI agents — IBAC stops prompt injection where detection always fails.*

[![PyPI version](https://badge.fury.io/py/jercept.svg)](https://pypi.org/project/jercept/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-493%20passing-brightgreen.svg)](tests/)
[![Type hints](https://img.shields.io/badge/type%20hints-100%25-blue.svg)](jercept/)
[![Version](https://img.shields.io/badge/version-1.2.0-indigo.svg)](CHANGELOG.md)

---

## The problem in one sentence

Hackers hide malicious instructions inside documents your AI agent reads — and the agent follows them, exporting databases, sending emails to attackers, executing code. Every existing tool tries to detect the attack. **Detection always fails.** Attackers obfuscate with emoji, Unicode homoglyphs, and paraphrasing.

## The solution in one sentence

**Jercept intercepts every tool call and checks it against what the user actually asked for.** Even if an injection gets through detection, the dangerous action is physically impossible — because the permission was never granted.

```
User: "check billing for customer 123"
                    ↓
       Jercept extracts intent → locks scope
                    ↓
         ✅ db.read  on  customer#123  — ALLOWED
         ❌ db.export                 — BLOCKED
         ❌ db.delete                 — BLOCKED
         ❌ code.execute              — BLOCKED
                    ↓
    Agent runs. Attacker's hidden instruction
    requests db.export. Blocked before execution.
    Database safe. Always.
```

This is **IBAC — Intent-Based Access Control.** Authorization beats detection.

---

## Why every competitor gets this wrong

| | Jercept | LLM Guard | NeMo Guardrails | AgentWard | Permit.io | Lakera |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Zero config — no rules to write | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Dynamic scope per request | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multi-turn scope negotiation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Blocks at tool layer | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| MCP server support | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| LangChain + OpenAI + CrewAI + AutoGen | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ |
| Works when detection fails | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multi-LLM (Anthropic/Gemini/Ollama) | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Built-in policy linter | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CLI scope preview | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Open source SDK | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Real-time attack dashboard | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |

Every competitor either requires pre-written rules, or only detects attacks without blocking them at the action layer. Jercept does neither.

---

## Install

```bash
pip install jercept

# Framework extras
pip install jercept[langchain]        # LangChain AgentExecutor
pip install jercept[openai-agents]    # OpenAI Agents SDK
pip install jercept[mcp]              # Model Context Protocol servers
pip install jercept[crewai]           # CrewAI
pip install jercept[autogen]          # AutoGen
pip install jercept[llamaindex]       # LlamaIndex
pip install jercept[anthropic]        # Anthropic Claude backend
pip install jercept[gemini]           # Google Gemini backend
pip install jercept[all]              # Everything
```

---

## Multi-LLM support — no OpenAI required

Jercept works with any LLM backend. Enterprises with data residency requirements can run entirely on-premise with Ollama — no API key, no internet, no data leaving your network.

```python
# Anthropic Claude
agent = protect_agent(my_agent, llm_provider="anthropic",
                      model="claude-3-haiku-20240307")

# Google Gemini
agent = protect_agent(my_agent, llm_provider="gemini",
                      model="gemini-1.5-flash")

# Local Ollama — completely air-gapped, no API key needed
agent = protect_agent(my_agent, llm_provider="ollama", model="llama3")
agent = protect_agent(my_agent, llm_provider="ollama", model="mistral")
```

| Provider | Install | Key needed |
|---|---|:-:|
| OpenAI (default) | `pip install jercept` | ✅ |
| Anthropic Claude | `pip install jercept[anthropic]` | ✅ |
| Google Gemini | `pip install jercept[gemini]` | ✅ |
| Ollama (local) | `pip install jercept` | ❌ |

---


### Session persistence (Redis / database)

`ConversationScope` now serialises to JSON — sessions survive pod restarts, scale-out, and deploys:

```python
import json
from jercept import ConversationScope, ExpansionMode

# Save session state after each turn
state_json = json.dumps(session.to_dict())
redis.set(f"session:{user_id}", state_json, ex=3600)

# Restore on next request
raw = redis.get(f"session:{user_id}")
session = (
    ConversationScope.from_dict(json.loads(raw), policy=my_policy)
    if raw else
    ConversationScope(
        initial_request=user_input,
        policy=my_policy,
        expansion_mode=ExpansionMode.CONFIRM,
    )
)
```

---

## CLI — debug and validate without running an agent

```bash
# See exactly what scope a request would generate
jercept preview "check billing for customer 123"
#   Extraction tier: Fast regex (no LLM call)
#   Latency:         1.2ms
#   ✓ Allowed: db.read
#   ● Resources: customer#123
#   ✗ Denied: db.export, db.delete, code.execute ...
#   Confidence: 95%

# Test with different providers
jercept preview "send email to team" --provider anthropic
jercept preview "run the script" --provider ollama --model llama3

# Validate a YAML policy file before deploying
jercept lint policies/billing.yaml
#   ✗ [ERROR] wildcard_dangerous_actions: db.* permits db.export, db.delete
#   ⚠ [WARNING] empty_allowed_resources: agent can access any table
```

---

## Policy linter — catch misconfigurations before production

```python
from jercept import IBACPolicy
from jercept.linter import lint_policy

policy = IBACPolicy(
    name="payments-agent",
    allowed_actions=["db.*"],       # ← linter catches this
    denied_actions=[],              # ← linter catches this too
)

result = lint_policy(policy)
print(result)
# ✗ [ERROR] wildcard_dangerous_actions: db.* implicitly permits db.export, db.delete
# ⚠ [WARNING] no_explicit_denies: denied_actions is empty
# ⚠ [WARNING] empty_allowed_resources: agent can access any table

if result.has_errors:
    raise SystemExit("Fix policy errors before deploying")
```

Also from CLI: `jercept lint policies/billing.yaml`

---

## Quickstart — 2 lines

```python
from jercept import protect_agent

agent = protect_agent(my_agent)                             # wrap any agent
result = await agent.run("check billing for customer 123") # run as normal

# After the run — inspect what happened
print(agent.session_scope)    # {"allowed_actions": ["db.read"], ...}
print(agent.audit_trail)      # every tool call: permitted or blocked
print(agent.was_attacked)     # True if any injection was caught
print(agent.blocked_actions)  # ["db.export"] — what the attacker tried
```

No configuration. No rules to write. No schema to define.

---

## How IBAC works

Every `agent.run()` call goes through a 5-step pipeline:

```
Step 1 — Injection scan    Regex + homoglyph detection (never blocks, always logs)
Step 2 — Intent extract    3-tier: cache (0ms) → regex (2ms) → LLM (~200ms)
Step 3 — Scope build       IBACScope: minimal permissions for this request only
Step 4 — Policy ceiling    Intersect scope with IBACPolicy (if configured)
Step 5 — Tool wrapping     Every tool call checked against scope before execution
```

The **3-tier extractor** means most requests never hit the LLM:
- **Cache** (0ms): semantically equivalent request seen before
- **Fast regex** (2ms): known patterns — billing, email, file ops, scripts
- **LLM fallback** (~200ms): novel requests needing semantic understanding

**The scope is immutable.** Once locked at request start, nothing — injected or otherwise — can expand it mid-run.

---

## Multi-turn agents — ConversationScope

Real agents need multiple turns. A booking agent starts with "find flights" but later needs to send a confirmation email. Single-request IBAC would block it — even though it's legitimate.

`ConversationScope` solves this with controlled scope expansion:

```python
from jercept import protect_agent, ConversationScope, ExpansionMode
from jercept.policy import DEVOPS_AGENT_POLICY

session = ConversationScope(
    initial_request="book me a flight to Tokyo",
    policy=DEVOPS_AGENT_POLICY,
    expansion_mode=ExpansionMode.AUTO,   # AUTO | CONFIRM | DENY
)
agent = protect_agent(my_agent, session=session)

# Turn 1 — api.call granted from intent
r1 = await agent.run("find the cheapest flight to Tokyo next Friday")

# Turn 2 — email.send not in original scope
# AUTO:    policy allows it → silently granted, continues
# CONFIRM: ScopeExpansionRequest raised → your app decides
# DENY:    IBACScopeViolation raised → strict blocking always
r2 = await agent.run("book it and email me the confirmation")

print(agent.session_summary)
# {"turns_completed": 2, "approved_actions": ["api.call", "email.send"],
#  "auto_approved": 1, "expansion_log": [...]}
```

### Expansion modes

| Mode | Behaviour | Best for |
|---|---|---|
| `ExpansionMode.AUTO` | Policy ceiling checked → grant silently if allowed | Automated pipelines |
| `ExpansionMode.CONFIRM` | Raise `ScopeExpansionRequest` → caller approves or denies | Interactive apps |
| `ExpansionMode.DENY` | Never expand — strict per-request scope | High-security contexts |

### CONFIRM mode

```python
try:
    result = await agent.run("book flight and email me confirmation")
except ScopeExpansionRequest as req:
    print(f"Agent wants: {req.requested_action}")   # "email.send"
    session.approve(req)   # grant for rest of session
    # session.deny(req)    # block permanently this session
    result = await agent.run("book flight and email me confirmation")
```

---

## Enterprise policies

Define what your agent is allowed to do at a role level. The session scope is always the **intersection** of user intent and policy ceiling — a user can never request more than the policy permits.

### Pre-built policies

```python
from jercept.policy import (
    BILLING_AGENT_POLICY,   # db.read + email.send only
    READONLY_DB_POLICY,     # db.read + file.read + email.read only
    SUPPORT_AGENT_POLICY,   # read + communicate, no mutations
    DEVOPS_AGENT_POLICY,    # file ops + code execution, no db destruction
)

agent = protect_agent(my_agent, policy=BILLING_AGENT_POLICY)
```

### Custom policy in Python

```python
from jercept import IBACPolicy

policy = IBACPolicy(
    name="payments-agent",
    allowed_actions=["db.read", "api.call", "email.send"],
    denied_actions=["db.delete", "db.export", "code.execute"],
    allowed_resources=["payment.*", "invoice.*", "customer.*"],
    description="Payments agent: read + API + notify only.",
)
agent = protect_agent(my_agent, policy=policy)
```

### Policy from YAML — GitOps-style

```yaml
# policies/payments_agent.yaml
name: payments-agent
allowed_actions: [db.read, api.call, email.send]
denied_actions:  [db.delete, db.export, code.execute]
allowed_resources: [payment.*, invoice.*, customer.*]
description: Payments agent policy
```

```python
from jercept import IBACPolicy

policy = IBACPolicy.from_yaml("policies/payments_agent.yaml")
agent  = protect_agent(my_agent, policy=policy)
```

---

## MCP server protection

Jercept wraps Model Context Protocol servers with the same IBAC enforcement. Compatible with Claude Desktop, Cursor, VS Code Copilot, and any MCP-compliant client.

```python
from jercept import protect_agent

# Auto-detected — wrap the MCP server exactly like any other agent
agent = protect_agent(my_mcp_server)
result = await agent.run("read the project config file")

# Or wrap the MCP server directly
from jercept import wrap_mcp_server
from jercept.core.enforcer import IBACEnforcer

enforcer = IBACEnforcer(scope)
protected_server = wrap_mcp_server(my_mcp_server, enforcer)
result = await protected_server.handle_request(json_rpc_request)
```

33 MCP tool mappings built-in: `read_file`, `write_file`, `execute_command`, `bash`, `web_search`, `database_query`, `send_email`, `github_create`, `slack_post`, and more.

---

## Explicit action declaration — `@ibac_tool`

When tool names are unconventional, declare their actions explicitly. Overrides keyword inference in all adapters.

```python
from jercept import ibac_tool

@ibac_tool("db.export")
def crm_sync() -> str:
    """Sync CRM data to external warehouse."""
    return export_crm_data()

@ibac_tool("db.write", "email.send")
def process_invoice(invoice_id: str) -> str:
    update_invoice_status(invoice_id)
    send_payment_confirmation(invoice_id)
    return "done"
```

---

## Production deployment

### Sync usage — Flask, scripts, non-async code

```python
agent  = protect_agent(my_agent)
result = agent.run_sync("check billing for customer 123")
```

### Production mode — sanitize error messages

```python
# Sanitizes IBACScopeViolation messages in logs — no scope internals
# exposed to users. Full details available internally on exc.action, exc.scope.
agent = protect_agent(my_agent, production_mode=True)
```

### Real-time monitoring dashboard

```python
agent = protect_agent(my_agent, telemetry_key="jercept_live_xxxx")
```

Get your free API key at **[jercept.com](https://jercept.com)**. The dashboard shows every tool call (permitted and blocked), block rate over time, top attack types, and per-session audit trails.

---

## Full API reference

### `protect_agent()`

```python
protect_agent(
    agent,                           # Any: LangChain, OpenAI Agents, CrewAI,
                                     #      AutoGen, LlamaIndex, MCP server
    model="gpt-4o-mini",             # str: LLM for intent extraction
    api_key=None,                    # str: OpenAI key (or OPENAI_API_KEY env)
    telemetry_key=None,              # str: Jercept dashboard API key
    production_mode=False,           # bool: sanitize error messages for users
    use_cache=True,                  # bool: LRU intent cache (0ms tier)
    use_fast_extract=True,           # bool: regex fast extraction (2ms tier)
    policy=None,                     # IBACPolicy: action ceiling for this agent
    session=None,                    # ConversationScope: multi-turn mode
) -> ProtectedAgent
```

### `ProtectedAgent` properties

| Property | Type | Description |
|---|---|---|
| `.session_scope` | `dict` | Scope generated for the last run |
| `.audit_trail` | `list[dict]` | Every tool call with action, resource, permitted, timestamp |
| `.was_attacked` | `bool` | True if any tool call was blocked |
| `.blocked_actions` | `list[str]` | Action strings that were denied this run |
| `.scan_result` | `ScanResult` | Regex injection scan result |
| `.active_policy` | `dict \| None` | Active IBACPolicy details |
| `.session_summary` | `dict \| None` | Full multi-turn audit (only when `session=` is set) |

### `ConversationScope`

```python
ConversationScope(
    initial_request,               # str: semantic anchor for the whole session
    policy=None,                   # IBACPolicy: ceiling for all expansions
    expansion_mode=ExpansionMode.CONFIRM,
    max_turns=20,                  # int: RuntimeError if exceeded
    max_expansions=10,             # int: IBACScopeViolation if exceeded
)
```

| Method / Property | Description |
|---|---|
| `.approve(req)` | Grant a `ScopeExpansionRequest` for the rest of this session |
| `.deny(req)` | Block the requested action permanently for this session |
| `.reset()` | Clear all state to start a new task in the same session object |
| `.summary()` | Full audit: turns, expansions, decisions, current scope |
| `.turn` | Current turn number (1-indexed) |
| `.approved_actions` | All actions granted so far across all turns |
| `.expansion_log` | Every expansion event with decision and timestamp |

### `IBACPolicy`

```python
IBACPolicy(
    name,                          # str: human-readable policy name
    allowed_actions=[],            # list[str]: actions this role may ever perform
    denied_actions=[],             # list[str]: always denied regardless of request
    allowed_resources=[],          # list[str]: resource patterns (glob supported)
    max_confidence_required=0.6,   # float: minimum extraction confidence
    description="",                # str: shown in audit reports
    version="1.0",                 # str: for change tracking in GitOps workflows
)

IBACPolicy.from_dict(data)         # load from plain dictionary
IBACPolicy.from_yaml(path)         # load from YAML file (requires pyyaml)
policy.apply(scope) → IBACScope    # intersect scope with policy ceiling
policy.to_dict() → dict            # serialize for storage or API
```

### `IBACScope`

```python
IBACScope(
    allowed_actions=[],            # list[str]: permitted IBAC actions
    allowed_resources=[],          # list[str]: permitted resources (glob)
    denied_actions=[],             # list[str]: always blocked (overrides allows)
    raw_intent="",                 # str: original user request — for audit trail
    confidence=0.0,                # float: extraction confidence 0.0–1.0
    ambiguous=False,               # bool: True if request was too vague to scope
)

scope.permits(action, resource=None) → bool    # check if action is in scope
scope.to_dict() → dict                         # serialize
IBACScope.from_dict(data) → IBACScope          # reconstruct from audit log or API
```

### Action taxonomy

All IBAC actions use dot-notation namespaces:

| Action | Meaning |
|---|---|
| `db.read` | Read from a database or data store |
| `db.write` | Insert or update database records |
| `db.export` | Export bulk data to a file or external system |
| `db.delete` | Delete database records |
| `file.read` | Read a file or document |
| `file.write` | Write or create a file |
| `file.upload` | Upload a file to a service |
| `file.download` | Download a file from a service |
| `email.read` | Read or fetch emails |
| `email.send` | Send an email or message |
| `api.call` | Call an external API or webhook |
| `web.browse` | Browse or search the web |
| `code.execute` | Execute code, scripts, or shell commands |

### Exceptions

```python
from jercept import IBACScopeViolation, IBACExtractionFailed, ScopeExpansionRequest

try:
    result = await agent.run(user_input)

except IBACExtractionFailed as e:
    # Request too ambiguous to derive a safe scope.
    # The agent never ran — no tools were called.
    print(e.reason)
    print(e.original_request)

except ScopeExpansionRequest as req:
    # CONFIRM mode: agent needs an out-of-scope action.
    # Your app decides whether to approve or deny.
    print(req.requested_action)   # "email.send"
    print(req.fn_name)            # "send_confirmation"
    print(req.turn)               # 1
    session.approve(req)

except IBACScopeViolation as e:
    # A tool call was blocked — prompt injection likely caught.
    # Message is sanitized in production_mode=True.
    print(e.action)               # "db.export"
    print(e.resource)             # "customers"
    print(e.scope.raw_intent)     # original user request
```

---

## Security architecture

```
┌──────────────────────────────────────────────────────┐
│                    User request                       │
└────────────────────┬─────────────────────────────────┘
                     │
              ┌──────▼──────┐
              │Regex scanner│  ← homoglyph-normalised. Never blocks.
              └──────┬──────┘    Logs risk score + matched patterns.
                     │
              ┌──────▼──────┐
              │  3-tier     │  ← cache → regex → LLM
              │  extractor  │    Produces immutable IBACScope.
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │Policy apply │  ← Intersects with IBACPolicy ceiling.
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │IBACEnforcer │  ← Wraps every tool before execution.
              └──────┬──────┘    Raises IBACScopeViolation on block.
                     │
           ┌──────────────────┐
           │                  │
    ✅ Permitted         ❌ Blocked
    Tool executes    IBACScopeViolation
                     Audit logged
                     Telemetry sent
```

**Defense in depth:** the detection layer logs and alerts. The IBAC enforcer always blocks. Even if every detection layer is bypassed, the scope is immutable — dangerous actions cannot execute.

---

## Performance

| Tier | Latency | Typical hit rate |
|---|---|---|
| LRU cache | ~0ms | 40–60% of requests |
| Fast regex (14 patterns) | ~2ms | 20–30% of requests |
| LLM extraction | ~200ms | 10–30% of requests |

**p50: 2ms overhead · p95: 8ms · p99: 220ms**

Run `python benchmarks/latency.py` to measure on your own workload.

---

## Supported frameworks

| Framework | Install |
|---|---|
| LangChain (AgentExecutor, LCEL) | `pip install jercept[langchain]` |
| OpenAI Agents SDK | `pip install jercept[openai-agents]` |
| CrewAI | `pip install jercept[crewai]` |
| AutoGen (ConversableAgent) | `pip install jercept[autogen]` |
| LlamaIndex (ReActAgent) | `pip install jercept[llamaindex]` |
| MCP (Model Context Protocol) | `pip install jercept[mcp]` |

---

## Self-host the dashboard

```bash
# Railway.app — one command
cd jercept-dashboard && railway up

# Docker
docker build -t jercept-dashboard .
docker run -p 8000:8000 \
  -e DATABASE_URL=postgresql+asyncpg://user:pass@host/db \
  jercept-dashboard
```

| Environment variable | Required | Description |
|---|:-:|---|
| `OPENAI_API_KEY` | ✅ | For intent extraction |
| `DATABASE_URL` | Dashboard only | PostgreSQL connection string |

---

## Contributing

```bash
git clone https://github.com/jercept/jercept
cd jercept
pip install -e ".[dev]"
pytest tests/ -v              # 321 tests
python benchmarks/latency.py  # latency profile
```

All PRs require tests for new functionality. Type hints and docstrings required on all public API. Open an issue before starting a large change.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Jercept Security](https://jercept.com).

---

<div align="center">

**"The same paradigm shift OAuth brought to web APIs, IBAC brings to agentic AI."**


</div>
