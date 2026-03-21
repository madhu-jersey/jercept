# Jercept

**Stop prompt injection at the source — not by detecting it, but by making dangerous actions impossible.**

---

## The Problem

AI agents are powerful. They can read emails, query databases, send messages, execute code. That's exactly what makes them useful — and exactly what makes them dangerous.

Here's what happens when an attacker targets an AI agent:

They hide a malicious instruction inside something the agent reads — a document, an email, a webpage. The agent reads it, follows the instruction, and exports your entire database to the attacker. Your detection system never caught it because the attack was disguised as normal text.

This happens because attackers are creative. They use Unicode characters that look identical to English letters. They write instructions that sound like system messages. They bury commands inside legitimate content. Detection always has gaps. Attackers always find them.

Jercept takes a completely different approach.

---

## How Jercept Works

Instead of trying to detect whether an instruction is malicious, Jercept asks one question at the start of every request:

**"What did the user actually ask for?"**

It extracts that intent, builds a minimal set of permissions around it, and locks that scope. From that point on, every tool call the agent makes gets checked against the scope. If a tool call wasn't permitted by the original request, it gets blocked — no matter what the LLM decided.

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

The scope is immutable. Once it's locked at the start of a request, nothing — no injected instruction, no clever phrasing, no authority claim — can expand it mid-run.

This is **IBAC — Intent-Based Access Control.**

---

## Getting Started

```bash
pip install jercept
```

Protecting your agent takes two lines:

```python
from jercept import protect_agent

agent = protect_agent(my_agent)
result = await agent.run("check billing for customer 123")
```

That's it. No configuration. No rules to write. No schema to define.

After the run, you can inspect exactly what happened:

```python
print(agent.session_scope)    # what permissions were granted
print(agent.audit_trail)      # every tool call, permitted or blocked
print(agent.was_attacked)     # True if any injection was caught
print(agent.blocked_actions)  # what the attacker tried to do
```

---

## Framework Support

Jercept works with the frameworks you're already using:

```bash
pip install jercept[langchain]        # LangChain AgentExecutor
pip install jercept[openai-agents]    # OpenAI Agents SDK
pip install jercept[mcp]              # Model Context Protocol servers
pip install jercept[crewai]           # CrewAI
pip install jercept[autogen]          # AutoGen
pip install jercept[llamaindex]       # LlamaIndex
pip install jercept[all]              # Everything
```

---

## LLM Support

Jercept works with any LLM backend. If you're running in an environment where data can't leave your network, you can use Ollama locally with no API key required.

```python
# Anthropic Claude
agent = protect_agent(my_agent, llm_provider="anthropic",
                      model="claude-3-haiku-20240307")

# Google Gemini
agent = protect_agent(my_agent, llm_provider="gemini",
                      model="gemini-1.5-flash")

# Ollama — completely local, no API key, no internet
agent = protect_agent(my_agent, llm_provider="ollama", model="llama3")
```

---

## Under The Hood

Every `agent.run()` call goes through five steps:

```
Step 1 — Injection scan      Detects homoglyphs and known patterns. Logs everything. Never blocks.
Step 2 — Intent extraction   3-tier pipeline: cache → regex → LLM
Step 3 — Scope build         Minimal permissions for this request only
Step 4 — Policy ceiling      Intersect scope with your IBACPolicy if configured
Step 5 — Tool enforcement    Every tool call checked before execution
```

The 3-tier extractor is what keeps Jercept fast:

- **Cache (0ms)** — If the same request was seen before, reuse the scope instantly. Handles 40–60% of requests.
- **Fast regex (2ms)** — Common patterns like "check billing" or "send email" get matched without hitting an LLM. Handles another 20–30%.
- **LLM fallback (~200ms)** — Novel or complex requests that need semantic understanding. Only 10–30% of requests ever reach this tier.

**p50: 2ms · p95: 8ms · p99: 220ms**

---

## Multi-Turn Agents

Single-request IBAC works well for simple agents. But real agents often need multiple turns to complete a task — a booking agent that first searches for flights, then books one, then sends a confirmation email.

`ConversationScope` handles this with controlled scope expansion:

```python
from jercept import protect_agent, ConversationScope, ExpansionMode
from jercept.policy import DEVOPS_AGENT_POLICY

session = ConversationScope(
    initial_request="book me a flight to Tokyo",
    policy=DEVOPS_AGENT_POLICY,
    expansion_mode=ExpansionMode.CONFIRM,
)
agent = protect_agent(my_agent, session=session)

# Turn 1 — api.call granted from intent
r1 = await agent.run("find the cheapest flight to Tokyo next Friday")

# Turn 2 — email.send wasn't in the original scope
# CONFIRM mode raises ScopeExpansionRequest so your app decides
r2 = await agent.run("book it and email me the confirmation")
```

Three expansion modes let you control how strictly scope is enforced:

**AUTO** — If your policy allows the action, grant it silently and continue. Good for automated pipelines.

**CONFIRM** — Raise a `ScopeExpansionRequest` and let your application decide whether to approve or deny. Good for interactive apps where a human is in the loop.

**DENY** — Never expand scope. Every action must be covered by the original request. Good for high-security environments.

```python
try:
    result = await agent.run("book flight and email me confirmation")
except ScopeExpansionRequest as req:
    print(f"Agent wants: {req.requested_action}")
    session.approve(req)
    result = await agent.run("book flight and email me confirmation")
```

---

## Policies

Policies define what an agent is allowed to do at a role level. The actual scope for any request is always the intersection of what the user asked for and what the policy permits — so users can never request more than their role allows.

```python
from jercept import IBACPolicy

policy = IBACPolicy(
    name="payments-agent",
    allowed_actions=["db.read", "api.call", "email.send"],
    denied_actions=["db.delete", "db.export", "code.execute"],
    allowed_resources=["payment.*", "invoice.*", "customer.*"],
    description="Payments agent: read and notify only.",
)
agent = protect_agent(my_agent, policy=policy)
```

If you prefer to manage policies as files rather than code, YAML is supported:

```yaml
# policies/payments_agent.yaml
name: payments-agent
allowed_actions: [db.read, api.call, email.send]
denied_actions:  [db.delete, db.export, code.execute]
allowed_resources: [payment.*, invoice.*, customer.*]
```

```python
policy = IBACPolicy.from_yaml("policies/payments_agent.yaml")
```

Jercept also ships with pre-built policies for common agent roles:

```python
from jercept.policy import (
    BILLING_AGENT_POLICY,    # db.read + email.send only
    READONLY_DB_POLICY,      # reads only, no mutations
    SUPPORT_AGENT_POLICY,    # read + communicate, nothing destructive
    DEVOPS_AGENT_POLICY,     # file ops + code execution, no db destruction
)
```

---

## Policy Linter

Before you deploy, run your policies through the linter:

```python
from jercept.linter import lint_policy

result = lint_policy(policy)
# ✗ [ERROR] wildcard_dangerous_actions: db.* implicitly permits db.export, db.delete
# ⚠ [WARNING] no_explicit_denies: denied_actions is empty

if result.has_errors:
    raise SystemExit("Fix policy errors before deploying")
```

Or from the CLI:

```bash
jercept lint policies/billing.yaml
```

---

## CLI

The `jercept preview` command shows you exactly what scope a request would generate — without running an agent:

```bash
jercept preview "check billing for customer 123"
#   Extraction tier: Fast regex (no LLM call)
#   Latency:         1.2ms
#   ✓ Allowed: db.read
#   ● Resources: customer#123
#   ✗ Denied: db.export, db.delete, code.execute
#   Confidence: 95%

jercept preview "send email to team" --provider anthropic
jercept preview "run the script" --provider ollama --model llama3
```

---

## MCP Server Protection

Jercept wraps Model Context Protocol servers with the same enforcement:

```python
from jercept import protect_agent

agent = protect_agent(my_mcp_server)
result = await agent.run("read the project config file")
```

33 MCP tool mappings are built in, covering `read_file`, `write_file`, `execute_command`, `bash`, `web_search`, `database_query`, `send_email`, `github_create`, `slack_post`, and more.

---

## Session Persistence

Sessions survive pod restarts and scale-out by serializing to JSON:

```python
import json
from jercept import ConversationScope, ExpansionMode

# Save after each turn
state_json = json.dumps(session.to_dict())
redis.set(f"session:{user_id}", state_json, ex=3600)

# Restore on the next request
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

## Action Taxonomy

All IBAC actions use dot-notation namespaces so tool mapping is predictable:

| Action | What it covers |
|---|---|
| `db.read` | Reading from a database |
| `db.write` | Inserting or updating records |
| `db.export` | Bulk data export |
| `db.delete` | Deleting records |
| `file.read` | Reading files |
| `file.write` | Writing or creating files |
| `file.upload` | Uploading to a service |
| `file.download` | Downloading from a service |
| `email.read` | Reading emails |
| `email.send` | Sending emails or messages |
| `api.call` | External API or webhook calls |
| `web.browse` | Web browsing or search |
| `code.execute` | Running code or shell commands |

---

## Exceptions

```python
from jercept import IBACScopeViolation, IBACExtractionFailed, ScopeExpansionRequest

try:
    result = await agent.run(user_input)

except IBACExtractionFailed as e:
    # Request was too ambiguous to build a safe scope.
    # The agent never ran — no tools were called.
    print(e.reason)

except ScopeExpansionRequest as req:
    # CONFIRM mode: agent needs an action outside the current scope.
    print(req.requested_action)
    session.approve(req)

except IBACScopeViolation as e:
    # A tool call was blocked. Prompt injection was likely caught.
    print(e.action)           # what was attempted
    print(e.scope.raw_intent) # the original user request
```

---

## Monitoring

Connect to the real-time dashboard to see every tool call, block rate over time, and per-session audit trails:

```python
agent = protect_agent(my_agent, telemetry_key="jercept_live_xxxx")
```

Get a free key at **jercept.com**.

---

## Contributing

```bash
git clone https://github.com/jercept/jercept
cd jercept
pip install -e ".[dev]"
pytest tests/ -v
python benchmarks/latency.py
```

Open an issue before starting a large change. All PRs need tests and type hints on public API.

---

## License

MIT — see [LICENSE](LICENSE).
