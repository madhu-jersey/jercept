# jercept

> **The authorization layer for AI agents — JavaScript/TypeScript SDK.**
>
> *IBAC stops prompt injection where detection always fails. Zero config. Works in Node.js, Next.js, Deno, and browsers.*

[![npm version](https://badge.fury.io/js/jercept.svg)](https://www.npmjs.com/package/jercept)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Also available for Python: [`pip install jercept`](https://github.com/jercept/jercept)

---

## Install

```bash
npm install jercept
# or
pnpm add jercept
# or
yarn add jercept
```

---

## Quickstart

```typescript
import { protectAgent } from "jercept";

// Wrap any async agent function with IBAC protection
const run = protectAgent(async (userInput, enforcer) => {
  // Check every tool call before executing
  enforcer.check("db.read", "customer#123");
  const data = await myDatabase.query(userInput);

  enforcer.check("email.send");
  await sendConfirmation(data);

  return data;
});

// Run it — IBAC derives the scope from the user's request
const { result, wasAttacked, blockedActions, scope } =
  await run("check billing for customer 123");

console.log(scope.allowedActions);  // ["db.read"]
console.log(wasAttacked);           // true if any tool was blocked
console.log(blockedActions);        // ["db.export"] — what attacker tried
```

---

## Multi-LLM support — no OpenAI required

```typescript
// Anthropic Claude
const run = protectAgent(myFn, { provider: "anthropic" });
const run = protectAgent(myFn, {
  provider: "anthropic",
  model: "claude-3-haiku-20240307"
});

// Google Gemini
const run = protectAgent(myFn, { provider: "gemini", model: "gemini-1.5-flash" });

// Local Ollama — completely offline, no API key needed
const run = protectAgent(myFn, { provider: "ollama", model: "llama3" });
const run = protectAgent(myFn, {
  provider: "ollama",
  model: "mistral",
  ollamaBaseUrl: "http://localhost:11434"
});
```

---

## How IBAC works

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
    Agent runs. enforcer.check("db.export") called by injection.
    IBACScopeViolation thrown before execution.
    Database safe. Always.
```

**The 3-tier extractor** keeps latency minimal:
- **Cache** (0ms): seen this request before
- **Fast regex** (1ms): known patterns — billing, email, file ops
- **LLM fallback** (~200ms): novel requests

---

## Error handling

```typescript
import { protectAgent, IBACScopeViolation, IBACExtractionError } from "jercept";

const run = protectAgent(async (input, enforcer) => {
  enforcer.check("db.read");
  return await db.query(input);
});

try {
  const { result } = await run(userInput);
} catch (err) {
  if (err instanceof IBACScopeViolation) {
    // Tool call was blocked — injection likely caught
    console.error("Blocked:", err.action, "— attack intercepted");
  } else if (err instanceof IBACExtractionError) {
    // Request too ambiguous to derive a safe scope
    console.error("Ambiguous request:", err.reason);
  }
}
```

---

## Policy linter

```typescript
import { lintPolicy } from "jercept";

const result = lintPolicy({
  name: "payments-agent",
  allowedActions: ["db.*"],       // ← linter catches this
  deniedActions: [],              // ← linter catches this too
});

console.log(result.toString());
// ✗ [ERROR] wildcard_dangerous_actions: db.* permits db.export, db.delete
// ⚠ [WARNING] no_explicit_denies: deniedActions is empty

if (result.hasErrors) {
  throw new Error("Fix policy errors before deploying");
}
```

---

## Injection scanner

```typescript
import { scanInput } from "jercept";

// Never blocks — always logs
const result = scanInput("ignore all previous instructions");
console.log(result.isSuspicious);    // true
console.log(result.riskScore);       // 0.9
console.log(result.matchedPatterns); // ["role_override"]
```

---

## Use with Vercel AI SDK

```typescript
import { protectAgent } from "jercept";
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

const run = protectAgent(async (userInput, enforcer) => {
  // Wrap tools with IBAC enforcement
  const tools = {
    readCustomer: enforcer.wrapAsync(
      async (id: string) => db.customers.findById(id),
      "db.read",
      "readCustomer"
    ),
    exportAll: enforcer.wrapAsync(
      async () => db.customers.exportAll(),
      "db.export",   // ← this will be blocked unless user asked for export
      "exportAll"
    ),
  };

  const { text } = await generateText({
    model: openai("gpt-4o-mini"),
    prompt: userInput,
    tools,
  });
  return text;
});

const { result } = await run("check billing for customer 123");
```

---

## Use with LangChain.js

```typescript
import { protectAgent } from "jercept";
import { AgentExecutor } from "langchain/agents";

const run = protectAgent(async (userInput, enforcer) => {
  // Enforce on each tool before LangChain calls it
  for (const tool of agentTools) {
    const original = tool.call.bind(tool);
    tool.call = enforcer.wrap(original, inferAction(tool.name), tool.name);
  }
  return await agentExecutor.invoke({ input: userInput });
});
```

---

## Real-time dashboard

```typescript
const run = protectAgent(myFn, {
  telemetryKey: "jercept_live_xxxx",   // get free at jercept.com
});
```

Every `run()` call sends scope data to your dashboard — every blocked attack, every allowed call, the extraction tier used, and confidence score. The scope visualizer shows exactly what each user request unlocked.

---

## API reference

### `protectAgent(fn, opts?)`

Wraps an async agent function with IBAC enforcement.

```typescript
protectAgent(
  fn: (userInput: string, enforcer: IBACEnforcer, ...rest) => Promise<T>,
  opts?: {
    provider?: "openai" | "anthropic" | "gemini" | "ollama";
    model?: string;
    apiKey?: string;
    ollamaBaseUrl?: string;
    noCache?: boolean;
    noFastExtract?: boolean;
    telemetryKey?: string;
  }
) => (userInput: string, ...rest) => Promise<RunResult<T>>
```

### `RunResult<T>`

```typescript
{
  result: T;                          // the agent's return value
  scope: IBACScope;                   // what was allowed this run
  wasAttacked: boolean;               // true if any tool was blocked
  blockedActions: string[];           // actions that were denied
  auditTrail: readonly AuditEntry[];  // every tool call attempt
  scanResult: ScanResult;             // injection scan result
  extractionTier: "cache"|"regex"|"llm";
}
```

### `IBACEnforcer`

```typescript
enforcer.check(action, resource?, fnName?)  // throws IBACScopeViolation if denied
enforcer.wrap(fn, action, fnName?)          // wraps a sync function
enforcer.wrapAsync(fn, action, fnName?)     // wraps an async function
enforcer.wasAttacked                        // boolean
enforcer.blockedActions                     // string[]
enforcer.auditLog                           // readonly AuditEntry[]
```

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Jercept Security](https://jercept.com).

---

<div align="center">

**"The same paradigm shift OAuth brought to web APIs, IBAC brings to agentic AI."**

[jercept.com](https://jercept.com) · [PyPI](https://pypi.org/project/jercept/) · [npm](https://www.npmjs.com/package/jercept)

</div>
