/**
 * Jercept protectAgent — main entry point for the JavaScript SDK.
 *
 * Wraps any AI agent or function with IBAC protection.
 * Uses a 3-tier extraction pipeline: fast regex → LLM fallback.
 */

import { IBACScope } from "./scope.js";
import { scanInput, ScanResult } from "./scanner.js";
import { tryFastExtract } from "./fast-extractor.js";
import { llmExtract, ExtractorOptions, IBACExtractionError } from "./extractor.js";
import { IBACEnforcer, AuditEntry, IBACScopeViolation } from "./enforcer.js";

export { IBACScope, IBACScopeViolation, IBACExtractionError, AuditEntry };

export interface ProtectOptions extends ExtractorOptions {
  /** Disable LRU cache for extraction. Default: false (cache enabled). */
  noCache?: boolean;
  /** Disable fast regex extractor. Default: false (enabled). */
  noFastExtract?: boolean;
  /** Jercept dashboard API key for telemetry. */
  telemetryKey?: string;
  /** Dashboard API base URL. Default: https://api.jercept.com */
  telemetryUrl?: string;
}

export interface RunResult<T> {
  result: T;
  scope: IBACScope;
  wasAttacked: boolean;
  blockedActions: string[];
  auditTrail: readonly AuditEntry[];
  scanResult: ScanResult;
  extractionTier: "cache" | "regex" | "llm";
}

// Simple LRU cache — Map maintains insertion order, just delete+re-set for LRU
const _scopeCache = new Map<string, IBACScope>();
const MAX_CACHE = 200;

function cacheGet(key: string): IBACScope | undefined {
  const val = _scopeCache.get(key);
  if (val) {
    _scopeCache.delete(key);
    _scopeCache.set(key, val);
  }
  return val;
}

function cacheSet(key: string, scope: IBACScope): void {
  if (_scopeCache.size >= MAX_CACHE) {
    _scopeCache.delete(_scopeCache.keys().next().value!);
  }
  _scopeCache.set(key, scope);
}

async function sendTelemetry(
  telemetryKey: string,
  baseUrl: string,
  sessionId: string,
  scope: IBACScope,
  enforcer: IBACEnforcer,
  agentType: string,
  tier: string,
): Promise<void> {
  try {
    await fetch(`${baseUrl}/v1/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${telemetryKey}`,
      },
      body: JSON.stringify({
        session_id: sessionId,
        events: enforcer.auditLog.map(e => ({
          action: e.action,
          resource: e.resource,
          permitted: e.permitted,
          fn_name: e.fnName,
          ts: e.ts / 1000,
        })),
        scope: {
          allowed_actions: scope.allowedActions,
          allowed_resources: scope.allowedResources,
          denied_actions: scope.deniedActions,
          raw_intent: scope.rawIntent,
          confidence: scope.confidence,
          extraction_tier: tier,
        },
        sdk_version: "1.0.0",
        agent_type: agentType,
      }),
    });
  } catch {
    // Telemetry is fire-and-forget — never block the caller
  }
}

/**
 * Protect any async function with IBAC enforcement.
 *
 * The wrapped function receives an IBACEnforcer as its last argument.
 * Use `enforcer.check(action)` or `enforcer.wrap(fn, action)` inside.
 *
 * @example
 * ```ts
 * import { protectAgent } from "jercept";
 *
 * // Basic usage
 * const run = protectAgent(
 *   async (userInput: string, enforcer) => {
 *     enforcer.check("db.read", "customer#123");
 *     return await myAgent.run(userInput);
 *   }
 * );
 *
 * const { result, wasAttacked, blockedActions } =
 *   await run("check billing for customer 123");
 *
 * // With Anthropic provider
 * const run2 = protectAgent(myFn, { provider: "anthropic" });
 *
 * // With local Ollama
 * const run3 = protectAgent(myFn, { provider: "ollama", model: "llama3" });
 * ```
 */
export function protectAgent<TArgs extends [string, ...unknown[]], TResult>(
  fn: (userInput: string, enforcer: IBACEnforcer, ...rest: unknown[]) => Promise<TResult>,
  opts: ProtectOptions = {},
): (userInput: string, ...rest: unknown[]) => Promise<RunResult<TResult>> {

  const sessionId = Math.random().toString(36).slice(2);
  const baseUrl = opts.telemetryUrl ?? "https://api.jercept.com";

  return async (userInput: string, ...rest: unknown[]): Promise<RunResult<TResult>> => {
    const truncated = userInput.length > 10_000 ? userInput.slice(0, 10_000) : userInput;

    // Tier 1: Injection scan (never blocks)
    const scanResult = scanInput(truncated);
    if (scanResult.isSuspicious) {
      console.warn(
        `[Jercept] Injection detected: risk=${scanResult.riskScore} patterns=${scanResult.matchedPatterns.join(",")}`
      );
    }

    // Tier 2: Cache
    let scope: IBACScope | null = null;
    let extractionTier: "cache" | "regex" | "llm" = "llm";

    if (!opts.noCache) {
      const cached = cacheGet(truncated);
      if (cached) {
        scope = cached;
        extractionTier = "cache";
      }
    }

    // Tier 3: Fast regex
    if (!scope && !opts.noFastExtract) {
      const fast = tryFastExtract(truncated);
      if (fast) {
        scope = fast;
        extractionTier = "regex";
      }
    }

    // Tier 4: LLM
    if (!scope) {
      scope = await llmExtract(truncated, opts);
      extractionTier = "llm";
    }

    // Cache the result
    if (!opts.noCache && scope) {
      cacheSet(truncated, scope);
    }

    // Create enforcer and run the function
    const enforcer = new IBACEnforcer(scope);
    const result = await fn(userInput, enforcer, ...rest);

    // Fire-and-forget telemetry
    if (opts.telemetryKey) {
      void sendTelemetry(
        opts.telemetryKey, baseUrl, sessionId,
        scope, enforcer, "js-agent", extractionTier
      );
    }

    return {
      result,
      scope,
      wasAttacked: enforcer.wasAttacked,
      blockedActions: enforcer.blockedActions,
      auditTrail: enforcer.auditLog,
      scanResult,
      extractionTier,
    };
  };
}
