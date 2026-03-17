/**
 * Jercept JavaScript/TypeScript SDK v1.0.0
 *
 * The authorization layer for AI agents.
 * IBAC stops prompt injection where detection always fails.
 *
 * @example
 * ```ts
 * import { protectAgent } from "jercept";
 *
 * // Wrap any async agent function
 * const run = protectAgent(async (input, enforcer) => {
 *   enforcer.check("db.read", "customer#123");
 *   return await myAgent.run(input);
 * });
 *
 * const { result, wasAttacked, blockedActions } =
 *   await run("check billing for customer 123");
 *
 * // With Anthropic Claude
 * const run2 = protectAgent(myFn, { provider: "anthropic" });
 *
 * // With local Ollama — no API key needed
 * const run3 = protectAgent(myFn, { provider: "ollama", model: "llama3" });
 * ```
 *
 * @packageDocumentation
 */

export {
  // Core
  protectAgent,
  type ProtectOptions,
  type RunResult,
} from "./protect.js";

export {
  // Scope
  createScope,
  permits,
  scopeToDict,
  scopeFromDict,
  globMatch,
  VALID_ACTIONS,
  DANGEROUS_ACTIONS,
  MAX_INPUT_LENGTH,
  type IBACScope,
  type IBACAction,
} from "./scope.js";

export {
  // Scanner
  scanInput,
  type ScanResult,
} from "./scanner.js";

export {
  // Fast extractor
  tryFastExtract,
} from "./fast-extractor.js";

export {
  // LLM extractor
  llmExtract,
  IBACExtractionError,
  type ExtractorOptions,
  type LLMProvider,
} from "./extractor.js";

export {
  // Enforcer
  IBACEnforcer,
  IBACScopeViolation,
  type AuditEntry,
} from "./enforcer.js";

export {
  // Linter
  lintPolicy,
  type JerceptPolicy,
  type LintResult,
  type LintFinding,
  type LintSeverity,
} from "./linter.js";

export const VERSION = "1.0.0";
