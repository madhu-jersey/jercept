/**
 * Jercept fast regex extractor — tier 2 of the 3-tier pipeline.
 *
 * Matches common request patterns in ~1ms without an LLM call.
 * Returns null if no pattern matches (falls through to LLM tier).
 */

import { IBACScope, createScope } from "./scope.js";

interface FastPattern {
  pattern: RegExp;
  allowedActions: string[];
  allowedResources?: string[];
  deniedActions: string[];
}

const ALL_DANGEROUS = ["db.export", "db.delete", "code.execute", "file.download"];
const ALL_ACTIONS = [
  "db.read","db.write","db.export","db.delete",
  "file.read","file.write","file.upload","file.download",
  "email.read","email.send","api.call","web.browse","code.execute",
];

const FAST_PATTERNS: FastPattern[] = [
  // Billing / financial read
  {
    pattern: /\b(check|view|show|get|fetch|look up|read|retrieve).{0,30}(billing|invoice|payment|charge|subscription|balance|account)/i,
    allowedActions: ["db.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "db.read"),
  },
  // Email read
  {
    pattern: /\b(check|read|fetch|get|show|view).{0,20}(email|inbox|mail|message)/i,
    allowedActions: ["email.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "email.read"),
  },
  // Email send
  {
    pattern: /\b(send|email|forward|draft|compose|write).{0,20}(email|message|notification|report|confirmation|alert)/i,
    allowedActions: ["email.send"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "email.send"),
  },
  // File read
  {
    pattern: /\b(read|open|load|view|show|get|fetch|parse).{0,20}(file|document|config|log|csv|pdf|txt|json|yaml)/i,
    allowedActions: ["file.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "file.read"),
  },
  // File write
  {
    pattern: /\b(write|save|create|update|edit|modify|generate).{0,20}(file|document|report|output)/i,
    allowedActions: ["file.write"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "file.write"),
  },
  // Web search/browse
  {
    pattern: /\b(search|browse|look up|find|google|research|fetch from|visit).{0,30}(web|internet|online|site|url|page)/i,
    allowedActions: ["web.browse"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "web.browse"),
  },
  // DB read
  {
    pattern: /\b(query|select|fetch|get|retrieve|look up|check|find|show|list|count).{0,30}(record|row|entry|customer|user|account|order|product|data|database|table)/i,
    allowedActions: ["db.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "db.read"),
  },
  // DB write
  {
    pattern: /\b(update|modify|change|set|insert|add|create|upsert).{0,30}(record|row|entry|customer|user|account|order|database)/i,
    allowedActions: ["db.write"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "db.write"),
  },
  // Code execution
  {
    pattern: /\b(run|execute|exec|launch|start).{0,20}(script|command|code|program|test|job|task|workflow)/i,
    allowedActions: ["code.execute"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "code.execute"),
  },
  // API call
  {
    pattern: /\b(call|hit|invoke|trigger|request|post to|send to).{0,20}(api|endpoint|webhook|service|integration)/i,
    allowedActions: ["api.call"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "api.call"),
  },
  // Account / balance lookup
  {
    pattern: /\b(what is|show me|get|check|fetch).{0,20}(balance|account|status|credit|limit)/i,
    allowedActions: ["db.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "db.read"),
  },
  // Pull up / look up
  {
    pattern: /\b(pull up|look up|bring up|display).{0,30}(account|record|profile|customer|user)/i,
    allowedActions: ["db.read"],
    deniedActions: ALL_ACTIONS.filter(a => a !== "db.read"),
  },
];

/**
 * Try to extract a scope using fast regex patterns.
 *
 * @param request - The user's natural language request.
 * @returns An IBACScope if a pattern matched, or null to fall through to LLM.
 */
export function tryFastExtract(request: string): IBACScope | null {
  const truncated = request.length > 10_000 ? request.slice(0, 10_000) : request;

  for (const fp of FAST_PATTERNS) {
    if (fp.pattern.test(truncated)) {
      return createScope({
        allowedActions: fp.allowedActions,
        allowedResources: fp.allowedResources ?? [],
        deniedActions: fp.deniedActions,
        rawIntent: request,
        confidence: 0.85,
        ambiguous: false,
      });
    }
  }
  return null;
}
